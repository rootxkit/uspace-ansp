//go:build integration

package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

func record(t *testing.T, db *store.Relational, n int) []audit.Recorded {
	t.Helper()
	var out []audit.Recorded
	for i := range n {
		err := db.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
			r, err := audit.Record(ctx, tx, audit.Event{
				ActorType: audit.ActorUser, ActorID: "u-1", Purpose: "test", EntityType: "restriction",
				EntityID: "r-" + string(rune('a'+i%3)), EventType: "restriction_planned",
				Payload: map[string]any{"i": i, "note": "<b>", "nested": map[string]any{"z": 1.5, "a": nil}},
			})
			out = append(out, r)
			return err
		})
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	return out
}

func verify(t *testing.T, db *store.Relational, month time.Time) (bool, *int64, audit.Result) {
	t.Helper()
	var ok bool
	var broken *int64
	var res audit.Result
	err := db.Do(context.Background(), func(ctx context.Context, c relational.DBTX, _ *relational.Queries) error {
		var err error
		if ok, broken, err = audit.Verify(ctx, c, month); err != nil {
			return err
		}
		res, err = audit.VerifyMonth(ctx, c, month)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ok, broken, res
}

// The chain verifies (and says over how many rows); a row tampered with
// by a superuser behind the trigger is found by id (E-01 pair).
func TestIntegrationChainVerifiesAndFindsTampering(t *testing.T) {
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	recs := record(t, db, 5)
	if recs[0].PrevHash != audit.GenesisHash {
		t.Fatalf("first row links to %s", recs[0].PrevHash)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].PrevHash != recs[i-1].Hash || recs[i].ID <= recs[i-1].ID {
			t.Fatalf("row %d does not link to row %d", i, i-1)
		}
	}
	month := recs[0].TS
	ok, broken, res := verify(t, db, month)
	if !ok || broken != nil || res.Rows != 5 || res.FirstID != recs[0].ID || res.LastID != recs[4].ID || res.LastHash != recs[4].Hash {
		t.Fatalf("intact chain: ok %v broken %v %+v", ok, broken, res)
	}
	// An empty month is ok with zero rows.
	if ok, broken, res := verify(t, db, month.AddDate(-1, 0, 0)); !ok || broken != nil || res.Rows != 0 {
		t.Fatalf("empty month: %v %v %+v", ok, broken, res)
	}

	tamper(t, dsn, `UPDATE events SET payload = '{"i": 99}' WHERE id = $1`, recs[2].ID)
	ok, broken, res = verify(t, db, month)
	if ok || broken == nil || *broken != recs[2].ID || res.Reason != audit.BrokenHash {
		t.Fatalf("tampered payload: ok %v broken %v %+v", ok, broken, res)
	}
	tamper(t, dsn, `UPDATE events SET prev_hash = repeat('2', 64) WHERE id = $1`, recs[1].ID)
	ok, broken, res = verify(t, db, month)
	if ok || *broken != recs[1].ID || res.Reason != audit.BrokenPrevHash {
		t.Fatalf("tampered link: %v %v %+v", ok, broken, res)
	}
}

// tamper rewrites events behind the append-only trigger, as only a
// superuser could.
func tamper(t *testing.T, dsn, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if tag, err := conn.Exec(ctx, sql, args...); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("tamper: %v %v", tag, err)
	}
}

// The first row of a month links to the last row of an earlier month.
func TestIntegrationFirstRowOfAMonthLinksBack(t *testing.T) {
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	// A row in an earlier month, written with the same hash rule (as the
	// owner; the application cannot back-date).
	earlier := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	row := audit.Row{
		ID: 1, TS: earlier, ActorType: "system", ActorID: "seed", Purpose: "test", EntityType: "test",
		EntityID: "1", EventType: "seeded", Payload: []byte(`{}`), PrevHash: audit.GenesisHash,
	}
	h, err := audit.Hash(&row)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT events_ensure_partition($1)`, earlier); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SELECT setval('events_id_seq', 1)`); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, `INSERT INTO events (id, ts, actor_type, actor_id, purpose, entity_type, entity_id, event_type, payload, prev_hash, hash)
		VALUES (1, $1, 'system', 'seed', 'test', 'test', '1', 'seeded', '{}', $2, $3)`, earlier, audit.GenesisHash, h)
	if err != nil {
		t.Fatal(err)
	}
	recs := record(t, db, 2)
	if recs[0].PrevHash != h || recs[0].ID != 2 {
		t.Fatalf("first row of the month links to %s (want %s), id %d", recs[0].PrevHash, h, recs[0].ID)
	}
	for _, m := range []time.Time{earlier, recs[0].TS} {
		if ok, broken, _ := verify(t, db, m); !ok || broken != nil {
			t.Fatalf("%s: %v %v", m.Format("2006-01"), ok, broken)
		}
	}
}

// Query pages newest first and filters by entity.
func TestIntegrationQuery(t *testing.T) {
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	recs := record(t, db, 7)
	var pages []audit.Page
	err := db.Do(context.Background(), func(ctx context.Context, c relational.DBTX, _ *relational.Queries) error {
		f := audit.Filter{Limit: 3}
		for {
			p, err := audit.Query(ctx, c, f)
			if err != nil {
				return err
			}
			pages = append(pages, p)
			if p.Next == 0 {
				break
			}
			f.Before = p.Next
		}
		p, err := audit.Query(ctx, c, audit.Filter{EntityType: "restriction", EntityID: "r-a"})
		pages = append(pages, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 4 || len(pages[0].Events) != 3 || pages[0].Events[0].ID != recs[6].ID ||
		len(pages[2].Events) != 1 || pages[2].Events[0].ID != recs[0].ID {
		t.Fatalf("pages %+v", pages)
	}
	only := pages[3].Events
	if len(only) != 3 || only[0].EntityID != "r-a" || !strings.Contains(string(only[0].Payload), `"<b>"`) {
		t.Fatalf("filtered %+v", only)
	}
}
