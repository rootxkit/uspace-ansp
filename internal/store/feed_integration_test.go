//go:build integration

package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/sources"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// The sources writer's repo: each Set commits the row with the next
// version taken under the lock, records the audit event, and returns the
// whole state with the epoch; Load reads the same state.
func TestIntegrationSourcesRepo(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	repo := store.SourcesRepo{DB: storetest.Relational(t, dsn, store.RoleRelational)}
	empty, err := repo.Load(ctx)
	if err != nil || empty.Version != 0 || len(empty.Controls) != 0 || empty.Epoch == "" {
		t.Fatalf("empty: %+v %v", empty, err)
	}
	inst := "adsb-tbs"
	row, doc, err := repo.Set(ctx, sources.Change{SourceType: "manned", InstanceID: &inst, Enabled: false, Reason: "maintenance", Actor: "admin1"})
	if err != nil || row.Enabled || row.Actor != "admin1" || doc.Version == 0 || len(doc.Controls) != 1 || doc.Epoch != empty.Epoch {
		t.Fatalf("set: %+v %+v %v", row, doc, err)
	}
	_, doc2, err := repo.Set(ctx, sources.Change{SourceType: "manned", Enabled: true, Reason: "type on", Actor: "admin1"})
	if err != nil || doc2.Version <= doc.Version || len(doc2.Controls) != 2 {
		t.Fatalf("second: %+v %v", doc2, err)
	}
	loaded, err := repo.Load(ctx)
	if err != nil || loaded.Version != doc2.Version || len(loaded.Controls) != 2 || loaded.Controls[0].InstanceID != nil {
		t.Fatalf("load: %+v %v", loaded, err)
	}
	if n := scalar[int64](t, dsn, `SELECT count(*) FROM events WHERE event_type = 'source_control_set' AND entity_id = 'manned/adsb-tbs'`); n != 1 {
		t.Fatalf("audit events %d", n)
	}
	// Concurrent writers: the versions follow the commit order, so the
	// state each returns is never older than one committed before it.
	var wg sync.WaitGroup
	versions := make(chan uint64, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, d, err := repo.Set(ctx, sources.Change{SourceType: "manned", InstanceID: &inst, Enabled: true, Reason: "r", Actor: "a"})
			if err != nil {
				t.Error(err)
				return
			}
			versions <- d.Version
		}()
	}
	wg.Wait()
	close(versions)
	seen := map[uint64]bool{}
	for v := range versions {
		if seen[v] {
			t.Fatalf("two commits returned state version %d", v)
		}
		seen[v] = true
	}
}

// A sample delivered twice (the mirror replay, a redelivery) lands once;
// the twin: a new msg_id lands.
func TestIntegrationMannedTracksDeduplicatedByMsgID(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	db := storetest.Timeseries(t, dsn, store.RoleTimeseries)
	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	batch := rows(3, base)
	ids := []string{"01K6N5SXS5AA819X9YP981068A", "01K6N5SXS5AA819X9YP981068B", "01K6N5SXS5AA819X9YP981068C"}
	for i := range batch {
		batch[i].MsgID = &ids[i]
	}
	w := db.Writer()
	if n, err := w.Insert(ctx, batch); err != nil || n != 3 {
		t.Fatalf("first: %d %v", n, err)
	}
	// The same three again, plus a repeat inside the batch.
	again := append(append([]timeseries.MannedTrackRow(nil), batch...), batch[0])
	if n, err := w.Insert(ctx, again); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	fresh := rows(1, base.Add(time.Hour))
	id := "01K6N5SXS5AA819X9YP981068D"
	fresh[0].MsgID = &id
	if n, err := w.Insert(ctx, fresh); err != nil || n != 1 {
		t.Fatalf("fresh: %d %v", n, err)
	}
	if n := scalar[int64](t, dsn, `SELECT count(*) FROM manned_tracks`); n != 4 {
		t.Fatalf("rows %d", n)
	}
	// Rows without a msg_id are never taken for duplicates.
	plain := rows(2, base)
	if n, err := w.Insert(ctx, plain); err != nil || n != 2 {
		t.Fatalf("without msg_id: %d %v", n, err)
	}
}

// projectionSpy records what Accounts tells the live-session projection.
type projectionSpy struct {
	mu      sync.Mutex
	started []string
	ended   []string
}

func (p *projectionSpy) Started(_ context.Context, jti string, _ auth.LiveSession) {
	p.mu.Lock()
	p.started = append(p.started, jti)
	p.mu.Unlock()
}

func (p *projectionSpy) Ended(_ context.Context, jtis ...string) {
	p.mu.Lock()
	p.ended = append(p.ended, jtis...)
	p.mu.Unlock()
}

// The live-session listing on the database clock (docs/PLAN.md section
// 15 row 21): a signed-in session is listed and told to the projection
// after its commit; after logout it is no longer listed and the
// projection is told it ended; an idle session is not listed.
func TestIntegrationLiveSessionsListing(t *testing.T) {
	ctx := ctxT(t)
	w := newAuthWorld(t)
	spy := &projectionSpy{}
	w.accounts.SetProjection(spy)
	if _, err := w.accounts.CreateUser(ctx, auth.Principal{}, "view1", authPW, auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	lr, err := w.accounts.Login(ctx, "view1", authPW, auth.RequestInfo{RemoteIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, code(t, lr.Enrolment.Secret, time.Now()), auth.RequestInfo{RemoteIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.started) != 1 || spy.started[0] != res.JTI {
		t.Fatalf("started %v", spy.started)
	}
	rows, err := w.repo.LiveSessions(ctx, auth.SessionIdleTimeout, 10)
	if err != nil || len(rows) != 1 || rows[0].JTI != res.JTI || rows[0].Role != auth.RoleViewer {
		t.Fatalf("listed %+v %v", rows, err)
	}
	// Idle: last_seen_at older than the idle bound on the database clock.
	if err := exec(t, w.dsn, `UPDATE user_sessions SET last_seen_at = now() - interval '31 minutes' WHERE jti = $1`, res.JTI); err != nil {
		t.Fatal(err)
	}
	if rows, _ := w.repo.LiveSessions(ctx, auth.SessionIdleTimeout, 10); len(rows) != 0 {
		t.Fatalf("an idle session listed: %+v", rows)
	}
	// Seen in use by the feed (ctl.sessions.seen): live again.
	if err := w.accounts.SessionSeen(ctx, res.JTI); err != nil {
		t.Fatal(err)
	}
	if rows, _ := w.repo.LiveSessions(ctx, auth.SessionIdleTimeout, 10); len(rows) != 1 {
		t.Fatal("a session seen in use is not listed")
	}
	cl, err := w.sessions.Verify(ctx, res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.accounts.Logout(ctx, auth.Principal{Session: true, Claims: cl}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := w.repo.LiveSessions(ctx, auth.SessionIdleTimeout, 10); len(rows) != 0 || len(spy.ended) != 1 || spy.ended[0] != res.JTI {
		t.Fatalf("after logout: rows %+v ended %v", rows, spy.ended)
	}
}
