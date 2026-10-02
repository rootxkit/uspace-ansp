//go:build integration

package store_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// exec runs sql on dsn as the login role (the owner in these tests).
func exec(t *testing.T, dsn, sql string, args ...any) error {
	t.Helper()
	conn, err := pgx.Connect(ctxT(t), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctxT(t), sql, args...)
	return err
}

func scalar[T any](t *testing.T, dsn, sql string, args ...any) T {
	t.Helper()
	conn, err := pgx.Connect(ctxT(t), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var v T
	if err := conn.QueryRow(ctxT(t), sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return v
}

func tableExists(t *testing.T, dsn, table string) bool {
	return scalar[bool](t, dsn, `SELECT to_regclass($1) IS NOT NULL`, table)
}

func extensionInstalled(t *testing.T, dsn, ext string) bool {
	return scalar[bool](t, dsn, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)`, ext)
}

// Both trees, each in its own scratch database: up, down to zero, up
// again; a second up applies nothing; a Down that leaves something
// behind fails the second up.
func TestIntegrationTreesUpDownUp(t *testing.T) {
	for _, tc := range []struct {
		tree      store.Tree
		tables    []string
		extension string
	}{
		{store.TreeRelational, []string{"events", "ansp_policy", "source_controls", "source_control_epoch", "restrictions", "restriction_versions", "restriction_requests", "adapters"}, "postgis"},
		{store.TreeTimeseries, []string{"manned_tracks", "feed_products"}, "timescaledb"},
	} {
		t.Run(tc.tree.Name, func(t *testing.T) {
			ctx := ctxT(t)
			dsn := storetest.Scratch(t, tc.tree, false)
			latest, err := store.Latest(tc.tree)
			if err != nil {
				t.Fatal(err)
			}
			for round := 1; round <= 2; round++ {
				res, err := store.Migrate(ctx, dsn, tc.tree)
				if err != nil {
					t.Fatalf("round %d up: %v", round, err)
				}
				if res.From != 0 || res.To != latest || res.Applied != int(latest) {
					t.Fatalf("round %d up: %+v, latest %d", round, res, latest)
				}
				for _, table := range append([]string{tc.tree.VersionTable}, tc.tables...) {
					if !tableExists(t, dsn, table) {
						t.Fatalf("round %d: %s missing after up", round, table)
					}
				}
				for _, other := range store.Trees() {
					if other.Name != tc.tree.Name && tableExists(t, dsn, other.VersionTable) {
						t.Fatalf("the %s database holds %s", tc.tree.Name, other.VersionTable)
					}
				}
				again, err := store.Migrate(ctx, dsn, tc.tree)
				if err != nil || again.Applied != 0 || again.From != latest || again.To != latest {
					t.Fatalf("round %d second up: %+v %v", round, again, err)
				}
				if err := store.DownTo(ctx, dsn, tc.tree, 0); err != nil {
					t.Fatalf("round %d down: %v", round, err)
				}
				for _, table := range tc.tables {
					if tableExists(t, dsn, table) {
						t.Fatalf("round %d: %s left after down", round, table)
					}
				}
				if extensionInstalled(t, dsn, tc.extension) {
					t.Fatalf("round %d: %s left after down", round, tc.extension)
				}
			}
			if _, err := store.Migrate(ctx, dsn, tc.tree); err != nil {
				t.Fatalf("final up: %v", err)
			}
		})
	}
}

// A tree run against the other tree's database fails on the version
// table, and names both (docs/PLAN.md 5.3).
func TestIntegrationTreeRefusesTheOtherDatabase(t *testing.T) {
	ctx := ctxT(t)
	tsDSN := storetest.Scratch(t, store.TreeTimeseries, true)
	_, err := store.Migrate(ctx, tsDSN, store.TreeRelational)
	if !errors.Is(err, store.ErrWrongDatabase) || !strings.Contains(err.Error(), "goose_db_version_timeseries") {
		t.Fatalf("relational tree on the timeseries database: %v", err)
	}
	if tableExists(t, tsDSN, "events") {
		t.Fatal("the refused tree left events behind")
	}
}

// RequireVersion: a schema one migration behind is refused with the
// tree, the present and the needed version; the current one passes; a
// database never migrated is version 0.
func TestIntegrationRequireVersion(t *testing.T) {
	ctx := ctxT(t)
	latest, _ := store.Latest(store.TreeRelational)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	if err := db.RequireVersion(ctx, latest); err != nil {
		t.Fatalf("current schema refused: %v", err)
	}
	if err := store.DownTo(ctx, dsn, store.TreeRelational, latest-1); err != nil {
		t.Fatal(err)
	}
	err := db.RequireVersion(ctx, latest)
	want := []string{"relational", "version " + itoa(latest-1), "needs " + itoa(latest)}
	if !errors.Is(err, store.ErrSchemaTooOld) {
		t.Fatalf("old schema: %v", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("%q lacks %q", err, w)
		}
	}

	empty := storetest.Scratch(t, store.TreeTimeseries, false)
	ts := storetest.Timeseries(t, empty, "")
	if v, err := ts.Version(ctx); err != nil || v != 0 {
		t.Fatalf("unmigrated: %d %v", v, err)
	}
	if err := ts.RequireVersion(ctx, 1); !errors.Is(err, store.ErrSchemaTooOld) {
		t.Fatalf("unmigrated: %v", err)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// events: ansp_app can INSERT (through the audit writer) and cannot
// UPDATE or DELETE (permission denied, before any trigger); the owner
// is stopped by the trigger; TRUNCATE is refused too.
func TestIntegrationEventsAppendOnly(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	err := db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `SELECT events_ensure_partition(clock_timestamp())`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO events (ts, actor_type, actor_id, purpose, entity_type, entity_id, event_type, prev_hash, hash)
			VALUES (clock_timestamp(), 'system', 'test', 'test', 'test', '1', 'test_event', repeat('0', 64), repeat('1', 64))`)
		return err
	})
	if err != nil {
		t.Fatalf("ansp_app INSERT: %v", err)
	}
	for _, sql := range []string{`UPDATE events SET actor_id = 'x'`, `DELETE FROM events`} {
		err := db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if store.SQLState(err) != store.StateInsufficientPrivilege || !strings.Contains(err.Error(), "permission denied for table events") {
			t.Fatalf("ansp_app %s: %v", sql, err)
		}
	}
	for _, sql := range []string{`UPDATE events SET actor_id = 'x'`, `DELETE FROM events`, `TRUNCATE events`} {
		err := exec(t, dsn, sql)
		if !strings.Contains(fmtErr(err), "events is append-only") {
			t.Fatalf("owner %s: %v", sql, err)
		}
	}
	if n := scalar[int64](t, dsn, `SELECT count(*) FROM events`); n != 1 {
		t.Fatalf("%d rows", n)
	}
}

func fmtErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// restriction_versions is insert-only for ansp_app; restrictions keeps
// UPDATE (its foreign keys point there, never at an insert-only table).
// Geometry crosses as GeoJSON and keeps its shape; the table's checks
// refuse a point without radius, a radius on a polygon, a line and an
// empty window.
func TestIntegrationRestrictions(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	poly := `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.6]]]}`
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	params := func(id, ref, ident, geom string, radius *float64) relational.InsertRestrictionParams {
		return relational.InsertRestrictionParams{
			ID: id, AnspRef: ref, Identifier: ident, UspaceAirspaceID: "GEOUS1", ZoneType: "PROHIBITED",
			GeomGeojson: geom, RadiusM: radius, LowerM: 0, LowerRef: "AMSL", UpperM: 300, UpperRef: "AMSL",
			StartsAt: start, EndsAt: start.Add(time.Hour), ReasonText: "test", CreatedBy: "watch",
		}
	}
	insert := func(p relational.InsertRestrictionParams) error {
		return db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Q.InsertRestriction(ctx, p)
			return err
		})
	}
	if err := insert(params("01JABCDEFGHJKMNPQRSTVWXYZ0", "ref-1", "DAR0001", poly, nil)); err != nil {
		t.Fatalf("polygon: %v", err)
	}
	radius := 500.0
	if err := insert(params("01JABCDEFGHJKMNPQRSTVWXYZ1", "ref-2", "DAR0002", `{"type":"Point","coordinates":[44.8,41.7]}`, &radius)); err != nil {
		t.Fatalf("point with radius: %v", err)
	}
	for name, p := range map[string]relational.InsertRestrictionParams{
		"point without radius": params("01JABCDEFGHJKMNPQRSTVWXYZ2", "ref-3", "DAR0003", `{"type":"Point","coordinates":[44.8,41.7]}`, nil),
		"polygon with radius":  params("01JABCDEFGHJKMNPQRSTVWXYZ3", "ref-4", "DAR0004", poly, &radius),
		"line":                 params("01JABCDEFGHJKMNPQRSTVWXYZ4", "ref-5", "DAR0005", `{"type":"LineString","coordinates":[[44.8,41.7],[44.9,41.7]]}`, nil),
		"identifier":           params("01JABCDEFGHJKMNPQRSTVWXYZ5", "ref-6", "DAR-001", poly, nil),
	} {
		if err := insert(p); store.SQLState(err) != store.StateCheckViolation {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad := params("01JABCDEFGHJKMNPQRSTVWXYZ6", "ref-7", "DAR0007", poly, nil)
	bad.EndsAt = bad.StartsAt
	if err := insert(bad); store.SQLState(err) != store.StateCheckViolation || !strings.Contains(err.Error(), "restrictions_window") {
		t.Fatalf("empty window: %v", err)
	}

	var row relational.RestrictionByIDRow
	err := db.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		row, err = q.RestrictionByID(ctx, "01JABCDEFGHJKMNPQRSTVWXYZ0")
		return err
	})
	if err != nil || row.State != relational.RestrictionStatePlanned || row.AnspVersion != 1 {
		t.Fatalf("read back: %+v %v", row, err)
	}
	g, err := store.ParseGeometry(row.GeomGeojson)
	if err != nil || g.Polygon == nil || len(g.Polygon.Rings[0]) != 4 || g.Polygon.Rings[0][1].LonDeg != 44.9 {
		t.Fatalf("geometry %q: %+v %v", row.GeomGeojson, g, err)
	}

	err = db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		return tx.Q.InsertRestrictionVersion(ctx, relational.InsertRestrictionVersionParams{
			RestrictionID: row.ID, Version: 1, Feature: []byte(`{"identifier":"DAR0001"}`), ChangedBy: "watch", ChangeReason: "planned",
		})
	})
	if err != nil {
		t.Fatalf("version insert: %v", err)
	}
	for _, sql := range []string{`UPDATE restriction_versions SET change_reason = 'x'`, `DELETE FROM restriction_versions`} {
		err := db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Fatalf("ansp_app %s: %v", sql, err)
		}
	}
	err = db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE restrictions SET state = 'active', ansp_version = 2 WHERE id = $1`, row.ID)
		return err
	})
	if err != nil {
		t.Fatalf("restrictions stays updatable: %v", err)
	}
	err = db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		req, err := tx.Q.InsertRestrictionRequest(ctx, relational.InsertRestrictionRequestParams{
			ID: "01JABCDEFGHJKMNPQRSTVWXYZ9", Requester: "authority-01", Source: "authority", Payload: []byte(`{"reason":"x"}`),
		})
		if err != nil || req.State != "received" {
			t.Fatalf("request: %+v %v", req, err)
		}
		return tx.Q.InsertRestrictionVersion(ctx, relational.InsertRestrictionVersionParams{
			RestrictionID: row.ID, Version: 2, Feature: []byte(`{}`), ChangedBy: "watch", ChangeReason: "activated",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ansp_ts_app may INSERT into manned_tracks (the Writer) and may not
// UPDATE or DELETE.
func TestIntegrationMannedTracksInsertOnly(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	db := storetest.Timeseries(t, dsn, store.RoleTimeseries)
	n, err := db.Writer().Insert(ctx, rows(1, time.Now().UTC()))
	if err != nil || n != 1 {
		t.Fatalf("insert: %d %v", n, err)
	}
	for _, sql := range []string{`UPDATE manned_tracks SET relevant = true`, `DELETE FROM manned_tracks`, `UPDATE feed_products SET tracks_sent = 0`} {
		err := db.Tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Fatalf("ansp_ts_app %s: %v", sql, err)
		}
	}
}

// The compression and retention policies of 0002 and 0003 exist as
// TimescaleDB jobs with the brief's intervals.
func TestIntegrationCompressionAndRetentionJobs(t *testing.T) {
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	for _, tc := range []struct {
		table, proc, key, want string
	}{
		{"manned_tracks", "policy_compression", "compress_after", "7 days"},
		{"manned_tracks", "policy_retention", "drop_after", "90 days"},
		{"feed_products", "policy_retention", "drop_after", "90 days"},
	} {
		got := scalar[string](t, dsn, `SELECT config->>$3 FROM timescaledb_information.jobs
			WHERE hypertable_name = $1 AND proc_name = $2`, tc.table, tc.proc, tc.key)
		if got != tc.want {
			t.Fatalf("%s %s %s = %q, want %q", tc.table, tc.proc, tc.key, got, tc.want)
		}
	}
	seg := scalar[string](t, dsn, `SELECT attname FROM timescaledb_information.compression_settings
		WHERE hypertable_name = 'manned_tracks' AND segmentby_column_index = 1`)
	order := scalar[bool](t, dsn, `SELECT NOT orderby_asc FROM timescaledb_information.compression_settings
		WHERE hypertable_name = 'manned_tracks' AND attname = 'captured_at'`)
	interval := scalar[string](t, dsn, `SELECT time_interval::text FROM timescaledb_information.dimensions
		WHERE hypertable_name = 'manned_tracks'`)
	if seg != "icao24" || !order || interval != "1 day" {
		t.Fatalf("segmentby %q, orderby desc %v, chunk %q", seg, order, interval)
	}
}

// 10 000 rows by CopyFrom land and are read back by icao24 and window;
// a row that does not validate is left out and counted.
func TestIntegrationCopyFrom10000(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	db := storetest.Timeseries(t, dsn, store.RoleTimeseries)
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	batch := rows(10_000, base)
	bad := batch[0]
	bad.ICAO24 = "zzzzzz"
	batch = append(batch, bad)
	w := db.Writer()
	n, err := w.Insert(ctx, batch)
	if err != nil || n != 10_000 {
		t.Fatalf("copy: %d %v", n, err)
	}
	if got := w.Counters().Get(store.CounterTrackRowsRefused); got != 1 {
		t.Fatalf("refused counter %d", got)
	}
	var count int64
	var track []timeseriesRow
	err = db.Do(ctx, func(ctx context.Context, q *tsQueries) error {
		var err error
		count, err = q.CountMannedTracksInWindow(ctx, tsCountParams(base, base.Add(3*time.Hour)))
		if err != nil {
			return err
		}
		track, err = q.MannedTracksByICAO24(ctx, tsByICAOParams("4b1803", base, base.Add(100*time.Second)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 10_000 {
		t.Fatalf("window holds %d rows", count)
	}
	// rows() interleaves 10 aircraft: 4b1803 is at seconds 3, 13, ... 93
	// of the first 100.
	if len(track) != 10 || track[0].Icao24 != "4b1803" || !track[0].CapturedAt.Equal(base.Add(3*time.Second)) ||
		!track[9].CapturedAt.Equal(base.Add(93*time.Second)) ||
		track[0].LatDeg != 41.7 || track[0].LonDeg < 44.79 || track[0].AltPressureM == nil || *track[0].AltPressureM != 1000 {
		t.Fatalf("read back %d rows: %+v", len(track), track)
	}
}

// E-10: with every connection held, the next call is refused after the
// acquire timeout, counted, not hung; once one is released it runs
// (presence twin).
func TestIntegrationPoolRefusesBeyondMax(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	pc := storetest.Pool(store.RoleRelational)
	pc.MaxConns, pc.AcquireTimeout = 2, 300*time.Millisecond
	db, err := store.OpenRelational(ctx, dsn, pc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	release := make(chan struct{})
	held := make(chan struct{}, 2)
	done := make(chan error, 2)
	for range 2 {
		go func() {
			done <- db.Do(ctx, func(context.Context, relational.DBTX, *relational.Queries) error {
				held <- struct{}{}
				<-release
				return nil
			})
		}()
	}
	<-held
	<-held
	start := time.Now()
	err = db.Ping(ctx)
	waited := time.Since(start)
	if !errors.Is(err, store.ErrPoolExhausted) || waited < 300*time.Millisecond || waited > 3*time.Second {
		t.Fatalf("third call: %v after %s", err, waited)
	}
	if db.Counters().Get(store.CounterPoolExhausted) != 1 {
		t.Fatalf("counter %d", db.Counters().Get(store.CounterPoolExhausted))
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Ping(ctx); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// A statement past the configured statement_timeout is cancelled by the
// server; one inside it runs.
func TestIntegrationStatementTimeout(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	pc := storetest.Pool(store.RoleRelational)
	pc.StatementTimeout = 200 * time.Millisecond
	db, err := store.OpenRelational(ctx, dsn, pc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	run := func(sql string) error {
		return db.Do(ctx, func(ctx context.Context, c relational.DBTX, _ *relational.Queries) error {
			_, err := c.Exec(ctx, sql)
			return err
		})
	}
	if err := run(`SELECT pg_sleep(0.01)`); err != nil {
		t.Fatalf("inside the bound: %v", err)
	}
	if err := run(`SELECT pg_sleep(2)`); store.SQLState(err) != "57014" {
		t.Fatalf("past the bound: %v", err)
	}
}

// The seeded policy is policy.Defaults; a new row takes the next version.
func TestIntegrationPolicySeedEqualsDefaults(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	repo := store.PolicyRepo{DB: storetest.Relational(t, dsn, store.RoleRelational)}
	p, err := repo.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Thresholds != policy.Defaults() || p.ChangedBy != "migration" {
		t.Fatalf("seed %+v, defaults %+v", p, policy.Defaults())
	}
	t2 := policy.Defaults()
	t2.StaleAfterS = 20
	np, err := repo.Insert(ctx, policy.Actor{Type: "user", ID: "admin-1"}, t2, nil)
	if err != nil || np.Version != 2 || np.StaleAfterS != 20 {
		t.Fatalf("insert: %+v %v", np, err)
	}
	if n := scalar[int64](t, dsn, `SELECT count(*) FROM events WHERE event_type = 'policy_updated' AND entity_id = '2'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	// The table's own check refuses what Validate would.
	t3 := policy.Defaults()
	t3.CISStaleBoundS = 0
	if _, err := repo.Insert(ctx, policy.Actor{Type: "user", ID: "admin-1"}, t3, nil); store.SQLState(err) != store.StateCheckViolation {
		t.Fatalf("zero threshold: %v", err)
	}
}

// source_controls: every write takes the next version, the epoch is the
// database's and stays; a type-wide row (no instance) is unique too.
func TestIntegrationSourceControls(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	inst := "replay-1"
	var rows []relational.SourceControl
	for _, p := range []relational.UpsertSourceControlParams{
		{SourceType: "manned", Enabled: false, Reason: "maintenance", Actor: "admin"},
		{SourceType: "manned", InstanceID: &inst, Enabled: false, Reason: "noisy", Actor: "admin"},
		{SourceType: "manned", Enabled: true, Reason: "back", Actor: "admin"},
	} {
		err := db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			r, err := tx.Q.UpsertSourceControl(ctx, p)
			rows = append(rows, r)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if rows[0].Version >= rows[1].Version || rows[1].Version >= rows[2].Version || rows[0].Epoch != rows[2].Epoch {
		t.Fatalf("versions and epoch: %+v", rows)
	}
	var list []relational.SourceControl
	var epoch [16]byte
	err := db.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		if list, err = q.ListSourceControls(ctx, 100); err != nil {
			return err
		}
		e, err := q.SourceControlEpoch(ctx)
		epoch = e
		return err
	})
	if err != nil || len(list) != 2 || list[0].InstanceID != nil || !list[0].Enabled || epoch != rows[0].Epoch {
		t.Fatalf("list %+v epoch %v %v", list, epoch, err)
	}
}

// Ping and the readiness check say ok against a reachable database and
// down, with the reason, once the pool is closed.
func TestIntegrationCheck(t *testing.T) {
	ctx := ctxT(t)
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	db, err := store.OpenTimeseries(ctx, dsn, storetest.Pool(store.RoleTimeseries), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := db.Check()
	if s, reason := c.Probe(ctx); s != "ok" || reason != "" || c.Name != "timeseries" || !c.Required {
		t.Fatalf("up: %s %q", s, reason)
	}
	db.Close()
	if s, reason := c.Probe(ctx); s != "down" || reason == "" {
		t.Fatalf("closed: %s %q", s, reason)
	}
	if _, err := store.OpenTimeseries(ctx, dsn, storetest.Pool("no_such_role"), nil); err == nil || !strings.Contains(err.Error(), "no_such_role") {
		t.Fatalf("unknown role: %v", err)
	}
}

type (
	tsQueries     = timeseries.Queries
	timeseriesRow = timeseries.MannedTracksByICAO24Row
)

func tsCountParams(from, to time.Time) timeseries.CountMannedTracksInWindowParams {
	return timeseries.CountMannedTracksInWindowParams{FromTs: from, ToTs: to}
}

func tsByICAOParams(icao24 string, from, to time.Time) timeseries.MannedTracksByICAO24Params {
	return timeseries.MannedTracksByICAO24Params{Icao24: icao24, FromTs: from, ToTs: to, PageSize: 1000}
}

// rows is n samples of 10 aircraft (4b1800..4b1809), one per second
// from base, aircraft i at second k when k % 10 == i.
func rows(n int, base time.Time) []timeseries.MannedTrackRow {
	out := make([]timeseries.MannedTrackRow, n)
	alt := 1000.0
	for k := range out {
		at := base.Add(time.Duration(k) * time.Second)
		out[k] = timeseries.MannedTrackRow{
			CapturedAt: at, TS: at, RxTS: at, TimeSource: "adapter", AdapterID: "replay-1",
			ICAO24:       "4b180" + strconv.Itoa(k%10),
			Position:     core.LatLon{LatDeg: 41.7, LonDeg: 44.79 + float64(k)/1e6},
			AltPressureM: &alt, SourceClass: "ads_b", Relevant: k%2 == 0, PolicyVersion: 1,
			Quality: []byte(`{"nic":8}`),
		}
	}
	return out
}
