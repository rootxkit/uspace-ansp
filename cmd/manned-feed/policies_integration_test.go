//go:build integration

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// `migrate timeseries` sets the retention and compression jobs to
// ANSP_TIMESERIES_RETENTION_DAYS and ANSP_TIMESERIES_COMPRESS_AFTER_DAYS
// and says so; run again it changes nothing; without them the jobs keep
// spec 05 section 4's intervals (the presence pair).
func TestIntegrationMigrateSetsTimeseriesPolicies(t *testing.T) {
	ts := storetest.Scratch(t, store.TreeTimeseries, false)
	base := []string{"ANSP_PROCESS=" + process, "ANSP_TIMESERIES_DSN=" + ts}
	jobs := func() string {
		t.Helper()
		conn, err := pgx.Connect(context.Background(), ts)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		var s string
		if err := conn.QueryRow(context.Background(), `SELECT string_agg(hypertable_name || ' ' || proc_name || ' ' ||
			coalesce(config->>'compress_after', config->>'drop_after'), ', ' ORDER BY hypertable_name, proc_name)
			FROM timescaledb_information.jobs WHERE hypertable_name IS NOT NULL`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	out := &syncBuffer{}
	if code := run(context.Background(), []string{"migrate", "timeseries"}, base, out); code != 0 {
		t.Fatalf("migrate exit %d:\n%s", code, out.String())
	}
	if got, want := jobs(), "feed_products policy_retention 90 days, manned_tracks policy_compression 7 days, manned_tracks policy_retention 90 days"; got != want {
		t.Fatalf("defaults: %s, want %s", got, want)
	}
	env := append([]string{"ANSP_TIMESERIES_RETENTION_DAYS=45", "ANSP_TIMESERIES_COMPRESS_AFTER_DAYS=1"}, base...)
	out = &syncBuffer{}
	if code := run(context.Background(), []string{"migrate", "timeseries"}, env, out); code != 0 {
		t.Fatalf("migrate exit %d:\n%s", code, out.String())
	}
	if got, want := jobs(), "feed_products policy_retention 45 days, manned_tracks policy_compression 1 day, manned_tracks policy_retention 45 days"; got != want {
		t.Fatalf("configured: %s, want %s", got, want)
	}
	if !strings.Contains(out.String(), `"msg":"migrate: timeseries policy set","process":"`+process) ||
		!strings.Contains(out.String(), `"table":"manned_tracks","policy":"policy_compression","from":"7 days","to":"1 day"`) ||
		!strings.Contains(out.String(), `"retention_days":45,"compress_after_days":1,"changed":3`) {
		t.Fatalf("migrate log:\n%s", out.String())
	}
	out = &syncBuffer{}
	if code := run(context.Background(), []string{"migrate", "timeseries"}, env, out); code != 0 || !strings.Contains(out.String(), `"changed":0`) {
		t.Fatalf("second migrate exit %d:\n%s", code, out.String())
	}
}
