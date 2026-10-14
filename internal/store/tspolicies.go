package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// TimeseriesPolicies are the retention and compression intervals of the
// timeseries tree's hypertables, in days, from the configuration
// (ANSP_TIMESERIES_RETENTION_DAYS, ANSP_TIMESERIES_COMPRESS_AFTER_DAYS).
// 0002 and 0003 create the jobs with spec 05 section 4's values (compress
// manned_tracks after 7 days, keep both tables 90 days); a deployment
// sets its own here, so a small host stays within its disk budget and a
// national retention period (Q8, pending GCAA) is a setting, not a
// migration.
type TimeseriesPolicies struct {
	RetentionDays     int
	CompressAfterDays int
}

// PolicyChange is one job ApplyTimeseriesPolicies changed.
type PolicyChange struct {
	Table  string // the hypertable
	Policy string // policy_retention or policy_compression
	From   string // the interval before, as TimescaleDB prints it
	To     string
}

// ErrPolicyMissing is a hypertable without the job its migration
// creates: nothing is changed, because a policy this code cannot find
// is one it would silently not apply.
var ErrPolicyMissing = errors.New("timeseries policy job missing")

// policyJob is one job ApplyTimeseriesPolicies keeps at its interval.
type policyJob struct {
	table, proc, key string
	days             func(TimeseriesPolicies) int
}

var policyJobs = []policyJob{
	{"manned_tracks", "policy_compression", "compress_after", func(p TimeseriesPolicies) int { return p.CompressAfterDays }},
	{"manned_tracks", "policy_retention", "drop_after", func(p TimeseriesPolicies) int { return p.RetentionDays }},
	{"feed_products", "policy_retention", "drop_after", func(p TimeseriesPolicies) int { return p.RetentionDays }},
}

// Validate refuses intervals TimescaleDB would accept but that make no
// sense: below a day, or compression at or past the retention (a chunk
// would be dropped before it is ever compressed).
func (p TimeseriesPolicies) Validate() error {
	switch {
	case p.RetentionDays < 1 || p.CompressAfterDays < 1:
		return fmt.Errorf("timeseries policies: retention %d and compression %d days must each be at least 1", p.RetentionDays, p.CompressAfterDays)
	case p.CompressAfterDays >= p.RetentionDays:
		return fmt.Errorf("timeseries policies: compression after %d days is not before the retention of %d days", p.CompressAfterDays, p.RetentionDays)
	}
	return nil
}

// ApplyTimeseriesPolicies sets every job of policyJobs to p in the
// timeseries database at dsn, in one transaction, and returns the jobs
// it changed (none when each already holds its interval: a second run
// changes nothing). The jobs are TimescaleDB's own rows, so the setting
// outlives every restart until the next migrate run sets it again. Only
// the migrate subcommand calls it, after the tree is current.
func ApplyTimeseriesPolicies(ctx context.Context, dsn string, p TimeseriesPolicies) ([]PolicyChange, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	db, err := openSQL(dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if err := refuseOtherTree(ctx, db, TreeTimeseries); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("timeseries policies: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var changes []PolicyChange
	for _, j := range policyJobs {
		want := days(j.days(p))
		var id int64
		var current string
		var same bool
		err := tx.QueryRowContext(ctx, `
			SELECT job_id, config->>$3, (config->>$3)::interval = $4::interval
			FROM timescaledb_information.jobs
			WHERE hypertable_schema = 'public' AND hypertable_name = $1 AND proc_name = $2`,
			j.table, j.proc, j.key, want).Scan(&id, &current, &same)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: %s has no %s (its migration creates it); nothing changed", ErrPolicyMissing, j.table, j.proc)
			}
			return nil, fmt.Errorf("timeseries policies: read the %s job of %s: %w", j.proc, j.table, err)
		}
		if same {
			continue
		}
		if _, err := tx.ExecContext(ctx, `SELECT alter_job($1::integer, config => jsonb_set(config, ARRAY[$2::text], to_jsonb($3::text)))
			FROM timescaledb_information.jobs WHERE job_id = $1::integer`, id, j.key, want); err != nil {
			return nil, fmt.Errorf("timeseries policies: set the %s job of %s to %s: %w", j.proc, j.table, want, err)
		}
		changes = append(changes, PolicyChange{Table: j.table, Policy: j.proc, From: current, To: want})
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("timeseries policies: commit: %w", err)
	}
	return changes, nil
}

// days is n days as PostgreSQL prints an interval ("1 day", "7 days"),
// so the job's config reads as TimescaleDB's own would.
func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return strconv.Itoa(n) + " days"
}
