package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// Relational is the relational database (PostgreSQL + PostGIS), opened
// by api only, the only writer (CLAUDE.md rule 6).
type Relational struct{ *pool }

// OpenRelational opens the bounded pool on dsn and checks one connection
// (as pc.Role). counters may be nil.
func OpenRelational(ctx context.Context, dsn string, pc PoolConfig, counters *core.Counters) (*Relational, error) {
	p, err := openPool(ctx, TreeRelational, dsn, pc, counters)
	if err != nil {
		return nil, err
	}
	return &Relational{p}, nil
}

// Tx is one relational transaction with the generated queries bound to
// it. It is a relational.DBTX, so audit.Record runs in it.
type Tx struct {
	pgx.Tx
	Q *relational.Queries
}

// Tx runs fn in one transaction: committed when fn returns nil, rolled
// back otherwise. A write that must pair with a KV put (a switch, the
// policy) puts inside fn and returns the KV error, so the row is never
// recorded without the put (LESSONS B-09).
func (r *Relational) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	return r.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return fn(ctx, Tx{Tx: tx, Q: relational.New(tx)})
	})
}

// Do runs fn on one pooled connection outside a transaction (reads).
func (r *Relational) Do(ctx context.Context, fn func(ctx context.Context, db relational.DBTX, q *relational.Queries) error) error {
	return r.conn(ctx, func(ctx context.Context, c *pgxpool.Conn) error {
		return fn(ctx, c, relational.New(c))
	})
}

// Version is the version the relational tree is at (0 before the first
// migration).
func (r *Relational) Version(ctx context.Context) (int64, error) {
	var v int64
	err := r.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		v, err = q.SchemaVersion(ctx)
		return err
	})
	return schemaVersion(TreeRelational, v, err)
}

// RequireVersion refuses a relational schema below need, naming the
// tree, the version present and the one needed (M36). A long-running
// process calls it at start with Latest(TreeRelational).
func (r *Relational) RequireVersion(ctx context.Context, need int64) error {
	got, err := r.Version(ctx)
	if err != nil {
		return err
	}
	return CheckVersion(TreeRelational, got, need)
}

// Check is the readiness check of the relational database.
func (r *Relational) Check() obs.Check { return check(obs.DepRelational, r.Ping) }

// Timeseries is the TimescaleDB database, written by manned-feed only.
type Timeseries struct{ *pool }

// OpenTimeseries opens the bounded pool on dsn and checks one connection
// (as pc.Role). counters may be nil.
func OpenTimeseries(ctx context.Context, dsn string, pc PoolConfig, counters *core.Counters) (*Timeseries, error) {
	p, err := openPool(ctx, TreeTimeseries, dsn, pc, counters)
	if err != nil {
		return nil, err
	}
	return &Timeseries{p}, nil
}

// Tx runs fn in one timeseries transaction.
func (t *Timeseries) Tx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return t.tx(ctx, fn)
}

// Do runs fn on one pooled connection outside a transaction.
func (t *Timeseries) Do(ctx context.Context, fn func(ctx context.Context, q *timeseries.Queries) error) error {
	return t.conn(ctx, func(ctx context.Context, c *pgxpool.Conn) error {
		return fn(ctx, timeseries.New(c))
	})
}

// Writer is the hypertable writer on this database (manned-feed).
func (t *Timeseries) Writer() *timeseries.Writer { return timeseries.NewWriter(t, t.counters) }

// Version is the version the timeseries tree is at.
func (t *Timeseries) Version(ctx context.Context) (int64, error) {
	var v int64
	err := t.Do(ctx, func(ctx context.Context, q *timeseries.Queries) error {
		var err error
		v, err = q.SchemaVersion(ctx)
		return err
	})
	return schemaVersion(TreeTimeseries, v, err)
}

// RequireVersion refuses a timeseries schema below need (M36).
func (t *Timeseries) RequireVersion(ctx context.Context, need int64) error {
	got, err := t.Version(ctx)
	if err != nil {
		return err
	}
	return CheckVersion(TreeTimeseries, got, need)
}

// Check is the readiness check of the timeseries database.
func (t *Timeseries) Check() obs.Check { return check(obs.DepTimeseries, t.Ping) }

// schemaVersion reads "no version table" and "no row" as version 0.
func schemaVersion(tree Tree, v int64, err error) (int64, error) {
	switch {
	case err == nil:
		return v, nil
	case IsNoRows(err), SQLState(err) == StateUndefinedTable:
		return 0, nil
	default:
		return 0, fmt.Errorf("%s: read schema version: %w", tree.Name, err)
	}
}

func check(name string, ping func(context.Context) error) obs.Check {
	return obs.Check{Name: name, Required: true, Probe: func(ctx context.Context) (obs.State, string) {
		if err := ping(ctx); err != nil {
			return obs.StateDown, err.Error()
		}
		return obs.StateOK, ""
	}}
}
