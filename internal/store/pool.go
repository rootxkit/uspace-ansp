package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// The roles the processes work as (migrations 0001 of each tree).
const (
	RoleRelational = "ansp_app"
	RoleTimeseries = "ansp_ts_app"
)

// Counters of the store (status line and /metrics, E-09).
const (
	// CounterPoolExhausted: a call waited AcquireTimeout for a pooled
	// connection and was refused.
	CounterPoolExhausted = "store_pool_exhausted"
	// CounterTrackRowsRefused: a manned_tracks row the Writer left out
	// (the rest of the batch lands).
	CounterTrackRowsRefused = timeseries.CounterTrackRowsRefused
)

// PoolConfig bounds a pool. Every field is required; FromConfig fills it
// from the ANSP_DB_* variables.
type PoolConfig struct {
	MaxConns int32
	// AcquireTimeout bounds the wait for a pooled connection.
	AcquireTimeout time.Duration
	// StatementTimeout is the server's statement_timeout and lock_timeout.
	StatementTimeout time.Duration
	// TxTimeout bounds a transaction without a deadline of its own and is
	// the server's idle_in_transaction_session_timeout.
	TxTimeout time.Duration
	// Role is SET on every new connection; empty keeps the login role
	// (the migrate subcommand and tests only).
	Role string
	// ApplicationName names the process in pg_stat_activity.
	ApplicationName string
}

// FromConfig is the pool of process cfg.Process working as role.
func FromConfig(cfg config.Config, role string) PoolConfig {
	return PoolConfig{
		MaxConns:         int32(cfg.DBMaxConns),
		AcquireTimeout:   time.Duration(cfg.DBAcquireTimeoutS) * time.Second,
		StatementTimeout: time.Duration(cfg.DBStatementTimeoutS) * time.Second,
		TxTimeout:        time.Duration(cfg.DBTxTimeoutS) * time.Second,
		Role:             role,
		ApplicationName:  "ansp-" + cfg.Process,
	}
}

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func (pc PoolConfig) validate() error {
	var errs []error
	if pc.MaxConns < 1 {
		errs = append(errs, core.Fieldf("max_conns", "must be at least 1"))
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"acquire_timeout", pc.AcquireTimeout}, {"statement_timeout", pc.StatementTimeout}, {"tx_timeout", pc.TxTimeout}} {
		if d.v <= 0 {
			errs = append(errs, core.Fieldf(d.name, "must be positive"))
		}
	}
	if pc.Role != "" && !roleName.MatchString(pc.Role) {
		errs = append(errs, core.Fieldf("role", "%q is not a lower-case role name", pc.Role))
	}
	return errors.Join(errs...)
}

// pgxConfig parses dsn into a bounded pool configuration.
func (pc PoolConfig) pgxConfig(dsn string) (*pgxpool.Config, error) {
	if err := pc.validate(); err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// The parse error may echo the DSN, which may carry a password.
		return nil, &core.FieldError{Field: "dsn", Reason: "not a valid PostgreSQL connection string"}
	}
	cfg.MaxConns = pc.MaxConns
	cfg.MinConns = 0
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	rp := cfg.ConnConfig.RuntimeParams
	rp["statement_timeout"] = ms(pc.StatementTimeout)
	rp["lock_timeout"] = ms(pc.StatementTimeout)
	rp["idle_in_transaction_session_timeout"] = ms(pc.TxTimeout)
	rp["timezone"] = "UTC"
	if pc.ApplicationName != "" {
		rp["application_name"] = pc.ApplicationName
	}
	if cfg.ConnConfig.ConnectTimeout == 0 || cfg.ConnConfig.ConnectTimeout > pc.AcquireTimeout {
		cfg.ConnConfig.ConnectTimeout = pc.AcquireTimeout
	}
	if pc.Role != "" {
		set := "SET ROLE " + pgx.Identifier{pc.Role}.Sanitize() //nolint:misspell // pgx API name
		role := pc.Role
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			if _, err := c.Exec(ctx, set); err != nil {
				return fmt.Errorf("set role %s: %w", role, err)
			}
			return nil
		}
	}
	return cfg, nil
}

// ErrPoolExhausted is a call refused because no pooled connection came
// free within AcquireTimeout (E-10: refused, never a hang).
var ErrPoolExhausted = errors.New("database pool exhausted")

// pool is the bounded pool both databases share the mechanics of.
type pool struct {
	tree     Tree
	p        *pgxpool.Pool
	pc       PoolConfig
	counters *core.Counters
}

func openPool(ctx context.Context, tree Tree, dsn string, pc PoolConfig, counters *core.Counters) (*pool, error) {
	cfg, err := pc.pgxConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("%s database: %w", tree.Name, err)
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%s database: open pool: %w", tree.Name, err)
	}
	if counters == nil {
		counters = &core.Counters{}
	}
	out := &pool{tree: tree, p: p, pc: pc, counters: counters}
	// One connection at start, so a wrong host, password or role is
	// reported now and not on the first request.
	if err := out.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return out, nil
}

// acquire waits at most AcquireTimeout for a connection.
func (p *pool) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, p.pc.AcquireTimeout)
	defer cancel()
	c, err := p.p.Acquire(actx)
	if err == nil {
		return c, nil
	}
	if ctx.Err() == nil && errors.Is(actx.Err(), context.DeadlineExceeded) {
		p.counters.Inc(CounterPoolExhausted)
		return nil, fmt.Errorf("%s database: %w: no connection free within %s (max %d)",
			p.tree.Name, ErrPoolExhausted, p.pc.AcquireTimeout, p.pc.MaxConns)
	}
	return nil, fmt.Errorf("%s database: acquire: %w", p.tree.Name, err)
}

// bounded gives ctx the transaction bound when it has no deadline.
func (p *pool) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, p.pc.TxTimeout)
}

// conn runs fn on one pooled connection outside a transaction.
func (p *pool) conn(ctx context.Context, fn func(ctx context.Context, c *pgxpool.Conn) error) error {
	ctx, cancel := p.bounded(ctx)
	defer cancel()
	c, err := p.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	return fn(ctx, c)
}

// tx runs fn in one transaction: committed when fn returns nil, rolled
// back otherwise.
func (p *pool) tx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) (err error) {
	ctx, cancel := p.bounded(ctx)
	defer cancel()
	c, err := p.acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	tx, err := c.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%s database: begin: %w", p.tree.Name, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	err = fn(ctx, tx)
	if err != nil {
		return err
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("%s database: commit: %w", p.tree.Name, err)
	}
	return nil
}

// Ping checks a connection can be acquired and used (readiness).
func (p *pool) Ping(ctx context.Context) error {
	return p.conn(ctx, func(ctx context.Context, c *pgxpool.Conn) error {
		if err := c.Ping(ctx); err != nil {
			return fmt.Errorf("%s database: ping: %w", p.tree.Name, err)
		}
		return nil
	})
}

// Close closes the pool.
func (p *pool) Close() { p.p.Close() }

// Counters are the store's counters.
func (p *pool) Counters() *core.Counters { return p.counters }

// LockKey derives an advisory lock key from a resource name, so keys
// are named in code, never numbered by hand.
func LockKey(name string) int64 { return relational.LockKey(name) }

// IsNoRows reports whether err is "no rows in result set".
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// SQLState is the PostgreSQL error code of err, or "".
func SQLState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// SQLStates the callers test for.
const (
	StateInsufficientPrivilege = "42501"
	StateUniqueViolation       = "23505"
	StateCheckViolation        = "23514"
	StateUndefinedTable        = "42P01"
)
