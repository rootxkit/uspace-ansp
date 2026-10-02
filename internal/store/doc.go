// Package store is the two databases of uspace-ansp (docs/PLAN.md
// section 5): the bounded pgx pools, the goose runner of the two
// migration trees, the sqlc queries and the transaction helper.
//
// Two trees, two databases, two version tables, never merged (CLAUDE.md
// rule 6, LESSONS B-15): migrations/relational (PostgreSQL + PostGIS,
// goose_db_version_relational, written by api only) and
// migrations/timeseries (TimescaleDB, goose_db_version_timeseries,
// written by manned-feed only). Migrate applies a tree under its own
// advisory lock and refuses a database that holds the other tree's
// version table; it is reachable only through the `migrate` subcommand
// (M36). A long-running process opens its database with OpenRelational
// or OpenTimeseries and calls RequireVersion(Latest(tree)), which
// refuses a schema older than the build and names the tree, the present
// and the needed version.
//
// Every connection works as the application role (ansp_app,
// ansp_ts_app), which may not UPDATE or DELETE the insert-only tables
// (events, restriction_versions, ansp_policy, manned_tracks,
// feed_products). Every call is bounded: a connection is waited for at
// most PoolConfig.AcquireTimeout and then refused with ErrPoolExhausted
// (counted as store_pool_exhausted); statements and lock waits by
// statement_timeout and lock_timeout; a transaction without a deadline
// by TxTimeout, which is also the server's
// idle_in_transaction_session_timeout. Stored instants come from the
// database clock.
//
// The generated queries live in the subpackages relational and
// timeseries (sqlc.yaml, `go generate ./internal/store`, checked by
// make generate-check). Geometry crosses them as GeoJSON text and is
// held in Go as uspace-core geodesy types (ParseGeometry, GeometryJSON);
// no geometry library is imported. timeseries.Writer copies manned
// tracks with COPY through a staging table, refusing a batch above
// timeseries.MaxBatchRows and counting each row it leaves out.
//
// Tx is the transaction helper: a write that must pair with a KV put
// (a source switch, the policy) puts inside the function and returns the
// KV error, so the row is never recorded without the put (LESSONS B-09).
// PolicyRepo is internal/policy's Repo on this database; it lives here
// so the hot path that follows the policy has no database import path.
// A library package never logs: errors and counters go to the caller.
package store
