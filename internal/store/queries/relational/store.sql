-- WP-1: the schema check, the clock and advisory locks.

-- name: SchemaVersion :one
-- The version the relational tree is at: goose v3 deletes the row of a
-- rolled-back migration, so the newest applied row is the version.
SELECT version_id FROM goose_db_version_relational
WHERE is_applied ORDER BY id DESC LIMIT 1;

-- name: DBNow :one
-- The database clock (not the transaction start): expiry, audit time
-- and every other stored instant come from here, never from a process
-- clock.
SELECT clock_timestamp()::timestamptz AS now;

-- name: AdvisoryXactLock :exec
-- Blocks until the transaction-scoped advisory lock key is held; it is
-- released at commit or rollback. Bounded by lock_timeout.
SELECT pg_advisory_xact_lock(sqlc.arg(key)::bigint);
