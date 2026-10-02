-- WP-1: the hash-chained audit log (internal/audit).

-- name: EnsureEventsPartition :one
SELECT events_ensure_partition(sqlc.arg(at)::timestamptz)::text AS partition;

-- name: NextEventID :one
SELECT nextval('events_id_seq')::bigint AS id;

-- name: NormalizeJSONB :one
-- The payload as PostgreSQL stores it (keys and numbers normalised), so
-- the hash covers what Verify will read back.
SELECT (sqlc.arg(doc)::jsonb)::text AS doc;

-- name: LastEventInRange :one
SELECT id, hash FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts)
ORDER BY id DESC LIMIT 1;

-- name: LastEventBefore :one
-- The chain predecessor of the first row of a month: the last row
-- written before it (lower id) in an earlier month.
SELECT id, hash FROM events
WHERE ts < sqlc.arg(before_ts) AND id < sqlc.arg(before_id)
ORDER BY id DESC LIMIT 1;

-- name: InsertEvent :exec
INSERT INTO events (
    id, ts, actor_type, actor_id, purpose, entity_type, entity_id,
    event_type, payload, prev_hash, hash
) VALUES (
    sqlc.arg(id), sqlc.arg(ts), sqlc.arg(actor_type), sqlc.arg(actor_id),
    sqlc.arg(purpose), sqlc.arg(entity_type), sqlc.arg(entity_id),
    sqlc.arg(event_type), sqlc.arg(payload), sqlc.arg(prev_hash), sqlc.arg(hash)
);

-- name: EventsInRange :many
-- One page of a month in chain order, for Verify.
SELECT id, ts, actor_type, actor_id, purpose, entity_type, entity_id,
       event_type, payload, prev_hash, hash
FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: QueryEvents :many
-- One page of /v1/audit, newest first: optionally one entity type (and
-- id), from since on, before the cursor id.
SELECT id, ts, actor_type, actor_id, purpose, entity_type, entity_id,
       event_type, payload, prev_hash, hash
FROM events
WHERE ts >= sqlc.arg(since)
  AND (sqlc.narg(entity_type)::text IS NULL OR entity_type = sqlc.narg(entity_type))
  AND (sqlc.narg(entity_id)::text IS NULL OR entity_id = sqlc.narg(entity_id))
  AND id < sqlc.arg(before_id)
ORDER BY id DESC
LIMIT sqlc.arg(page_size);
