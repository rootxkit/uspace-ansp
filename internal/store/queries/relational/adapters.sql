-- WP-1: the adapter registry.

-- name: UpsertAdapter :one
INSERT INTO adapters (id, kind, display_name, source_class, config)
VALUES (sqlc.arg(id), sqlc.arg(kind), sqlc.arg(display_name), sqlc.arg(source_class), sqlc.arg(config))
ON CONFLICT (id) DO UPDATE SET
    kind = EXCLUDED.kind, display_name = EXCLUDED.display_name,
    source_class = EXCLUDED.source_class, config = EXCLUDED.config
RETURNING *;

-- name: SetAdapterStatus :execrows
UPDATE adapters
SET status = sqlc.arg(status), last_frame_at = sqlc.narg(last_frame_at),
    last_status_at = clock_timestamp(), counters = sqlc.arg(counters)
WHERE id = sqlc.arg(id);

-- name: AdapterByID :one
SELECT * FROM adapters WHERE id = sqlc.arg(id);

-- name: ListAdapters :many
SELECT * FROM adapters ORDER BY id LIMIT sqlc.arg(page_size);
