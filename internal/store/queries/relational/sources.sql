-- WP-1: source_controls, for WP-6's internal/sources writer and its
-- periodic republish (LESSONS B-09).

-- name: SourceControlEpoch :one
SELECT epoch FROM source_control_epoch WHERE singleton;

-- name: ListSourceControls :many
SELECT source_type, instance_id, enabled, reason, actor, changed_at, version, epoch
FROM source_controls
ORDER BY source_type, instance_id NULLS FIRST
LIMIT sqlc.arg(page_size);

-- name: MaxSourceControlVersion :one
SELECT COALESCE(max(version), 0)::bigint AS version FROM source_controls;

-- name: UpsertSourceControl :one
-- One switch, with the next version of the sequence and the epoch of
-- this database; the caller holds the writers' advisory lock (B-09).
INSERT INTO source_controls (source_type, instance_id, enabled, reason, actor, changed_at, version, epoch)
VALUES (
    sqlc.arg(source_type), sqlc.narg(instance_id), sqlc.arg(enabled), sqlc.arg(reason), sqlc.arg(actor),
    clock_timestamp(), nextval('source_controls_version_seq'),
    (SELECT epoch FROM source_control_epoch WHERE singleton)
)
ON CONFLICT (source_type, instance_id) DO UPDATE SET
    enabled = EXCLUDED.enabled, reason = EXCLUDED.reason, actor = EXCLUDED.actor,
    changed_at = EXCLUDED.changed_at, version = EXCLUDED.version, epoch = EXCLUDED.epoch
RETURNING source_type, instance_id, enabled, reason, actor, changed_at, version, epoch;
