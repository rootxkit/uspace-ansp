-- WP-9: the F3548 constraint manager (internal/dss, the DSS channel of
-- internal/deliver). Every instant is the database's clock.

-- name: DSSInfo :one
-- What a DSS job of a version reads at its attempt.
SELECT r.id, r.ansp_ref, r.dss_constraint_id, r.dss_ovn, r.state AS current_state, v.version, v."constraint"
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = sqlc.arg(version)::bigint
WHERE r.id = sqlc.arg(id);

-- name: SettleDSS :exec
-- The restriction's standing in the DSS from what is queued and what
-- was written: pending while a DSS write is queued (since the first time
-- it was), failed when the caller says so, else written (an ovn held),
-- deleted (a reference written, no ovn), or none.
WITH q AS (
    SELECT EXISTS (SELECT 1 FROM deliveries d
                   WHERE d.restriction_id = sqlc.arg(id) AND d.kind IN ('dss_put', 'dss_delete') AND d.state = 'queued') AS pending
)
UPDATE restrictions r SET
    dss_state = CASE WHEN q.pending THEN 'pending'
                     WHEN sqlc.arg(failed)::boolean THEN 'failed'
                     WHEN r.dss_ovn IS NOT NULL THEN 'written'
                     WHEN r.dss_reference IS NOT NULL THEN 'deleted'
                     ELSE 'none' END,
    dss_pending_since = CASE WHEN q.pending OR sqlc.arg(failed)::boolean
                             THEN COALESCE(r.dss_pending_since, clock_timestamp()) ELSE NULL END
FROM q
WHERE r.id = sqlc.arg(id);

-- name: InsertDSSWrite :exec
INSERT INTO dss_constraint_writes (restriction_id, ansp_version, op, delivery_id, constraint_id, ovn, dss_version, reference, subscribers)
VALUES (sqlc.arg(restriction_id), sqlc.arg(ansp_version), sqlc.arg(op), sqlc.arg(delivery_id), sqlc.arg(constraint_id),
        sqlc.narg(ovn), sqlc.narg(dss_version), sqlc.narg(reference), sqlc.arg(subscribers))
ON CONFLICT (restriction_id, ansp_version, op) DO NOTHING;

-- name: RecordDSSPut :exec
-- The DSS accepted a put of version: its ovn, version and reference are
-- the restriction's (a put of an older version never replaces a newer).
UPDATE restrictions SET
    dss_ovn = sqlc.arg(ovn), dss_version = sqlc.arg(dss_version), dss_reference = sqlc.arg(reference),
    dss_put_version = sqlc.arg(version)::bigint, dss_written_at = clock_timestamp()
WHERE id = sqlc.arg(id) AND COALESCE(dss_put_version, 0) <= sqlc.arg(version)::bigint;

-- name: RecordDSSDelete :exec
-- The DSS deleted the reference (or held none): no ovn is held any more;
-- the reference stays for the details' retention.
UPDATE restrictions SET dss_ovn = NULL, dss_written_at = clock_timestamp()
WHERE id = sqlc.arg(id);

-- name: InsertDSSNotification :exec
INSERT INTO dss_notifications (delivery_id, subscription_id, notification_index, restriction_id, ansp_version,
                               constraint_id, subscriber, op, dss_answered_at)
VALUES (sqlc.arg(delivery_id), sqlc.arg(subscription_id), sqlc.arg(notification_index), sqlc.arg(restriction_id),
        sqlc.arg(ansp_version), sqlc.arg(constraint_id), sqlc.arg(subscriber), sqlc.arg(op), clock_timestamp())
ON CONFLICT (delivery_id, subscription_id) DO NOTHING;

-- name: SettleDSSNotifications :exec
UPDATE dss_notifications SET
    status = sqlc.arg(status),
    sent_at = CASE WHEN sqlc.arg(status)::text = 'sent' THEN clock_timestamp() ELSE NULL END
WHERE delivery_id = sqlc.arg(delivery_id) AND status = 'queued';

-- name: DSSNotificationJob :many
-- A uss_notify job's subscriptions with the write it reports: the
-- reference the DSS answered and the details of that version.
SELECT n.constraint_id, n.op, n.subscription_id, n.notification_index,
       w.reference, (v."constraint" -> 'details')::jsonb AS details
FROM dss_notifications n
LEFT JOIN dss_constraint_writes w ON w.restriction_id = n.restriction_id AND w.ansp_version = n.ansp_version AND w.op = n.op
LEFT JOIN restriction_versions v ON v.restriction_id = n.restriction_id AND v.version = n.ansp_version
WHERE n.delivery_id = sqlc.arg(delivery_id)
ORDER BY n.subscription_id
LIMIT 10001;

-- name: CancelQueuedTo :many
UPDATE deliveries SET state = 'cancelled', cancel_reason = sqlc.arg(reason), lease_token = NULL, lease_until = NULL
WHERE kind = sqlc.arg(kind) AND restriction_id = sqlc.arg(restriction_id) AND target = sqlc.arg(target)
  AND ansp_version < sqlc.arg(below) AND state = 'queued'
RETURNING id, target, ansp_version;

-- name: LateNotifications :many
-- Subscriber notifications still queued latency_s after the DSS
-- answered (their queuing), with no uss_notify_late alarm yet.
SELECT d.id, d.restriction_id, d.ansp_version, d.target, d.queued_at
FROM deliveries d
WHERE d.kind = 'uss_notify' AND d.state = 'queued'
  AND d.queued_at <= clock_timestamp() - make_interval(secs => sqlc.arg(latency_s)::float8)
  AND NOT EXISTS (SELECT 1 FROM delivery_alarms a WHERE a.delivery_id = d.id AND a.kind = 'uss_notify_late')
ORDER BY d.queued_at
LIMIT sqlc.arg(page_size);

-- name: ClearableLateAlarms :many
SELECT a.id, a.delivery_id, d.state
FROM delivery_alarms a JOIN deliveries d ON d.id = a.delivery_id
WHERE a.kind = 'uss_notify_late' AND a.cleared_at IS NULL AND d.state <> 'queued'
ORDER BY a.raised_at
LIMIT sqlc.arg(page_size);

-- name: ClearAlarm :one
UPDATE delivery_alarms SET cleared_at = clock_timestamp(), clear_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(id) AND cleared_at IS NULL
RETURNING *;

-- name: DSSBacklog :one
SELECT count(*)::bigint AS n, COALESCE(min(queued_at), 'epoch'::timestamptz)::timestamptz AS oldest
FROM deliveries WHERE kind IN ('dss_put', 'dss_delete') AND state = 'queued';

-- name: WrittenConstraint :one
-- GET /uss/v1/constraints/{entityid}: the reference the DSS last
-- accepted and the details of that version, and whether the restriction
-- ended longer than retention_s ago.
SELECT r.dss_reference::jsonb AS reference, (v."constraint" -> 'details')::jsonb AS details,
       (r.state IN ('ended', 'cancelled')
        AND COALESCE(r.ended_at_actual, r.ends_at) + make_interval(secs => sqlc.arg(retention_s)::float8) < clock_timestamp())::boolean AS expired
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = r.dss_put_version
WHERE r.dss_constraint_id = sqlc.arg(constraint_id) AND r.dss_reference IS NOT NULL;
