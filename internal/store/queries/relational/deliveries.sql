-- WP-8: the outbox (internal/deliver). Every instant is the database's
-- clock (clock_timestamp()), never a replica's.

-- name: InsertDelivery :one
-- A queued job; no row back means the same job (kind, idempotency key,
-- target) exists already.
INSERT INTO deliveries (id, kind, subject_ref, restriction_id, ansp_version, op, target, idempotency_key,
                        max_attempts, queued_at, window_ends_at, next_retry_at, body, policy_version)
VALUES (sqlc.arg(id), sqlc.arg(kind), sqlc.arg(subject_ref), sqlc.arg(restriction_id), sqlc.arg(ansp_version),
        sqlc.arg(op), sqlc.arg(target), sqlc.arg(idempotency_key), sqlc.arg(max_attempts), clock_timestamp(),
        clock_timestamp() + make_interval(secs => sqlc.arg(window_s)::float8), clock_timestamp(),
        sqlc.narg(body), sqlc.narg(policy_version))
ON CONFLICT ON CONSTRAINT deliveries_unique_job DO NOTHING
RETURNING id;

-- name: ClaimDelivery :one
-- Leases a queued, due row whose earlier versions to the same target
-- are settled, for one attempt. The DSS writes of a restriction (put and
-- delete) are one channel: a delete waits for the put before it (WP-9).
UPDATE deliveries d SET
    lease_token = sqlc.arg(token), lease_until = clock_timestamp() + make_interval(secs => sqlc.arg(lease_s)::float8),
    attempt = d.attempt + 1, last_attempt_at = clock_timestamp()
WHERE d.id = sqlc.arg(id) AND d.state = 'queued'
  AND (d.lease_until IS NULL OR d.lease_until < clock_timestamp())
  AND d.next_retry_at <= clock_timestamp()
  AND NOT EXISTS (
      SELECT 1 FROM deliveries p
      WHERE (p.kind = d.kind OR (p.kind IN ('dss_put', 'dss_delete') AND d.kind IN ('dss_put', 'dss_delete')))
        AND p.restriction_id = d.restriction_id AND p.target = d.target
        AND p.ansp_version < d.ansp_version AND p.state = 'queued')
RETURNING d.id, d.kind, d.subject_ref, d.restriction_id, d.ansp_version, d.op, d.target, d.idempotency_key, d.state,
          d.attempt, d.max_attempts, d.queued_at, d.window_ends_at, d.next_retry_at, d.bus_seq, d.last_attempt_at,
          d.sent_at, d.status_code, d.response_excerpt, d.last_error, d.method, d.url, d.body, d.cancel_reason,
          clock_timestamp()::timestamptz AS now;

-- name: DeliveryClaimState :one
-- Why a claim did not lease the row: its state, lease, due time and the
-- soonest due time of an earlier version still queued.
SELECT d.state, d.lease_until, d.next_retry_at, clock_timestamp()::timestamptz AS now,
       -- the epoch when nothing earlier is queued
       COALESCE((SELECT min(GREATEST(p.next_retry_at, COALESCE(p.lease_until, p.next_retry_at)))
        FROM deliveries p
        WHERE (p.kind = d.kind OR (p.kind IN ('dss_put', 'dss_delete') AND d.kind IN ('dss_put', 'dss_delete')))
          AND p.restriction_id = d.restriction_id AND p.target = d.target
          AND p.ansp_version < d.ansp_version AND p.state = 'queued'), 'epoch'::timestamptz)::timestamptz AS blocked_until
FROM deliveries d WHERE d.id = sqlc.arg(id);

-- name: DeferDelivery :exec
-- A row blocked behind an earlier version is due no sooner than it
-- (the outbox scan then does not take it for a stuck message).
UPDATE deliveries SET next_retry_at = GREATEST(next_retry_at, sqlc.arg(until)::timestamptz)
WHERE id = sqlc.arg(id) AND state = 'queued';

-- name: PrepareDelivery :one
-- Fixes the request at the first attempt; a prepared row keeps its own.
UPDATE deliveries SET
    method = COALESCE(method, sqlc.arg(method)), url = COALESCE(url, sqlc.arg(url)), body = COALESCE(body, sqlc.arg(body))
WHERE id = sqlc.arg(id) AND lease_token = sqlc.arg(token)
RETURNING id, kind, subject_ref, restriction_id, ansp_version, op, target, idempotency_key, state,
          attempt, max_attempts, queued_at, window_ends_at, next_retry_at, bus_seq, last_attempt_at,
          sent_at, status_code, response_excerpt, last_error, method, url, body, cancel_reason;

-- name: FinishDelivery :one
-- The outcome of an attempt, only while the lease is still this
-- attempt's.
UPDATE deliveries SET
    state = sqlc.arg(state), lease_token = NULL, lease_until = NULL,
    status_code = sqlc.narg(status_code), response_excerpt = sqlc.narg(response_excerpt), last_error = sqlc.narg(last_error),
    sent_at = CASE WHEN sqlc.arg(state)::delivery_state = 'sent' THEN clock_timestamp() ELSE sent_at END,
    next_retry_at = CASE WHEN sqlc.arg(state)::delivery_state = 'queued' THEN sqlc.arg(retry_at)::timestamptz ELSE next_retry_at END,
    cancel_reason = sqlc.narg(cancel_reason)
WHERE id = sqlc.arg(id) AND lease_token = sqlc.arg(token) AND state = 'queued'
RETURNING id;

-- name: InsertDeliveryAttempt :exec
INSERT INTO delivery_attempts (delivery_id, attempt, at, duration_ms, status_code, outcome, error, response_excerpt)
VALUES (sqlc.arg(delivery_id), sqlc.arg(attempt), clock_timestamp(), sqlc.arg(duration_ms), sqlc.narg(status_code),
        sqlc.arg(outcome), sqlc.narg(error), sqlc.narg(response_excerpt))
ON CONFLICT (delivery_id, attempt) DO NOTHING;

-- name: CountDeliveryAttempts :one
SELECT count(*)::bigint FROM delivery_attempts WHERE delivery_id = sqlc.arg(delivery_id);

-- name: PendingDeliveries :many
-- Queued rows never published (older than the publish grace), and rows
-- whose message is overdue: due for longer than the stuck grace with no
-- attempt and no publish since.
SELECT id, kind, bus_seq, (bus_published_at IS NOT NULL)::boolean AS stuck
FROM deliveries
WHERE state = 'queued' AND (lease_until IS NULL OR lease_until < clock_timestamp()) AND (
      (bus_published_at IS NULL AND queued_at < clock_timestamp() - make_interval(secs => sqlc.arg(publish_grace_s)::float8))
   OR (bus_published_at IS NOT NULL
       AND next_retry_at < clock_timestamp() - make_interval(secs => sqlc.arg(stuck_grace_s)::float8)
       AND GREATEST(bus_published_at, COALESCE(last_attempt_at, bus_published_at)) < clock_timestamp() - make_interval(secs => sqlc.arg(stuck_grace_s)::float8)))
ORDER BY next_retry_at
LIMIT sqlc.arg(page_size);

-- name: QueuedOfVersion :many
SELECT id, kind, bus_seq FROM deliveries
WHERE restriction_id = sqlc.arg(restriction_id) AND ansp_version = sqlc.arg(ansp_version)
  AND state = 'queued' AND bus_published_at IS NULL
ORDER BY id
LIMIT 300;

-- name: MarkDeliveryBusPublished :one
UPDATE deliveries SET bus_seq = sqlc.arg(seq), bus_published_at = clock_timestamp()
WHERE id = sqlc.arg(id) AND bus_seq = sqlc.arg(seq)::integer - 1
RETURNING id;

-- name: DeliveryVersion :one
-- A version of a restriction (0: its current one) with what a delivery
-- needs: the restriction now, the version's window and feature, and the
-- state of the version before it.
SELECT r.id, r.ansp_ref, r.identifier, r.uspace_airspace_id, r.state AS current_state, r.ansp_version AS current_version,
       r.published_version, v.version, v.state, v.starts_at, v.ends_at, v.feature::text AS feature, v.changed_at,
       r.dss_state, r.dss_pending_since, r.dss_put_version, r.dss_version,
       COALESCE((SELECT p.state::text FROM restriction_versions p
                 WHERE p.restriction_id = r.id AND p.version = v.version - 1), '')::text AS prev_state
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id
 AND v.version = CASE WHEN sqlc.arg(version)::bigint = 0 THEN r.ansp_version ELSE sqlc.arg(version)::bigint END
WHERE r.id = sqlc.arg(id);

-- name: MarkPublishedVersion :one
-- The CISP confirmed version: published_version never moves back.
UPDATE restrictions SET published_version = GREATEST(COALESCE(published_version, 0), sqlc.arg(version)::bigint)
WHERE id = sqlc.arg(id) AND sqlc.arg(version)::bigint <= ansp_version
RETURNING state, ansp_version, published_version;

-- name: CancelQueuedDeliveries :many
UPDATE deliveries SET state = 'cancelled', cancel_reason = sqlc.arg(reason), lease_token = NULL, lease_until = NULL
WHERE kind = sqlc.arg(kind) AND restriction_id = sqlc.arg(restriction_id) AND ansp_version <= sqlc.arg(up_to)
  AND state = 'queued'
RETURNING id, target, ansp_version;

-- name: OverdueRestrictions :many
-- Active restrictions whose current version is not published to the
-- CISP for longer than after_s, and ended or cancelled ones whose open
-- alarm is at an earlier version (their active version went out on the
-- degraded direct path, so their end goes there too, at once), without
-- an open alarm at that version.
SELECT r.id, r.ansp_version, v.changed_at,
       COALESCE((SELECT a.id FROM delivery_alarms a
                 WHERE a.restriction_id = r.id AND a.kind = 'cisp_not_published' AND a.cleared_at IS NULL), '')::text AS alarm_id
FROM restrictions r
JOIN restriction_versions v ON v.restriction_id = r.id AND v.version = r.ansp_version
WHERE COALESCE(r.published_version, 0) < r.ansp_version
  AND ((r.state = 'active' AND v.changed_at <= clock_timestamp() - make_interval(secs => sqlc.arg(after_s)::float8))
       OR (r.state IN ('ended', 'cancelled')
           AND EXISTS (SELECT 1 FROM delivery_alarms a
                       WHERE a.restriction_id = r.id AND a.kind = 'cisp_not_published' AND a.cleared_at IS NULL
                         AND a.ansp_version < r.ansp_version)))
  AND NOT EXISTS (SELECT 1 FROM delivery_alarms a
                  WHERE a.restriction_id = r.id AND a.kind = 'cisp_not_published' AND a.cleared_at IS NULL
                    AND a.ansp_version >= r.ansp_version)
ORDER BY v.changed_at
LIMIT sqlc.arg(page_size);

-- name: ClearableAlarms :many
-- Open cisp_not_published alarms whose current version the CISP holds,
-- or whose restriction is no longer active and whose current version
-- (its end) has been delivered directly: the alarm stands at that
-- version and no direct delivery of it is still queued.
SELECT a.id, a.restriction_id, r.state, r.ansp_version, COALESCE(r.published_version, 0)::bigint AS published_version
FROM delivery_alarms a JOIN restrictions r ON r.id = a.restriction_id
WHERE a.kind = 'cisp_not_published' AND a.cleared_at IS NULL
  AND (COALESCE(r.published_version, 0) >= r.ansp_version
       OR (r.state <> 'active' AND a.ansp_version >= r.ansp_version
           AND NOT EXISTS (SELECT 1 FROM deliveries d
                           WHERE d.kind = 'direct_degraded' AND d.restriction_id = r.id
                             AND d.ansp_version = r.ansp_version AND d.state = 'queued')))
ORDER BY a.raised_at
LIMIT sqlc.arg(page_size);

-- name: InsertAlarm :one
-- No row back: an equal alarm is open (one cisp_not_published per
-- restriction, one alarm per delivery and kind).
INSERT INTO delivery_alarms (id, kind, restriction_id, ansp_version, delivery_id, raised_at, since, detail)
VALUES (sqlc.arg(id), sqlc.arg(kind), sqlc.narg(restriction_id), sqlc.narg(ansp_version), sqlc.narg(delivery_id),
        clock_timestamp(), sqlc.arg(since), sqlc.arg(detail))
ON CONFLICT DO NOTHING
RETURNING *;

-- name: OpenCISPAlarm :one
SELECT * FROM delivery_alarms
WHERE restriction_id = sqlc.arg(restriction_id) AND kind = 'cisp_not_published' AND cleared_at IS NULL;

-- name: AlarmOfDelivery :one
SELECT * FROM delivery_alarms WHERE delivery_id = sqlc.arg(delivery_id) AND kind = sqlc.arg(kind);

-- name: AdvanceAlarm :exec
UPDATE delivery_alarms SET ansp_version = sqlc.arg(ansp_version), detail = sqlc.arg(detail)
WHERE id = sqlc.arg(id) AND cleared_at IS NULL AND ansp_version < sqlc.arg(ansp_version);

-- name: ClearCISPAlarm :one
UPDATE delivery_alarms SET cleared_at = clock_timestamp(), clear_reason = sqlc.arg(reason)
WHERE restriction_id = sqlc.arg(restriction_id) AND kind = 'cisp_not_published' AND cleared_at IS NULL
RETURNING *;

-- name: AcknowledgeAlarm :one
-- A person's acknowledgement: it closes a failed or abandoned delivery's
-- alarm; a cisp_not_published, uss_notify_late or occurrence_undelivered
-- alarm stays open until what resolves it.
UPDATE delivery_alarms SET
    acknowledged_by = sqlc.arg(by), acknowledged_at = clock_timestamp(), ack_reason = sqlc.arg(reason),
    cleared_at = CASE WHEN kind IN ('cisp_not_published', 'uss_notify_late', 'occurrence_undelivered') THEN cleared_at ELSE clock_timestamp() END,
    clear_reason = CASE WHEN kind IN ('cisp_not_published', 'uss_notify_late', 'occurrence_undelivered') THEN clear_reason ELSE 'acknowledged' END
WHERE id = sqlc.arg(id) AND acknowledged_at IS NULL AND cleared_at IS NULL
RETURNING *;

-- name: AlarmByID :one
SELECT * FROM delivery_alarms WHERE id = sqlc.arg(id);

-- name: ListAlarms :many
SELECT * FROM delivery_alarms
WHERE sqlc.arg(all_alarms)::boolean OR cleared_at IS NULL
ORDER BY raised_at DESC, id DESC
LIMIT sqlc.arg(page_size);

-- name: ExpediteQueued :many
-- The reconciliation: the queued rows of the restriction are due now.
UPDATE deliveries SET next_retry_at = clock_timestamp()
WHERE kind = sqlc.arg(kind) AND restriction_id = sqlc.arg(restriction_id) AND state = 'queued'
RETURNING id, kind, bus_seq;

-- name: RequeueAbandoned :one
UPDATE deliveries SET state = 'queued', max_attempts = LEAST(attempt + sqlc.arg(extra)::integer, 100000),
    window_ends_at = clock_timestamp() + make_interval(secs => sqlc.arg(window_s)::float8),
    next_retry_at = clock_timestamp(), lease_token = NULL, lease_until = NULL
WHERE kind = sqlc.arg(kind) AND restriction_id = sqlc.arg(restriction_id) AND ansp_version = sqlc.arg(ansp_version)
  AND state = 'abandoned'
RETURNING id, kind, bus_seq;

-- name: ActiveAnspRefs :many
SELECT ansp_ref FROM restrictions WHERE state = 'active' ORDER BY ansp_ref LIMIT sqlc.arg(page_size);

-- name: UnpublishedActive :many
SELECT id, ansp_ref, ansp_version FROM restrictions
WHERE state = 'active' AND COALESCE(published_version, 0) < ansp_version
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: DeliveryChannels :many
SELECT kind, state, attempt, last_attempt_at, status_code, next_retry_at
FROM deliveries
WHERE restriction_id = sqlc.arg(restriction_id) AND ansp_version = sqlc.arg(ansp_version)
ORDER BY queued_at
LIMIT 300;
