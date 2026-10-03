-- WP-10: the Annex V inbox and the occurrence reports (internal/coord).
-- Every instant is the database clock, or the clock the service passes
-- as now (its default is the database clock; a test passes a fake one).

-- name: InsertNotice :one
-- A received notice; no row back means the sender sent this notice_ref
-- before (the caller reads that one).
INSERT INTO coordination_notices (id, kind, sender_client_id, ussp_id, notice_ref, payload, payload_sha256, intent_refs,
                                  authorisation_numbers, ack_required, sender_unverified, restriction_ids, cis_version, received_at)
VALUES (sqlc.arg(id), sqlc.arg(kind), sqlc.arg(sender_client_id), sqlc.arg(ussp_id), sqlc.arg(notice_ref), sqlc.arg(payload),
        sqlc.arg(payload_sha256), sqlc.arg(intent_refs)::uuid[], sqlc.arg(authorisation_numbers)::text[], sqlc.arg(ack_required),
        sqlc.arg(sender_unverified), sqlc.arg(restriction_ids)::text[], sqlc.narg(cis_version), sqlc.arg(received_at))
ON CONFLICT ON CONSTRAINT coordination_notices_sender_ref DO NOTHING
RETURNING *;

-- name: NoticeBySenderRef :one
SELECT * FROM coordination_notices WHERE sender_client_id = sqlc.arg(sender_client_id) AND notice_ref = sqlc.arg(notice_ref);

-- name: NoticeByID :one
SELECT * FROM coordination_notices WHERE id = sqlc.arg(id);

-- name: ListNotices :many
-- The inbox, newest first: state received (not escalated), escalated
-- (received and escalated) or acknowledged; open is every notice not
-- acknowledged (the console's snapshot).
SELECT * FROM coordination_notices
WHERE (sqlc.narg(state)::text IS NULL
       OR (sqlc.narg(state)::text = 'received' AND state = 'received' AND escalated_at IS NULL)
       OR (sqlc.narg(state)::text = 'escalated' AND state = 'received' AND escalated_at IS NOT NULL)
       OR (sqlc.narg(state)::text = 'open' AND state = 'received')
       OR (sqlc.narg(state)::text = 'acknowledged' AND state = 'acknowledged'))
  AND (sqlc.narg(since)::timestamptz IS NULL OR received_at >= sqlc.narg(since)::timestamptz)
ORDER BY received_at DESC, id DESC
LIMIT sqlc.arg(page_size);

-- name: AcknowledgeNotice :one
-- A person's acknowledgement (Art. 13(2)); no row back when the notice
-- is acknowledged already or does not exist.
UPDATE coordination_notices SET
    state = 'acknowledged', acknowledged_by = sqlc.arg(role), acknowledged_user = sqlc.arg(user_id),
    acknowledged_at = clock_timestamp(), ack_note = sqlc.narg(note), event_seq = event_seq + 1
WHERE id = sqlc.arg(id) AND state = 'received'
RETURNING *;

-- name: EscalateDue :many
-- The notices that need a person and have none: not acknowledged
-- escalation_s after receipt, then again every repeat_s. Rows another
-- replica is escalating are skipped, so each escalation happens once.
UPDATE coordination_notices n SET
    escalated_at = COALESCE(n.escalated_at, sqlc.arg(now)::timestamptz), last_escalated_at = sqlc.arg(now)::timestamptz,
    escalations = n.escalations + 1, event_seq = n.event_seq + 1
WHERE n.id IN (
    SELECT c.id FROM coordination_notices c
    WHERE c.state = 'received' AND c.ack_required
      AND c.received_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(escalation_s)::float8)
      AND (c.last_escalated_at IS NULL
           OR c.last_escalated_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(repeat_s)::float8))
    ORDER BY c.received_at
    LIMIT sqlc.arg(page_size)
    FOR UPDATE SKIP LOCKED)
RETURNING n.*;

-- name: NoticesBehindBus :many
-- Notices whose latest change is not on coord.v1 yet.
SELECT * FROM coordination_notices WHERE bus_seq < event_seq ORDER BY id LIMIT sqlc.arg(page_size);

-- name: MarkNoticeBus :exec
UPDATE coordination_notices SET bus_seq = GREATEST(bus_seq, sqlc.arg(seq)::int)
WHERE id = sqlc.arg(id) AND sqlc.arg(seq)::int <= event_seq;

-- name: CountNoticesBehindBus :one
SELECT count(*)::bigint FROM coordination_notices WHERE bus_seq < event_seq;

-- name: IntersectingRestrictions :many
-- The planned or active restrictions that intersect any of the boxes
-- (each the conservative envelope of one notice volume, uspace-core
-- f3548.Volume4DToZonesEnvelope, as a JSON array of {min_lon, min_lat,
-- max_lon, max_lat, t_start, t_end}) in its time window: a polygon in
-- degrees against the box, a circle as its geodesic buffer.
SELECT DISTINCT r.id
FROM restrictions r,
     jsonb_to_recordset(sqlc.arg(boxes)::jsonb)
         AS b(min_lon double precision, min_lat double precision, max_lon double precision, max_lat double precision,
              t_start timestamptz, t_end timestamptz)
WHERE r.state IN ('planned', 'active')
  AND r.starts_at < b.t_end AND r.ends_at > b.t_start
  AND ST_Intersects(
        CASE WHEN r.radius_m IS NULL THEN r.geom ELSE ST_Buffer(r.geom::geography, r.radius_m)::geometry END,
        ST_MakeEnvelope(b.min_lon, b.min_lat, b.max_lon, b.max_lat, 4326))
ORDER BY r.id
LIMIT sqlc.arg(page_size);

-- name: NextOccurrenceRef :one
SELECT ('ANSP-OCC-' || to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY') || '-'
        || lpad(nextval('occurrence_report_seq')::text, 4, '0'))::text AS report_ref;

-- name: InsertOccurrence :one
INSERT INTO occurrence_reports (id, report_ref, channel, occurred_at, became_aware_at, category, aircraft, manned, intent_refs,
                                min_separation, narrative, reporter_person_ref_sealed, reporter_key_id, created_by, delivery_id,
                                deadline_at)
VALUES (sqlc.arg(id), sqlc.arg(report_ref), sqlc.arg(channel), sqlc.arg(occurred_at), sqlc.arg(became_aware_at), sqlc.arg(category),
        sqlc.arg(aircraft), sqlc.arg(manned), sqlc.arg(intent_refs)::uuid[], sqlc.narg(min_separation), sqlc.arg(narrative),
        sqlc.narg(reporter_person_ref_sealed), sqlc.narg(reporter_key_id), sqlc.arg(created_by), sqlc.arg(delivery_id),
        sqlc.arg(became_aware_at)::timestamptz + interval '72 hours')
RETURNING *;

-- name: OccurrenceByDelivery :one
SELECT * FROM occurrence_reports WHERE delivery_id = sqlc.arg(delivery_id);

-- name: UndeliveredOccurrences :many
-- Reports whose delivery is not sent alarm_after_s after became_aware_at
-- (at now) and have no occurrence_undelivered alarm yet.
SELECT o.id, o.report_ref, o.delivery_id, o.became_aware_at, o.deadline_at, d.state AS delivery_state
FROM occurrence_reports o JOIN deliveries d ON d.id = o.delivery_id
WHERE d.state <> 'sent'
  AND o.became_aware_at <= sqlc.arg(now)::timestamptz - make_interval(secs => sqlc.arg(alarm_after_s)::float8)
  AND NOT EXISTS (SELECT 1 FROM delivery_alarms a WHERE a.delivery_id = o.delivery_id AND a.kind = 'occurrence_undelivered')
ORDER BY o.became_aware_at
LIMIT sqlc.arg(page_size);

-- name: DeliveredOccurrenceAlarms :many
-- Open occurrence_undelivered alarms whose report is now delivered.
SELECT a.id, a.delivery_id
FROM delivery_alarms a JOIN deliveries d ON d.id = a.delivery_id
WHERE a.kind = 'occurrence_undelivered' AND a.cleared_at IS NULL AND d.state = 'sent'
ORDER BY a.raised_at
LIMIT sqlc.arg(page_size);
