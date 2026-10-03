-- WP-10: the Annex V coordination inbox and the occurrence outbox
-- (docs/PLAN.md section 5.1 coordination_notices, occurrence_reports;
-- 2021/664 Art. 13(2), Annex V; 376/2014 Art. 4(8)).
--
-- coordination_notices: one row per notice a USSP sent, id = the ack_id
-- of its receipt. (sender_client_id, notice_ref) is unique: a repeat of
-- a notice answers the first receipt; payload_sha256 is the SHA-256 of
-- the canonical JSON of the body as received, so a reused notice_ref
-- with another body is told apart. The acknowledgement is two states
-- (section 15 gap 6): received (the receipt) and acknowledged (a
-- person, acknowledged_by holds the role, acknowledged_user the account
-- id for the audit; neither is a name). A nonconformance or contingent
-- notice needs the acknowledgement (ack_required); intent_notice and
-- ended do not (informational). escalated_at is the first escalation
-- (not acknowledged within notice_escalation_s), last_escalated_at and
-- escalations the repeats every 30 s until acknowledged; they are on the
-- row so that a restart, a rolling update with a new hostname or another
-- replica carries on the escalation, never clears it. event_seq counts
-- the notice's changes (received, each escalation, the acknowledgement)
-- and bus_seq the last one put on coord.v1: a change not yet on the bus
-- is published again by the ticker, so a missed acknowledgement or
-- escalation is never forgotten. sender_unverified: accepted while no
-- CIS USSP list was projected (never refused for lack of our own data).
-- restriction_ids are the planned or active restrictions the notice's
-- volumes intersect in space and time, computed at receipt.
--
-- occurrence_reports: an ANSP staff occurrence report queued to the
-- authority through the outbox (deliveries kind occurrence, no
-- restriction). reporter_person_ref_sealed is the reporter's opaque
-- reference sealed under ANSP_SECRETS_KEY_FILE (AES-256-GCM, bound to
-- the report id), reporter_key_id names that key; the clear value is
-- built into the request at each attempt and never stored (the
-- delivery's body column stays empty for this kind). deadline_at is
-- became_aware_at + 72 h (Art. 4(8)); a report not delivered 60 h after
-- became_aware_at raises the alarm occurrence_undelivered, open until
-- the delivery is sent.

-- +goose Up
CREATE TABLE coordination_notices (
    id                    text        PRIMARY KEY CHECK (id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    kind                  text        NOT NULL CHECK (kind IN ('intent_notice', 'nonconformance', 'contingent', 'ended')),
    sender_client_id      text        NOT NULL CHECK (sender_client_id <> '' AND length(sender_client_id) <= 256),
    ussp_id               text        NOT NULL CHECK (ussp_id <> '' AND length(ussp_id) <= 64),
    notice_ref            text        NOT NULL CHECK (notice_ref <> '' AND length(notice_ref) <= 128),
    payload               jsonb       NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    payload_sha256        bytea       NOT NULL CHECK (octet_length(payload_sha256) = 32),
    intent_refs           uuid[]      NOT NULL CHECK (cardinality(intent_refs) BETWEEN 1 AND 100),
    authorisation_numbers text[]      NOT NULL CHECK (cardinality(authorisation_numbers) <= 100),
    received_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    state                 text        NOT NULL DEFAULT 'received' CHECK (state IN ('received', 'acknowledged')),
    ack_required          boolean     NOT NULL,
    sender_unverified     boolean     NOT NULL DEFAULT false,
    acknowledged_by       text        CHECK (acknowledged_by IN ('watch_supervisor', 'viewer', 'admin')),
    acknowledged_user     text        CHECK (acknowledged_user <> '' AND length(acknowledged_user) <= 256),
    acknowledged_at       timestamptz,
    ack_note              text        CHECK (length(ack_note) <= 500),
    escalated_at          timestamptz,
    last_escalated_at     timestamptz,
    escalations           integer     NOT NULL DEFAULT 0 CHECK (escalations >= 0),
    restriction_ids       text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(restriction_ids) <= 1000),
    cis_version           text        CHECK (length(cis_version) <= 64),
    event_seq             integer     NOT NULL DEFAULT 1 CHECK (event_seq >= 1),
    bus_seq               integer     NOT NULL DEFAULT 0 CHECK (bus_seq >= 0),
    CONSTRAINT coordination_notices_sender_ref UNIQUE (sender_client_id, notice_ref),
    CONSTRAINT coordination_notices_ack_whole CHECK (
        (state = 'acknowledged') = (acknowledged_at IS NOT NULL)
        AND (acknowledged_at IS NULL) = (acknowledged_by IS NULL)
        AND (acknowledged_at IS NULL) = (acknowledged_user IS NULL)
    ),
    CONSTRAINT coordination_notices_escalation_whole CHECK (
        (escalated_at IS NULL) = (last_escalated_at IS NULL) AND (escalated_at IS NULL) = (escalations = 0)
    ),
    CONSTRAINT coordination_notices_escalate_only_required CHECK (ack_required OR escalated_at IS NULL),
    CONSTRAINT coordination_notices_bus_behind CHECK (bus_seq <= event_seq)
);
CREATE INDEX coordination_notices_received_idx ON coordination_notices (received_at DESC, id DESC);
CREATE INDEX coordination_notices_open_idx ON coordination_notices (received_at) WHERE state = 'received' AND ack_required;
CREATE INDEX coordination_notices_bus_idx ON coordination_notices (id) WHERE bus_seq < event_seq;

CREATE SEQUENCE occurrence_report_seq;

CREATE TABLE occurrence_reports (
    id                         text        PRIMARY KEY CHECK (id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    report_ref                 text        NOT NULL UNIQUE CHECK (report_ref ~ '^ANSP-OCC-[0-9]{4}-[0-9]{4,}$'),
    channel                    text        NOT NULL CHECK (channel IN ('mandatory', 'voluntary')),
    occurred_at                timestamptz NOT NULL,
    became_aware_at            timestamptz NOT NULL,
    category                   text        NOT NULL CHECK (category IN (
        'airprox', 'nonconformance_in_prohibited', 'lost_link_in_uspace', 'emergency', 'other')),
    aircraft                   jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(aircraft) = 'array'),
    manned                     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(manned) = 'array'),
    intent_refs                uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(intent_refs) <= 50),
    min_separation             jsonb       CHECK (jsonb_typeof(min_separation) = 'object'),
    narrative                  text        NOT NULL CHECK (narrative <> '' AND length(narrative) <= 10000),
    reporter_person_ref_sealed bytea       CHECK (octet_length(reporter_person_ref_sealed) <= 512),
    reporter_key_id            text        CHECK (reporter_key_id ~ '^[0-9a-f]{16}$'),
    created_by                 text        NOT NULL CHECK (created_by <> '' AND length(created_by) <= 256),
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivery_id                text        NOT NULL UNIQUE REFERENCES deliveries (id),
    deadline_at                timestamptz NOT NULL,
    CONSTRAINT occurrence_reports_sealed_whole CHECK ((reporter_person_ref_sealed IS NULL) = (reporter_key_id IS NULL)),
    CONSTRAINT occurrence_reports_deadline CHECK (deadline_at = became_aware_at + interval '72 hours'),
    CONSTRAINT occurrence_reports_aware_after CHECK (became_aware_at >= occurred_at)
);
CREATE INDEX occurrence_reports_aware_idx ON occurrence_reports (became_aware_at);

ALTER TABLE delivery_alarms DROP CONSTRAINT delivery_alarms_kind_check;
ALTER TABLE delivery_alarms ADD CONSTRAINT delivery_alarms_kind_check
    CHECK (kind IN ('cisp_not_published', 'delivery_failed', 'delivery_abandoned', 'uss_notify_late', 'occurrence_undelivered'));

GRANT SELECT, INSERT, UPDATE ON coordination_notices TO ansp_app;
GRANT SELECT, INSERT ON occurrence_reports TO ansp_app;
GRANT USAGE, SELECT ON SEQUENCE occurrence_report_seq TO ansp_app;

-- +goose Down
DELETE FROM delivery_alarms WHERE kind = 'occurrence_undelivered';
ALTER TABLE delivery_alarms DROP CONSTRAINT IF EXISTS delivery_alarms_kind_check;
ALTER TABLE delivery_alarms ADD CONSTRAINT delivery_alarms_kind_check
    CHECK (kind IN ('cisp_not_published', 'delivery_failed', 'delivery_abandoned', 'uss_notify_late'));
DROP TABLE IF EXISTS occurrence_reports;
DROP SEQUENCE IF EXISTS occurrence_report_seq;
DROP TABLE IF EXISTS coordination_notices;
