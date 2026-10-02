-- WP-8: the outbox (docs/PLAN.md section 5.1 deliveries, D5).
--
-- deliveries: one row per job, written in the transaction that makes
-- the change it carries (a restriction version, an alarm), and published
-- as deliver.v1.<kind> on the DELIVER work queue only after that commit.
-- The row is the truth; the message only says "look at this row". The
-- pair (kind, idempotency_key, target) is unique, so enqueuing the same
-- job twice writes one row. A worker leases a row for one attempt
-- (lease_token, lease_until on the database clock) before it calls out,
-- so two replicas never send the same job at once and nothing holds a
-- lock while the call is in flight. bus_seq counts the publishes of the
-- row (the message id is <id>.<bus_seq>), so a lost publish is repaired
-- by the outbox scan and never sent twice by two scans. method, url and
-- body are fixed at the first attempt and kept: every retry sends the
-- same bytes, which the CISP's replay rule (the pair with the same body)
-- needs. max_attempts bounds the retries (count), queued_at plus the
-- window bounds them in time; past either the row is abandoned, never
-- silently dropped.
--
-- delivery_attempts: one row per attempt (bounded by max_attempts),
-- with what was answered.
--
-- delivery_alarms: what a person must see. cisp_not_published (a
-- restriction active here and not published to the CISP for its current
-- version after cisp_alarm_after_s) is cleared by the publication, with
-- its duration, or when the restriction is no longer active;
-- delivery_failed and delivery_abandoned stay open until a person
-- acknowledges them with a reason (audited). At most one open
-- cisp_not_published per restriction and one alarm per delivery and
-- kind (the unique indexes), so concurrent replicas raise it once.

-- +goose Up
CREATE TYPE delivery_kind AS ENUM (
    'cisp_publish', 'cisp_heartbeat', 'dss_put', 'dss_delete', 'uss_notify', 'direct_degraded', 'occurrence'
);
CREATE TYPE delivery_state AS ENUM ('queued', 'sent', 'failed', 'abandoned', 'cancelled');

CREATE TABLE deliveries (
    id               text           PRIMARY KEY CHECK (id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    kind             delivery_kind  NOT NULL,
    subject_ref      text           NOT NULL CHECK (subject_ref <> '' AND length(subject_ref) <= 256),
    restriction_id   text           REFERENCES restrictions (id),
    ansp_version     bigint         CHECK (ansp_version >= 1),
    op               text           NOT NULL CHECK (op ~ '^[a-z_]{1,32}$'),
    target           text           NOT NULL CHECK (target <> '' AND length(target) <= 512),
    idempotency_key  text           NOT NULL CHECK (idempotency_key <> '' AND length(idempotency_key) <= 300),
    state            delivery_state NOT NULL DEFAULT 'queued',
    attempt          integer        NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts     integer        NOT NULL CHECK (max_attempts >= 1 AND max_attempts <= 100000),
    queued_at        timestamptz    NOT NULL DEFAULT clock_timestamp(),
    window_ends_at   timestamptz    NOT NULL,
    next_retry_at    timestamptz    NOT NULL DEFAULT clock_timestamp(),
    lease_token      text           CHECK (length(lease_token) <= 64),
    lease_until      timestamptz,
    bus_seq          integer        NOT NULL DEFAULT 0 CHECK (bus_seq >= 0),
    bus_published_at timestamptz,
    last_attempt_at  timestamptz,
    sent_at          timestamptz,
    status_code      integer        CHECK (status_code BETWEEN 100 AND 599),
    response_excerpt text           CHECK (length(response_excerpt) <= 2048),
    last_error       text           CHECK (length(last_error) <= 1024),
    method           text           CHECK (method IN ('POST', 'PATCH', 'PUT', 'DELETE')),
    url              text           CHECK (length(url) <= 2048),
    body             bytea          CHECK (octet_length(body) <= 262144),
    cancel_reason    text           CHECK (cancel_reason ~ '^[a-z_]{1,64}$'),
    policy_version   bigint,
    CONSTRAINT deliveries_unique_job UNIQUE (kind, idempotency_key, target),
    CONSTRAINT deliveries_restriction_whole CHECK ((restriction_id IS NULL) = (ansp_version IS NULL)),
    CONSTRAINT deliveries_sent_has_time CHECK (state <> 'sent' OR sent_at IS NOT NULL),
    CONSTRAINT deliveries_cancel_reason CHECK ((state = 'cancelled') = (cancel_reason IS NOT NULL)),
    CONSTRAINT deliveries_lease_whole CHECK ((lease_token IS NULL) = (lease_until IS NULL))
);
CREATE INDEX deliveries_queued_idx ON deliveries (next_retry_at) WHERE state = 'queued';
CREATE INDEX deliveries_restriction_idx ON deliveries (restriction_id, kind, ansp_version);

CREATE TABLE delivery_attempts (
    delivery_id      text        NOT NULL REFERENCES deliveries (id),
    attempt          integer     NOT NULL CHECK (attempt >= 1),
    at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    duration_ms      integer     NOT NULL CHECK (duration_ms >= 0),
    status_code      integer     CHECK (status_code BETWEEN 100 AND 599),
    outcome          text        NOT NULL CHECK (outcome IN ('sent', 'retry', 'failed', 'abandoned', 'cancelled')),
    error            text        CHECK (length(error) <= 1024),
    response_excerpt text        CHECK (length(response_excerpt) <= 2048),
    PRIMARY KEY (delivery_id, attempt)
);

CREATE TABLE delivery_alarms (
    id              text        PRIMARY KEY CHECK (id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    kind            text        NOT NULL CHECK (kind IN ('cisp_not_published', 'delivery_failed', 'delivery_abandoned')),
    restriction_id  text        REFERENCES restrictions (id),
    ansp_version    bigint      CHECK (ansp_version >= 1),
    delivery_id     text        REFERENCES deliveries (id),
    raised_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    since           timestamptz NOT NULL,
    detail          text        NOT NULL CHECK (detail <> '' AND length(detail) <= 1024),
    cleared_at      timestamptz,
    clear_reason    text        CHECK (clear_reason ~ '^[a-z_]{1,64}$'),
    acknowledged_by text        CHECK (acknowledged_by <> '' AND length(acknowledged_by) <= 256),
    acknowledged_at timestamptz,
    ack_reason      text        CHECK (ack_reason <> '' AND length(ack_reason) <= 1000),
    CONSTRAINT delivery_alarms_cleared_whole CHECK ((cleared_at IS NULL) = (clear_reason IS NULL)),
    CONSTRAINT delivery_alarms_ack_whole CHECK (
        (acknowledged_at IS NULL) = (acknowledged_by IS NULL) AND (acknowledged_at IS NULL) = (ack_reason IS NULL)
    ),
    CONSTRAINT delivery_alarms_subject CHECK (
        (kind = 'cisp_not_published' AND restriction_id IS NOT NULL AND ansp_version IS NOT NULL)
        OR (kind <> 'cisp_not_published' AND delivery_id IS NOT NULL)
    )
);
CREATE UNIQUE INDEX delivery_alarms_one_open_cisp ON delivery_alarms (restriction_id)
    WHERE kind = 'cisp_not_published' AND cleared_at IS NULL;
CREATE UNIQUE INDEX delivery_alarms_one_per_delivery ON delivery_alarms (delivery_id, kind)
    WHERE delivery_id IS NOT NULL;
CREATE INDEX delivery_alarms_open_idx ON delivery_alarms (raised_at) WHERE cleared_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON deliveries TO ansp_app;
GRANT SELECT, INSERT ON delivery_attempts TO ansp_app;
GRANT SELECT, INSERT, UPDATE ON delivery_alarms TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS delivery_alarms;
DROP TABLE IF EXISTS delivery_attempts;
DROP TABLE IF EXISTS deliveries;
DROP TYPE IF EXISTS delivery_state;
DROP TYPE IF EXISTS delivery_kind;
