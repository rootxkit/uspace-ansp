-- WP-9: the F3548 constraint manager (docs/PLAN.md section 5.1, 02 F2,
-- 02 F6, 09 section 1.4).
--
-- restrictions gains the restriction's standing in the DSS: dss_state
-- (none, pending while a DSS write is queued, written, deleted, failed),
-- dss_pending_since (set while pending or failed: the console's "dss:
-- pending since T"; a DSS outage never blocks the CISP publication, D6),
-- dss_reference (the ConstraintReference the DSS last answered a put
-- with, its ovn included: what GET /uss/v1/constraints/{entityid}
-- serves, with the details of dss_put_version) and dss_written_at.
-- dss_constraint_id, dss_ovn and dss_version are WP-1's (0005).
--
-- dss_constraint_writes: one row per write the DSS accepted (a put or a
-- delete of one version), insert-only, with the reference it answered
-- and how many subscribers it named: the record of what the DSS held
-- when, and the reference a version's notifications carry.
--
-- dss_notifications: one row per subscription the DSS named, with the
-- uss_notify delivery that carries it, its notification_index, when the
-- DSS answered, when it was sent and its state (02 F6: every subscriber
-- notified within CstrPublishedNotificationLatencySeconds, or the miss
-- visible).
--
-- delivery_alarms gains the kind uss_notify_late: a notification still
-- queued CstrPublishedNotificationLatencySeconds after the DSS answered;
-- open until the notification is settled.

-- +goose Up
ALTER TABLE restrictions
    ADD COLUMN dss_state         text        NOT NULL DEFAULT 'none'
        CHECK (dss_state IN ('none', 'pending', 'written', 'deleted', 'failed')),
    ADD COLUMN dss_pending_since timestamptz,
    ADD COLUMN dss_reference     jsonb       CHECK (jsonb_typeof(dss_reference) = 'object'),
    ADD COLUMN dss_put_version   bigint      CHECK (dss_put_version >= 1),
    ADD COLUMN dss_written_at    timestamptz,
    ADD CONSTRAINT restrictions_dss_pending_since CHECK (
        (dss_state IN ('pending', 'failed')) = (dss_pending_since IS NOT NULL)
    ),
    ADD CONSTRAINT restrictions_dss_ovn_bound CHECK (length(dss_ovn) BETWEEN 1 AND 256),
    ADD CONSTRAINT restrictions_dss_reference_whole CHECK ((dss_reference IS NULL) = (dss_put_version IS NULL));

CREATE INDEX restrictions_dss_pending_idx ON restrictions (dss_pending_since) WHERE dss_pending_since IS NOT NULL;

CREATE TABLE dss_constraint_writes (
    restriction_id text        NOT NULL REFERENCES restrictions (id),
    ansp_version   bigint      NOT NULL CHECK (ansp_version >= 1),
    op             text        NOT NULL CHECK (op IN ('put', 'delete')),
    delivery_id    text        NOT NULL REFERENCES deliveries (id),
    constraint_id  uuid        NOT NULL,
    ovn            text        CHECK (length(ovn) BETWEEN 1 AND 256),
    dss_version    bigint,
    reference      jsonb       CHECK (jsonb_typeof(reference) = 'object'),
    subscribers    integer     NOT NULL CHECK (subscribers >= 0),
    written_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (restriction_id, ansp_version, op),
    CONSTRAINT dss_constraint_writes_put_reference CHECK (op <> 'put' OR (reference IS NOT NULL AND ovn IS NOT NULL))
);

CREATE TABLE dss_notifications (
    delivery_id        text        NOT NULL REFERENCES deliveries (id),
    subscription_id    uuid        NOT NULL,
    notification_index integer     NOT NULL CHECK (notification_index >= 0),
    restriction_id     text        NOT NULL REFERENCES restrictions (id),
    ansp_version       bigint      NOT NULL CHECK (ansp_version >= 1),
    constraint_id      uuid        NOT NULL,
    subscriber         text        NOT NULL CHECK (subscriber <> '' AND length(subscriber) <= 512),
    op                 text        NOT NULL CHECK (op IN ('put', 'delete')),
    dss_answered_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    sent_at            timestamptz,
    status             text        NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'sent', 'failed', 'abandoned', 'cancelled')),
    PRIMARY KEY (delivery_id, subscription_id),
    CONSTRAINT dss_notifications_sent_has_time CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);
CREATE INDEX dss_notifications_restriction_idx ON dss_notifications (restriction_id, ansp_version);

ALTER TABLE delivery_alarms DROP CONSTRAINT delivery_alarms_kind_check;
ALTER TABLE delivery_alarms ADD CONSTRAINT delivery_alarms_kind_check
    CHECK (kind IN ('cisp_not_published', 'delivery_failed', 'delivery_abandoned', 'uss_notify_late'));

GRANT SELECT, INSERT ON dss_constraint_writes TO ansp_app;
GRANT SELECT, INSERT, UPDATE ON dss_notifications TO ansp_app;

-- +goose Down
DELETE FROM delivery_alarms WHERE kind = 'uss_notify_late';
ALTER TABLE delivery_alarms DROP CONSTRAINT IF EXISTS delivery_alarms_kind_check;
ALTER TABLE delivery_alarms ADD CONSTRAINT delivery_alarms_kind_check
    CHECK (kind IN ('cisp_not_published', 'delivery_failed', 'delivery_abandoned'));
DROP TABLE IF EXISTS dss_notifications;
DROP TABLE IF EXISTS dss_constraint_writes;
DROP INDEX IF EXISTS restrictions_dss_pending_idx;
ALTER TABLE restrictions
    DROP CONSTRAINT IF EXISTS restrictions_dss_reference_whole,
    DROP CONSTRAINT IF EXISTS restrictions_dss_ovn_bound,
    DROP CONSTRAINT IF EXISTS restrictions_dss_pending_since,
    DROP COLUMN IF EXISTS dss_written_at,
    DROP COLUMN IF EXISTS dss_put_version,
    DROP COLUMN IF EXISTS dss_reference,
    DROP COLUMN IF EXISTS dss_pending_since,
    DROP COLUMN IF EXISTS dss_state;
