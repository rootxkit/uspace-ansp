-- source_controls: the current switch per source type (instance_id
-- NULL) and per instance (docs/PLAN.md section 5.1, spec 04 section
-- 3.6, LESSONS B-09, predecessor U-15). The history is in events. WP-6's
-- internal/sources writes a row in the same transaction as the KV put
-- and refuses with 503 when KV cannot take it.
--
-- version comes from source_controls_version_seq, so it only goes
-- forward. epoch is the one source_control_epoch row, set once by
-- gen_random_uuid() when this migration runs: a restored database keeps
-- its epoch, a database created again gets a new one, which is what
-- uspace-core sources.Follower keys on.

-- +goose Up
CREATE TABLE source_control_epoch (
    singleton  boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch      uuid        NOT NULL DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO source_control_epoch DEFAULT VALUES;

CREATE SEQUENCE source_controls_version_seq AS bigint MINVALUE 1;

CREATE TABLE source_controls (
    source_type text        NOT NULL CHECK (source_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    instance_id text        CHECK (instance_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    enabled     boolean     NOT NULL,
    reason      text        NOT NULL CHECK (reason <> '' AND length(reason) <= 500),
    actor       text        NOT NULL CHECK (actor <> ''),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    version     bigint      NOT NULL DEFAULT nextval('source_controls_version_seq') CHECK (version >= 1),
    epoch       uuid        NOT NULL,
    UNIQUE NULLS NOT DISTINCT (source_type, instance_id)
);

ALTER SEQUENCE source_controls_version_seq OWNED BY source_controls.version;

GRANT SELECT ON source_control_epoch TO ansp_app;
GRANT SELECT, INSERT, UPDATE ON source_controls TO ansp_app;
GRANT USAGE, SELECT ON SEQUENCE source_controls_version_seq TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS source_controls;
DROP SEQUENCE IF EXISTS source_controls_version_seq;
DROP TABLE IF EXISTS source_control_epoch;
