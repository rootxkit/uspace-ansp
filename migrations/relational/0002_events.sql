-- The append-only audit log (docs/PLAN.md section 5.1, spec 06 section
-- 2 T7): every write, switch, view of the inbox and export.
--
-- Partitioned by month on ts; partitions are created on demand by
-- events_ensure_partition, which internal/audit calls under the month's
-- advisory lock. Each row carries prev_hash and hash:
--
--     hash = hex(sha256(prev_hash || canonical JSON of the row))
--
-- chained in id order within a month, the first row of a month linking
-- to the last row before it, the first row ever to 64 zeros.
--
-- ansp_app may SELECT and INSERT and nothing else. A trigger refuses
-- UPDATE, DELETE and TRUNCATE for every role, the owner included, so a
-- rewrite needs a superuser bypassing the trigger, which Verify then
-- detects. No foreign key references events: PostgreSQL checks a foreign
-- key with SELECT ... FOR KEY SHARE as the referenced table's owner,
-- which needs UPDATE on it, and an insert-only table must not need it.

-- +goose Up
CREATE TABLE events (
    id          bigserial   NOT NULL,
    ts          timestamptz NOT NULL,
    actor_type  text        NOT NULL CHECK (actor_type IN ('user', 'client', 'system')),
    actor_id    text        NOT NULL CHECK (actor_id <> ''),
    purpose     text        NOT NULL CHECK (purpose <> ''),
    entity_type text        NOT NULL CHECK (entity_type <> ''),
    entity_id   text        NOT NULL CHECK (entity_id <> ''),
    event_type  text        NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    prev_hash   text        NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash        text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX events_entity_idx ON events (entity_type, entity_id, ts);
CREATE INDEX events_ts_idx ON events (ts, id);

-- +goose StatementBegin
CREATE FUNCTION events_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'events is append-only: % refused', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER events_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_refuse_change();

-- events_ensure_partition creates the UTC month partition holding at
-- when it is missing and returns its name; the partition gets its own
-- TRUNCATE guard (row triggers are inherited, statement triggers on
-- TRUNCATE are not). SECURITY DEFINER so that ansp_app, which may not
-- create tables, can call it.
-- +goose StatementBegin
CREATE FUNCTION events_ensure_partition(at timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    month_start timestamptz := date_trunc('month', at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    month_end   timestamptz := (date_trunc('month', at AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC';
    part        text        := 'events_' || to_char(at AT TIME ZONE 'UTC', 'YYYY_MM');
BEGIN
    IF to_regclass(part) IS NULL THEN
        EXECUTE format('CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
                       part, month_start, month_end);
        EXECUTE format('CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON %I '
                       'FOR EACH STATEMENT EXECUTE FUNCTION events_refuse_change()', part);
    END IF;
    RETURN part;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER events_no_truncate
    BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION events_refuse_change();

REVOKE ALL ON FUNCTION events_ensure_partition(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION events_ensure_partition(timestamptz) TO ansp_app;
GRANT SELECT, INSERT ON events TO ansp_app;
GRANT USAGE ON SEQUENCE events_id_seq TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS events CASCADE;
DROP FUNCTION IF EXISTS events_ensure_partition(timestamptz);
DROP FUNCTION IF EXISTS events_refuse_change();
