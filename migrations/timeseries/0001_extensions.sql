-- Timeseries tree (TimescaleDB), written by manned-feed only.
-- goose version table: goose_db_version_timeseries. Never run against
-- the relational database; the two trees are never merged (CLAUDE.md
-- rule 6, LESSONS B-15).
--
-- ansp_ts_app is the role manned-feed works as (internal/store sets it
-- on every connection with SET ROLE). It may SELECT and INSERT on the
-- hypertables and nothing else (spec 06 T7: no UPDATE on manned_tracks);
-- each table's migration grants it explicitly. Created NOLOGIN when
-- missing; roles are cluster-wide, so the Down revokes and never drops.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS postgis;

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ansp_ts_app') THEN
        CREATE ROLE ansp_ts_app NOLOGIN;
    END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO ansp_ts_app;
GRANT SELECT ON goose_db_version_timeseries TO ansp_ts_app;

-- +goose Down
REVOKE ALL ON goose_db_version_timeseries FROM ansp_ts_app;
REVOKE USAGE ON SCHEMA public FROM ansp_ts_app;
DROP EXTENSION IF EXISTS postgis;
DROP EXTENSION IF EXISTS timescaledb;
