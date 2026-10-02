-- Relational tree (PostgreSQL 16 + PostGIS 3.4), written by api only.
-- goose version table: goose_db_version_relational. Never run against
-- the timeseries database; the two trees are never merged (CLAUDE.md
-- rule 6, LESSONS B-15).
--
-- ansp_app is the role api works as (internal/store sets it on every
-- connection with SET ROLE; the login user is granted membership by the
-- deployment). It is created NOLOGIN here when missing, so a deployment
-- that provisions it beforehand needs no CREATEROLE for the migrator.
-- Each later migration grants it, table by table, exactly what the
-- application may do. Roles are cluster-wide: the Down revokes and never
-- drops it.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS postgis;

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ansp_app') THEN
        CREATE ROLE ansp_app NOLOGIN;
    END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO ansp_app;
GRANT SELECT ON goose_db_version_relational TO ansp_app;

-- +goose Down
REVOKE ALL ON goose_db_version_relational FROM ansp_app;
REVOKE USAGE ON SCHEMA public FROM ansp_app;
DROP EXTENSION IF EXISTS postgis;
