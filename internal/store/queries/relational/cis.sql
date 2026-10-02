-- WP-7: cis_cache, the CIS projection. Every instant is the database
-- clock.

-- name: SaveCISVersion :one
-- The dataset's row becomes this version unless it holds a higher one
-- (the WHERE runs under the row's lock); no row back means it does.
INSERT INTO cis_cache (dataset, version, etag, fetched_at, installed_at, cis_updated_at, body)
VALUES (sqlc.arg(dataset), sqlc.arg(version), sqlc.arg(etag), clock_timestamp(), clock_timestamp(),
        sqlc.narg(cis_updated_at), sqlc.arg(body))
ON CONFLICT (dataset) DO UPDATE SET
    version = EXCLUDED.version, etag = EXCLUDED.etag, fetched_at = EXCLUDED.fetched_at,
    installed_at = CASE WHEN cis_cache.version = EXCLUDED.version THEN cis_cache.installed_at ELSE EXCLUDED.installed_at END,
    cis_updated_at = EXCLUDED.cis_updated_at, body = EXCLUDED.body
WHERE cis_cache.version <= EXCLUDED.version
RETURNING fetched_at;

-- name: TouchCISVersion :one
-- The CISP confirmed the version (304): fetched_at moves.
UPDATE cis_cache SET fetched_at = clock_timestamp()
WHERE dataset = sqlc.arg(dataset) AND version = sqlc.arg(version)
RETURNING fetched_at;

-- name: ListCISVersions :many
SELECT dataset, version, etag, fetched_at, body FROM cis_cache ORDER BY dataset LIMIT 10;
