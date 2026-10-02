-- WP-7: cis_cache, the CIS projection, and cis_notifications_seen, the
-- replay guard of the CISP's change notifications. Every instant is the
-- database clock.

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

-- name: CISNotificationLive :one
-- Whether the delivery id is remembered and not expired, and how many
-- delivery ids are.
SELECT
    EXISTS (SELECT 1 FROM cis_notifications_seen s
            WHERE s.issuer = sqlc.arg(issuer) AND s.jti = sqlc.arg(jti) AND s.expires_at > clock_timestamp()) AS seen,
    (SELECT count(*) FROM cis_notifications_seen l WHERE l.expires_at > clock_timestamp())::bigint AS live;

-- name: RememberCISNotification :one
-- Records the delivery id for ttl_s; an expired row of the same id is
-- reused. No row back means the id is live: a replay, or a concurrent
-- delivery of the same id that won.
INSERT INTO cis_notifications_seen (issuer, jti, seen_at, expires_at)
VALUES (sqlc.arg(issuer), sqlc.arg(jti), clock_timestamp(), clock_timestamp() + make_interval(secs => sqlc.arg(ttl_s)::float8))
ON CONFLICT (issuer, jti) DO UPDATE SET seen_at = EXCLUDED.seen_at, expires_at = EXCLUDED.expires_at
WHERE cis_notifications_seen.expires_at <= clock_timestamp()
RETURNING expires_at;

-- name: SweepCISNotifications :execrows
-- Deletes at most max_rows expired delivery ids.
DELETE FROM cis_notifications_seen
WHERE ctid IN (SELECT ctid FROM cis_notifications_seen WHERE expires_at <= clock_timestamp() LIMIT sqlc.arg(max_rows));
