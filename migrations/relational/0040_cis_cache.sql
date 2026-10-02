-- cis_cache: the projection of the CISP's datasets (docs/PLAN.md section
-- 5.1, P), one row per dataset: the version this system uses, its ETag,
-- when the CISP last confirmed it (fetched_at, the database clock) and
-- the document as the CISP served it. Only a version whose publisher's
-- signature verified is stored (WP-7). The row is replaced only by a
-- version not below it, compared under the row's lock, so a slower api
-- instance never rolls it back. Projected, read-only locally: the CISP
-- is the authority (LESSONS G-08).
--
-- cis_notifications_seen: the delivery ids (jti) of the CISP's signed
-- change notifications, kept JTITTL on the database clock so a replay is
-- caught across restarts and api instances (core's CompactVerifier keeps
-- no nonce memory). Bounded by the receiver (MaxLiveJTIs) and swept.

-- +goose Up
CREATE TABLE cis_cache (
    dataset        text        PRIMARY KEY CHECK (dataset IN ('uspace_airspace', 'ussp_list', 'restrictions')),
    version        bigint      NOT NULL CHECK (version >= 1),
    etag           text        NOT NULL CHECK (length(etag) <= 256),
    fetched_at     timestamptz NOT NULL,
    installed_at   timestamptz NOT NULL,
    cis_updated_at timestamptz,
    body           jsonb       NOT NULL CHECK (jsonb_typeof(body) = 'object')
);

CREATE TABLE cis_notifications_seen (
    issuer     text        NOT NULL CHECK (issuer <> '' AND length(issuer) <= 512),
    jti        text        NOT NULL CHECK (jti <> '' AND length(jti) <= 256),
    seen_at    timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE INDEX cis_notifications_seen_expires_at ON cis_notifications_seen (expires_at);

GRANT SELECT, INSERT, UPDATE ON cis_cache TO ansp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cis_notifications_seen TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS cis_notifications_seen;
DROP TABLE IF EXISTS cis_cache;
