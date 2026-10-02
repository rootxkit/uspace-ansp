-- Dynamic airspace restrictions (docs/PLAN.md section 5.1, spec 01
-- section 4 N1, ATS.TR.237): restrictions, every published version of
-- each, and the inbound restriction requests (F11). WP-5 owns the state
-- machine on top of these tables.
--
-- Geometry is geometry(Geometry, 4326) limited to a Polygon or a Point;
-- radius_m is set exactly when the geometry is a Point (a circle), and
-- is positive. Distance and area are computed on geography (03
-- conventions); the GiST index serves bbox queries. Vertical limits
-- carry their reference in lower_ref and upper_ref: AMSL or WGS84, never
-- AGL (CLAUDE.md rule 9). The F3548 limits (duration, planning horizon,
-- area, vertices) are judged in internal/restriction against
-- uspace-core/f3548 constants, not here; this table holds only the
-- invariants no version may break.
--
-- restriction_versions is insert-only for ansp_app (06 T7: the record of
-- what was published, by whom and why). Its foreign key points at
-- restrictions, which stays updatable; nothing references
-- restriction_versions, because PostgreSQL checks a foreign key with
-- SELECT ... FOR KEY SHARE, which needs UPDATE on the referenced table.

-- +goose Up
CREATE TYPE restriction_state AS ENUM ('planned', 'active', 'ended', 'cancelled');

CREATE TABLE restriction_requests (
    id              text        PRIMARY KEY CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    requester       text        NOT NULL CHECK (requester <> ''),
    source          text        NOT NULL CHECK (source IN ('authority', 'console')),
    payload         jsonb       NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    received_at     timestamptz NOT NULL DEFAULT now(),
    state           text        NOT NULL DEFAULT 'received' CHECK (state IN ('received', 'accepted', 'declined')),
    decided_by      text,
    decided_at      timestamptz,
    decision_reason text,
    restriction_id  text,
    CONSTRAINT restriction_requests_decision CHECK (
        (state = 'received' AND decided_by IS NULL AND decided_at IS NULL)
        OR (state <> 'received' AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT restriction_requests_accepted CHECK ((state = 'accepted') = (restriction_id IS NOT NULL))
);

CREATE INDEX restriction_requests_state_idx ON restriction_requests (state, received_at);

CREATE TABLE restrictions (
    id                 text              PRIMARY KEY CHECK (id ~ '^[0-9A-HJKMNP-TV-Z]{26}$'),
    ansp_ref           text              NOT NULL UNIQUE CHECK (ansp_ref ~ '^[A-Za-z0-9._:-]{1,128}$'),
    identifier         text              NOT NULL UNIQUE CHECK (identifier ~ '^DAR[0-9A-Z]{4}$'),
    uspace_airspace_id text              NOT NULL CHECK (uspace_airspace_id <> ''),
    zone_type          text              NOT NULL CHECK (zone_type IN ('PROHIBITED', 'REQ_AUTHORIZATION')),
    geom               geometry(Geometry, 4326) NOT NULL,
    radius_m           double precision,
    lower_m            double precision  NOT NULL,
    lower_ref          text              NOT NULL CHECK (lower_ref IN ('AMSL', 'WGS84')),
    upper_m            double precision  NOT NULL,
    upper_ref          text              NOT NULL CHECK (upper_ref IN ('AMSL', 'WGS84')),
    starts_at          timestamptz       NOT NULL,
    ends_at            timestamptz       NOT NULL,
    reason_text        text              NOT NULL CHECK (reason_text <> '' AND length(reason_text) <= 2000),
    state              restriction_state NOT NULL DEFAULT 'planned',
    ansp_version       bigint            NOT NULL DEFAULT 1 CHECK (ansp_version >= 1),
    created_by         text              NOT NULL CHECK (created_by <> ''),
    activated_by       text,
    ended_by           text,
    cancelled_by       text,
    created_at         timestamptz       NOT NULL DEFAULT now(),
    activated_at       timestamptz,
    ended_at_actual    timestamptz,
    request_id         text              REFERENCES restriction_requests (id),
    published_version  bigint            CHECK (published_version >= 1),
    dss_constraint_id  uuid              UNIQUE,
    dss_ovn            text,
    dss_version        bigint,
    supersedes_id      text              REFERENCES restrictions (id),
    CONSTRAINT restrictions_geom_kind CHECK (GeometryType(geom) IN ('POLYGON', 'POINT')),
    CONSTRAINT restrictions_radius_with_point CHECK (
        (GeometryType(geom) = 'POINT') = (radius_m IS NOT NULL)
    ),
    CONSTRAINT restrictions_radius_positive CHECK (radius_m > 0 AND radius_m < 'Infinity'),
    CONSTRAINT restrictions_limits_finite CHECK (
        lower_m > '-Infinity' AND lower_m < 'Infinity' AND upper_m > '-Infinity' AND upper_m < 'Infinity'
    ),
    CONSTRAINT restrictions_window CHECK (ends_at > starts_at),
    CONSTRAINT restrictions_published_le_version CHECK (published_version <= ansp_version),
    CONSTRAINT restrictions_not_self_superseding CHECK (supersedes_id <> id)
);

CREATE INDEX restrictions_geom_idx ON restrictions USING gist (geom);
CREATE INDEX restrictions_state_idx ON restrictions (state, starts_at, ends_at);

ALTER TABLE restriction_requests
    ADD CONSTRAINT restriction_requests_restriction_fk FOREIGN KEY (restriction_id) REFERENCES restrictions (id);

CREATE TABLE restriction_versions (
    restriction_id text        NOT NULL REFERENCES restrictions (id),
    version        bigint      NOT NULL CHECK (version >= 1),
    feature        jsonb       NOT NULL CHECK (jsonb_typeof(feature) = 'object'),
    "constraint"   jsonb       CHECK (jsonb_typeof("constraint") = 'object'),
    changed_by     text        NOT NULL CHECK (changed_by <> ''),
    changed_at     timestamptz NOT NULL DEFAULT now(),
    change_reason  text        NOT NULL CHECK (change_reason <> '' AND length(change_reason) <= 2000),
    PRIMARY KEY (restriction_id, version)
);

GRANT SELECT, INSERT, UPDATE ON restriction_requests, restrictions TO ansp_app;
GRANT SELECT, INSERT ON restriction_versions TO ansp_app;

-- +goose Down
DROP TABLE IF EXISTS restriction_versions;
ALTER TABLE IF EXISTS restriction_requests DROP CONSTRAINT IF EXISTS restriction_requests_restriction_fk;
DROP TABLE IF EXISTS restrictions;
DROP TABLE IF EXISTS restriction_requests;
DROP TYPE IF EXISTS restriction_state;
