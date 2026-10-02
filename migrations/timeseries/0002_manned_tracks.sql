-- manned_tracks: every manned sample handed to U-space, as handed
-- (docs/PLAN.md section 5.2, ATS.OR.127(a)). Every sample is kept,
-- relevant or not (LESSONS B-12: relevance is a flag, never a filter at
-- the edge).
--
-- 1-day chunks on captured_at, compressed after 7 days (segmented by
-- icao24, ordered by captured_at DESC) and dropped after 90 days (spec
-- 05 section 4; a longer national period is Q8). ansp_ts_app may SELECT
-- and INSERT only: no UPDATE or DELETE (spec 06 T7). The retention and
-- compression jobs run as the table owner.
--
-- Units and datums are in the names (E-13): alt_pressure_m is pressure
-- altitude and never an AMSL value; alt_wgs84_m is the geometric
-- altitude when the source gives one. quality is the source's quality
-- block as received.

-- +goose Up
CREATE TABLE manned_tracks (
    captured_at    timestamptz      NOT NULL,
    ts             timestamptz      NOT NULL,
    rx_ts          timestamptz      NOT NULL,
    time_source    text             NOT NULL CHECK (time_source <> ''),
    backlog        boolean          NOT NULL DEFAULT false,
    adapter_id     text             NOT NULL CHECK (adapter_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    icao24         text             NOT NULL CHECK (icao24 ~* '^[0-9a-f]{6}$'),
    callsign       text             CHECK (length(callsign) <= 8),
    geom           geometry(Point, 4326) NOT NULL,
    alt_pressure_m double precision,
    alt_wgs84_m    double precision,
    gs_ms          double precision CHECK (gs_ms >= 0),
    track_deg      double precision CHECK (track_deg >= 0 AND track_deg < 360),
    vrate_ms       double precision,
    emergency      boolean,
    squawk         text             CHECK (squawk ~ '^[0-7]{4}$'),
    source_class   text             NOT NULL CHECK (source_class IN ('ads_b', 'mode_s', 'ssr', 'atm_feed', 'ads_l')),
    quality        jsonb            NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(quality) = 'object'),
    relevant       boolean          NOT NULL,
    policy_version bigint           NOT NULL CHECK (policy_version >= 0)
);

SELECT create_hypertable('manned_tracks', by_range('captured_at', INTERVAL '1 day'));

CREATE INDEX manned_tracks_icao24_idx ON manned_tracks (icao24, captured_at DESC);
CREATE INDEX manned_tracks_geom_idx ON manned_tracks USING gist (geom);

ALTER TABLE manned_tracks SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'icao24',
    timescaledb.compress_orderby = 'captured_at DESC'
);
SELECT add_compression_policy('manned_tracks', INTERVAL '7 days');
SELECT add_retention_policy('manned_tracks', INTERVAL '90 days');

GRANT SELECT, INSERT ON manned_tracks TO ansp_ts_app;

-- +goose Down
SELECT remove_retention_policy('manned_tracks', if_exists => true);
SELECT remove_compression_policy('manned_tracks', if_exists => true);
DROP TABLE IF EXISTS manned_tracks;
