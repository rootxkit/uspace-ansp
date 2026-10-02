-- WP-1: the timeseries reads and the feed record. The bulk insert of
-- manned_tracks is store.Writer (CopyFrom into a staging table), not a
-- generated query.

-- name: SchemaVersion :one
SELECT version_id FROM goose_db_version_timeseries
WHERE is_applied ORDER BY id DESC LIMIT 1;

-- name: MannedTracksByICAO24 :many
-- One aircraft's samples in [from_ts, to_ts), oldest first, bounded.
SELECT captured_at, ts, rx_ts, time_source, backlog, adapter_id, icao24, callsign,
       ST_Y(geom)::double precision AS lat_deg, ST_X(geom)::double precision AS lon_deg,
       alt_pressure_m, alt_wgs84_m, gs_ms, track_deg, vrate_ms, emergency, squawk,
       source_class, quality, relevant, policy_version
FROM manned_tracks
WHERE icao24 = sqlc.arg(icao24) AND captured_at >= sqlc.arg(from_ts) AND captured_at < sqlc.arg(to_ts)
ORDER BY captured_at
LIMIT sqlc.arg(page_size);

-- name: CountMannedTracksInWindow :one
SELECT count(*)::bigint AS n FROM manned_tracks
WHERE captured_at >= sqlc.arg(from_ts) AND captured_at < sqlc.arg(to_ts);

-- name: InsertFeedProduct :exec
INSERT INTO feed_products (at, client_id, tracks_sent, tracks_relevant, degraded, policy_version)
VALUES (clock_timestamp(), sqlc.arg(client_id), sqlc.arg(tracks_sent), sqlc.arg(tracks_relevant),
        sqlc.arg(degraded), sqlc.arg(policy_version));

-- name: FeedProductsByClient :many
SELECT at, client_id, tracks_sent, tracks_relevant, degraded, policy_version
FROM feed_products
WHERE client_id = sqlc.arg(client_id) AND at >= sqlc.arg(from_ts) AND at < sqlc.arg(to_ts)
ORDER BY at
LIMIT sqlc.arg(page_size);
