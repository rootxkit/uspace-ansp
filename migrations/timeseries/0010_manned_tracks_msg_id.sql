-- manned_tracks.msg_id (WP-6): the envelope's msg_id of the sample, so
-- that a sample delivered twice (the MAN_MIRROR replay after an outage,
-- a redelivery after a failed insert) lands once. The writer skips a row
-- whose (icao24, captured_at, msg_id) is already present, on the
-- existing (icao24, captured_at) index; no unique index is added on the
-- compressed hypertable. Nullable: rows written before this migration
-- have none. Its format (a ULID) is checked by the writer.

-- +goose Up
ALTER TABLE manned_tracks ADD COLUMN msg_id text;

-- +goose Down
ALTER TABLE manned_tracks DROP COLUMN IF EXISTS msg_id;
