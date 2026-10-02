// Package dump1090 reads dump1090's decoded outputs: the SBS
// (BaseStation) text port and aircraft.json. Every field name and column
// position comes from the documents pinned in SOURCE (repository, commit
// and SHA-256; scripts/check-contracts.sh re-fetches them), never from
// memory (E-03, CLAUDE.md rule 8); the assumptions SOURCE marks are
// cited where they are used.
//
// SBS (sbs.go, sbsadapter.go): a TCP client that only reads, 22 columns
// per line as modesSendSBSOutput writes them, lines bounded by
// max_line_bytes, empty heartbeat lines counted, a session that hears
// nothing for feed_idle_timeout_s ended for the runner to reconnect.
// Lines without a position hold their fields per aircraft (bounded,
// evictions counted) for the next line with one, within
// held_field_max_age_s on the feed's clock. Column 12 without "H" is
// barometric (pressure altitude), with "H" geometric (WGS84), never
// mixed (D-03). Columns 7-8 give the feed time, 9-10 the feed's "now".
//
// aircraft.json (aircraftjson.go): polled at poll_period_s with GET,
// bounded by max_json_bytes; "now" - "seen_pos" is a position's feed
// time; a position older than max_age_s is backlog; alt_baro is pressure
// altitude (or "ground"), alt_geom WGS84; an aircraft without a position
// is counted skipped_no_position. Nothing here panics on any input
// (FuzzSBSLine, FuzzAircraftJSON).
package dump1090
