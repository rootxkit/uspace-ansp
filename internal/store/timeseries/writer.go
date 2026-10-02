package timeseries

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/core"
)

// This file is hand-written beside the sqlc output: sqlc writes only its
// own files (db.go, models.go, *.sql.go) and never touches it.

// MannedTrackRow is one manned_tracks sample (docs/PLAN.md section
// 5.2), as manned-feed hands it to the writer.
type MannedTrackRow struct {
	CapturedAt time.Time
	TS         time.Time
	RxTS       time.Time
	TimeSource string
	Backlog    bool
	AdapterID  string
	ICAO24     string
	Callsign   *string
	Position   core.LatLon
	// AltPressureM is pressure altitude, never an AMSL value.
	AltPressureM *float64
	AltWGS84M    *float64
	GSMS         *float64
	TrackDeg     *float64
	VRateMS      *float64
	Emergency    *bool
	Squawk       *string
	SourceClass  string
	// Quality is the source's quality block as received (a JSON object);
	// empty is {}.
	Quality       json.RawMessage
	Relevant      bool
	PolicyVersion int64
	// MsgID is the envelope's msg_id (migration 0010): a row whose
	// (icao24, captured_at, msg_id) is already stored is skipped, so a
	// sample delivered twice lands once. nil writes none and skips
	// nothing.
	MsgID *string
}

// MaxBatchRows bounds one Insert: about 10 minutes of a busy sky at 1 Hz
// (LESSONS B-07); a larger batch is refused whole and the caller splits.
const MaxBatchRows = 50_000

// MaxQualityBytes bounds the quality block of one row.
const MaxQualityBytes = 4096

// ErrBatchTooLarge refuses a batch above MaxBatchRows.
var ErrBatchTooLarge = errors.New("batch too large")

var (
	icao24Pattern  = regexp.MustCompile(`^[0-9A-Fa-f]{6}$`)
	adapterPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	squawkPattern  = regexp.MustCompile(`^[0-7]{4}$`)
	ulidPattern    = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	sourceClasses  = []string{"ads_b", "mode_s", "ssr", "atm_feed", "ads_l"}
)

// Validate refuses a row the hypertable's checks would refuse, naming
// the field, so one bad sample never fails the whole COPY.
func (r *MannedTrackRow) Validate() error {
	var errs []error
	for _, t := range []struct {
		field string
		v     time.Time
	}{{"captured_at", r.CapturedAt}, {"ts", r.TS}, {"rx_ts", r.RxTS}} {
		if t.v.IsZero() {
			errs = append(errs, core.Fieldf(t.field, "required"))
		}
	}
	if r.TimeSource == "" {
		errs = append(errs, core.Fieldf("time_source", "required"))
	}
	if !adapterPattern.MatchString(r.AdapterID) {
		errs = append(errs, core.Fieldf("adapter_id", "not an adapter slug"))
	}
	if !icao24Pattern.MatchString(r.ICAO24) {
		errs = append(errs, core.Fieldf("icao24", "not 6 hexadecimal digits"))
	}
	if r.Callsign != nil && len(*r.Callsign) > 8 {
		errs = append(errs, core.Fieldf("callsign", "longer than 8 characters"))
	}
	if !r.Position.Valid() {
		errs = append(errs, core.Fieldf("position", "not a valid WGS84 position"))
	}
	for _, f := range []struct {
		field string
		v     *float64
	}{{"alt_pressure_m", r.AltPressureM}, {"alt_wgs84_m", r.AltWGS84M}, {"gs_ms", r.GSMS}, {"track_deg", r.TrackDeg}, {"vrate_ms", r.VRateMS}} {
		if f.v != nil && !core.IsFinite(*f.v) {
			errs = append(errs, core.Fieldf(f.field, "not a finite number"))
		}
	}
	if r.GSMS != nil && *r.GSMS < 0 {
		errs = append(errs, core.Fieldf("gs_ms", "negative"))
	}
	if r.TrackDeg != nil && (*r.TrackDeg < 0 || *r.TrackDeg >= 360) {
		errs = append(errs, core.Fieldf("track_deg", "outside [0, 360)"))
	}
	if r.Squawk != nil && !squawkPattern.MatchString(*r.Squawk) {
		errs = append(errs, core.Fieldf("squawk", "not 4 octal digits"))
	}
	if !slices.Contains(sourceClasses, r.SourceClass) {
		errs = append(errs, core.Fieldf("source_class", "not one of ads_b, mode_s, ssr, atm_feed, ads_l"))
	}
	if r.MsgID != nil && !ulidPattern.MatchString(*r.MsgID) {
		errs = append(errs, core.Fieldf("msg_id", "not a ULID"))
	}
	if r.PolicyVersion < 0 {
		errs = append(errs, core.Fieldf("policy_version", "negative"))
	}
	if len(r.Quality) > MaxQualityBytes {
		errs = append(errs, core.Fieldf("quality", "longer than %d bytes", MaxQualityBytes))
	} else if len(r.Quality) > 0 {
		var obj map[string]any
		if json.Unmarshal(r.Quality, &obj) != nil || obj == nil {
			errs = append(errs, core.Fieldf("quality", "not a JSON object"))
		}
	}
	return errors.Join(errs...)
}

// TxRunner runs a function in one transaction (store.Timeseries).
type TxRunner interface {
	Tx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error
}

// Writer bulk-inserts manned_tracks with COPY (spec 05 section 5:
// batched COPY). It is safe for concurrent use.
type Writer struct {
	db       TxRunner
	counters *core.Counters
}

// CounterTrackRowsRefused counts the rows Insert left out because they
// did not validate (the rest of the batch lands).
const CounterTrackRowsRefused = "store_track_rows_refused"

// NewWriter is a Writer on db; counters may be nil.
func NewWriter(db TxRunner, counters *core.Counters) *Writer {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Writer{db: db, counters: counters}
}

// Counters are the writer's counters.
func (w *Writer) Counters() *core.Counters { return w.counters }

// stageColumns are the COPY columns: the position as two doubles, which
// the INSERT turns into the Point (pgx has no binary codec for PostGIS
// geometry, and no geometry library is allowed here).
var stageColumns = []string{
	"captured_at", "ts", "rx_ts", "time_source", "backlog", "adapter_id", "icao24", "callsign",
	"lat_deg", "lon_deg", "alt_pressure_m", "alt_wgs84_m", "gs_ms", "track_deg", "vrate_ms",
	"emergency", "squawk", "source_class", "quality", "relevant", "policy_version", "msg_id",
}

const createStage = `CREATE TEMP TABLE manned_tracks_stage (
    captured_at timestamptz, ts timestamptz, rx_ts timestamptz, time_source text, backlog boolean,
    adapter_id text, icao24 text, callsign text, lat_deg double precision, lon_deg double precision,
    alt_pressure_m double precision, alt_wgs84_m double precision, gs_ms double precision,
    track_deg double precision, vrate_ms double precision, emergency boolean, squawk text,
    source_class text, quality jsonb, relevant boolean, policy_version bigint, msg_id text
) ON COMMIT DROP`

const insertFromStage = `INSERT INTO manned_tracks (
    captured_at, ts, rx_ts, time_source, backlog, adapter_id, icao24, callsign, geom,
    alt_pressure_m, alt_wgs84_m, gs_ms, track_deg, vrate_ms, emergency, squawk,
    source_class, quality, relevant, policy_version, msg_id)
SELECT DISTINCT ON (coalesce(s.msg_id, gen_random_uuid()::text))
    s.captured_at, s.ts, s.rx_ts, s.time_source, s.backlog, s.adapter_id, s.icao24, s.callsign,
    ST_SetSRID(ST_MakePoint(s.lon_deg, s.lat_deg), 4326),
    s.alt_pressure_m, s.alt_wgs84_m, s.gs_ms, s.track_deg, s.vrate_ms, s.emergency, s.squawk,
    s.source_class, s.quality, s.relevant, s.policy_version, s.msg_id
FROM manned_tracks_stage s
WHERE s.msg_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM manned_tracks m
    WHERE m.icao24 = s.icao24 AND m.captured_at = s.captured_at AND m.msg_id = s.msg_id)`

// Insert copies rows into manned_tracks in one transaction and returns
// how many landed. A row that does not validate is left out and counted
// (store_track_rows_refused); a row whose msg_id is already stored (or
// repeated in the batch) is skipped, so the count may be lower than the
// rows given; a batch above MaxBatchRows is refused whole before the
// database is touched.
func (w *Writer) Insert(ctx context.Context, rows []MannedTrackRow) (int64, error) {
	if len(rows) > MaxBatchRows {
		return 0, fmt.Errorf("%w: %d rows, at most %d", ErrBatchTooLarge, len(rows), MaxBatchRows)
	}
	src := make([][]any, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.Validate() != nil {
			w.counters.Inc(CounterTrackRowsRefused)
			continue
		}
		quality := r.Quality
		if len(quality) == 0 {
			quality = json.RawMessage(`{}`)
		}
		src = append(src, []any{
			r.CapturedAt, r.TS, r.RxTS, r.TimeSource, r.Backlog, r.AdapterID, r.ICAO24, r.Callsign,
			r.Position.LatDeg, r.Position.LonDeg, r.AltPressureM, r.AltWGS84M, r.GSMS, r.TrackDeg, r.VRateMS,
			r.Emergency, r.Squawk, r.SourceClass, []byte(quality), r.Relevant, r.PolicyVersion, r.MsgID,
		})
	}
	if len(src) == 0 {
		return 0, nil
	}
	var n int64
	err := w.db.Tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, createStage); err != nil {
			return fmt.Errorf("manned_tracks: stage: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"manned_tracks_stage"}, stageColumns, pgx.CopyFromRows(src)); err != nil {
			return fmt.Errorf("manned_tracks: copy: %w", err)
		}
		tag, err := tx.Exec(ctx, insertFromStage)
		if err != nil {
			return fmt.Errorf("manned_tracks: insert: %w", err)
		}
		n = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
