package timeseries

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rootxkit/uspace-core/core"
)

// fakeDB records whether a transaction was opened and fails it.
type fakeDB struct {
	calls int
	err   error
}

func (f *fakeDB) Tx(_ context.Context, _ func(context.Context, pgx.Tx) error) error {
	f.calls++
	return f.err
}

func good() MannedTrackRow {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	alt, gs, trk := 900.0, 60.0, 359.9
	cs, sq := "GEO123", "7000"
	return MannedTrackRow{
		CapturedAt: at, TS: at, RxTS: at, TimeSource: "adapter", AdapterID: "replay-1", ICAO24: "4B1803",
		Callsign: &cs, Position: core.LatLon{LatDeg: 41.7, LonDeg: 44.8}, AltPressureM: &alt, GSMS: &gs,
		TrackDeg: &trk, Squawk: &sq, SourceClass: "ads_b", Quality: []byte(`{"nic":8}`), PolicyVersion: 1,
	}
}

func TestValidateAcceptsAGoodRow(t *testing.T) {
	r := good()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Quality = nil
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every field the hypertable checks is refused here first, by name.
func TestValidateRefusesEachField(t *testing.T) {
	nan, neg, full := math.NaN(), -1.0, 360.0
	long, badSq := "ABCDEFGHI", "8000"
	for field, mutate := range map[string]func(*MannedTrackRow){
		"captured_at":    func(r *MannedTrackRow) { r.CapturedAt = time.Time{} },
		"ts":             func(r *MannedTrackRow) { r.TS = time.Time{} },
		"rx_ts":          func(r *MannedTrackRow) { r.RxTS = time.Time{} },
		"time_source":    func(r *MannedTrackRow) { r.TimeSource = "" },
		"adapter_id":     func(r *MannedTrackRow) { r.AdapterID = "Replay 1" },
		"icao24":         func(r *MannedTrackRow) { r.ICAO24 = "4b18" },
		"callsign":       func(r *MannedTrackRow) { r.Callsign = &long },
		"position":       func(r *MannedTrackRow) { r.Position.LatDeg = 91 },
		"alt_pressure_m": func(r *MannedTrackRow) { r.AltPressureM = &nan },
		"gs_ms":          func(r *MannedTrackRow) { r.GSMS = &neg },
		"track_deg":      func(r *MannedTrackRow) { r.TrackDeg = &full },
		"squawk":         func(r *MannedTrackRow) { r.Squawk = &badSq },
		"source_class":   func(r *MannedTrackRow) { r.SourceClass = "radar" },
		"policy_version": func(r *MannedTrackRow) { r.PolicyVersion = -1 },
		"quality":        func(r *MannedTrackRow) { r.Quality = []byte(`[1]`) },
	} {
		r := good()
		mutate(&r)
		err := r.Validate()
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("%s: %v", field, err)
		}
	}
	r := good()
	r.Quality = []byte(`{"x":"` + strings.Repeat("a", MaxQualityBytes) + `"}`)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "quality") {
		t.Fatalf("oversize quality: %v", err)
	}
}

// E-10: a batch past MaxBatchRows is refused whole before any
// transaction; one at the bound reaches the database.
func TestInsertBatchBound(t *testing.T) {
	db := &fakeDB{err: errors.New("database said no")}
	w := NewWriter(db, nil)
	_, err := w.Insert(context.Background(), make([]MannedTrackRow, MaxBatchRows+1))
	if !errors.Is(err, ErrBatchTooLarge) || db.calls != 0 {
		t.Fatalf("past the bound: %v, %d transactions", err, db.calls)
	}
	at := make([]MannedTrackRow, MaxBatchRows)
	for i := range at {
		at[i] = good()
	}
	if _, err := w.Insert(context.Background(), at); err == nil || !strings.Contains(err.Error(), "database said no") || db.calls != 1 {
		t.Fatalf("at the bound: %v, %d transactions", err, db.calls)
	}
}

// Invalid rows are counted and left out; a batch with none left opens
// no transaction (absence), one valid row opens one (presence).
func TestInsertCountsRefusedRows(t *testing.T) {
	db := &fakeDB{}
	counters := &core.Counters{}
	w := NewWriter(db, counters)
	bad := good()
	bad.ICAO24 = "x"
	n, err := w.Insert(context.Background(), []MannedTrackRow{bad, bad})
	if err != nil || n != 0 || db.calls != 0 || w.Counters().Get(CounterTrackRowsRefused) != 2 {
		t.Fatalf("all refused: %d %v, %d transactions, %d counted", n, err, db.calls, counters.Get(CounterTrackRowsRefused))
	}
	if _, err := w.Insert(context.Background(), []MannedTrackRow{bad, good()}); err != nil || db.calls != 1 ||
		counters.Get(CounterTrackRowsRefused) != 3 {
		t.Fatalf("one valid: %v, %d transactions", err, db.calls)
	}
}
