package manned_test

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// newNorm is a normaliser at a fixed clock with the default policy
// edited by edit.
func newNorm(edit func(*manned.Policy)) (*manned.Normaliser, *core.Counters, *[]manned.Refusal) {
	p := manned.Defaults()
	if edit != nil {
		edit(&p)
	}
	c := &core.Counters{}
	n := manned.NewNormaliser("adsb-tbs", manned.SourceClassADSB, manned.StaticPolicy{Policy: p, Version: 4}, c)
	n.Now = func() time.Time { return t0.Add(time.Hour) }
	var refusals []manned.Refusal
	n.OnRefuse = func(r manned.Refusal) { refusals = append(refusals, r) }
	return n, c, &refusals
}

// sample is a sample of icao at feed time ts (nil for none) and lat.
func sample(icao string, ts *time.Time, lat float64) manned.RawSample {
	return manned.RawSample{
		FeedTS: ts, ICAO24: icao, Position: &manned.LatLonSample{LatDeg: lat, LonDeg: 44.8},
		AltPressureM: manned.F(900), GSMS: manned.F(70), TrackDeg: manned.F(90),
	}
}

func at(s float64) *time.Time { return manned.T(t0.Add(manned.Seconds(s))) }

// T-03: within one aircraft, a sample older on the feed's clock than
// the one held is dropped and counted; a newer one is accepted (E-01).
func TestOrderInOrderAcceptedOutOfOrderDropped(t *testing.T) {
	n, c, _ := newNorm(nil)
	rx := t0.Add(time.Hour)
	if got := n.Take([]manned.RawSample{sample("f0a001", at(10), 41.70)}, rx); len(got) != 1 {
		t.Fatal("first")
	}
	if got := n.Take([]manned.RawSample{sample("f0a001", at(11), 41.71)}, rx.Add(time.Second)); len(got) != 1 {
		t.Fatal("in order was dropped")
	}
	if c.Get(manned.CounterOutOfOrder) != 0 {
		t.Fatal("counted an in-order sample")
	}
	if got := n.Take([]manned.RawSample{sample("f0a001", at(9), 41.72)}, rx.Add(2*time.Second)); len(got) != 0 {
		t.Fatal("out of order was accepted")
	}
	if c.Get(manned.CounterOutOfOrder) != 1 {
		t.Fatal(c.Snapshot())
	}
	// Another aircraft has its own order.
	if got := n.Take([]manned.RawSample{sample("f0a002", at(1), 41.72)}, rx.Add(3*time.Second)); len(got) != 1 {
		t.Fatal("another aircraft was ordered against the first")
	}
}

// Dedupe: the same (feed time, position) inside the window is a
// duplicate; a fresh time or position is not (E-01).
func TestDedupeFreshAndDuplicate(t *testing.T) {
	n, c, _ := newNorm(nil)
	rx := t0.Add(time.Hour)
	if got := n.Take([]manned.RawSample{sample("f0a001", at(10), 41.70), sample("f0a001", at(10), 41.70)}, rx); len(got) != 1 {
		t.Fatalf("a repeated sample was published twice: %d", len(got))
	}
	if c.Get(manned.CounterDuplicates) != 1 {
		t.Fatal(c.Snapshot())
	}
	fresh := []manned.RawSample{sample("f0a001", at(10), 41.71), sample("f0a001", at(11), 41.71)}
	if got := n.Take(fresh, rx.Add(time.Second)); len(got) != 2 {
		t.Fatalf("a fresh position or time was taken for a duplicate: %d", len(got))
	}
	if c.Get(manned.CounterDuplicates) != 1 {
		t.Fatal(c.Snapshot())
	}
	// Without a feed time the window runs on the read time.
	a := sample("f0a003", nil, 41.70)
	a.ReadAt = rx
	b := a
	b.ReadAt = rx.Add(time.Second)
	d := a
	d.ReadAt = rx.Add(5 * time.Second)
	if got := n.Take([]manned.RawSample{a}, rx); len(got) != 1 {
		t.Fatal("no feed time")
	}
	if got := n.Take([]manned.RawSample{b}, b.ReadAt); len(got) != 0 {
		t.Fatal("same position inside the window was not a duplicate")
	}
	if got := n.Take([]manned.RawSample{d}, d.ReadAt); len(got) != 1 {
		t.Fatal("same position after the window was a duplicate")
	}
}

// T-01, T-02, T-12: with a feed time the sample is placed on the batch's
// own spacing, ts is the feed's time and the source is source_clock;
// without one it is placed at its read, ts is nil, the source is system
// and the sample is counted placed_at_arrival (E-01 pair).
func TestFeedTimePresentAndAbsent(t *testing.T) {
	n, c, _ := newNorm(nil)
	rx := t0.Add(time.Hour)
	// The feed's clock is an hour behind ours: it never matters.
	batch := []manned.RawSample{sample("f0a001", at(8), 41.70), sample("f0a002", at(10), 41.70)}
	got := n.Take(batch, rx)
	if len(got) != 2 {
		t.Fatal(len(got))
	}
	if !got[1].Times.CapturedAt.Equal(rx) || !got[0].Times.CapturedAt.Equal(rx.Add(-2*time.Second)) {
		t.Fatalf("placement %v %v", got[0].Times.CapturedAt, got[1].Times.CapturedAt)
	}
	if got[0].Times.Source != core.TimeSourceClock || got[0].Times.TS == nil || !got[0].Times.TS.Equal(*at(8)) || !got[0].Times.RxTS.Equal(rx) {
		t.Fatalf("%+v", got[0].Times)
	}
	if c.Get(manned.CounterPlacedAtArrival) != 0 {
		t.Fatal("counted a sample with a feed time")
	}
	// The feed's own "now" is the batch's newest when it is later.
	s := sample("f0a003", at(20), 41.70)
	s.FeedNow = at(23)
	got = n.Take([]manned.RawSample{s}, rx)
	if !got[0].Times.CapturedAt.Equal(rx.Add(-3 * time.Second)) {
		t.Fatalf("feed now ignored: %v", got[0].Times.CapturedAt)
	}
	none := sample("f0a004", nil, 41.70)
	none.ReadAt = rx.Add(-time.Second)
	got = n.Take([]manned.RawSample{none}, rx)
	if len(got) != 1 || got[0].Times.TS != nil || got[0].Times.Source != core.TimeSystem || !got[0].Times.CapturedAt.Equal(none.ReadAt) {
		t.Fatalf("%+v", got[0].Times)
	}
	if c.Get(manned.CounterPlacedAtArrival) != 1 {
		t.Fatal(c.Snapshot())
	}
}

// T-02: a spacing beyond max_spacing_s is clamped and counted.
func TestSpacingClamped(t *testing.T) {
	n, c, _ := newNorm(func(p *manned.Policy) { p.MaxSpacingS = 10 })
	rx := t0.Add(time.Hour)
	got := n.Take([]manned.RawSample{sample("f0a001", at(0), 41.7), sample("f0a002", at(60), 41.7)}, rx)
	if !got[0].Times.CapturedAt.Equal(rx.Add(-10*time.Second)) || c.Get(manned.CounterSpacingClamped) != 1 {
		t.Fatalf("%v %v", got[0].Times.CapturedAt, c.Snapshot())
	}
}

// T-13: a captured_at ahead of the clock beyond the tolerance is
// clamped to now and counted; inside the tolerance it is kept (E-01).
func TestFutureCapturedAtClamped(t *testing.T) {
	n, c, _ := newNorm(nil)
	now := t0.Add(time.Hour)
	inside := now.Add(500 * time.Millisecond)
	got := n.Take([]manned.RawSample{sample("f0a001", at(1), 41.7)}, inside)
	if !got[0].Times.CapturedAt.Equal(inside) || c.Get(manned.CounterFutureClamped) != 0 {
		t.Fatal("clamped inside the tolerance")
	}
	ahead := now.Add(5 * time.Second)
	got = n.Take([]manned.RawSample{sample("f0a001", at(2), 41.71)}, ahead)
	if !got[0].Times.CapturedAt.Equal(now) || c.Get(manned.CounterFutureClamped) != 1 {
		t.Fatalf("%v %v", got[0].Times.CapturedAt, c.Snapshot())
	}
}

// Refusals are counted by field and heard once each; a valid sample is
// not refused (E-01).
func TestRefusalsByField(t *testing.T) {
	n, c, refusals := newNorm(nil)
	rx := t0.Add(time.Hour)
	bad := []manned.RawSample{
		{ICAO24: "~f0a001", Position: &manned.LatLonSample{LatDeg: 1, LonDeg: 1}},
		{ICAO24: "f0a001"},
		{ICAO24: "f0a001", Position: &manned.LatLonSample{LatDeg: 91, LonDeg: 1}},
		{ICAO24: "f0a001", Position: &manned.LatLonSample{LatDeg: math.NaN(), LonDeg: 1}},
	}
	if got := n.Take(bad, rx); len(got) != 0 {
		t.Fatal(got)
	}
	if c.Get("refused_icao24") != 1 || c.Get("refused_position") != 3 || c.Get(manned.CounterRefused) != 4 || len(*refusals) != 4 {
		t.Fatalf("%v %v", c.Snapshot(), *refusals)
	}
	if (*refusals)[0].Field != "icao24" || (*refusals)[1].Reason != "absent" {
		t.Fatal(*refusals)
	}
	// Upper case from the feed is normalised, not refused.
	if got := n.Take([]manned.RawSample{sample(" F0A001 ", at(1), 41.7)}, rx); len(got) != 1 || got[0].ICAO24 != "f0a001" {
		t.Fatal(got)
	}
	if c.Get(manned.CounterRefused) != 4 {
		t.Fatal("a valid sample was refused")
	}
}

// An optional member that is not a measurement is cleared and counted;
// the aircraft is still published (CLAUDE.md rule 4).
func TestOptionalMembersClearedNotRefused(t *testing.T) {
	n, c, _ := newNorm(nil)
	s := sample("f0a001", at(1), 41.7)
	s.AltPressureM = manned.F(math.Inf(1))
	s.AltWGS84M = manned.F(-5000)
	s.GSMS = manned.F(-3)
	s.TrackDeg = manned.F(360)
	s.VRateMS = manned.F(math.NaN())
	s.Callsign = manned.S("WAY TOO LONG")
	s.Squawk = manned.S("8888")
	s.Emergency, s.SPI = manned.B(true), manned.B(false)
	s.Quality = map[string]any{"nic": 8.0, "bad": math.NaN(), "list": []any{"a", 1.0}, "ok": []any{"gs"}, "n": 3, "s": []string{"x"}}
	got := n.Take([]manned.RawSample{s}, t0.Add(time.Hour))
	if len(got) != 1 {
		t.Fatal("refused instead of cleared")
	}
	tr := got[0]
	if tr.AltPressureM != nil || tr.AltWGS84M != nil || tr.GSMS != nil || tr.TrackDeg != nil || tr.VRateMS != nil || tr.Callsign != nil || tr.Squawk != nil {
		t.Fatalf("%+v", tr)
	}
	if *tr.Emergency != true || *tr.SPI != false || tr.Quality["nic"] != 8.0 || tr.Quality["n"] != 3.0 || tr.Quality["bad"] != nil || tr.Quality["list"] != nil {
		t.Fatalf("%+v", tr.Quality)
	}
	for _, k := range []string{"alt_pressure_m", "alt_wgs84_m", "gs_ms", "track_deg", "vrate_ms", "callsign", "squawk", "quality"} {
		if c.Get(manned.ClearedPrefix+k) != 1 {
			t.Errorf("cleared_%s = %d", k, c.Get(manned.ClearedPrefix+k))
		}
	}
	// A blank callsign is no callsign, not a clearing.
	s2 := sample("f0a002", at(1), 41.7)
	s2.Callsign = manned.S("        ")
	if got := n.Take([]manned.RawSample{s2}, t0.Add(time.Hour)); got[0].Callsign != nil || c.Get("cleared_callsign") != 1 {
		t.Fatal("blank callsign")
	}
	// Too many quality members: none kept.
	s3 := sample("f0a003", at(1), 41.7)
	s3.Quality = map[string]any{}
	for i := range 40 {
		s3.Quality[fmt.Sprintf("k%d", i)] = 1.0
	}
	if got := n.Take([]manned.RawSample{s3}, t0.Add(time.Hour)); got[0].Quality != nil {
		t.Fatal("unbounded quality")
	}
}

// E-10: max_aircraft exceeded evicts the least recently heard aircraft,
// counted; at the bound nothing is evicted.
func TestMaxAircraftEviction(t *testing.T) {
	n, c, _ := newNorm(func(p *manned.Policy) { p.MaxAircraft = 2 })
	rx := t0.Add(time.Hour)
	n.Take([]manned.RawSample{sample("f0a001", at(1), 41.7)}, rx)
	n.Take([]manned.RawSample{sample("f0a002", at(1), 41.7)}, rx.Add(time.Second))
	if c.Get(manned.CounterEvicted) != 0 || n.Held() != 2 {
		t.Fatal("evicted at the bound")
	}
	n.Take([]manned.RawSample{sample("f0a003", at(1), 41.7)}, rx.Add(2*time.Second))
	if c.Get(manned.CounterEvicted) != 1 || n.Held() != 2 {
		t.Fatal(c.Snapshot())
	}
	// f0a001 was evicted: its order state is gone, so an older sample of
	// it is accepted again (the eviction is visible in the counter).
	if got := n.Take([]manned.RawSample{sample("f0a001", at(0), 41.8)}, rx.Add(3*time.Second)); len(got) != 1 {
		t.Fatal("the evicted aircraft kept its state")
	}
	if seen := n.AircraftSeen(rx.Add(3*time.Second), 1500*time.Millisecond); seen != 2 {
		t.Fatal(seen)
	}
}

func TestBacklogCountedAndOnTheWire(t *testing.T) {
	n, c, _ := newNorm(nil)
	s := sample("f0a001", at(1), 41.7)
	s.Backlog = true
	got := n.Take([]manned.RawSample{s, sample("f0a002", at(1), 41.7)}, t0.Add(time.Hour))
	if !got[0].Times.Backlog || got[1].Times.Backlog || c.Get(manned.CounterBacklogSamples) != 1 {
		t.Fatal(c.Snapshot())
	}
	raw, _ := json.Marshal(&got[0])
	if err := schematest.Validate(t, schematest.Compile(t, schematest.TrackManned), raw); err != nil {
		t.Fatal(err)
	}
	if got[0].PolicyVersion != 4 || got[0].SourceInstance != "adsb-tbs" || got[0].SourceClass != "ads_b" {
		t.Fatalf("%+v", got[0])
	}
}

func TestSampleSourceClassOverrides(t *testing.T) {
	n, _, _ := newNorm(nil)
	s := sample("f0a001", at(1), 41.7)
	s.SourceClass = manned.SourceClassModeS
	if got := n.Take([]manned.RawSample{s}, t0.Add(time.Hour)); got[0].SourceClass != "mode_s" {
		t.Fatal(got[0].SourceClass)
	}
	if n.Take(nil, t0) != nil {
		t.Fatal("empty batch")
	}
}

// BenchmarkNormalise is one batch of 50 aircraft (docs/PLAN.md section
// 9: <= 20 us per sample).
func BenchmarkNormalise(b *testing.B) {
	n := manned.NewNormaliser("adsb-tbs", manned.SourceClassADSB, manned.StaticPolicy{Policy: manned.Defaults()}, nil)
	batch := make([]manned.RawSample, 50)
	rx := t0
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		for k := range batch {
			batch[k] = sample(fmt.Sprintf("f0%04x", k), at(float64(i)), 41.0+float64(k)/100)
		}
		rx = rx.Add(time.Second)
		if got := n.Take(batch, rx); len(got) != 50 {
			b.Fatal(len(got))
		}
	}
}
