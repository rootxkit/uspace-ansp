package picture

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/sources"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

// fixedPolicy is a followed policy at version 3 with the defaults.
type fixedPolicy struct{ p policy.Policy }

func (f fixedPolicy) Current() (policy.Policy, bool) { return f.p, true }

func defaultPolicy() fixedPolicy {
	return fixedPolicy{policy.Policy{Version: 3, Thresholds: policy.Defaults()}}
}

func track(icao, instance string, lat, lon float64, altPressureM *float64, at time.Time) manned.Track {
	return manned.Track{
		Schema: manned.SchemaTrack, MsgID: manned.NewULID(at), Producer: manned.Producer,
		Times: core.Times{RxTS: at, CapturedAt: at, Source: core.TimeReceiver}, Trust: core.TrustSurveillance,
		Source: manned.SourceANSPFeed, SourceInstance: instance, ICAO24: icao,
		Position: core.LatLon{LatDeg: lat, LonDeg: lon}, AltPressureM: altPressureM, SourceClass: manned.SourceClassADSB,
	}
}

// uspace is a synthetic U-space volume over [44.70, 44.90] x [41.65,
// 41.80] with a ceiling of 1500 m AMSL (GEO-TEST, never real airspace).
func uspace(t *testing.T) *zones.Zone {
	t.Helper()
	ring := geodesy.RingFromLonLat([][2]float64{{44.70, 41.65}, {44.90, 41.65}, {44.90, 41.80}, {44.70, 41.80}, {44.70, 41.65}})
	poly := &geodesy.Polygon{Rings: []geodesy.Ring{ring}}
	return &zones.Zone{Identifier: "GEO-TEST-U1", Country: "GEO", Type: core.ZoneUSpace,
		Upper: &zones.Limit{ValueM: 1500, Ref: core.RefAMSL}, Polygon: poly, BBox: poly.BBox()}
}

func newPicture(t *testing.T, sw Switches, cis CIS) (*Picture, *clock) {
	t.Helper()
	c := &clock{now: t0}
	return New(defaultPolicy(), sw, cis, c.Now, DefaultLimits()), c
}

func alt(m float64) *float64 { return &m }

func TestObserveKeepsTheLatestAndDropsOutOfOrder(t *testing.T) {
	p, _ := newPicture(t, nil, nil)
	if v, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0)); v != Shown || e.State != StateLive {
		t.Fatalf("first: %v %+v", v, e)
	}
	if v, _ := p.Observe(track("4ca7b5", "adsb-tbs", 41.71, 44.8, alt(900), t0.Add(-time.Second))); v != OutOfOrder {
		t.Fatalf("an older sample: %v", v)
	}
	if v, _ := p.Observe(track("4ca7b5", "adsb-tbs", 41.71, 44.8, alt(900), t0)); v != OutOfOrder {
		t.Fatalf("an equal sample: %v", v)
	}
	// The twin: a newer one replaces it.
	if v, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.72, 44.8, alt(900), t0.Add(time.Second))); v != Shown || e.Track.Position.LatDeg != 41.72 {
		t.Fatalf("newer: %v %+v", v, e)
	}
	if n := p.Counters().Snapshot()[CounterOutOfOrder]; n != 2 {
		t.Fatalf("out_of_order %d", n)
	}
	snap := p.Snapshot(nil)
	if len(snap) != 1 || snap[0].Track.Position.LatDeg != 41.72 {
		t.Fatalf("snapshot %+v", snap)
	}
}

// TestLiveThenStaleThenEvicted is T-06 and the eviction bound.
func TestLiveThenStaleThenEvicted(t *testing.T) {
	p, c := newPicture(t, nil, nil)
	p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0))
	if a := p.Tick(t0.Add(15 * time.Second)); len(a.Changed) != 0 {
		t.Fatalf("stale at exactly stale_after_s: %+v", a)
	}
	a := p.Tick(t0.Add(15*time.Second + time.Millisecond))
	if len(a.Changed) != 1 || a.Changed[0].State != StateStale || a.Changed[0].AgeS < 15 {
		t.Fatalf("not stale after stale_after_s: %+v", a)
	}
	if a := p.Tick(t0.Add(20 * time.Second)); len(a.Changed) != 0 {
		t.Fatalf("stale reported twice: %+v", a)
	}
	c.Set(t0.Add(20 * time.Second))
	if s := p.Snapshot(nil); s[0].State != StateStale || s[0].AgeS != 20 {
		t.Fatalf("snapshot %+v", s)
	}
	a = p.Tick(t0.Add(301 * time.Second))
	if len(a.Evicted) != 1 || a.Evicted[0] != "4ca7b5" || p.Len() != 0 {
		t.Fatalf("not evicted: %+v", a)
	}
	if p.Counters().Snapshot()[CounterEvictedAge] != 1 {
		t.Fatal("eviction not counted")
	}
}

// TestAStaleAircraftIsLiveAgainOnlyWithANewSample: the twin of stale.
func TestAStaleAircraftIsLiveAgainOnlyWithANewSample(t *testing.T) {
	p, c := newPicture(t, nil, nil)
	p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0))
	p.Tick(t0.Add(16 * time.Second))
	c.Set(t0.Add(17 * time.Second))
	v, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0.Add(17*time.Second)))
	if v != Shown || e.State != StateLive {
		t.Fatalf("new sample: %v %+v", v, e)
	}
}

type switches struct {
	mu  sync.Mutex
	off map[string]sources.Decision
}

func (s *switches) Decision(_ string, instance *string) sources.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.off[*instance]; ok {
		return d
	}
	return sources.Decision{Enabled: true, Known: true}
}

func (s *switches) disable(instance, actor, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	why := coresources.WhyInstance
	s.off[instance] = sources.Decision{Why: &why, Actor: actor, Reason: reason, Known: true}
}

func (s *switches) enable(instance string) {
	s.mu.Lock()
	delete(s.off, instance)
	s.mu.Unlock()
}

// TestADisabledAdapterAgesOutAsSourceDisabledWithinOneTick is SC-08
// steps 2-3 in unit form: only that adapter's aircraft, with who and why.
func TestADisabledAdapterAgesOutAsSourceDisabledWithinOneTick(t *testing.T) {
	sw := &switches{off: map[string]sources.Decision{}}
	p, c := newPicture(t, sw, nil)
	p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0))
	p.Observe(track("4ca7b6", "adsb-kut", 42.2, 42.7, alt(900), t0))
	// Enabled: nothing changes (the absence half).
	if a := p.Tick(t0.Add(time.Second)); len(a.Changed) != 0 {
		t.Fatalf("enabled: %+v", a)
	}
	sw.disable("adsb-tbs", "admin1", "receiver maintenance")
	a := p.Tick(t0.Add(2 * time.Second))
	if len(a.Changed) != 1 || a.Changed[0].Track.ICAO24 != "4ca7b5" || a.Changed[0].State != StateSourceDisabled {
		t.Fatalf("one tick after the switch: %+v", a)
	}
	if d := a.Changed[0].Disabled; d == nil || d.Actor != "admin1" || d.Reason != "receiver maintenance" {
		t.Fatalf("who and why: %+v", d)
	}
	// A sample still in flight from the disabled adapter is not shown.
	c.Set(t0.Add(3 * time.Second))
	if v, _ := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0.Add(3*time.Second))); v != SourceDisabled {
		t.Fatalf("a disabled source's sample: %v", v)
	}
	for _, e := range p.Snapshot(nil) {
		if e.Track.ICAO24 == "4ca7b6" && e.State != StateLive {
			t.Fatalf("the other adapter's aircraft changed: %+v", e)
		}
	}
	// Re-enabled: the last sample is stale until a new one arrives.
	sw.enable("adsb-tbs")
	a = p.Tick(t0.Add(4 * time.Second))
	if len(a.Changed) != 1 || a.Changed[0].State != StateStale || a.Changed[0].Disabled != nil {
		t.Fatalf("re-enabled: %+v", a)
	}
	c.Set(t0.Add(5 * time.Second))
	if v, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0.Add(5*time.Second))); v != Shown || e.State != StateLive {
		t.Fatalf("new sample after re-enable: %v %+v", v, e)
	}
}

// TestBacklogIsRecordedNotShownLive is T-04 and its twin.
func TestBacklogIsRecordedNotShownLive(t *testing.T) {
	p, _ := newPicture(t, nil, nil)
	b := track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0)
	b.Times.Backlog = true
	if v, _ := p.Observe(b); v != Backlog {
		t.Fatalf("backlog: %v", v)
	}
	snap := p.Snapshot(nil)
	if len(snap) != 1 || snap[0].State != StateBacklogOnly {
		t.Fatalf("snapshot %+v", snap)
	}
	b2 := b
	b2.Times.CapturedAt = t0.Add(time.Second)
	p.Observe(b2)
	if s := p.Snapshot(nil); !s[0].Track.Times.CapturedAt.Equal(b2.Times.CapturedAt) || s[0].State != StateBacklogOnly {
		t.Fatalf("newer backlog %+v", s)
	}
	// Backlog is never aged into a state that looks shown.
	if a := p.Tick(t0.Add(20 * time.Second)); len(a.Changed) != 0 {
		t.Fatalf("backlog aged: %+v", a)
	}
	// The twin: the same sample without backlog is shown live.
	live := b
	live.Times.Backlog = false
	if v, e := p.Observe(live); v != Shown || e.State != StateLive {
		t.Fatalf("the twin: %v %+v", v, e)
	}
	// A backlog sample of an aircraft already shown does not move it.
	late := b
	late.Times.CapturedAt = t0.Add(10 * time.Second)
	p.Observe(late)
	if s := p.Snapshot(nil); s[0].State != StateLive || !s[0].Track.Times.CapturedAt.Equal(t0) {
		t.Fatalf("backlog moved a live aircraft: %+v", s[0])
	}
	if p.Counters().Snapshot()[CounterBacklog] != 3 {
		t.Fatal("backlog not counted")
	}
}

// TestASampleOlderThanStaleAfterIsNeverShownLive is SC-15 in unit form:
// a stalled feed's samples arrive late with their own time.
func TestASampleOlderThanStaleAfterIsNeverShownLive(t *testing.T) {
	p, c := newPicture(t, nil, nil)
	c.Set(t0.Add(30 * time.Second))
	v, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0))
	if v != Shown || e.State != StateStale || e.AgeS != 30 {
		t.Fatalf("late sample %v %+v", v, e)
	}
	if p.Counters().Snapshot()[CounterArrivedStale] != 1 {
		t.Fatal("not counted")
	}
	// The twin: a fresh sample is live.
	if _, e := p.Observe(track("4ca7b5", "adsb-tbs", 41.7, 44.8, alt(900), t0.Add(29*time.Second))); e.State != StateLive {
		t.Fatalf("fresh: %+v", e)
	}
}

// TestMaxAircraftEvictsTheOldest is E-10.
func TestMaxAircraftEvictsTheOldest(t *testing.T) {
	c := &clock{now: t0.Add(time.Minute)}
	p := New(defaultPolicy(), nil, nil, c.Now, Limits{MaxAircraft: 3, EvictAfterS: 300})
	for i := 0; i < 3; i++ {
		p.Observe(track(fmt.Sprintf("00000%d", i), "a", 41.7, 44.8, alt(900), t0.Add(time.Duration(i)*time.Second)))
	}
	if p.Counters().Snapshot()[CounterEvictedCapacity] != 0 {
		t.Fatal("evicted at the bound")
	}
	p.Observe(track("000009", "a", 41.7, 44.8, alt(900), t0.Add(10*time.Second)))
	if p.Len() != 3 || p.Counters().Snapshot()[CounterEvictedCapacity] != 1 {
		t.Fatalf("len %d", p.Len())
	}
	for _, e := range p.Snapshot(nil) {
		if e.Track.ICAO24 == "000000" {
			t.Fatal("the oldest was kept")
		}
	}
	if New(nil, nil, nil, nil, Limits{}).Limits() != DefaultLimits() {
		t.Fatal("an invalid limit was kept")
	}
}

func TestLimitsValidate(t *testing.T) {
	if DefaultLimits().Validate() != nil {
		t.Fatal("defaults refused")
	}
	for _, l := range []Limits{{MaxAircraft: 0, EvictAfterS: 1}, {MaxAircraft: 1, EvictAfterS: 0}, {MaxAircraft: 1, EvictAfterS: -1}} {
		if l.Validate() == nil {
			t.Errorf("%+v accepted", l)
		}
	}
}

func TestSnapshotFiltersByBBox(t *testing.T) {
	p, _ := newPicture(t, nil, nil)
	p.Observe(track("4ca7b5", "a", 41.7, 44.8, alt(900), t0))
	p.Observe(track("4ca7b6", "a", 42.5, 41.6, alt(900), t0))
	box := geodesy.BBox{MinLat: 41.6, MinLon: 44.6, MaxLat: 41.9, MaxLon: 45.0}
	got := p.Snapshot(&box)
	if len(got) != 1 || got[0].Track.ICAO24 != "4ca7b5" {
		t.Fatalf("bbox: %+v", got)
	}
	if len(p.Snapshot(nil)) != 2 {
		t.Fatal("nil bbox")
	}
}

// TestRelevanceInsideOutsideAndWithoutProjection is the relevance
// presence/absence pair and SC-22's status (E-02).
func TestRelevanceInsideOutsideAndWithoutProjection(t *testing.T) {
	cis := StaticCIS{P: Projection{Volumes: []*zones.Zone{uspace(t)}, Version: "42", FetchedAt: t0.Add(-12 * time.Second)}}
	p, _ := newPicture(t, nil, cis)
	inside := track("4ca7b5", "a", 41.72, 44.80, alt(900), t0)
	if r := p.RelevanceOf(&inside); !r.Relevant || !r.Evaluated || r.Volume != "GEO-TEST-U1" {
		t.Fatalf("inside: %+v", r)
	}
	// 3 km east of the volume: inside the 5 km margin.
	near := track("4ca7b6", "a", 41.72, 44.935, alt(900), t0)
	if r := p.RelevanceOf(&near); !r.Relevant {
		t.Fatalf("within the margin: %+v", r)
	}
	far := track("4ca7b7", "a", 42.5, 41.6, alt(900), t0)
	if r := p.RelevanceOf(&far); r.Relevant || !r.Evaluated {
		t.Fatalf("far: %+v", r)
	}
	if p.Relevant(&far) {
		t.Fatal("Relevant disagrees")
	}
	if got := p.RelevanceStatus(); got != "relevance: CIS version 42, 1 volumes, age 12 s" {
		t.Fatalf("status %q", got)
	}
	// No projection: everything relevant, not evaluated, and said so.
	q, _ := newPicture(t, nil, NoCIS{})
	if r := q.RelevanceOf(&far); !r.Relevant || r.Evaluated {
		t.Fatalf("no projection: %+v", r)
	}
	if got := q.RelevanceStatus(); got != StatusNoProjection {
		t.Fatalf("status %q", got)
	}
	_, e := q.Observe(far)
	if !e.Relevance.Relevant || q.Counters().Snapshot()[CounterNotEvaluated] != 1 {
		t.Fatalf("observe without projection: %+v", e.Relevance)
	}
	empty, _ := newPicture(t, nil, StaticCIS{})
	if r := empty.RelevanceOf(&far); !r.Relevant || r.Evaluated || empty.RelevanceStatus() != StatusNoProjection {
		t.Fatalf("an empty projection: %+v", r)
	}
}

// TestRelevanceCeilingWithThePressureBand: below the ceiling plus margin
// as indicated, inside only the widened band (relevant, flagged), above
// it (not relevant), and without an altitude (relevant, flagged).
func TestRelevanceCeilingWithThePressureBand(t *testing.T) {
	cis := StaticCIS{P: Projection{Volumes: []*zones.Zone{uspace(t)}, Version: "42", FetchedAt: t0}}
	p, _ := newPicture(t, nil, cis)
	// Ceiling 1500 + margin 1500 = 3000 m; core's pressure band 250 m.
	for _, c := range []struct {
		name       string
		altM       *float64
		relevant   bool
		withinBand *bool
		notJudged  string
	}{
		{"below", alt(2900), true, ptrBool(true), ""},
		{"within the band only", alt(3100), true, ptrBool(false), ""},
		{"above the band", alt(3300), false, nil, ""},
		{"no altitude", nil, true, nil, "no_altitude"},
	} {
		tr := track("4ca7b5", "a", 41.72, 44.80, c.altM, t0)
		r := p.RelevanceOf(&tr)
		if r.Relevant != c.relevant || r.NotJudged != c.notJudged {
			t.Errorf("%s: %+v", c.name, r)
			continue
		}
		if c.withinBand != nil && (r.WithinBand == nil || *r.WithinBand != *c.withinBand || r.VerticalKnown) {
			t.Errorf("%s: band %+v", c.name, r)
		}
	}
	tr := track("4ca7b5", "a", 41.72, 44.80, alt(3100), t0)
	p.Observe(tr)
	tr2 := track("4ca7b6", "a", 41.72, 44.80, nil, t0)
	p.Observe(tr2)
	c := p.Counters().Snapshot()
	if c[CounterOutsideBand] != 1 || c[CounterCeilingNotJudged] != 1 {
		t.Fatalf("counters %v", c)
	}
}

func ptrBool(b bool) *bool { return &b }

// TestRelevanceOfAnUnlimitedOrUnjudgeableCeiling: no ceiling is relevant
// at any height; an AGL ceiling cannot be judged here and is relevant,
// flagged (fail-safe).
func TestRelevanceOfAnUnlimitedOrUnjudgeableCeiling(t *testing.T) {
	open := uspace(t)
	open.Upper = nil
	agl := uspace(t)
	agl.Identifier = "GEO-TEST-U2"
	agl.Upper = &zones.Limit{ValueM: 120, Ref: core.RefAGL}
	for name, z := range map[string]*zones.Zone{"open": open, "agl": agl} {
		p, _ := newPicture(t, nil, StaticCIS{P: Projection{Volumes: []*zones.Zone{nil, z}}})
		tr := track("4ca7b5", "a", 41.72, 44.80, alt(9000), t0)
		r := p.RelevanceOf(&tr)
		if !r.Relevant {
			t.Errorf("%s: %+v", name, r)
		}
		if name == "agl" && r.NotJudged != "no_terrain" {
			t.Errorf("agl: %+v", r)
		}
	}
	// Two volumes: the judged one wins over the unjudged one.
	p, _ := newPicture(t, nil, StaticCIS{P: Projection{Volumes: []*zones.Zone{agl, uspace(t)}}})
	tr := track("4ca7b5", "a", 41.72, 44.80, alt(1000), t0)
	if r := p.RelevanceOf(&tr); r.Volume != "GEO-TEST-U1" || r.NotJudged != "" {
		t.Fatalf("preferred %+v", r)
	}
}

func TestRelevanceAcrossTheAntimeridian(t *testing.T) {
	ring := geodesy.RingFromLonLat([][2]float64{{179.5, 10}, {-179.5, 10}, {-179.5, 11}, {179.5, 11}, {179.5, 10}})
	poly := &geodesy.Polygon{Rings: []geodesy.Ring{ring}}
	z := &zones.Zone{Identifier: "GEO-TEST-AM", Type: core.ZoneUSpace, Polygon: poly, BBox: poly.BBox()}
	p, _ := newPicture(t, nil, StaticCIS{P: Projection{Volumes: []*zones.Zone{z}}})
	for _, lon := range []float64{180, -180, 179.9, -179.9} {
		tr := track("4ca7b5", "a", 10.5, lon, alt(100), t0)
		if !p.Relevant(&tr) {
			t.Errorf("lon %v not relevant", lon)
		}
	}
}

// TestPictureConcurrentUse is the concurrency test of a stateful
// component (docs/PLAN.md section 14), meaningful under -race.
func TestPictureConcurrentUse(t *testing.T) {
	p, _ := newPicture(t, nil, nil)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p.Observe(track(fmt.Sprintf("%06x", g*1000+i%50), "a", 41.7, 44.8, alt(900), t0.Add(time.Duration(i)*time.Millisecond)))
				if i%20 == 0 {
					p.Tick(t0.Add(time.Duration(i) * time.Millisecond))
					p.Snapshot(nil)
				}
			}
		}(g)
	}
	wg.Wait()
	if p.Len() != 200 {
		t.Fatalf("len %d", p.Len())
	}
}

func BenchmarkPictureObserve(b *testing.B) {
	c := &clock{now: t0}
	p := New(defaultPolicy(), nil, NoCIS{}, c.Now, DefaultLimits())
	tracks := make([]manned.Track, 100)
	for i := range tracks {
		tracks[i] = track(fmt.Sprintf("%06x", i), "a", 41.7, 44.8, alt(900), t0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := tracks[i%100]
		tr.Times.CapturedAt = t0.Add(time.Duration(i) * time.Microsecond)
		p.Observe(tr)
	}
}

func BenchmarkRelevance(b *testing.B) {
	vols := make([]*zones.Zone, 20)
	for i := range vols {
		lon := 40.0 + float64(i)*0.3
		ring := geodesy.RingFromLonLat([][2]float64{{lon, 41.6}, {lon + 0.2, 41.6}, {lon + 0.2, 41.8}, {lon, 41.8}, {lon, 41.6}})
		poly := &geodesy.Polygon{Rings: []geodesy.Ring{ring}}
		vols[i] = &zones.Zone{Identifier: fmt.Sprintf("GEO-TEST-B%d", i), Type: core.ZoneUSpace,
			Upper: &zones.Limit{ValueM: 1500, Ref: core.RefAMSL}, Polygon: poly, BBox: poly.BBox()}
	}
	c := &clock{now: t0}
	p := New(defaultPolicy(), nil, StaticCIS{P: Projection{Volumes: vols}}, c.Now, DefaultLimits())
	tr := track("4ca7b5", "a", 41.7, 45.75, alt(900), t0) // inside the last volume: all 20 checked
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Relevant(&tr) {
			b.Fatal("not relevant")
		}
	}
}

func BenchmarkSnapshot100(b *testing.B) {
	c := &clock{now: t0}
	p := New(defaultPolicy(), nil, NoCIS{}, c.Now, DefaultLimits())
	for i := 0; i < 100; i++ {
		p.Observe(track(fmt.Sprintf("%06x", i), "a", 41.7, 44.8, alt(900), t0))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(p.Snapshot(nil)) != 100 {
			b.Fatal("snapshot")
		}
	}
}
