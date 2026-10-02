package manned

import (
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/timeplace"
)

// Counter names of the adapter (E-09): stable snake_case, exported as
// metrics and carried in src.v1.manned.<adapter>. A refusal increments
// refused and refused_<field>; a cleared optional member increments
// cleared_<field>.
const (
	CounterAccepted        = "accepted"          // handed to the publisher
	CounterRefused         = "refused"           // every refusal, whatever the field
	CounterNormalised      = "normalised"        // tracks the normaliser produced
	CounterOutOfOrder      = "out_of_order"      // older on the feed's clock than the sample held (T-03)
	CounterDuplicates      = "duplicates"        // same feed time and position inside the dedupe window
	CounterPlacedAtArrival = "placed_at_arrival" // no feed time: placed at the adapter's read (T-12)
	CounterSpacingClamped  = "spacing_clamped"   // a batch spacing beyond max_spacing_s (T-02)
	CounterFutureClamped   = "future_clamped"    // captured_at ahead of the clock beyond the tolerance (T-13)
	CounterBacklogSamples  = "backlog_samples"   // tracks marked backlog
	CounterStalledReads    = "stalled_reads"     // confirmed stalls (T-11)
	CounterEvicted         = "evicted_aircraft"  // an aircraft dropped from the held set at max_aircraft (E-10)

	RefusedPrefix = "refused_"
	ClearedPrefix = "cleared_"
)

// Refusal is one refused sample: the aircraft (as the feed spelled it,
// bounded), the member at fault and why.
type Refusal struct {
	ICAO24 string
	Field  string
	Reason string
}

// maxRecentKeys bounds the dedupe keys held per aircraft.
const maxRecentKeys = 16

type dedupeKey struct {
	hasTS    bool
	feedTSNs int64
	lat, lon float64
	at       time.Time
}

type held struct {
	lastFeedTS *time.Time
	lastRx     time.Time
	recent     []dedupeKey
}

// Normaliser turns the raw samples of one adapter instance into tracks:
// time placement, refusal, clearing, order and dedupe, under the policy
// of the moment. One per adapter instance. Safe for concurrent use (Take
// is called by one goroutine; AircraftSeen by the status loop).
type Normaliser struct {
	instance    string
	sourceClass string
	policy      PolicySource
	counters    *core.Counters

	// Now is the adapter's clock; NewID mints msg_id; OnRefuse, when
	// set, hears every refusal (the process logs it, rate limited).
	Now      func() time.Time
	NewID    func(time.Time) string
	OnRefuse func(Refusal)

	mu       sync.Mutex
	aircraft map[string]*held
}

// NewNormaliser is the normaliser of adapter instance (source_instance)
// whose feeds are sourceClass unless a sample says otherwise.
func NewNormaliser(instance, sourceClass string, pol PolicySource, counters *core.Counters) *Normaliser {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Normaliser{
		instance: instance, sourceClass: sourceClass, policy: pol, counters: counters,
		Now: time.Now, NewID: NewULID, aircraft: map[string]*held{},
	}
}

// Counters are the normaliser's counters.
func (n *Normaliser) Counters() *core.Counters { return n.counters }

// AircraftSeen is the number of aircraft with a track accepted within
// window before now.
func (n *Normaliser) AircraftSeen(now time.Time, window time.Duration) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, h := range n.aircraft {
		if now.Sub(h.lastRx) <= window {
			c++
		}
	}
	return c
}

// Held is the number of aircraft whose order and dedupe state is held.
func (n *Normaliser) Held() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.aircraft)
}

func (n *Normaliser) refuse(icao, field, reason string) {
	n.counters.Inc(CounterRefused)
	n.counters.Inc(RefusedPrefix + field)
	if n.OnRefuse != nil {
		if len(icao) > 16 {
			icao = icao[:16]
		}
		n.OnRefuse(Refusal{ICAO24: icao, Field: field, Reason: reason})
	}
}

// Take normalises one batch read at rxTS (the adapter's clock at read).
// Samples with a feed time are placed with timeplace.PlaceBatch,
// captured_at = rxTS - (newest feed time of the batch - feed time), the
// newest taken over the samples' times and the feed's own "now" (T-01,
// T-02); samples without one are placed at their read and counted
// placed_at_arrival (T-12). The feed's clock is never compared with
// anything but itself. Tracks come back in batch order.
func (n *Normaliser) Take(batch []RawSample, rxTS time.Time) []Track {
	if len(batch) == 0 {
		return nil
	}
	pol, version := n.policy.Current()
	now := n.Now()
	captured := n.place(batch, rxTS, &pol)
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Track, 0, len(batch))
	for i := range batch {
		if t, ok := n.one(&batch[i], captured[i], rxTS, now, &pol, version); ok {
			out = append(out, t)
		}
	}
	return out
}

// place is the captured_at of every sample of batch.
func (n *Normaliser) place(batch []RawSample, rxTS time.Time, pol *Policy) []time.Time {
	captured := make([]time.Time, len(batch))
	var idx []int
	var ts []time.Time
	for i := range batch {
		if batch[i].FeedTS != nil {
			idx = append(idx, i)
			ts = append(ts, *batch[i].FeedTS)
		}
	}
	if len(idx) > 0 {
		for i := range batch {
			if batch[i].FeedNow != nil {
				ts = append(ts, *batch[i].FeedNow)
			}
		}
		placed, clamped := timeplace.PlaceBatch(rxTS, ts, Seconds(pol.MaxSpacingS))
		n.counters.Add(CounterSpacingClamped, uint64(clamped))
		for k, i := range idx {
			captured[i] = placed[k]
		}
	}
	for i := range batch {
		if batch[i].FeedTS == nil {
			at := batch[i].ReadAt
			if at.IsZero() || at.After(rxTS) {
				at = rxTS
			}
			captured[i] = at
			n.counters.Inc(CounterPlacedAtArrival)
		}
	}
	return captured
}

func (n *Normaliser) one(s *RawSample, capturedAt, rxTS, now time.Time, pol *Policy, version uint64) (Track, bool) {
	icao := strings.ToLower(strings.TrimSpace(s.ICAO24))
	if !ValidICAO24(icao) {
		n.refuse(s.ICAO24, "icao24", "not six hex digits")
		return Track{}, false
	}
	if s.Position == nil {
		n.refuse(icao, "position", "absent")
		return Track{}, false
	}
	pos := core.LatLon{LatDeg: s.Position.LatDeg, LonDeg: s.Position.LonDeg}
	if !pos.Valid() {
		n.refuse(icao, "position", "not finite or out of range")
		return Track{}, false
	}
	if limit := now.Add(Seconds(pol.FutureToleranceS)); capturedAt.After(limit) {
		capturedAt = now
		n.counters.Inc(CounterFutureClamped)
	}
	source := core.TimeSourceClock
	if s.FeedTS == nil {
		source = core.TimeSystem
	}
	h := n.stateOf(icao, pol)
	if s.FeedTS != nil && h.lastFeedTS != nil && s.FeedTS.Before(*h.lastFeedTS) {
		n.counters.Inc(CounterOutOfOrder)
		return Track{}, false
	}
	key := dedupeKey{lat: pos.LatDeg, lon: pos.LonDeg, at: rxTS}
	if s.FeedTS != nil {
		key.hasTS, key.feedTSNs, key.at = true, s.FeedTS.UnixNano(), *s.FeedTS
	} else if !s.ReadAt.IsZero() {
		key.at = s.ReadAt
	}
	if h.duplicate(key, Seconds(pol.DedupeWindowS)) {
		n.counters.Inc(CounterDuplicates)
		return Track{}, false
	}
	class := n.sourceClass
	if s.SourceClass != "" {
		class = s.SourceClass
	}
	t := Track{
		Schema: SchemaTrack, MsgID: n.NewID(now), Producer: Producer,
		Times: core.Times{RxTS: rxTS, CapturedAt: capturedAt, Source: source, Backlog: s.Backlog},
		Trust: core.TrustSurveillance, Source: SourceANSPFeed, SourceInstance: n.instance,
		ICAO24: icao, Position: pos, SourceClass: class, PolicyVersion: version,
	}
	if s.FeedTS != nil {
		ts := *s.FeedTS
		t.Times.TS = &ts
	}
	n.fill(&t, s, pol)
	if err := t.ValidateWith(pol); err != nil {
		field, reason := "track", err.Error()
		var fe *core.FieldError
		if errors.As(err, &fe) {
			field, reason = fe.Field, fe.Reason
		}
		n.refuse(icao, field, reason)
		return Track{}, false
	}
	h.accept(key, s.FeedTS, rxTS, Seconds(pol.DedupeWindowS))
	n.counters.Inc(CounterNormalised)
	if t.Times.Backlog {
		n.counters.Inc(CounterBacklogSamples)
	}
	return t, true
}

// fill copies the optional members, clearing (and counting) every one
// that is not a measurement: not finite, outside the policy's bounds, or
// not of the schema's form. A cleared member is null on the wire; the
// aircraft is still published (CLAUDE.md rule 4).
func (n *Normaliser) fill(t *Track, s *RawSample, pol *Policy) {
	cleared := func(field string) { n.counters.Inc(ClearedPrefix + field) }
	num := func(field string, v *float64, lo, hi float64, openHi bool) *float64 {
		if v == nil {
			return nil
		}
		if !core.IsFinite(*v) || *v < lo || *v > hi || (openHi && *v == hi) {
			cleared(field)
			return nil
		}
		x := *v
		return &x
	}
	t.AltPressureM = num("alt_pressure_m", s.AltPressureM, pol.MinAltM, pol.MaxAltM, false)
	t.AltWGS84M = num("alt_wgs84_m", s.AltWGS84M, pol.MinAltM, pol.MaxAltM, false)
	t.GSMS = num("gs_ms", s.GSMS, 0, pol.MaxGSMS, false)
	t.TrackDeg = num("track_deg", s.TrackDeg, 0, 360, true)
	t.VRateMS = num("vrate_ms", s.VRateMS, -pol.MaxVRateMS, pol.MaxVRateMS, false)
	if s.Callsign != nil {
		if c := strings.TrimSpace(*s.Callsign); c != "" {
			if ValidCallsign(c) {
				t.Callsign = &c
			} else {
				cleared("callsign")
			}
		}
	}
	if s.Squawk != nil {
		if ValidSquawk(*s.Squawk) {
			q := *s.Squawk
			t.Squawk = &q
		} else {
			cleared("squawk")
		}
	}
	if s.Emergency != nil {
		e := *s.Emergency
		t.Emergency = &e
	}
	if s.SPI != nil {
		p := *s.SPI
		t.SPI = &p
	}
	if len(s.Quality) > 0 {
		q, ok := sanitizeQuality(s.Quality, pol.MaxQualityKeys)
		if !ok {
			cleared("quality")
		}
		if len(q) > 0 {
			t.Quality = q
		}
	}
}

// maxQualityString bounds a string in the quality block.
const maxQualityString = 64

// maxQualityList bounds a list in the quality block.
const maxQualityList = 16

// sanitizeQuality keeps the members of q that are JSON scalars (finite
// numbers, bools, short strings) or short lists of short strings, at
// most maxKeys of them (else none); ok is false when anything was
// dropped.
func sanitizeQuality(q map[string]any, maxKeys int) (map[string]any, bool) {
	if len(q) > maxKeys {
		return nil, false
	}
	out := make(map[string]any, len(q))
	ok := true
	for k, v := range q {
		if len(k) == 0 || len(k) > maxQualityString {
			ok = false
			continue
		}
		switch x := v.(type) {
		case bool:
			out[k] = x
		case string:
			if len(x) > maxQualityString {
				ok = false
				continue
			}
			out[k] = x
		case float64:
			if !core.IsFinite(x) {
				ok = false
				continue
			}
			out[k] = x
		case int:
			out[k] = float64(x)
		case []string:
			if l, good := stringList(x); good {
				out[k] = l
			} else {
				ok = false
			}
		case []any:
			strs := make([]string, 0, len(x))
			good := true
			for _, e := range x {
				s, isStr := e.(string)
				if !isStr {
					good = false
					break
				}
				strs = append(strs, s)
			}
			if l, fine := stringList(strs); good && fine {
				out[k] = l
			} else {
				ok = false
			}
		default:
			ok = false
		}
	}
	return out, ok
}

func stringList(x []string) ([]string, bool) {
	if len(x) > maxQualityList {
		return nil, false
	}
	for _, s := range x {
		if len(s) > maxQualityString {
			return nil, false
		}
	}
	return append([]string{}, x...), true
}

// stateOf is the state of icao, created (evicting the least recently heard
// aircraft at max_aircraft, counted) when absent. Called with mu held.
func (n *Normaliser) stateOf(icao string, pol *Policy) *held {
	if h, ok := n.aircraft[icao]; ok {
		return h
	}
	if len(n.aircraft) >= pol.MaxAircraft {
		var oldest string
		var at time.Time
		first := true
		for k, h := range n.aircraft {
			if first || h.lastRx.Before(at) {
				oldest, at, first = k, h.lastRx, false
			}
		}
		delete(n.aircraft, oldest)
		n.counters.Inc(CounterEvicted)
	}
	h := &held{}
	n.aircraft[icao] = h
	return h
}

// duplicate reports whether k repeats a key accepted within window.
func (h *held) duplicate(k dedupeKey, window time.Duration) bool {
	for _, r := range h.recent {
		if r.hasTS != k.hasTS || r.lat != k.lat || r.lon != k.lon {
			continue
		}
		if k.hasTS && r.feedTSNs != k.feedTSNs {
			continue
		}
		if absDuration(k.at.Sub(r.at)) <= window {
			return true
		}
	}
	return false
}

// accept records an accepted sample: the newest feed time, the read time
// and the dedupe key, keeping only keys inside the window (and at most
// maxRecentKeys of them).
func (h *held) accept(k dedupeKey, feedTS *time.Time, rxTS time.Time, window time.Duration) {
	if feedTS != nil && (h.lastFeedTS == nil || feedTS.After(*h.lastFeedTS)) {
		ts := *feedTS
		h.lastFeedTS = &ts
	}
	h.lastRx = rxTS
	kept := h.recent[:0]
	for _, r := range h.recent {
		if absDuration(k.at.Sub(r.at)) <= window {
			kept = append(kept, r)
		}
	}
	kept = append(kept, k)
	if len(kept) > maxRecentKeys {
		kept = kept[len(kept)-maxRecentKeys:]
	}
	h.recent = kept
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		if d == math.MinInt64 {
			return math.MaxInt64
		}
		return -d
	}
	return d
}
