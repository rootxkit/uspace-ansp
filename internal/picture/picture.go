package picture

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/sources"
)

// State is how an aircraft is shown.
type State string

// The states of an entry. Live, stale and source_disabled are the
// states of track/manned/v1; backlog_only is an aircraft known only from
// backlog samples, which are recorded and never shown live (T-04).
const (
	StateLive           State = "live"
	StateStale          State = "stale"
	StateSourceDisabled State = "source_disabled"
	StateBacklogOnly    State = "backlog_only"
)

// Limits bound the picture. They are not ansp_policy columns yet
// (docs/PLAN.md section 15 gap 32): DefaultLimits holds them in one
// place, validated, until a migration adds them.
type Limits struct {
	// MaxAircraft bounds the entries; past it the oldest is evicted,
	// counted (E-10).
	MaxAircraft int
	// EvictAfterS removes an aircraft this long after its last sample
	// (it was shown stale from stale_after_s on).
	EvictAfterS float64
}

// DefaultLimits are 5000 aircraft (manned.Defaults().MaxAircraft, the
// adapter's bound) and eviction after 300 s.
func DefaultLimits() Limits {
	return Limits{MaxAircraft: manned.Defaults().MaxAircraft, EvictAfterS: 300}
}

// Validate refuses a bound that would disarm the picture.
func (l Limits) Validate() error {
	switch {
	case l.MaxAircraft <= 0:
		return core.Fieldf("max_aircraft", "must be greater than zero")
	case !core.IsFinite(l.EvictAfterS) || l.EvictAfterS <= 0:
		return core.Fieldf("evict_after_s", "must be a finite number greater than zero")
	}
	return nil
}

// Counters of the picture (E-09).
const (
	CounterObserved         = "picture_observed"
	CounterShown            = "picture_shown"
	CounterOutOfOrder       = "picture_out_of_order"
	CounterBacklog          = "picture_backlog_not_shown"
	CounterArrivedStale     = "picture_arrived_stale"
	CounterDisabledDropped  = "picture_source_disabled_dropped"
	CounterEvictedCapacity  = "picture_evicted_capacity"
	CounterEvictedAge       = "picture_evicted_age"
	CounterNotRelevant      = "picture_not_relevant"
	CounterNotEvaluated     = "picture_relevance_not_evaluated"
	CounterOutsideBand      = "picture_relevant_outside_band"
	CounterCeilingNotJudged = "picture_ceiling_not_judged"
)

// PolicySource is the followed ansp_policy (policy.Follower).
type PolicySource interface {
	Current() (policy.Policy, bool)
}

// Switches are the followed source switches (sources.Follower).
type Switches interface {
	Decision(sourceType string, instance *string) sources.Decision
}

// Entry is one aircraft as the picture holds it.
type Entry struct {
	// Track is the last sample shown (or, for backlog_only, the last
	// backlog sample).
	Track manned.Track
	State State
	// AgeS is now - captured_at when the entry was read.
	AgeS      float64
	Relevance Relevance
	// Disabled is the switch that disabled the source, for
	// source_disabled (who, when, why; B-11).
	Disabled *sources.Decision
}

// Verdict is what Observe did with a sample.
type Verdict int

// The verdicts.
const (
	// Shown: the sample is the aircraft's latest and is in the picture
	// (live, or already stale on arrival).
	Shown Verdict = iota + 1
	// OutOfOrder: not newer than the sample held (T-03); dropped.
	OutOfOrder
	// Backlog: history (T-04); recorded by the writer, never shown live.
	Backlog
	// SourceDisabled: its adapter is switched off; not shown.
	SourceDisabled
)

// Ageing is what one Tick changed.
type Ageing struct {
	// Changed are the entries whose state changed, as they are now.
	Changed []Entry
	// Evicted are the icao24 removed for age.
	Evicted []string
}

type held struct {
	track     manned.Track
	state     State
	relevance Relevance
	disabled  *sources.Decision
}

// Picture is the live manned picture: the last sample per icao24, its
// age, state and relevance. Safe for concurrent use.
type Picture struct {
	pol    PolicySource
	src    Switches
	cis    CIS
	now    func() time.Time
	limits Limits
	zpol   zones.Policy

	counters core.Counters

	mu      sync.RWMutex
	entries map[string]*held
}

// New is an empty picture. clock may be nil (time.Now). An invalid lim
// is replaced by DefaultLimits (the caller validates its configuration
// first).
func New(pol PolicySource, src Switches, cis CIS, clock func() time.Time, lim Limits) *Picture {
	if clock == nil {
		clock = time.Now
	}
	if cis == nil {
		cis = NoCIS{}
	}
	if lim.Validate() != nil {
		lim = DefaultLimits()
	}
	return &Picture{pol: pol, src: src, cis: cis, now: clock, limits: lim, zpol: zones.DefaultPolicy(), entries: map[string]*held{}}
}

// Counters are the picture's counters.
func (p *Picture) Counters() *core.Counters { return &p.counters }

// Limits are the picture's bounds.
func (p *Picture) Limits() Limits { return p.limits }

// thresholds are the followed policy's: stale after, the margins.
func (p *Picture) thresholds() policy.Policy {
	if p.pol == nil {
		return policy.Policy{Thresholds: policy.Defaults()}
	}
	cur, _ := p.pol.Current()
	return cur
}

func (p *Picture) decision(instance string) sources.Decision {
	if p.src == nil {
		return sources.Decision{Enabled: true}
	}
	return p.src.Decision(sources.SourceTypeManned, &instance)
}

// Relevant is whether t is relevant to U-space now (RelevanceOf).
func (p *Picture) Relevant(t *manned.Track) bool { return p.RelevanceOf(t).Relevant }

// RelevanceOf judges t against the CIS projection with the policy's
// margins. With no projection every aircraft is relevant, not evaluated.
func (p *Picture) RelevanceOf(t *manned.Track) Relevance {
	proj, ok := p.cis.Projection()
	if !ok {
		return Relevance{Relevant: true}
	}
	pol := p.thresholds()
	return relevance(t, proj, pol.FeedMarginLateralM, pol.FeedMarginVerticalM, p.zpol)
}

// RelevanceStatus is the relevance line of the process status (E-02).
func (p *Picture) RelevanceStatus() string {
	proj, ok := p.cis.Projection()
	if !ok || len(proj.Volumes) == 0 {
		return StatusNoProjection
	}
	return fmt.Sprintf("relevance: CIS version %s, %d volumes, age %.0f s", proj.Version, len(proj.Volumes),
		math.Max(0, p.now().Sub(proj.FetchedAt).Seconds()))
}

func (p *Picture) count(r Relevance) {
	switch {
	case !r.Evaluated:
		p.counters.Inc(CounterNotEvaluated)
	case !r.Relevant:
		p.counters.Inc(CounterNotRelevant)
	case r.NotJudged != "":
		p.counters.Inc(CounterCeilingNotJudged)
	case r.WithinBand != nil && !*r.WithinBand:
		p.counters.Inc(CounterOutsideBand)
	}
}

// Observe takes one sample. A sample not newer than the one held is
// dropped (T-03); a backlog sample is recorded by the writer and never
// shown live (T-04: an aircraft known only from backlog is
// backlog_only); a sample of a disabled source is not shown (B-11). A
// shown sample older than stale_after_s on arrival is shown stale and
// counted (SC-15: never live with a time it does not have). A new
// aircraft past MaxAircraft evicts the one heard longest ago, counted.
func (p *Picture) Observe(t manned.Track) (Verdict, Entry) {
	p.counters.Inc(CounterObserved)
	now := p.now()
	pol := p.thresholds()
	if !t.Times.Backlog {
		if d := p.decision(t.SourceInstance); !d.Enabled {
			p.counters.Inc(CounterDisabledDropped)
			return SourceDisabled, Entry{}
		}
	}
	rel := p.RelevanceOf(&t)
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.entries[t.ICAO24]
	if t.Times.Backlog {
		p.counters.Inc(CounterBacklog)
		if !ok {
			p.insert(t.ICAO24, &held{track: t, state: StateBacklogOnly, relevance: rel})
		} else if h.state == StateBacklogOnly && t.Times.CapturedAt.After(h.track.Times.CapturedAt) {
			h.track, h.relevance = t, rel
		}
		return Backlog, Entry{}
	}
	if ok && h.state != StateBacklogOnly && !t.Times.CapturedAt.After(h.track.Times.CapturedAt) {
		p.counters.Inc(CounterOutOfOrder)
		return OutOfOrder, Entry{}
	}
	p.count(rel)
	state := StateLive
	if now.Sub(t.Times.CapturedAt) > manned.Seconds(pol.StaleAfterS) {
		state = StateStale
		p.counters.Inc(CounterArrivedStale)
	}
	if !ok {
		h = &held{}
		p.insert(t.ICAO24, h)
	}
	h.track, h.state, h.relevance, h.disabled = t, state, rel, nil
	p.counters.Inc(CounterShown)
	return Shown, entryOf(h, now)
}

// insert adds h, evicting the entry heard longest ago at capacity. The
// caller holds the lock.
func (p *Picture) insert(icao string, h *held) {
	if len(p.entries) >= p.limits.MaxAircraft {
		var oldest string
		var at time.Time
		for k, e := range p.entries {
			if oldest == "" || e.track.Times.CapturedAt.Before(at) {
				oldest, at = k, e.track.Times.CapturedAt
			}
		}
		delete(p.entries, oldest)
		p.counters.Inc(CounterEvictedCapacity)
	}
	p.entries[icao] = h
}

func entryOf(h *held, now time.Time) Entry {
	e := Entry{Track: h.track, State: h.state, Relevance: h.relevance, AgeS: math.Max(0, now.Sub(h.track.Times.CapturedAt).Seconds())}
	if h.disabled != nil {
		d := *h.disabled
		e.Disabled = &d
	}
	return e
}

// Tick ages the picture at now: an aircraft whose source is switched
// off becomes source_disabled (B-11: within one tick, and only that
// source's aircraft), one without a sample for stale_after_s since its
// captured_at becomes stale (T-06), one without a sample for
// evict_after_s is removed. It returns every change.
func (p *Picture) Tick(now time.Time) Ageing {
	pol := p.thresholds()
	staleAfter := manned.Seconds(pol.StaleAfterS)
	evictAfter := manned.Seconds(p.limits.EvictAfterS)
	decisions := map[string]sources.Decision{}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out Ageing
	for icao, h := range p.entries {
		age := now.Sub(h.track.Times.CapturedAt)
		if age > evictAfter {
			delete(p.entries, icao)
			out.Evicted = append(out.Evicted, icao)
			p.counters.Inc(CounterEvictedAge)
			continue
		}
		if h.state == StateBacklogOnly {
			continue
		}
		inst := h.track.SourceInstance
		d, seen := decisions[inst]
		if !seen {
			d = p.decision(inst)
			decisions[inst] = d
		}
		next := StateLive
		switch {
		case !d.Enabled:
			next = StateSourceDisabled
		case age > staleAfter:
			next = StateStale
		}
		if next == StateSourceDisabled && h.state != StateSourceDisabled {
			dc := d
			h.disabled = &dc
		}
		if next == StateLive && h.state != StateLive {
			// A stale or source_disabled aircraft becomes live again only
			// with a new sample; a re-enabled source's last one is stale.
			next = StateStale
		}
		if next == h.state {
			continue
		}
		if next != StateSourceDisabled {
			h.disabled = nil
		}
		h.state = next
		out.Changed = append(out.Changed, entryOf(h, now))
	}
	sort.Slice(out.Changed, func(i, j int) bool { return out.Changed[i].Track.ICAO24 < out.Changed[j].Track.ICAO24 })
	sort.Strings(out.Evicted)
	return out
}

// Snapshot is every entry inside bbox (nil: everywhere), by icao24, with
// its age at now. Backlog-only entries are included with their state;
// the caller decides what it may show.
func (p *Picture) Snapshot(bbox *geodesy.BBox) []Entry {
	now := p.now()
	p.mu.RLock()
	out := make([]Entry, 0, len(p.entries))
	for _, h := range p.entries {
		if bbox != nil && !bbox.Contains(h.track.Position) {
			continue
		}
		out = append(out, entryOf(h, now))
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Track.ICAO24 < out[j].Track.ICAO24 })
	return out
}

// Len is the number of entries.
func (p *Picture) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}
