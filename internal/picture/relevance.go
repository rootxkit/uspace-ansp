package picture

import (
	"math"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// Projection is the U-space airspace of the CIS projection the
// relevance filter judges against: the volumes as uspace-core zones
// (ed318.ToZones of the uspace_airspace dataset), the dataset version
// and when it was fetched.
type Projection struct {
	Volumes   []*zones.Zone
	Version   string
	FetchedAt time.Time
}

// CIS gives the current projection; ok is false while there is none.
// internal/cis (WP-7) provides it; until it lands manned-feed runs with
// NoCIS.
type CIS interface {
	Projection() (p Projection, ok bool)
}

// NoCIS is the CIS of a process without a projection: every aircraft is
// relevant and the status says relevance is not evaluated (SC-22: an
// empty filter must never look like an empty sky).
type NoCIS struct{}

// Projection is none.
func (NoCIS) Projection() (Projection, bool) { return Projection{}, false }

// StaticCIS is a fixed projection (tests, fixtures).
type StaticCIS struct{ P Projection }

// Projection is the fixed projection.
func (s StaticCIS) Projection() (Projection, bool) { return s.P, true }

// Relevance is the relevance of one sample and what it rests on (B-12:
// relevance is a flag, never a filter at the edge).
type Relevance struct {
	Relevant bool
	// Evaluated is false when there was no CIS projection: Relevant is
	// then true for every aircraft.
	Evaluated bool
	// Volume is the identifier of the U-space volume that made it
	// relevant.
	Volume string
	// VerticalKnown is false when the ceiling was judged on a pressure
	// altitude (widened by the pressure uncertainty, 04 §3.1) or could
	// not be judged; WithinBand says, for a pressure judgement, whether
	// the aircraft was below the ceiling plus margin as indicated (true)
	// or only within the widened band (false: still relevant, flagged).
	VerticalKnown bool
	WithinBand    *bool
	// NotJudged names why the ceiling could not be judged (core's
	// reasons: no_altitude, no_terrain, no_geoid, invalid_zone); the
	// aircraft is then relevant (fail-safe).
	NotJudged string
}

// Relevance reasons in the status line.
const (
	StatusNoProjection = "relevance: not evaluated (no CIS projection)"
)

// relevance judges t against the projection with the margins, all
// through uspace-core: the volume's shape (Zone.ContainsHorizontally),
// its bounding box padded by marginLateralM (geodesy.BBox.PadM: core
// holds no buffer of a polygon, so the margin is applied to the box, a
// superset that errs towards relevant), and the ceiling raised by
// marginVerticalM judged by zones.JudgeVertical on alt_pressure_m with
// core's pressure uncertainty (R-09) as a USPACE zone.
func relevance(t *manned.Track, proj Projection, marginLateralM, marginVerticalM float64, zpol zones.Policy) Relevance {
	if len(proj.Volumes) == 0 {
		return Relevance{Relevant: true}
	}
	out := Relevance{Evaluated: true}
	for _, v := range proj.Volumes {
		if v == nil || !horizontallyNear(v, t.Position, marginLateralM) {
			continue
		}
		r, ok := vertical(v, t, marginVerticalM, zpol)
		if !ok {
			continue
		}
		r.Evaluated, r.Relevant, r.Volume = true, true, v.Identifier
		if r.VerticalKnown && r.NotJudged == "" {
			return r // as good as it gets
		}
		if !out.Relevant || better(&r, &out) {
			out = r
		}
	}
	return out
}

// better prefers a judged ceiling within the band over a widened or
// unjudged one, so the flag reported is the most certain.
func better(a, b *Relevance) bool {
	score := func(r *Relevance) int {
		switch {
		case r.NotJudged != "":
			return 0
		case r.WithinBand != nil && !*r.WithinBand:
			return 1
		}
		return 2
	}
	return score(a) > score(b)
}

func horizontallyNear(v *zones.Zone, p core.LatLon, marginM float64) bool {
	if in, err := v.ContainsHorizontally(p); err == nil && in {
		return true
	}
	padded := v.BBox.PadM(marginM)
	if padded.Contains(p) {
		return true
	}
	if math.Abs(p.LonDeg) == 180 {
		return padded.Contains(core.LatLon{LatDeg: p.LatDeg, LonDeg: -p.LonDeg})
	}
	return false
}

// vertical judges the ceiling plus margin; ok is false when the aircraft
// is judged above it.
func vertical(v *zones.Zone, t *manned.Track, marginM float64, zpol zones.Policy) (Relevance, bool) {
	if v.Upper == nil {
		return Relevance{VerticalKnown: true}, true // no ceiling
	}
	ceiling := &zones.Zone{
		Identifier: v.Identifier, Country: v.Country, Type: core.ZoneUSpace,
		Upper: &zones.Limit{ValueM: v.Upper.ValueM + marginM, Ref: v.Upper.Ref},
	}
	ac := zones.Aircraft{AltAMSLM: t.AltPressureM, AltSource: core.AltPressure}
	if t.AltPressureM == nil {
		ac.AltSource = core.AltNone
	}
	res := zones.JudgeVertical(ceiling, ac, zones.Env{}, zpol)
	switch {
	case res.NotEvaluated || res.LimitNotJudged:
		return Relevance{NotJudged: res.Reasons.String()}, true
	case res.Raise == nil:
		return Relevance{}, false
	}
	r := Relevance{VerticalKnown: true}
	d := res.Raise.Detail
	if d.VerticalKnown != nil && !*d.VerticalKnown {
		r.VerticalKnown = false
		r.WithinBand = d.WithinBand
	}
	return r, true
}
