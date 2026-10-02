package restriction

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/geoid"
)

// ConstraintType is ConstraintDetails.type of a dynamic restriction
// (docs/PLAN.md section 15 gap 16).
const ConstraintType = "DAR"

// Counters of the constraint derivation.
const (
	// CounterGeoidUnavailable: an AMSL limit could not be made HAE
	// because no geoid is configured or it could not answer.
	CounterGeoidUnavailable = "constraint_geoid_unavailable"
	// CounterGeozoneUnmapped: ed318.ToED269 cannot map the feature, so
	// ConstraintDetails.geozone is omitted (the constraint stays valid).
	CounterGeozoneUnmapped = "constraint_geozone_unmapped"
)

// ErrGeoidUnavailable refuses a constraint of an AMSL restriction when
// the geoid cannot answer: a wrong altitude is worse than none (503
// geoid_unavailable).
var ErrGeoidUnavailable = errors.New("geoid unavailable")

// Derivation records how the W84 altitudes of a version were derived
// (restriction_versions.constraint.derivation; gap 3): for an AMSL limit
// the undulation used (the minimum over the outline for the lower limit,
// the maximum for the upper: the conservative envelope) and the range
// seen.
type Derivation struct {
	LowerRef          core.VerticalRef `json:"lower_ref"`
	UpperRef          core.VerticalRef `json:"upper_ref"`
	LowerUndulationM  *float64         `json:"lower_undulation_m,omitempty"`
	UpperUndulationM  *float64         `json:"upper_undulation_m,omitempty"`
	UndulationMinM    *float64         `json:"undulation_min_m,omitempty"`
	UndulationMaxM    *float64         `json:"undulation_max_m,omitempty"`
	UndulationSamples int              `json:"undulation_samples,omitempty"`
	GeozoneOmitted    string           `json:"geozone_omitted,omitempty"`
}

// StoredConstraint is the restriction_versions.constraint document of a
// version: the details as they will be written to the DSS (WP-9 adds the
// reference when it writes them) and the derivation.
type StoredConstraint struct {
	Details    f3548.ConstraintDetails `json:"details"`
	Derivation Derivation              `json:"derivation"`
}

// Volumes is the one F3548 Volume4D of r (W84, metres): its outline, a
// WGS84 limit passed through and an AMSL limit made HAE with
// geoid.HAEFromAMSL, the lower with the minimum undulation over the
// outline and the upper with the maximum (a conservative envelope, gap
// 3), and the window as F3548 RFC3339 times. g may be nil when neither
// limit is AMSL; otherwise a nil g, or one that cannot answer, is
// ErrGeoidUnavailable, never a guessed altitude.
func Volumes(r Restriction, g geoid.Undulator) ([]f3548.Volume4D, Derivation, error) {
	d := Derivation{LowerRef: r.LowerRef, UpperRef: r.UpperRef}
	lower, upper := r.LowerM, r.UpperM
	if r.LowerRef == RefAMSL || r.UpperRef == RefAMSL {
		lo, hi, n, err := undulationRange(r.Shape, g)
		if err != nil {
			return nil, d, err
		}
		d.UndulationMinM, d.UndulationMaxM, d.UndulationSamples = &lo, &hi, n
		if r.LowerRef == RefAMSL {
			lower = geoid.HAEFromAMSL(r.LowerM, lo)
			d.LowerUndulationM = ptr(lo)
		}
		if r.UpperRef == RefAMSL {
			upper = geoid.HAEFromAMSL(r.UpperM, hi)
			d.UpperUndulationM = ptr(hi)
		}
	} else if r.LowerRef != RefWGS84 || r.UpperRef != RefWGS84 {
		return nil, d, core.Fieldf("lower_ref", "only AMSL and WGS84 limits make an F3548 volume (D3)")
	}
	v3 := f3548.Volume3D{
		AltitudeLower: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: lower},
		AltitudeUpper: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: upper},
	}
	if r.Shape.IsCircle() {
		c := f3548.LatLngPoint{Lat: r.Shape.Center.LatDeg, Lng: r.Shape.Center.LonDeg}
		v3.OutlineCircle = &f3548.Circle{Center: &c, Radius: &f3548.Radius{Units: f3548.RadiusUnitsM, Value: float32(r.Shape.RadiusM)}}
	} else {
		// F3548 Polygon: the vertices without the closing repeat.
		n := len(r.Shape.Ring)
		if n > 0 && r.Shape.Ring[0] == r.Shape.Ring[n-1] {
			n--
		}
		vs := make([]f3548.LatLngPoint, 0, n)
		for _, p := range r.Shape.Ring[:n] {
			vs = append(vs, f3548.LatLngPoint{Lat: p.LatDeg, Lng: p.LonDeg})
		}
		v3.OutlinePolygon = &f3548.Polygon{Vertices: vs}
	}
	v := f3548.Volume4D{
		Volume:    v3,
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: r.StartsAt.UTC().Truncate(time.Millisecond)},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: r.EndsAt.UTC().Truncate(time.Millisecond)},
	}
	if _, _, _, err := f3548.Volume4DToZonesEnvelope(v); err != nil {
		return nil, d, err
	}
	return []f3548.Volume4D{v}, d, nil
}

// undulationRange is the least and greatest undulation over the outline:
// every vertex of a polygon; a circle's centre and the four corners of
// its bounding box.
func undulationRange(s Shape, g geoid.Undulator) (lo, hi float64, n int, err error) {
	if g == nil {
		return 0, 0, 0, ErrGeoidUnavailable
	}
	var pts []core.LatLon
	if s.IsCircle() {
		b := geodesy.Circle{Center: *s.Center, RadiusM: s.RadiusM}.BBox()
		pts = []core.LatLon{*s.Center, {LatDeg: b.MinLat, LonDeg: b.MinLon}, {LatDeg: b.MinLat, LonDeg: b.MaxLon}, {LatDeg: b.MaxLat, LonDeg: b.MinLon}, {LatDeg: b.MaxLat, LonDeg: b.MaxLon}}
	} else {
		pts = s.Ring
	}
	lo, hi = math.Inf(1), math.Inf(-1)
	for _, p := range pts {
		u, err := g.UndulationM(p)
		if err != nil || !core.IsFinite(u) {
			return 0, 0, 0, ErrGeoidUnavailable
		}
		lo, hi = math.Min(lo, u), math.Max(hi, u)
	}
	if len(pts) == 0 {
		return 0, 0, 0, ErrGeoidUnavailable
	}
	return lo, hi, len(pts), nil
}

// Details is the ConstraintDetails of r: its volumes, type DAR, and the
// ED-318 feature as an ED-269 geozone where ed318.ToED269 can map it,
// else no geozone and CounterGeozoneUnmapped counted (gap 16: a DAR has
// no ED-269 reason, so in practice it is always omitted).
func Details(r Restriction, feature *ed318.Feature, g geoid.Undulator, counters *core.Counters) (StoredConstraint, error) {
	vols, d, err := Volumes(r, g)
	if err != nil {
		if errors.Is(err, ErrGeoidUnavailable) && counters != nil {
			counters.Inc(CounterGeoidUnavailable)
		}
		return StoredConstraint{}, err
	}
	typ := ConstraintType
	out := StoredConstraint{Details: f3548.ConstraintDetails{Volumes: vols, Type: &typ}, Derivation: d}
	gz, err := geozone(feature)
	if err != nil {
		if counters != nil {
			counters.Inc(CounterGeozoneUnmapped)
		}
		out.Derivation.GeozoneOmitted = err.Error()
		return out, nil
	}
	out.Details.Geozone = gz
	return out, nil
}

// geozone maps feature to the F3548 GeoZone through ed318.ToED269 and
// ed269.Export.
func geozone(feature *ed318.Feature) (*f3548.GeoZone, error) {
	if feature == nil {
		return nil, errors.New("no feature")
	}
	doc, err := ed318.ToED269(&ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{*feature}}, FeatureLang)
	if err != nil {
		return nil, err
	}
	raw, err := ed269.Export(doc)
	if err != nil {
		return nil, err
	}
	var col struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(raw, &col); err != nil || len(col.Features) != 1 {
		return nil, errors.New("the ED-269 document is not one zone")
	}
	var gz f3548.GeoZone
	if err := json.Unmarshal(col.Features[0], &gz); err != nil {
		return nil, err
	}
	return &gz, nil
}
