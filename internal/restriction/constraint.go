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
	// CounterGeoidUnavailable: an AMSL or AGL limit could not be made
	// HAE because no geoid is configured or it could not answer.
	CounterGeoidUnavailable = "constraint_geoid_unavailable"
	// CounterGeozoneUnmapped: ed318.ToED269 cannot map the feature, so
	// ConstraintDetails.geozone is omitted (the constraint stays valid).
	CounterGeozoneUnmapped = "constraint_geozone_unmapped"
)

// ErrGeoidUnavailable refuses a constraint of an AMSL or AGL restriction when
// the geoid cannot answer: a wrong altitude is worse than none (503
// geoid_unavailable).
var ErrGeoidUnavailable = errors.New("geoid unavailable")

// Derivation records how the W84 altitudes of a version were derived
// (restriction_versions.constraint.derivation; gap 3): for an AMSL or
// AGL limit the undulation used (the minimum over the outline for the
// lower limit, the maximum for the upper: the conservative envelope) and
// the range seen; for an AGL limit also the ground used (the lowest
// under the area for the lower limit, the highest for the upper) and
// what it was read from (LESSONS D-05).
type Derivation struct {
	LowerRef          core.VerticalRef `json:"lower_ref"`
	UpperRef          core.VerticalRef `json:"upper_ref"`
	LowerUndulationM  *float64         `json:"lower_undulation_m,omitempty"`
	UpperUndulationM  *float64         `json:"upper_undulation_m,omitempty"`
	UndulationMinM    *float64         `json:"undulation_min_m,omitempty"`
	UndulationMaxM    *float64         `json:"undulation_max_m,omitempty"`
	UndulationSamples int              `json:"undulation_samples,omitempty"`
	LowerGroundM      *float64         `json:"lower_ground_m,omitempty"`
	UpperGroundM      *float64         `json:"upper_ground_m,omitempty"`
	GroundMinM        *float64         `json:"ground_min_m,omitempty"`
	GroundMaxM        *float64         `json:"ground_max_m,omitempty"`
	GroundSamples     int              `json:"ground_samples,omitempty"`
	GroundDatasets    []string         `json:"ground_datasets,omitempty"`
	GroundSpacingM    *float64         `json:"ground_spacing_m,omitempty"`
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
// WGS84 limit passed through, an AMSL limit made HAE with
// geoid.HAEFromAMSL and an AGL limit made AMSL with the DEM first (AMSL
// = AGL + ground, D-02). The lower limit takes the lowest ground under
// the area and the least undulation over the outline, the upper the
// highest and the greatest: a conservative envelope that never shrinks
// below the restriction (gap 3). The window is F3548 RFC3339 times. A
// limit that needs the geoid without one that answers is
// ErrGeoidUnavailable; one that needs the ground where it is not known
// everywhere is ErrTerrainUnavailable: never a guessed altitude.
func Volumes(r Restriction, dt Datums) ([]f3548.Volume4D, Derivation, error) {
	d := Derivation{LowerRef: r.LowerRef, UpperRef: r.UpperRef}
	for _, ref := range []core.VerticalRef{r.LowerRef, r.UpperRef} {
		switch ref {
		case RefAGL, RefAMSL, RefWGS84:
		default:
			return nil, d, core.Fieldf("lower_ref", "%q: only AGL, AMSL and WGS84 limits make an F3548 volume (D3)", string(ref))
		}
	}
	env := &envelope{shape: r.Shape, datums: dt}
	lower, err := env.haeBound(r.LowerM, r.LowerRef, false)
	if err != nil {
		return nil, d, err
	}
	upper, err := env.haeBound(r.UpperM, r.UpperRef, true)
	if err != nil {
		return nil, d, err
	}
	if err := ordered(r, env, lower, upper); err != nil {
		return nil, d, err
	}
	if env.undulationRead {
		lo, hi := env.undulationLo, env.undulationHi
		d.UndulationMinM, d.UndulationMaxM, d.UndulationSamples = &lo, &hi, env.undulationSamples
		if r.LowerRef != RefWGS84 {
			d.LowerUndulationM = ptr(lo)
		}
		if r.UpperRef != RefWGS84 {
			d.UpperUndulationM = ptr(hi)
		}
	}
	if g := env.ground; g != nil {
		d.GroundMinM, d.GroundMaxM, d.GroundSamples = ptr(g.MinM), ptr(g.MaxM), g.Samples
		d.GroundDatasets, d.GroundSpacingM = g.Datasets, ptr(g.SpacingM)
		if r.LowerRef == RefAGL {
			d.LowerGroundM = ptr(g.MinM)
		}
		if r.UpperRef == RefAGL {
			d.UpperGroundM = ptr(g.MaxM)
		}
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

// ordered refuses limits that are not lower below upper everywhere under
// the restriction. Validate compares limits in one reference (AGL with
// AGL is the same comparison at every point); limits in different
// references are compared here, as AMSL over the area: the lower limit
// at the highest it reaches and the upper at the lowest, so a
// restriction inverted or empty anywhere (an AMSL floor above an AGL
// ceiling over the low ground) is refused, never widened into a volume
// that hides it. The W84 volume itself must not be inverted or empty.
func ordered(r Restriction, env *envelope, lowerHAE, upperHAE float64) error {
	if r.LowerRef != r.UpperRef {
		lo, err := env.amslBound(r.LowerM, r.LowerRef, true)
		if err != nil {
			return err
		}
		hi, err := env.amslBound(r.UpperM, r.UpperRef, false)
		if err != nil {
			return err
		}
		if !(lo < hi) {
			return core.Fieldf("upper_m", "%v m %s is not above lower_m %v m %s everywhere under the restriction: the lower limit reaches %.1f m AMSL and the upper limit falls to %.1f m AMSL", r.UpperM, r.UpperRef, r.LowerM, r.LowerRef, lo, hi)
		}
	}
	if !(lowerHAE < upperHAE) {
		return core.Fieldf("upper_m", "the F3548 volume would be inverted or empty: %.1f m to %.1f m W84", lowerHAE, upperHAE)
	}
	return nil
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
func Details(r Restriction, feature *ed318.Feature, dt Datums, counters *core.Counters) (StoredConstraint, error) {
	vols, d, err := Volumes(r, dt)
	if err != nil && counters != nil {
		switch {
		case errors.Is(err, ErrGeoidUnavailable):
			counters.Inc(CounterGeoidUnavailable)
		case errors.Is(err, ErrTerrainUnavailable):
			counters.Inc(CounterTerrainUnavailable)
		}
	}
	if err != nil {
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
