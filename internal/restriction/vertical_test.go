package restriction

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/terrain"
)

// fakeGround answers a fixed range, or none, and records the boxes and
// bounds it was asked for.
type fakeGround struct {
	r     *terrain.Range
	err   error
	boxes []geodesy.BBox
	max   []int
}

func (g *fakeGround) RangeM(b geodesy.BBox, maxSamples int) (*terrain.Range, error) {
	g.boxes = append(g.boxes, b)
	g.max = append(g.max, maxSamples)
	return g.r, g.err
}

// hills is ground from 500 to 800 m AMSL under the fixture box.
func hills() *fakeGround {
	return &fakeGround{r: &terrain.Range{MinM: 500, MaxM: 800, Samples: 1200, Cells: 1, Datasets: []string{"COP-DEM GLO-30"}, SpacingM: 30.9}}
}

func aglSample() Restriction {
	r := sample()
	r.LowerM, r.LowerRef, r.UpperM, r.UpperRef = 0, RefAGL, 120, RefAGL
	return r
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// The presence case of gap 3: a 0-120 m AGL restriction over ground of
// 500..800 m is the W84 volume from the lowest ground plus the least
// undulation up to the highest ground plus 120 m plus the greatest
// undulation, so it never shrinks below the restriction anywhere; the
// derivation says which ground and which undulation each limit took and
// what the ground was read from.
func TestVolumesAGL(t *testing.T) {
	g := hills()
	vs, d, err := Volumes(aglSample(), Datums{Geoid: gridGeoid{}, Ground: g})
	if err != nil || len(vs) != 1 {
		t.Fatal(err)
	}
	lo, hi := 11.56, 11.64 // gridGeoid over the box's vertices
	v := vs[0].Volume
	if !near(v.AltitudeLower.Value, 500+0+lo) || !near(v.AltitudeUpper.Value, 800+120+hi) || v.AltitudeLower.Reference != f3548.W84 || v.AltitudeUpper.Reference != f3548.W84 {
		t.Fatalf("%+v %+v", v.AltitudeLower, v.AltitudeUpper)
	}
	if d.LowerRef != RefAGL || *d.LowerGroundM != 500 || *d.UpperGroundM != 800 || *d.GroundMinM != 500 || *d.GroundMaxM != 800 ||
		d.GroundSamples != 1200 || d.GroundDatasets[0] != "COP-DEM GLO-30" || *d.GroundSpacingM != 30.9 ||
		!near(*d.LowerUndulationM, lo) || !near(*d.UpperUndulationM, hi) {
		t.Fatalf("%+v", d)
	}
	// The ground is read once, over the restriction's box, with the bound.
	b := box().BBox()
	if len(g.boxes) != 1 || g.boxes[0] != b || g.max[0] != TerrainMaxSamples || b.MinLon != 44.78 || b.MaxLat != 41.73 {
		t.Fatalf("%+v %v", g.boxes, g.max)
	}
	raw, _ := json.Marshal(d)
	for _, member := range []string{`"lower_ground_m":500`, `"upper_ground_m":800`, `"ground_datasets":["COP-DEM GLO-30"]`} {
		if !strings.Contains(string(raw), member) {
			t.Fatalf("%s not in %s", member, raw)
		}
	}
}

// A circle reads the ground over a box that holds the whole circle.
func TestVolumesAGLCircle(t *testing.T) {
	r := circle()
	r.LowerRef, r.UpperRef = RefAGL, RefAGL
	g := hills()
	if _, _, err := Volumes(r, Datums{Geoid: gridGeoid{}, Ground: g}); err != nil {
		t.Fatal(err)
	}
	if len(g.boxes) != 1 {
		t.Fatal(g.boxes)
	}
	b := g.boxes[0]
	for _, p := range []core.LatLon{{LatDeg: 41.71 + 0.0135, LonDeg: 44.80}, {LatDeg: 41.71 - 0.0135, LonDeg: 44.80}, {LatDeg: 41.71, LonDeg: 44.80 + 0.018}, {LatDeg: 41.71, LonDeg: 44.80 - 0.018}} {
		if !b.Contains(p) {
			t.Fatalf("the box %+v does not hold the circle's edge %v", b, p)
		}
	}
}

// Mixed references: an AGL lower limit with an AMSL upper takes the
// lowest ground for the lower only; the AMSL upper is the geoid's alone.
func TestVolumesAGLLowerAMSLUpper(t *testing.T) {
	r := aglSample()
	r.UpperM, r.UpperRef = 1500, RefAMSL
	vs, d, err := Volumes(r, Datums{Geoid: gridGeoid{}, Ground: hills()})
	if err != nil {
		t.Fatal(err)
	}
	if !near(vs[0].Volume.AltitudeLower.Value, 500+11.56) || !near(vs[0].Volume.AltitudeUpper.Value, 1500+11.64) || d.UpperGroundM != nil || *d.LowerGroundM != 500 {
		t.Fatalf("%+v %+v", vs[0].Volume, d)
	}
}

// Fail closed: without terrain, with ground that is not known
// everywhere under the area, or with a terrain that cannot answer, an
// AGL limit makes no volume (ErrTerrainUnavailable, counted), never a
// volume over a guessed ground; an area too large to read is a problem
// on geometry; the geoid is still needed after the ground.
func TestVolumesAGLTerrainUnavailable(t *testing.T) {
	f, _ := Feature(aglSample(), cfg)
	for name, g := range map[string]Ground{
		"no terrain":        nil,
		"unknown ground":    &fakeGround{},
		"terrain error":     &fakeGround{err: errors.New("disk")},
		"not finite ground": &fakeGround{r: &terrain.Range{MinM: math.NaN(), MaxM: 800}},
	} {
		var c core.Counters
		_, err := Details(aglSample(), f, Datums{Geoid: gridGeoid{}, Ground: g}, &c)
		if !errors.Is(err, ErrTerrainUnavailable) || c.Get(CounterTerrainUnavailable) != 1 || c.Get(CounterGeoidUnavailable) != 0 {
			t.Fatalf("%s: %v %v", name, err, c.Snapshot())
		}
	}
	_, _, err := Volumes(aglSample(), Datums{Geoid: gridGeoid{}, Ground: &fakeGround{err: core.Fieldf("bbox", "touches 70 cells; at most 64")}})
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "geometry" || !strings.Contains(fe.Reason, "70 cells") || errors.Is(err, ErrTerrainUnavailable) {
		t.Fatalf("too large: %v", err)
	}
	var c core.Counters
	if _, err := Details(aglSample(), f, Datums{Ground: hills()}, &c); !errors.Is(err, ErrGeoidUnavailable) || c.Get(CounterGeoidUnavailable) != 1 {
		t.Fatalf("no geoid: %v", err)
	}
	r := aglSample()
	r.LowerRef = "QNH"
	if _, _, err := Volumes(r, Datums{Geoid: gridGeoid{}, Ground: hills()}); err == nil || !strings.Contains(err.Error(), "QNH") {
		t.Fatalf("unknown reference: %v", err)
	}
}

// A WGS84 or AMSL restriction never reads the ground (the absence twin
// of TestVolumesAGL): no terrain is needed and none is asked.
func TestVolumesWithoutAGLReadNoGround(t *testing.T) {
	g := hills()
	if _, d, err := Volumes(sample(), Datums{Geoid: gridGeoid{}, Ground: g}); err != nil || len(g.boxes) != 0 || d.GroundMinM != nil {
		t.Fatalf("%v %v %+v", err, g.boxes, d)
	}
}

// Placement compares like with like and converts only where the
// references differ, conservatively over the restriction's area.
func TestPlaceVerticalReferences(t *testing.T) {
	ctx := context.Background()
	tx := memTx{newMemRepo(t0)}
	agl := func(upper float64) Input {
		in := input(t0, t0.Add(time.Hour))
		in.LowerM, in.LowerRef, in.UpperM, in.UpperRef = 0, RefAGL, upper, RefAGL
		return in
	}
	amsl := func(upper float64) Input {
		in := input(t0, t0.Add(time.Hour))
		in.UpperM = upper
		return in
	}
	aglAirspace := Snapshot{Version: "7", Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 120, RefAGL)}}
	amslAirspace := Snapshot{Version: "8", Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefAMSL)}}
	wgsAirspace := Snapshot{Version: "9", Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1000, RefWGS84)}}

	t.Run("AGL in an AGL airspace is compared directly and needs no terrain", func(t *testing.T) {
		if id, err := Place(ctx, agl(120), aglAirspace, tx, Datums{}); err != nil || id != "GEOTU01" {
			t.Fatalf("%v %v", id, err)
		}
		rf := refusalOf(t, func() error { _, err := Place(ctx, agl(121), aglAirspace, tx, Datums{}); return err }())
		if rf.Slug != SlugInvalid || !hasField(rf, "upper_m", "121 m AGL is above the U-space airspace's upper limit 120 m AGL") {
			t.Fatalf("%+v", rf)
		}
	})
	t.Run("AGL in an AMSL airspace takes the highest ground", func(t *testing.T) {
		// 700 + 800 = 1500: at the ceiling; 701 is above it over the hill.
		if _, err := Place(ctx, agl(700), amslAirspace, tx, Datums{Ground: hills()}); err != nil {
			t.Fatal(err)
		}
		rf := refusalOf(t, func() error { _, err := Place(ctx, agl(701), amslAirspace, tx, Datums{Ground: hills()}); return err }())
		if rf.Slug != SlugInvalid || !hasField(rf, "upper_m", "reaches 1501.0 m AMSL") {
			t.Fatalf("%+v", rf)
		}
	})
	t.Run("AMSL in an AGL airspace takes the lowest ground", func(t *testing.T) {
		// The airspace's ceiling is 500 + 120 = 620 m AMSL at its lowest.
		if _, err := Place(ctx, amsl(620), aglAirspace, tx, Datums{Ground: hills()}); err != nil {
			t.Fatal(err)
		}
		rf := refusalOf(t, func() error { _, err := Place(ctx, amsl(621), aglAirspace, tx, Datums{Ground: hills()}); return err }())
		if rf.Slug != SlugInvalid || !hasField(rf, "upper_m", "620.0 m AMSL at its lowest") {
			t.Fatalf("%+v", rf)
		}
	})
	t.Run("a conversion without terrain is refused, never passed", func(t *testing.T) {
		for name, dt := range map[string]Datums{"no terrain": {}, "unknown ground": {Ground: &fakeGround{}}} {
			rf := refusalOf(t, func() error { _, err := Place(ctx, agl(100), amslAirspace, tx, dt); return err }())
			if rf.Status != 503 || rf.Slug != SlugTerrainUnavailable || rf.RetryAfter == 0 || !strings.Contains(rf.Detail, "ANSP_TERRAIN_DIR") {
				t.Fatalf("%s: %+v", name, rf)
			}
		}
		_, err := Place(ctx, agl(100), amslAirspace, tx, Datums{Ground: &fakeGround{err: core.Fieldf("bbox", "holds more than 5 samples")}})
		if rf := refusalOf(t, err); rf.Status != 400 || !hasField(rf, "geometry", "too large") {
			t.Fatalf("%+v", rf)
		}
	})
	t.Run("AMSL in a WGS84 airspace takes the greatest undulation for the airspace", func(t *testing.T) {
		// 1000 m HAE less at most 11.64 m: 988.36 m AMSL at its lowest.
		if _, err := Place(ctx, amsl(988), wgsAirspace, tx, Datums{Geoid: gridGeoid{}}); err != nil {
			t.Fatal(err)
		}
		if _, err := Place(ctx, amsl(989), wgsAirspace, tx, Datums{Geoid: gridGeoid{}}); refusalOf(t, err).Slug != SlugInvalid {
			t.Fatalf("989 m AMSL accepted under 988.36: %v", err)
		}
		rf := refusalOf(t, func() error { _, err := Place(ctx, amsl(900), wgsAirspace, tx, Datums{}); return err }())
		if rf.Status != 503 || rf.Slug != SlugGeoidUnavailable {
			t.Fatalf("%+v", rf)
		}
	})
	t.Run("an airspace limit in an unknown reference is a mismatch", func(t *testing.T) {
		odd := uspaceFeature("GEOTU01", 120, "QNH")
		rf := refusalOf(t, func() error {
			_, err := Place(ctx, agl(100), Snapshot{Airspaces: []ed318.Feature{odd}}, tx, Datums{Ground: hills()})
			return err
		}())
		if rf.Slug != SlugReferenceMismatch || !hasField(rf, "upper_ref", "QNH") {
			t.Fatalf("%+v", rf)
		}
	})
}

// The service end to end: an AGL restriction in an AGL U-space airspace
// is planned, activated and published with its AGL feature and its
// absolute constraint; without terrain it is placed (AGL against AGL
// needs none) but refused 503 at the constraint, counted, and an end
// still succeeds without one.
func TestServiceAGLRestriction(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.Ground = hills()
	f.svc.Airspaces = staticAirspaces{snap: Snapshot{Version: "44", FetchedAt: t0, Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 120, RefAGL)}}}
	in := input(t0, t0.Add(time.Hour))
	in.LowerRef, in.UpperM, in.UpperRef = RefAGL, 100, RefAGL
	r, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "rescue helicopter on scene", nil); err != nil || r.State != StateActive {
		t.Fatalf("%+v %v", r, err)
	}
	feat, probs := ed318.Parse(collection(r.Feature), ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	layer := feat.Features[0].Geometry.Layer
	if layer.LowerReference != RefAGL || layer.UpperReference != RefAGL || *layer.Upper != 100 {
		t.Fatalf("%+v", layer)
	}
	var sc StoredConstraint
	if err := json.Unmarshal(r.Constraint, &sc); err != nil {
		t.Fatal(err)
	}
	if v := sc.Details.Volumes[0].Volume; !near(v.AltitudeLower.Value, 500+11.56) || !near(v.AltitudeUpper.Value, 900+11.64) || *sc.Derivation.UpperGroundM != 800 {
		t.Fatalf("%+v %+v", v, sc.Derivation)
	}
	if got := f.bus.subjects(); len(got) != 2 || got[1] != "restr.v1.active" {
		t.Fatalf("%v", got)
	}

	f.svc.Ground = nil
	_, _, err = f.svc.Plan(ctx, supervisor, in, PlanOptions{})
	if rf := refusalOf(t, err); rf.Status != 503 || rf.Slug != SlugTerrainUnavailable {
		t.Fatalf("%+v", rf)
	}
	if f.svc.Counters().Get(CounterTerrainUnavailable) != 1 {
		t.Fatal(f.svc.Counters().Snapshot())
	}
	ended, err := f.svc.Apply(ctx, supervisor, r.ID, OpEnd, "rescue completed", nil)
	if err != nil || ended.State != StateEnded || ended.Constraint != nil {
		t.Fatalf("end without terrain: %+v %v", ended, err)
	}
}

// The blocker of review: limits in different references are ordered
// everywhere under the restriction, as AMSL over the area, the lower at
// its highest and the upper at its lowest. Over 500..800 m ground, a
// floor of 0 m AGL reaches 800 m AMSL: an upper limit of 900 m AMSL is
// above it everywhere (presence), 700 m AMSL is below it over the hill
// (refused, never widened into a volume that hides the inversion). An
// AMSL floor over an AGL ceiling likewise; a WGS84 ceiling against an
// AMSL floor through the geoid; and an empty W84 volume.
func TestVolumesOrderedEverywhere(t *testing.T) {
	dt := Datums{Geoid: gridGeoid{}, Ground: hills()}
	mixed := func(lower float64, lowerRef core.VerticalRef, upper float64, upperRef core.VerticalRef) Restriction {
		r := sample()
		r.LowerM, r.LowerRef, r.UpperM, r.UpperRef = lower, lowerRef, upper, upperRef
		return r
	}
	for name, tc := range map[string]struct {
		r      Restriction
		reason string // "" accepted
	}{
		"AGL floor under an AMSL ceiling everywhere":  {mixed(0, RefAGL, 900, RefAMSL), ""},
		"AGL floor above an AMSL ceiling on the hill": {mixed(0, RefAGL, 700, RefAMSL), "reaches 800.0 m AMSL"},
		"AMSL floor under an AGL ceiling everywhere":  {mixed(550, RefAMSL, 100, RefAGL), ""},
		"AMSL floor above an AGL ceiling in the low":  {mixed(650, RefAMSL, 100, RefAGL), "falls to 600.0 m AMSL"},
		"WGS84 ceiling above an AMSL floor":           {mixed(100, RefAMSL, 120, RefWGS84), ""},
		"WGS84 ceiling below an AMSL floor":           {mixed(100, RefAMSL, 105, RefWGS84), "falls to 93.4 m AMSL"},
		"an empty volume (Validate bypassed)":         {mixed(100, RefWGS84, 100, RefWGS84), "inverted or empty"},
	} {
		vs, _, err := Volumes(tc.r, dt)
		if tc.reason == "" {
			if err != nil || !(vs[0].Volume.AltitudeLower.Value < vs[0].Volume.AltitudeUpper.Value) {
				t.Errorf("%s: %v %+v", name, err, vs)
			}
			continue
		}
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != "upper_m" || !strings.Contains(fe.Reason, tc.reason) {
			t.Errorf("%s: %v, want upper_m %q", name, err, tc.reason)
		}
	}
	// The ordering needs the datum it converts with: fail closed.
	if _, _, err := Volumes(mixed(0, RefAGL, 900, RefAMSL), Datums{Geoid: gridGeoid{}}); !errors.Is(err, ErrTerrainUnavailable) {
		t.Fatalf("without terrain: %v", err)
	}
}

// The service refuses the inverted plan 400 on upper_m, and stores
// nothing.
func TestServiceRefusesAnInvertedMixedRestriction(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.Ground = hills()
	in := input(t0, t0.Add(time.Hour))
	in.LowerM, in.LowerRef, in.UpperM, in.UpperRef = 0, RefAGL, 700, RefAMSL
	_, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{})
	if rf := refusalOf(t, err); rf.Status != 400 || rf.Slug != SlugInvalid || !hasField(rf, "upper_m", "not above lower_m") {
		t.Fatalf("%+v", rf)
	}
	if got := f.bus.subjects(); len(got) != 0 {
		t.Fatalf("published %v", got)
	}
	in.UpperM = 900
	if _, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{}); err != nil {
		t.Fatalf("ordered everywhere: %v", err)
	}
}
