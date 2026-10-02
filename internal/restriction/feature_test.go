package restriction

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"
)

func sample() Restriction {
	return Restriction{
		ID: "01K6P0A1B2C3D4E5F6G7H8J9KM", AnspRef: "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM", Identifier: "DAR7K2Q", UspaceAirspaceID: "GEOTU01",
		ZoneType: core.ZoneProhibited, Shape: box(), LowerM: 0, LowerRef: RefAMSL, UpperM: 120, UpperRef: RefAMSL,
		StartsAt: t0, EndsAt: t0.Add(4 * time.Hour), ReasonText: "Search and rescue (synthetic)", State: StatePlanned, AnspVersion: 1,
	}
}

var cfg = FeatureConfig{Country: "GEO", AuthorityName: "Test ANSP", AuthorityService: "Watch", AuthorityEmail: "watch@example.test", AuthorityPhone: "+995000000"}

// The feature's members are D4's, read back through ed318.Parse.
func TestFeatureMembers(t *testing.T) {
	f, err := Feature(sample(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := f.Properties
	if p.Identifier != "DAR7K2Q" || p.Country != "GEO" || p.Type != core.ZoneProhibited || p.Variant != VariantCommon ||
		len(p.Reason) != 1 || p.Reason[0] != ReasonDAR || *p.Message[0].Text != "Search and rescue (synthetic)" || p.Message[0].Lang != "en" ||
		*p.Name[0].Text != "Search and rescue (synthetic)" || len(p.ZoneAuthority) != 1 || p.ZoneAuthority[0].Purpose != PurposeInformation ||
		*p.ZoneAuthority[0].Email != "watch@example.test" {
		t.Fatalf("%+v", p)
	}
	tp := p.LimitedApplicability[0]
	if len(p.LimitedApplicability) != 1 || tp.StartDateTime.Text != "2026-10-02T12:00:00.000Z" || tp.EndDateTime.Text != "2026-10-02T16:00:00.000Z" {
		t.Fatalf("%+v", p.LimitedApplicability)
	}
	var ext map[string]string
	if err := json.Unmarshal(p.ExtendedProperties[ExtendedKey], &ext); err != nil || ext["ansp_ref"] != sample().AnspRef || ext["restriction_id"] != sample().ID || ext["uspace_airspace_id"] != "GEOTU01" || len(ext) != 3 {
		t.Fatalf("extended %v %v", ext, err)
	}
	l := f.Geometry.Layer
	if *l.Upper != 120 || l.UpperReference != RefAMSL || *l.Lower != 0 || l.LowerReference != RefAMSL || *l.Uom != "m" {
		t.Fatalf("layer %+v", l)
	}
}

// Export -> Parse -> Export is the identity (equal by value), and the
// exported bytes carry the member names of uspace-core/ed318.
func TestFeatureRoundTrip(t *testing.T) {
	for name, r := range map[string]Restriction{"polygon": sample(), "circle": circle()} {
		f, err := Feature(r, cfg)
		if err != nil {
			t.Fatal(name, err)
		}
		raw, err := CheckFeature(f)
		if err != nil {
			t.Fatal(name, err)
		}
		back, err := ParseFeature(raw)
		if err != nil {
			t.Fatal(name, err)
		}
		again, err := CheckFeature(back)
		if err != nil || !jsonEqual(t, raw, again) {
			t.Fatalf("%s: round trip differs:\n%s\n%s", name, raw, again)
		}
		for _, member := range []string{`"limitedApplicability"`, `"zoneAuthority"`, `"upperReference"`, `"lowerReference"`, `"uom":"m"`, `"reason":["DAR"]`, `"variant":"COMMON"`} {
			if !strings.Contains(string(raw), member) {
				t.Fatalf("%s: no %s in %s", name, member, raw)
			}
		}
	}
}

func circle() Restriction {
	r := sample()
	c := core.LatLon{LatDeg: 41.71, LonDeg: 44.80}
	r.Shape = Shape{Center: &c, RadiusM: 1500}
	r.LowerRef, r.UpperRef = RefWGS84, RefWGS84
	return r
}

// ed318.ToZones makes one zone of the feature whose containment agrees
// with the input: a point inside, a point outside (E-01 pair).
func TestFeatureToZonesContainment(t *testing.T) {
	for name, r := range map[string]Restriction{"polygon": sample(), "circle": circle()} {
		f, err := Feature(r, cfg)
		if err != nil {
			t.Fatal(err)
		}
		zs, err := ed318.ToZones(&ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{*f}}, nil)
		if err != nil || len(zs) != 1 {
			t.Fatalf("%s: %d %v", name, len(zs), err)
		}
		in, err := zs[0].ContainsHorizontally(core.LatLon{LatDeg: 41.715, LonDeg: 44.80})
		if err != nil || !in {
			t.Fatalf("%s inside: %v %v", name, in, err)
		}
		out, err := zs[0].ContainsHorizontally(core.LatLon{LatDeg: 41.80, LonDeg: 44.95})
		if err != nil || out {
			t.Fatalf("%s outside: %v %v", name, out, err)
		}
		if !zs[0].AppliesAt(t0.Add(time.Hour)) || zs[0].AppliesAt(t0.Add(5*time.Hour)) {
			t.Fatalf("%s window", name)
		}
	}
}

// WithEnd changes the period's endDateTime and nothing else: the CISP's
// extend rule (409 feature_changed otherwise).
func TestWithEndChangesOnlyTheEnd(t *testing.T) {
	f, _ := Feature(sample(), cfg)
	before, _ := CheckFeature(f)
	g, err := WithEnd(f, t0.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := CheckFeature(g)
	if jsonEqual(t, before, after) || !sameExceptEnd(t, before, after) {
		t.Fatalf("%s\n%s", before, after)
	}
	if !strings.Contains(string(after), `"endDateTime":"2026-10-02T18:00:00.000Z"`) {
		t.Fatalf("%s", after)
	}
	if f.Properties.LimitedApplicability[0].EndDateTime.Text != "2026-10-02T16:00:00.000Z" {
		t.Fatal("WithEnd changed its input")
	}
	if _, err := WithEnd(nil, t0); err == nil {
		t.Fatal("nil feature")
	}
}

// What the feature refuses: an identifier outside D4, no authority, and
// a shape ED-318 refuses (across the antimeridian).
func TestFeatureRefusals(t *testing.T) {
	r := sample()
	r.Identifier = "DAR-001"
	if _, err := Feature(r, cfg); err == nil || !strings.Contains(err.Error(), "DAR plus 4") {
		t.Fatalf("identifier: %v", err)
	}
	if _, err := Feature(sample(), FeatureConfig{Country: "GEO"}); err == nil || !strings.Contains(err.Error(), "ANSP_AUTHORITY_NAME") {
		t.Fatalf("authority: %v", err)
	}
	r = sample()
	r.Shape = Shape{Ring: []core.LatLon{{LatDeg: 0, LonDeg: 179.9}, {LatDeg: 0, LonDeg: -179.9}, {LatDeg: 0.1, LonDeg: -179.9}, {LatDeg: 0.1, LonDeg: 179.9}, {LatDeg: 0, LonDeg: 179.9}}}
	if _, err := Feature(r, cfg); err == nil || !strings.Contains(err.Error(), "geometry") {
		t.Fatalf("antimeridian: %v", err)
	}
	if _, err := ParseFeature(json.RawMessage(`{"type":"Feature"}`)); err == nil {
		t.Fatal("broken stored feature")
	}
	long := strings.Repeat("é", 250)
	r = sample()
	r.ReasonText = long
	f, err := Feature(r, cfg)
	if err != nil || len([]rune(*f.Properties.Message[0].Text)) != MaxTextChars {
		t.Fatalf("bounded text: %v", err)
	}
}

// The collection served to a pull_url carries core's metadata members
// issued and provider (M15), never creationDateTime or originator.
func TestFeatureCollection(t *testing.T) {
	f, _ := Feature(sample(), cfg)
	raw, _ := CheckFeature(f)
	out, err := FeatureCollection([]json.RawMessage{raw}, t0, "Test ANSP")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"issued":"2026-10-02T12:00:00.000Z"`) || !strings.Contains(s, `"provider"`) || strings.Contains(s, "creationDateTime") || strings.Contains(s, "originator") {
		t.Fatalf("%s", s)
	}
	if _, err := FeatureCollection([]json.RawMessage{json.RawMessage(`{}`)}, t0, "x"); err == nil {
		t.Fatal("a broken feature")
	}
}

// The identifier: DAR plus 4 base-36, 7 characters, unique over 10 000
// mints, the space bounded.
func TestIdentifier(t *testing.T) {
	seen := map[string]bool{}
	for n := range int64(10_000) {
		id, err := Identifier(n, 777)
		if err != nil || len(id) != 7 || !ValidIdentifier(id) || seen[id] {
			t.Fatalf("%d: %q %v", n, id, err)
		}
		seen[id] = true
	}
	a, _ := Identifier(0, 0)
	b, _ := Identifier(1, 0)
	if a == "DAR0000" && b == "DAR0001" {
		t.Fatal("consecutive")
	}
	for _, tc := range [][2]int64{{-1, 0}, {IdentifierSpace, 0}, {0, -1}, {0, IdentifierSpace}} {
		if _, err := Identifier(tc[0], tc[1]); err == nil {
			t.Fatalf("%v accepted", tc)
		}
	}
	last, err := Identifier(IdentifierSpace-1, IdentifierSpace-1)
	if err != nil || !ValidIdentifier(last) {
		t.Fatal(last, err)
	}
	for _, bad := range []string{"DAR-001", "DAR00000", "dar0000", "DARabcd", "XAR0000", "DAR000"} {
		if ValidIdentifier(bad) {
			t.Fatalf("%q valid", bad)
		}
	}
	u := NewULID(t0)
	if len(u) != 26 || u[0] > '7' || NewULID(t0) == u {
		t.Fatal(u)
	}
	if NewULID(time.Unix(-5, 0))[0] != '0' || NewULID(time.Unix(1<<50, 0))[0] != '7' {
		t.Fatal("clamped ULID")
	}
}

// The constraint: AMSL -> HAE with a fixture undulation that varies
// across the polygon (44.78..44.82 E: N 11.56..11.64 m): the lower limit
// with the minimum, the upper with the maximum; the derivation records
// both; W84, metres, RFC3339; one volume.
func TestVolumesAMSL(t *testing.T) {
	r := sample()
	r.LowerM, r.UpperM = 100, 300
	vs, d, err := Volumes(r, gridGeoid{})
	if err != nil || len(vs) != 1 {
		t.Fatal(err)
	}
	v := vs[0].Volume
	lo, hi := 11.56, 11.64
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	if !near(v.AltitudeLower.Value, 100+lo) || !near(v.AltitudeUpper.Value, 300+hi) || v.AltitudeLower.Reference != f3548.W84 || v.AltitudeUpper.Units != f3548.AltitudeUnitsM {
		t.Fatalf("%+v %+v", v.AltitudeLower, v.AltitudeUpper)
	}
	if !near(*d.LowerUndulationM, lo) || !near(*d.UpperUndulationM, hi) || !near(*d.UndulationMinM, lo) || !near(*d.UndulationMaxM, hi) || d.UndulationSamples != 5 {
		t.Fatalf("%v %v %v %v", *d.LowerUndulationM, *d.UpperUndulationM, *d.UndulationMinM, *d.UndulationMaxM)
	}
	if len(v.OutlinePolygon.Vertices) != 4 || v.OutlineCircle != nil || vs[0].TimeStart.Format != f3548.RFC3339 || !vs[0].TimeEnd.Value.Equal(r.EndsAt) {
		t.Fatalf("%+v", vs[0])
	}
}

// A WGS84 restriction passes through unchanged and needs no geoid; a
// circle keeps its centre and radius in metres.
func TestVolumesWGS84Circle(t *testing.T) {
	r := circle()
	vs, d, err := Volumes(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	v := vs[0].Volume
	if v.AltitudeLower.Value != 0 || v.AltitudeUpper.Value != 120 || v.OutlineCircle.Radius.Value != 1500 || v.OutlineCircle.Radius.Units != f3548.RadiusUnitsM ||
		v.OutlineCircle.Center.Lat != 41.71 || d.UndulationSamples != 0 {
		t.Fatalf("%+v %+v", v, d)
	}
	// A circle's AMSL limits take the undulations at its centre and box.
	r.LowerRef, r.UpperRef = RefAMSL, RefAMSL
	if _, d, err := Volumes(r, gridGeoid{}); err != nil || d.UndulationSamples != 5 || *d.UndulationMinM >= *d.UndulationMaxM {
		t.Fatalf("%+v %v", d, err)
	}
}

// Without a geoid (or one that cannot answer) an AMSL limit is refused
// and counted, never guessed; a reference outside D3 is refused.
func TestVolumesGeoidUnavailable(t *testing.T) {
	var c core.Counters
	f, _ := Feature(sample(), cfg)
	if _, err := Details(sample(), f, nil, &c); err != ErrGeoidUnavailable || c.Get(CounterGeoidUnavailable) != 1 { //nolint:errorlint // the sentinel itself
		t.Fatalf("%v %v", err, c.Snapshot())
	}
	if _, err := Details(sample(), f, gridGeoid{fail: true}, &c); err != ErrGeoidUnavailable || c.Get(CounterGeoidUnavailable) != 2 { //nolint:errorlint // the sentinel itself
		t.Fatal(err)
	}
	r := sample()
	r.LowerRef, r.UpperRef = core.RefAGL, core.RefAGL
	if _, _, err := Volumes(r, gridGeoid{}); err == nil {
		t.Fatal("AGL volume")
	}
	r = sample()
	r.Shape = Shape{Ring: []core.LatLon{{LatDeg: 1, LonDeg: 1}}}
	r.LowerRef, r.UpperRef = RefWGS84, RefWGS84
	if _, _, err := Volumes(r, nil); err == nil {
		t.Fatal("a one-vertex outline")
	}
	if _, _, _, err := undulationRange(Shape{}, gridGeoid{}); err == nil {
		t.Fatal("no points")
	}
}

// Details: type DAR, the volumes, and no geozone (ed318.ToED269 refuses
// a DAR: gap 16), counted and said in the derivation.
func TestDetailsGeozoneOmitted(t *testing.T) {
	var c core.Counters
	f, _ := Feature(sample(), cfg)
	sc, err := Details(sample(), f, gridGeoid{}, &c)
	if err != nil || *sc.Details.Type != ConstraintType || len(sc.Details.Volumes) != 1 || sc.Details.Geozone != nil {
		t.Fatalf("%+v %v", sc, err)
	}
	if c.Get(CounterGeozoneUnmapped) != 1 || !strings.Contains(sc.Derivation.GeozoneOmitted, "DAR") {
		t.Fatalf("%v %q", c.Snapshot(), sc.Derivation.GeozoneOmitted)
	}
	if _, err := geozone(nil); err == nil {
		t.Fatal("nil feature")
	}
}

// The presence pair of the omission: a feature ToED269 can map (reason
// other than DAR) becomes the geozone.
func TestGeozoneMapped(t *testing.T) {
	f, _ := Feature(sample(), cfg)
	g := *f
	g.Properties.Reason = []string{"EMERGENCY"}
	gz, err := geozone(&g)
	if err != nil || gz == nil || gz.Identifier != "DAR7K2Q" {
		t.Fatalf("%+v %v", gz, err)
	}
}

func BenchmarkFeature(b *testing.B) {
	r := sample()
	for b.Loop() {
		if _, err := Feature(r, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVolumes(b *testing.B) {
	r := sample()
	g := gridGeoid{}
	for b.Loop() {
		if _, _, err := Volumes(r, g); err != nil {
			b.Fatal(err)
		}
	}
}
