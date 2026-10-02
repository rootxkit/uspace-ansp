package restriction

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

func fieldIn(errs []*core.FieldError, field, reason string) bool {
	for _, e := range errs {
		if e.Field == field && strings.Contains(e.Reason, reason) {
			return true
		}
	}
	return false
}

// Each rule: the accepted input (presence), then one refusal per rule
// with its field and reason, everything reported, nothing repaired.
func TestValidateRules(t *testing.T) {
	ok := input(t0, t0.Add(4*time.Hour))
	if chain, errs := Validate(ok, t0); len(errs) != 0 || chain != nil {
		t.Fatalf("accepted input refused: %v", errs)
	}
	for _, tc := range []struct {
		name          string
		mutate        func(*Input)
		field, reason string
	}{
		{"AGL lower, the D3 text", func(in *Input) { in.LowerRef = core.RefAGL }, "lower_ref", ReasonAGL},
		{"AGL upper", func(in *Input) { in.UpperRef = core.RefAGL }, "upper_ref", ReasonAGL},
		{"a limit without its reference (D-01)", func(in *Input) { in.UpperRef = "" }, "upper_ref", "without its reference"},
		{"an unknown reference", func(in *Input) { in.LowerRef = "QNH" }, "lower_ref", "not AMSL or WGS84"},
		{"lower not below upper", func(in *Input) { in.LowerM = 120 }, "upper_m", "not above lower_m"},
		{"a limit not finite", func(in *Input) { in.UpperM = inf() }, "upper_m", "finite"},
		{"lower not finite", func(in *Input) { in.LowerM = inf() }, "lower_m", "finite"},
		{"zone type", func(in *Input) { in.ZoneType = "CONDITIONAL" }, "zone_type", "PROHIBITED or REQ_AUTHORIZATION"},
		{"no reason", func(in *Input) { in.ReasonText = "  " }, "reason_text", "required"},
		{"reason over 200", func(in *Input) { in.ReasonText = strings.Repeat("x", 201) }, "reason_text", "at most 200"},
		{"ends before it starts", func(in *Input) { in.EndsAt = in.StartsAt }, "ends_at", "not after starts_at"},
		{"starts in the past", func(in *Input) { in.StartsAt = t0.Add(-2 * time.Minute) }, "starts_at", "in the past"},
		{"beyond the planning horizon", func(in *Input) { in.StartsAt = t0.Add(57 * 24 * time.Hour); in.EndsAt = in.StartsAt.Add(time.Hour) }, "starts_at", "CstrMaxPlanningHorizonDays"},
		{"ended already", func(in *Input) { in.StartsAt = t0.Add(-30 * time.Second); in.EndsAt = t0.Add(-time.Second) }, "ends_at", "not after now"},
		{"no start", func(in *Input) { in.StartsAt = time.Time{} }, "starts_at", "required"},
		{"no end", func(in *Input) { in.EndsAt = time.Time{} }, "ends_at", "required"},
		{"no geometry", func(in *Input) { in.Shape = Shape{} }, "geometry", "required"},
		{"across the antimeridian", func(in *Input) {
			in.Shape = Shape{Ring: []core.LatLon{{LatDeg: 0, LonDeg: 179.9}, {LatDeg: 0, LonDeg: -179.9}, {LatDeg: 0.1, LonDeg: -179.9}, {LatDeg: 0.1, LonDeg: 179.9}, {LatDeg: 0, LonDeg: 179.9}}}
		}, "geometry", "antimeridian"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := ok
			tc.mutate(&in)
			_, errs := Validate(in, t0)
			if !fieldIn(errs, tc.field, tc.reason) {
				t.Fatalf("want %s %q in %v", tc.field, tc.reason, errs)
			}
		})
	}
	// Every problem reported at once.
	bad := ok
	bad.LowerRef, bad.UpperRef, bad.ReasonText, bad.ZoneType = core.RefAGL, "", "", "USPACE"
	if _, errs := Validate(bad, t0); len(errs) < 4 {
		t.Fatalf("not all reported: %v", errs)
	}
	// The start lead: a start up to 60 s back is accepted.
	lead := ok
	lead.StartsAt = t0.Add(-StartLead)
	if _, errs := Validate(lead, t0); len(errs) != 0 {
		t.Fatalf("start within the lead: %v", errs)
	}
}

func inf() float64 {
	var z float64
	return 1 / z
}

// 30 h is a chain proposal of 24 h + 6 h, not a refusal; a chain whose
// re-issue would start beyond the horizon is refused.
func TestValidateChain(t *testing.T) {
	chain, errs := Validate(input(t0, t0.Add(30*time.Hour)), t0)
	if len(errs) != 0 || len(chain) != 2 || !chain[0].EndsAt.Equal(t0.Add(24*time.Hour)) || !chain[1].StartsAt.Equal(chain[0].EndsAt) || !chain[1].EndsAt.Equal(t0.Add(30*time.Hour)) {
		t.Fatalf("%v %v", chain, errs)
	}
	if exact, errs := Validate(input(t0, t0.Add(24*time.Hour)), t0); exact != nil || errs != nil {
		t.Fatalf("24 h is one restriction: %v %v", exact, errs)
	}
	start := t0.Add(55 * 24 * time.Hour)
	if _, errs := Validate(input(start, start.Add(72*time.Hour)), t0); !fieldIn(errs, "ends_at", "re-issue") {
		t.Fatalf("chain past the horizon: %v", errs)
	}
	if got := Chain(t0, t0.Add(48*time.Hour)); len(got) != 2 {
		t.Fatalf("48 h: %v", got)
	}
	if w := (Window{StartsAt: t0, EndsAt: t0.Add(time.Hour)}).String(); w != "2026-10-02T12:00:00.000Z to 2026-10-02T13:00:00.000Z" {
		t.Fatal(w)
	}
}

func ring(n int) string {
	pts := make([]string, 0, n+1)
	for i := range n {
		// A circle of n vertices around (44.8, 41.7), about 1 km.
		a := 2 * math.Pi * float64(i) / float64(n)
		pts = append(pts, fmt.Sprintf("[%.7f,%.7f]", 44.8+0.01*math.Cos(a), 41.7+0.01*math.Sin(a)))
	}
	pts = append(pts, pts[0])
	return `{"type":"Polygon","coordinates":[[` + strings.Join(pts, ",") + `]]}`
}

// The geometry as the API takes it: 1000 vertices accepted, 1001 refused
// (E-10, CstrMaxVertices), holes and open rings refused, a circle needs
// its radius.
func TestParseShape(t *testing.T) {
	if s, errs := ParseShape(json.RawMessage(ring(1000)), nil); len(errs) != 0 || len(s.Ring) != 1001 {
		t.Fatalf("1000 vertices: %v", errs)
	}
	r := 500.0
	neg := -1.0
	huge := 2e6
	for _, tc := range []struct {
		name, geom    string
		radius        *float64
		field, reason string
	}{
		{"1001 vertices", ring(1001), nil, "geometry.coordinates[0]", "CstrMaxVertices"},
		{"a hole", `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.6]],[[44.8,41.65],[44.85,41.65],[44.85,41.7],[44.8,41.65]]]}`, nil, "geometry.coordinates", "no holes"},
		{"no ring", `{"type":"Polygon","coordinates":[]}`, nil, "geometry.coordinates", "no ring"},
		{"open ring", `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.7]]]}`, nil, "geometry.coordinates[0]", "not closed"},
		{"three positions", `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.7,41.6]]]}`, nil, "geometry.coordinates[0]", "at least 4"},
		{"a bad position", `{"type":"Polygon","coordinates":[[[44.7],[44.9,41.6],[44.9,41.8],[44.7,41.6]]]}`, nil, "geometry.coordinates[0][0]", "[lng, lat]"},
		{"out of range", `{"type":"Polygon","coordinates":[[[44.7,91],[44.9,41.6],[44.9,41.8],[44.7,91]]]}`, nil, "geometry.coordinates[0][0]", "valid WGS84"},
		{"radius on a polygon", `{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.6]]]}`, &r, "radius_m", "belongs to a Point"},
		{"not rings", `{"type":"Polygon","coordinates":"x"}`, nil, "geometry.coordinates", "list of rings"},
		{"point without radius", `{"type":"Point","coordinates":[44.8,41.7]}`, nil, "radius_m", "required"},
		{"negative radius", `{"type":"Point","coordinates":[44.8,41.7]}`, &neg, "radius_m", "positive"},
		{"huge radius", `{"type":"Point","coordinates":[44.8,41.7]}`, &huge, "radius_m", "more than"},
		{"point out of range", `{"type":"Point","coordinates":[200,41.7]}`, &r, "geometry.coordinates", "valid WGS84"},
		{"point not a position", `{"type":"Point","coordinates":[1]}`, &r, "geometry.coordinates", "[lng, lat]"},
		{"a line", `{"type":"LineString","coordinates":[[1,2],[3,4]]}`, nil, "geometry.type", "not Polygon or Point"},
		{"an unknown member", `{"type":"Point","coordinates":[44.8,41.7],"crs":"x"}`, &r, "geometry", "not a GeoJSON"},
		{"null", `null`, nil, "geometry", "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := ParseShape(json.RawMessage(tc.geom), tc.radius)
			if !fieldIn(errs, tc.field, tc.reason) {
				t.Fatalf("want %s %q in %v", tc.field, tc.reason, errs)
			}
		})
	}
	if s, errs := ParseShape(json.RawMessage(`{"type":"Point","coordinates":[44.8,41.7]}`), &r); len(errs) != 0 || !s.IsCircle() || s.RadiusM != 500 {
		t.Fatalf("circle: %v", errs)
	}
}

const createBody = `{"uspace_airspace_id":"GEOTU01","zone_type":"PROHIBITED","geometry":{"type":"Polygon","coordinates":[[[44.78,41.70],[44.82,41.70],[44.82,41.73],[44.78,41.73],[44.78,41.70]]]},"lower_m":0,"lower_ref":"AMSL","upper_m":120,"upper_ref":"AMSL","starts_at":"2026-10-02T12:00:00.000Z","ends_at":"2026-10-02T16:00:00.000Z","reason_text":"Search and rescue (synthetic)"}`

// The bodies are closed: an unknown or misspelt member is refused by
// name, never read as absent; each kind refuses the other's members.
func TestDecodeArea(t *testing.T) {
	b, in, errs := DecodeArea([]byte(createBody), BodyCreate)
	if len(errs) != 0 || in.UspaceAirspaceID != "GEOTU01" || in.ZoneType != core.ZoneProhibited || !in.StartsAt.Equal(t0) || b.ConfirmChain != nil {
		t.Fatalf("%+v %v", in, errs)
	}
	if _, errs := Validate(in, t0); len(errs) != 0 {
		t.Fatalf("decoded body refused: %v", errs)
	}
	for _, tc := range []struct {
		name, body, kind, field, reason string
	}{
		{"misspelt ends_at", strings.Replace(createBody, `"ends_at"`, `"end_at"`, 1), BodyCreate, "end_at", "not a member"},
		{"trailing content", createBody + `{}`, BodyCreate, "body", "after the JSON object"},
		{"not JSON", `{`, BodyCreate, "body", "not the JSON object"},
		{"wrong type", strings.Replace(createBody, `"lower_m":0`, `"lower_m":"0"`, 1), BodyCreate, "lower_m", "type"},
		{"no airspace on a create", strings.Replace(createBody, `"uspace_airspace_id":"GEOTU01",`, ``, 1), BodyCreate, "uspace_airspace_id", "required"},
		{"a long airspace id", strings.Replace(createBody, `GEOTU01`, `GEOTU0123`, 1), BodyCreate, "uspace_airspace_id", "1 to 7"},
		{"client_ref on a create", strings.Replace(createBody, `{`, `{"client_ref":"x",`, 1), BodyCreate, "client_ref", "Idempotency-Key"},
		{"case_ref on a create", strings.Replace(createBody, `{`, `{"case_ref":"x",`, 1), BodyCreate, "case_ref", "request"},
		{"zone_type on a request", strings.Replace(createBody, `{`, `{"client_ref":"x",`, 1), BodyRequest, "zone_type", "supervisor"},
		{"no client_ref", createBody, BodyRequest, "client_ref", "required"},
		{"confirm_chain on a request", strings.Replace(createBody, `"zone_type":"PROHIBITED",`, `"client_ref":"x","confirm_chain":true,`, 1), BodyRequest, "confirm_chain", "supervisor"},
		{"a long client_ref", strings.Replace(createBody, `"zone_type":"PROHIBITED",`, `"client_ref":"`+strings.Repeat("r", 129)+`",`, 1), BodyRequest, "client_ref", "longer"},
		{"a long case_ref", strings.Replace(createBody, `"zone_type":"PROHIBITED",`, `"client_ref":"r","case_ref":"`+strings.Repeat("c", 129)+`",`, 1), BodyRequest, "case_ref", "longer"},
		{"no lower_m", strings.Replace(createBody, `"lower_m":0,`, ``, 1), BodyCreate, "lower_m", "required"},
		{"no offset", strings.Replace(createBody, `12:00:00.000Z`, `12:00:00.000`, 1), BodyCreate, "starts_at", "offset"},
		{"microseconds", strings.Replace(createBody, `12:00:00.000Z`, `12:00:00.000001Z`, 1), BodyCreate, "starts_at", "millisecond"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, errs := DecodeArea([]byte(tc.body), tc.kind)
			if !fieldIn(errs, tc.field, tc.reason) {
				t.Fatalf("want %s %q in %v", tc.field, tc.reason, errs)
			}
		})
	}
	req := strings.Replace(createBody, `"zone_type":"PROHIBITED",`, `"client_ref":"GCAA-1","case_ref":"EVT-1",`, 1)
	if b, _, errs := DecodeArea([]byte(req), BodyRequest); len(errs) != 0 || *b.ClientRef != "GCAA-1" {
		t.Fatalf("request: %v", errs)
	}
	long := `{"` + strings.Repeat("k", 200) + `":1}`
	if _, _, errs := DecodeArea([]byte(long), BodyCreate); len(errs[0].Field) > 64 {
		t.Fatal("an unknown member echoed whole")
	}
}

func TestDecodeReason(t *testing.T) {
	if b, errs := DecodeReason([]byte(`{"reason":"rescue completed"}`), true, false, false); len(errs) != 0 || b.ReasonOr("x") != "rescue completed" {
		t.Fatal(errs)
	}
	if b, errs := DecodeReason(nil, false, false, false); len(errs) != 0 || b.ReasonOr("default") != "default" {
		t.Fatal(errs)
	}
	b, errs := DecodeReason([]byte(`{"ends_at":"2026-10-02T18:00:00.000Z","reason":"longer"}`), true, true, false)
	end, eerrs := b.EndOf()
	if len(errs) != 0 || len(eerrs) != 0 || !end.Equal(t0.Add(6*time.Hour)) {
		t.Fatal(errs, eerrs)
	}
	for _, tc := range []struct {
		body                        string
		required, allowEnd, allowZT bool
		field                       string
	}{
		{``, true, false, false, "reason"},
		{`{"reason":" "}`, true, false, false, "reason"},
		{`{"reason":"` + strings.Repeat("x", 501) + `"}`, true, false, false, "reason"},
		{`{"reason":"x","ends_at":"2026-10-02T18:00:00.000Z"}`, true, false, false, "ends_at"},
		{`{"reason":"x"}`, true, true, false, "ends_at"},
		{`{"reason":"x","zone_type":"PROHIBITED"}`, true, false, false, "zone_type"},
		{`{"reason":"x","colour":1}`, true, false, false, "colour"},
		{`{"reason":"x"} []`, true, false, false, "body"},
		{`[`, true, false, false, "body"},
	} {
		if _, errs := DecodeReason([]byte(tc.body), tc.required, tc.allowEnd, tc.allowZT); !fieldIn(errs, tc.field, "") {
			t.Fatalf("%s: want %s in %v", tc.body, tc.field, errs)
		}
	}
	if _, errs := DecodeReason([]byte(`{"reason":"x","zone_type":"PROHIBITED"}`), false, false, true); len(errs) != 0 {
		t.Fatal(errs)
	}
}

// Placement in the fixture U-space airspace (44.6..45.0 E, 41.6..41.9 N,
// up to 1500 m AMSL): inside accepted; partly outside, nowhere, an
// unknown id refused with the M9 reason; upper above the airspace's
// refused; a different reference is reference_mismatch; with no id the
// one covering airspace is inferred, several must be chosen.
func TestPlace(t *testing.T) {
	ctx := context.Background()
	m := newMemRepo(t0)
	snap := Snapshot{Version: "42", Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefAMSL)}}
	tx := memTx{m}
	in := input(t0, t0.Add(time.Hour))
	if id, err := Place(ctx, in, snap, tx); err != nil || id != "GEOTU01" {
		t.Fatalf("inside: %v %v", id, err)
	}
	partly := in
	partly.Shape = Shape{Ring: []core.LatLon{{LatDeg: 41.85, LonDeg: 44.95}, {LatDeg: 41.85, LonDeg: 45.05}, {LatDeg: 41.88, LonDeg: 45.05}, {LatDeg: 41.88, LonDeg: 44.95}, {LatDeg: 41.85, LonDeg: 44.95}}}
	_, err := Place(ctx, partly, snap, tx)
	if rf := refusalOf(t, err); rf.Slug != SlugOutsideUSpace || !hasField(rf, "geometry", "partly outside") {
		t.Fatalf("partly: %+v", rf)
	}
	away := in
	away.Shape = Shape{Ring: []core.LatLon{{LatDeg: 42.5, LonDeg: 43.0}, {LatDeg: 42.5, LonDeg: 43.1}, {LatDeg: 42.6, LonDeg: 43.1}, {LatDeg: 42.5, LonDeg: 43.0}}}
	_, err = Place(ctx, away, snap, tx)
	if rf := refusalOf(t, err); rf.Slug != SlugOutsideUSpace || !hasField(rf, "geometry", "intersects no current USPACE feature") || !strings.Contains(rf.Detail, "M9") {
		t.Fatalf("away: %+v", rf)
	}
	unknown := in
	unknown.UspaceAirspaceID = "GEOXX99"
	if rf := refusalOf(t, func() error { _, err := Place(ctx, unknown, snap, tx); return err }()); !hasField(rf, "uspace_airspace_id", "not a current USPACE feature") {
		t.Fatalf("unknown: %+v", rf)
	}
	high := in
	high.UpperM = 1600
	if rf := refusalOf(t, func() error { _, err := Place(ctx, high, snap, tx); return err }()); rf.Slug != SlugInvalid || !hasField(rf, "upper_m", "above the U-space airspace's upper limit") {
		t.Fatalf("high: %+v", rf)
	}
	other := in
	other.UpperRef, other.LowerRef = RefWGS84, RefWGS84
	if rf := refusalOf(t, func() error { _, err := Place(ctx, other, snap, tx); return err }()); rf.Slug != SlugReferenceMismatch || !hasField(rf, "upper_ref", "1500 m AMSL") {
		t.Fatalf("mismatch: %+v", rf)
	}
	inferred := in
	inferred.UspaceAirspaceID = ""
	if id, err := Place(ctx, inferred, snap, tx); err != nil || id != "GEOTU01" {
		t.Fatalf("inferred: %v %v", id, err)
	}
	two := Snapshot{Version: "43", Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefAMSL), uspaceFeature("GEOTU02", 1500, RefAMSL)}}
	if rf := refusalOf(t, func() error { _, err := Place(ctx, inferred, two, tx); return err }()); !hasField(rf, "uspace_airspace_id", "GEOTU01, GEOTU02") {
		t.Fatalf("two: %+v", rf)
	}
	// An unlimited airspace (no upper) admits any upper limit; feet are
	// converted for the comparison.
	unlimited := uspaceFeature("GEOTU01", 0, RefAMSL)
	unlimited.Geometry.Layer.Upper = nil
	if _, err := Place(ctx, high, Snapshot{Airspaces: []ed318.Feature{unlimited}}, tx); err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	feet := uspaceFeature("GEOTU01", 5000, RefAMSL)
	ft := ed318.UomFeet
	feet.Geometry.Layer.Uom = &ft
	if _, err := Place(ctx, high, Snapshot{Airspaces: []ed318.Feature{feet}}, tx); err == nil {
		t.Fatal("1600 m above 5000 ft (1524 m)")
	}
	// A non-USPACE feature never places a restriction.
	zone := uspaceFeature("GEOTU01", 1500, RefAMSL)
	zone.Properties.Type = core.ZoneProhibited
	if _, err := Place(ctx, in, Snapshot{Airspaces: []ed318.Feature{zone}}, tx); err == nil {
		t.Fatal("placed in a zone that is not U-space")
	}
}

// A U-space airspace published as layers (a GeometryCollection) and as a
// circle: its parts are measured each.
func TestAirspaceParts(t *testing.T) {
	f := uspaceFeature("GEOTU01", 1500, RefAMSL)
	layered := f
	layered.Geometry = ed318.Geometry{Type: ed318.GeometryCollection, Geometries: []ed318.Geometry{f.Geometry, f.Geometry}}
	parts, err := airspaceParts(&layered)
	if err != nil || len(parts) != 2 || *parts[1].UpperM != 1500 {
		t.Fatalf("%+v %v", parts, err)
	}
	c := core.LatLon{LatDeg: 41.7, LonDeg: 44.8}
	r := 5000.0
	circ := f
	circ.Geometry = ed318.Geometry{Type: ed318.GeometryPoint, Center: &c, RadiusM: &r}
	parts, err = airspaceParts(&circ)
	if err != nil || *parts[0].RadiusM != 5000 || parts[0].UpperM != nil || !strings.Contains(parts[0].GeoJSON, "Point") {
		t.Fatalf("%+v %v", parts, err)
	}
	circ.Geometry.RadiusM = nil
	if _, err := airspaceParts(&circ); err == nil {
		t.Fatal("a point without a radius")
	}
	circ.Geometry.Type = "LineString"
	if _, err := airspaceParts(&circ); err == nil {
		t.Fatal("a line")
	}
	if _, err := Place(context.Background(), Input{Shape: box(), UspaceAirspaceID: "GEOTU01"}, Snapshot{Airspaces: []ed318.Feature{circ}}, memTx{newMemRepo(t0)}); err == nil {
		t.Fatal("an airspace that cannot be measured")
	}
}
