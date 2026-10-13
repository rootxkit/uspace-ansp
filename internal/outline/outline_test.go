package outline

import (
	"errors"
	"math"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
)

// tbilisi is a test centre, not a configured place.
var tbilisi = core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}

func TestCircleIsClosedCounterclockwiseOnTheGeodesicCircle(t *testing.T) {
	const radiusM = 1500.0
	ring, err := Circle(tbilisi, radiusM)
	if err != nil {
		t.Fatal(err)
	}
	if len(ring) != Vertices+1 {
		t.Fatalf("got %d positions, want %d (closed)", len(ring), Vertices+1)
	}
	if ring[0] != ring[len(ring)-1] {
		t.Fatalf("ring is not closed: %v vs %v", ring[0], ring[len(ring)-1])
	}
	// Every vertex at the radius by core's inverse solver, to the
	// rounding of the written position (1e-8 degree, about a millimetre).
	for i, p := range ring[:Vertices] {
		d, err := geodesy.DistanceM(tbilisi, core.LatLon{LatDeg: p[1], LonDeg: p[0]})
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(d-radiusM) > 0.01 {
			t.Fatalf("vertex %d is %v m from the centre, want %v", i, d, radiusM)
		}
	}
	// Due north first, then west of the centre: counterclockwise.
	if ring[0][1] <= tbilisi.LatDeg || math.Abs(ring[0][0]-tbilisi.LonDeg) > 1e-7 {
		t.Fatalf("first vertex %v is not due north of the centre", ring[0])
	}
	if ring[1][0] >= tbilisi.LonDeg {
		t.Fatalf("second vertex %v is not west of the centre", ring[1])
	}
	area := 0.0
	for i := range Vertices {
		a, b := ring[i], ring[i+1]
		area += a[0]*b[1] - b[0]*a[1]
	}
	if area <= 0 {
		t.Fatalf("signed area %v: the ring is clockwise", area)
	}
}

func TestCircleAcceptsTheBounds(t *testing.T) {
	for _, c := range []struct {
		name    string
		centre  core.LatLon
		radiusM float64
	}{
		{"largest radius", tbilisi, MaxRadiusM},
		{"smallest radius", tbilisi, 0.001},
		{"north bound", core.LatLon{LatDeg: MaxAbsLatDeg, LonDeg: 0}, 1000},
		{"antimeridian", core.LatLon{LatDeg: 0, LonDeg: 180}, 1000},
	} {
		if _, err := Circle(c.centre, c.radiusM); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestCircleRefusesOutOfBoundsNamingTheField(t *testing.T) {
	for _, c := range []struct {
		name    string
		centre  core.LatLon
		radiusM float64
		field   string
	}{
		{"zero radius", tbilisi, 0, "radius_m"},
		{"negative radius", tbilisi, -1, "radius_m"},
		{"radius past the bound", tbilisi, MaxRadiusM + 1, "radius_m"},
		{"NaN radius", tbilisi, math.NaN(), "radius_m"},
		{"infinite radius", tbilisi, math.Inf(1), "radius_m"},
		{"past 89 degrees", core.LatLon{LatDeg: 89.5, LonDeg: 0}, 1000, "lat"},
		{"NaN latitude", core.LatLon{LatDeg: math.NaN(), LonDeg: 0}, 1000, "lat"},
		{"longitude past 180", core.LatLon{LatDeg: 0, LonDeg: 180.5}, 1000, "lng"},
	} {
		ring, err := Circle(c.centre, c.radiusM)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != c.field {
			t.Errorf("%s: got %v (%v), want a field error on %s", c.name, err, ring, c.field)
		}
	}
}
