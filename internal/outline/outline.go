// Package outline draws a circle as a polygon a map can render: the
// outline the console's restriction editor shows while a circle is
// planned (GET /v1/outlines/circle; uspace-ui DrawLayer's circleOutline).
//
// It is a drawing, never a judgement: a restriction is validated, stored,
// published and judged as its centre and radius (internal/restriction
// ParseShape, uspace-core), and nothing in the ANSP tests a position
// against the outline. Every vertex is placed on the geodesic circle by
// uspace-core's direct solver, geodesy.Destination (Vincenty on WGS84):
// the ANSP solves nothing itself, and web/ does no geodesy at all.
//
// Pure: no I/O, no logging, no global state.
package outline

import (
	"errors"
	"fmt"
	"math"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geodesy"
)

// Vertices is the number of distinct vertices of a drawn circle. A
// display resolution, not a threshold: at 64 the chord between two
// vertices lies within 0.12 % of the radius inside the circle.
const Vertices = 64

const (
	// MaxRadiusM is the largest radius drawn: the restriction editor's
	// own bound (ed318.MaxCircleRadiusM, internal/restriction ParseShape).
	MaxRadiusM = ed318.MaxCircleRadiusM
	// MaxAbsLatDeg keeps the centre off the poles, where the outline's
	// azimuths lose their meaning.
	MaxAbsLatDeg = 89
	// decimals is the precision of a written position: 1e-8 degree,
	// about a millimetre.
	decimals = 1e8
)

// ErrNotDrawable is returned when core's solver gives no valid position
// for a vertex; the circle is then not drawn, never guessed.
var ErrNotDrawable = errors.New("outline: a vertex has no valid position")

// Circle is the closed ring of Vertices vertices on the geodesic circle
// about centre, as GeoJSON positions [lng, lat]: counterclockwise
// (RFC 7946 section 3.1.6), starting due north, the last position equal
// to the first. A centre or radius out of bounds is a *core.FieldError
// naming lat, lng or radius_m, checked before anything is computed.
func Circle(centre core.LatLon, radiusM float64) ([][2]float64, error) {
	switch {
	case math.IsNaN(centre.LatDeg) || math.IsInf(centre.LatDeg, 0) || math.Abs(centre.LatDeg) > MaxAbsLatDeg:
		return nil, core.Fieldf("lat", "must be a number within %v degrees of the equator", float64(MaxAbsLatDeg))
	case math.IsNaN(centre.LonDeg) || math.IsInf(centre.LonDeg, 0) || math.Abs(centre.LonDeg) > 180:
		return nil, core.Fieldf("lng", "must be a number from -180 to 180")
	case math.IsNaN(radiusM) || math.IsInf(radiusM, 0) || radiusM <= 0 || radiusM > MaxRadiusM:
		return nil, core.Fieldf("radius_m", "must be above 0 and at most %d m", MaxRadiusM)
	}
	ring := make([][2]float64, 0, Vertices+1)
	for k := range Vertices {
		// Counterclockwise: azimuths decrease from north through west.
		azDeg := math.Mod(360-360*float64(k)/float64(Vertices), 360)
		p := geodesy.Destination(centre, azDeg, radiusM)
		if !p.Valid() {
			return nil, fmt.Errorf("%w (azimuth %v)", ErrNotDrawable, azDeg)
		}
		ring = append(ring, [2]float64{math.Round(p.LonDeg*decimals) / decimals, math.Round(p.LatDeg*decimals) / decimals})
	}
	return append(ring, ring[0]), nil
}
