package restriction

import (
	"errors"
	"fmt"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/terrain"
)

// Ground bounds the ground elevation over a box: uspace-core's
// terrain.Store (ANSP_TERRAIN_DIR). A (nil, nil) answer is ground that
// is not known everywhere in the box (LESSONS D-04).
type Ground interface {
	RangeM(b geodesy.BBox, maxSamples int) (*terrain.Range, error)
}

// Datums are what turns a limit from one vertical reference into
// another (gap 3): the geoid for AMSL and WGS84, the ground for AGL.
// Either may be nil; a conversion that needs a missing one is refused,
// never guessed.
type Datums struct {
	Geoid  geoid.Undulator
	Ground Ground
}

// ErrTerrainUnavailable refuses a conversion of an AGL limit when the
// ground under the restriction is not known everywhere: no terrain is
// configured, a cell is outside its index, a tile cannot be read or a
// sample is NoData (503 terrain_unavailable). A volume made from a
// guessed ground could lie below it.
var ErrTerrainUnavailable = errors.New("terrain unavailable")

// CounterTerrainUnavailable counts an AGL limit that could not be made absolute
// because the ground under the restriction is not known.
const CounterTerrainUnavailable = "constraint_terrain_unavailable"

// TerrainMaxSamples bounds the DEM samples one restriction reads: core's
// default, about four times F3548's largest constraint at GLO-30.
const TerrainMaxSamples = terrain.DefaultMaxRangeSamples

// BBox is the box that holds s: a polygon's outer ring, or a box that
// holds the whole circle (core's, conservatively larger).
func (s Shape) BBox() geodesy.BBox {
	if s.IsCircle() {
		return geodesy.Circle{Center: *s.Center, RadiusM: s.RadiusM}.BBox()
	}
	return geodesy.Polygon{Rings: []geodesy.Ring{s.Ring}}.BBox()
}

// groundRange is the least and greatest ground over s's box. A box the
// terrain refuses (too many cells or samples, across the antimeridian)
// is a problem on geometry; ground that is not known is
// ErrTerrainUnavailable.
func groundRange(s Shape, g Ground) (*terrain.Range, error) {
	if g == nil {
		return nil, ErrTerrainUnavailable
	}
	r, err := g.RangeM(s.BBox(), TerrainMaxSamples)
	if err != nil {
		var fe *core.FieldError
		if errors.As(err, &fe) {
			return nil, core.Fieldf("geometry", "is too large for the ground under it to be read for an AGL limit (%s)", fe.Error())
		}
		return nil, fmt.Errorf("%w: %w", ErrTerrainUnavailable, err)
	}
	if r == nil || !core.IsFinite(r.MinM) || !core.IsFinite(r.MaxM) {
		return nil, ErrTerrainUnavailable
	}
	return r, nil
}

// envelope is the conversions of one restriction area, each read at most
// once: the undulation range over the outline and the ground range over
// its box.
type envelope struct {
	shape  Shape
	datums Datums

	undulationRead    bool
	undulationLo      float64
	undulationHi      float64
	undulationSamples int
	undulationErr     error

	ground    *terrain.Range
	groundErr error
	groundOK  bool
}

func (e *envelope) undulation() (lo, hi float64, err error) {
	if !e.undulationRead {
		e.undulationRead = true
		e.undulationLo, e.undulationHi, e.undulationSamples, e.undulationErr = undulationRange(e.shape, e.datums.Geoid)
	}
	return e.undulationLo, e.undulationHi, e.undulationErr
}

func (e *envelope) terrain() (*terrain.Range, error) {
	if !e.groundOK {
		e.groundOK = true
		e.ground, e.groundErr = groundRange(e.shape, e.datums.Ground)
	}
	return e.ground, e.groundErr
}

// amslBound is a limit of value v in ref as AMSL over the whole area:
// with high, the highest it reaches anywhere (an AGL limit over the
// highest ground, a WGS84 one over the lowest geoid); else the lowest.
// AGL becomes AMSL by the DEM (AMSL = AGL + ground, D-02); WGS84 by the
// geoid.
func (e *envelope) amslBound(v float64, ref core.VerticalRef, high bool) (float64, error) {
	switch ref {
	case RefAMSL:
		return v, nil
	case RefAGL:
		g, err := e.terrain()
		if err != nil {
			return 0, err
		}
		if high {
			return v + g.MaxM, nil
		}
		return v + g.MinM, nil
	case RefWGS84:
		lo, hi, err := e.undulation()
		if err != nil {
			return 0, err
		}
		if high {
			return geoid.AMSLFromHAE(v, lo), nil
		}
		return geoid.AMSLFromHAE(v, hi), nil
	}
	return 0, core.Fieldf("ref", "%q is not AGL, AMSL or WGS84", string(ref))
}

// haeBound is a limit of value v in ref as HAE (F3548 W84) over the
// whole area, the lowest with high false and the highest with high
// true: the lower limit of a volume takes the lowest ground and the
// least undulation, the upper the highest and the greatest, so the
// volume never shrinks below the restriction (gap 3).
func (e *envelope) haeBound(v float64, ref core.VerticalRef, high bool) (float64, error) {
	if ref == RefWGS84 {
		return v, nil
	}
	amsl, err := e.amslBound(v, ref, high)
	if err != nil {
		return 0, err
	}
	lo, hi, err := e.undulation()
	if err != nil {
		return 0, err
	}
	if high {
		return geoid.HAEFromAMSL(amsl, hi), nil
	}
	return geoid.HAEFromAMSL(amsl, lo), nil
}
