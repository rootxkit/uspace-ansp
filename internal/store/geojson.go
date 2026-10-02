package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
)

// Geometry crosses sqlc as GeoJSON text (ST_GeomFromGeoJSON on the way
// in, ST_AsGeoJSON on the way out) and is held in Go as uspace-core
// geodesy types: a restriction is a Polygon, or a Point with radius_m
// (a geodesy.Circle). This file only maps between the two; validation of
// the shape (vertices, area, containment) is internal/restriction's on
// uspace-core.

// Bounds of a geometry read back from the database or written to it.
const (
	MaxGeometryBytes = 1 << 20 // the body cap of docs/PLAN.md section 8, T9
	MaxRings         = 64
	MaxVertices      = 10_000 // per ring; the F3548 vertex limit is judged above this
)

// Geometry is a Polygon or a Point; exactly one is set.
type Geometry struct {
	Polygon *geodesy.Polygon
	Point   *core.LatLon
}

type geoJSON struct {
	Type        string          `json:"type"`
	Coordinates json.RawMessage `json:"coordinates"`
}

// GeometryJSON is the GeoJSON text of g ([lon, lat] positions, RFC 7946).
func GeometryJSON(g Geometry) (string, error) {
	var buf bytes.Buffer
	switch {
	case g.Polygon != nil && g.Point == nil:
		if len(g.Polygon.Rings) == 0 || len(g.Polygon.Rings) > MaxRings {
			return "", core.Fieldf("geometry", "a polygon has 1 to %d rings", MaxRings)
		}
		buf.WriteString(`{"type":"Polygon","coordinates":[`)
		for i, ring := range g.Polygon.Rings {
			if err := geodesy.ValidRing(ring, MaxVertices); err != nil {
				return "", core.Fieldf(fmt.Sprintf("geometry.rings[%d]", i), "%s", reason(err))
			}
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('[')
			for j, p := range ring {
				if j > 0 {
					buf.WriteByte(',')
				}
				writePosition(&buf, p)
			}
			buf.WriteByte(']')
		}
		buf.WriteString(`]}`)
	case g.Point != nil && g.Polygon == nil:
		if !g.Point.Valid() {
			return "", core.Fieldf("geometry", "the point is not a valid WGS84 position")
		}
		buf.WriteString(`{"type":"Point","coordinates":`)
		writePosition(&buf, *g.Point)
		buf.WriteByte('}')
	default:
		return "", core.Fieldf("geometry", "exactly one of polygon and point")
	}
	return buf.String(), nil
}

func writePosition(buf *bytes.Buffer, p core.LatLon) {
	buf.WriteByte('[')
	buf.WriteString(strconv.FormatFloat(p.LonDeg, 'f', -1, 64))
	buf.WriteByte(',')
	buf.WriteString(strconv.FormatFloat(p.LatDeg, 'f', -1, 64))
	buf.WriteByte(']')
}

func reason(err error) string {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return fe.Reason
	}
	return err.Error()
}

// ParseGeometry reads the GeoJSON text of a Polygon or a Point, bounded
// in bytes, rings and vertices; anything else is refused with a field
// error, never a panic.
func ParseGeometry(text string) (Geometry, error) {
	if len(text) > MaxGeometryBytes {
		return Geometry{}, core.Fieldf("geometry", "longer than %d bytes", MaxGeometryBytes)
	}
	var g geoJSON
	if err := decodeOne(text, &g); err != nil {
		return Geometry{}, core.Fieldf("geometry", "not a GeoJSON geometry")
	}
	switch g.Type {
	case "Polygon":
		var rings [][][2]float64
		if err := decodeOne(string(g.Coordinates), &rings); err != nil {
			return Geometry{}, core.Fieldf("geometry.coordinates", "not polygon coordinates")
		}
		if len(rings) == 0 || len(rings) > MaxRings {
			return Geometry{}, core.Fieldf("geometry.coordinates", "a polygon has 1 to %d rings", MaxRings)
		}
		poly := geodesy.Polygon{Rings: make([]geodesy.Ring, 0, len(rings))}
		for i, r := range rings {
			ring := geodesy.RingFromLonLat(r)
			if err := geodesy.ValidRing(ring, MaxVertices); err != nil {
				return Geometry{}, core.Fieldf(fmt.Sprintf("geometry.coordinates[%d]", i), "%s", reason(err))
			}
			poly.Rings = append(poly.Rings, ring)
		}
		return Geometry{Polygon: &poly}, nil
	case "Point":
		var pos [2]float64
		if err := decodeOne(string(g.Coordinates), &pos); err != nil {
			return Geometry{}, core.Fieldf("geometry.coordinates", "not a position")
		}
		p := core.LatLon{LatDeg: pos[1], LonDeg: pos[0]}
		if !p.Valid() {
			return Geometry{}, core.Fieldf("geometry.coordinates", "not a valid WGS84 position")
		}
		return Geometry{Point: &p}, nil
	default:
		return Geometry{}, core.Fieldf("geometry.type", "%q is neither Polygon nor Point", truncate(g.Type, 32))
	}
}

// decodeOne decodes exactly one JSON value into v.
func decodeOne(text string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
