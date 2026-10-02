package store

import (
	"errors"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

// ParseGeometry reads text from the database and, through WP-5, from
// request bodies: any input yields a geometry or a field error, never a
// panic, and an accepted geometry writes back to GeoJSON that parses to
// the same shape.
func FuzzParseGeometry(f *testing.F) {
	for _, seed := range []string{
		`{"type":"Polygon","coordinates":[[[44.7,41.6],[44.9,41.6],[44.9,41.8],[44.7,41.6]]]}`,
		`{"type":"Point","coordinates":[44.8,41.7]}`,
		`{"type":"LineString","coordinates":[[1,2],[3,4]]}`,
		`{"type":"Polygon","coordinates":[[]]}`,
		`{"type":"Point","coordinates":[1e400,0]}`,
		`null`, `[]`, `{`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		g, err := ParseGeometry(text)
		if err != nil {
			var fe *core.FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("not a field error: %v", err)
			}
			return
		}
		out, err := GeometryJSON(g)
		if err != nil {
			t.Fatalf("accepted %q but cannot write it back: %v", text, err)
		}
		again, err := ParseGeometry(out)
		if err != nil || (again.Point == nil) != (g.Point == nil) {
			t.Fatalf("round trip of %q via %q: %v", text, out, err)
		}
	})
}
