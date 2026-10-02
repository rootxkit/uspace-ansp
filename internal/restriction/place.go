package restriction

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// ErrNoProjection is the CIS projection holding no uspace_airspace
// dataset yet (WP-7 fills it). A restriction is then refused 503 cis_stale:
// without a current designation it is unpublishable (M9).
var ErrNoProjection = errors.New("no CIS projection of the uspace_airspace dataset")

// Snapshot is the current uspace_airspace dataset of the CIS projection
// (docs/PLAN.md section 5.1 cis_cache): its version, when it was
// fetched, and its features.
type Snapshot struct {
	Version   string
	FetchedAt time.Time
	Airspaces []ed318.Feature
}

// Airspaces gives the current snapshot (internal/cis, WP-7).
type Airspaces interface {
	Current(ctx context.Context) (Snapshot, error)
}

// NoProjection is the Airspaces of a process without a CIS projection:
// every placement is refused 503 cis_stale and says why.
type NoProjection struct{}

// Current is ErrNoProjection.
func (NoProjection) Current(context.Context) (Snapshot, error) { return Snapshot{}, ErrNoProjection }

// Part is one geometry part of a U-space airspace as the store measures
// it: GeoJSON (Polygon or Point) and, for a circle, its radius; and the
// part's upper limit in metres with its reference (nil: unlimited).
type Part struct {
	GeoJSON  string
	RadiusM  *float64
	UpperM   *float64
	UpperRef core.VerticalRef
}

// Relation is how a restriction's shape lies to a part.
type Relation struct {
	Intersects bool
	Covers     bool
}

// Measurer measures shapes on the database (PostGIS): core has no area
// or polygon intersection, and the store computes both on geography
// (03 conventions) the way the CISP does.
type Measurer interface {
	AreaM2(ctx context.Context, s Shape) (float64, error)
	Relate(ctx context.Context, s Shape, p Part) (Relation, error)
}

// cisAge is how old snap is at now, refused 503 cis_stale when there is
// none or it is older than boundS.
func cisAge(snap Snapshot, err error, now time.Time, boundS float64) (float64, error) {
	if errors.Is(err, ErrNoProjection) {
		return 0, &Refusal{Status: 503, Slug: SlugCISStale, Detail: "no CIS projection of the uspace_airspace dataset yet; a restriction cannot be placed (M9)", RetryAfter: 30 * time.Second}
	}
	if err != nil {
		return 0, &Refusal{Status: 503, Slug: SlugCISStale, Detail: "the CIS projection cannot be read now", RetryAfter: 5 * time.Second}
	}
	age := now.Sub(snap.FetchedAt).Seconds()
	if age < 0 {
		age = 0
	}
	if !(boundS > 0) {
		return 0, &Refusal{Status: 503, Slug: SlugCISStale, Detail: "the policy has no positive cis_stale_bound_s; no projection can be judged current", RetryAfter: 30 * time.Second}
	}
	if age > boundS {
		return age, &Refusal{Status: 503, Slug: SlugCISStale, Detail: fmt.Sprintf("the CIS projection (version %s) is %.0f s old; the bound is %.0f s (cis_stale_bound_s)", snap.Version, age, boundS), RetryAfter: 10 * time.Second}
	}
	return age, nil
}

// Place finds the U-space airspace in lies in (M9, gap 13): the named
// USPACE feature of snap, or, with none named, the one USPACE feature
// that covers the shape. The shape must lie inside it (a restriction
// partly outside is refused: the ATC unit limits airspace inside U-space
// airspace, 2021/664 Art. 4), and upper_m may not exceed the airspace's
// upper limit in the same reference; with references that differ the
// answer is reference_mismatch, never a silent conversion.
func Place(ctx context.Context, in Input, snap Snapshot, m Measurer) (string, error) {
	var candidates []*ed318.Feature
	for i := range snap.Airspaces {
		f := &snap.Airspaces[i]
		if f.Properties.Type != core.ZoneUSpace {
			continue
		}
		if in.UspaceAirspaceID == "" || f.Properties.Identifier == in.UspaceAirspaceID {
			candidates = append(candidates, f)
		}
	}
	if in.UspaceAirspaceID != "" && len(candidates) == 0 {
		return "", refuse(400, SlugOutsideUSpace, "a restriction modifies a designated U-space airspace (M9)",
			core.Fieldf("uspace_airspace_id", "%q is not a current USPACE feature of the CIS projection (version %s)", in.UspaceAirspaceID, snap.Version))
	}
	type placed struct {
		id    string
		parts []Part
	}
	var covering []placed
	anyIntersect := false
	for _, f := range candidates {
		parts, err := airspaceParts(f)
		if err != nil {
			return "", fmt.Errorf("airspace %s: %w", f.Properties.Identifier, err)
		}
		var cov []Part
		for _, p := range parts {
			rel, err := m.Relate(ctx, in.Shape, p)
			if err != nil {
				return "", err
			}
			anyIntersect = anyIntersect || rel.Intersects
			if rel.Covers {
				cov = append(cov, p)
			}
		}
		if len(cov) > 0 {
			covering = append(covering, placed{id: f.Properties.Identifier, parts: cov})
		}
	}
	switch {
	case len(covering) == 0 && !anyIntersect:
		return "", refuse(400, SlugOutsideUSpace, "a restriction modifies a designated U-space airspace (M9); the CISP refuses one outside every current USPACE feature",
			core.Fieldf("geometry", "intersects no current USPACE feature of the CIS projection (version %s)", snap.Version))
	case len(covering) == 0:
		return "", refuse(400, SlugOutsideUSpace, "a restriction lies inside the U-space airspace it modifies (2021/664 Art. 4)",
			core.Fieldf("geometry", "lies partly outside the U-space airspace; draw it inside the USPACE feature"))
	case len(covering) > 1:
		ids := make([]string, 0, len(covering))
		for _, c := range covering {
			ids = append(ids, c.id)
		}
		return "", invalid(core.Fieldf("uspace_airspace_id", "the restriction lies in several U-space airspaces (%s); name one", strings.Join(ids, ", ")))
	}
	return covering[0].id, upperWithin(in, covering[0].parts)
}

// upperWithin holds upper_m to the airspace's upper limit, comparing
// only limits in the same reference.
func upperWithin(in Input, parts []Part) error {
	var sameRefCeilings []float64
	var otherRefs []string
	for _, p := range parts {
		switch {
		case p.UpperM == nil:
			return nil // unlimited above
		case p.UpperRef == in.UpperRef:
			if in.UpperM <= *p.UpperM {
				return nil
			}
			sameRefCeilings = append(sameRefCeilings, *p.UpperM)
		default:
			otherRefs = append(otherRefs, fmt.Sprintf("%v m %s", *p.UpperM, p.UpperRef))
		}
	}
	if len(sameRefCeilings) > 0 {
		return invalid(core.Fieldf("upper_m", "%v m %s is above the U-space airspace's upper limit %v m %s", in.UpperM, in.UpperRef, slicesMax(sameRefCeilings), in.UpperRef))
	}
	return refuse(400, SlugReferenceMismatch, "the restriction's upper limit and the U-space airspace's are in different references; give the limit in the airspace's reference",
		core.Fieldf("upper_ref", "%s cannot be compared with the airspace's upper limit (%s) without a conversion this system does not make silently", in.UpperRef, strings.Join(otherRefs, ", ")))
}

func slicesMax(v []float64) float64 {
	out := math.Inf(-1)
	for _, x := range v {
		out = math.Max(out, x)
	}
	return out
}

// airspaceParts is the geometry parts of a U-space airspace feature,
// each with its upper limit in metres.
func airspaceParts(f *ed318.Feature) ([]Part, error) {
	gs := []ed318.Geometry{f.Geometry}
	if f.Geometry.Type == ed318.GeometryCollection {
		gs = f.Geometry.Geometries
	}
	out := make([]Part, 0, len(gs))
	for i := range gs {
		g := &gs[i]
		layer := g.Layer
		if layer == nil {
			layer = f.Geometry.Layer
		}
		p := Part{}
		switch g.Type {
		case ed318.GeometryPolygon:
			var b strings.Builder
			b.WriteString(`{"type":"Polygon","coordinates":[`)
			for i, ring := range g.Rings {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteByte('[')
				for k, pt := range ring {
					if k > 0 {
						b.WriteByte(',')
					}
					writePos(&b, pt)
				}
				b.WriteByte(']')
			}
			b.WriteString(`]}`)
			p.GeoJSON = b.String()
		case ed318.GeometryPoint:
			if g.Center == nil || g.RadiusM == nil {
				return nil, errors.New("a Point without a circle extent")
			}
			s := Shape{Center: g.Center}
			p.GeoJSON = s.GeoJSON()
			r := *g.RadiusM
			p.RadiusM = &r
		default:
			return nil, fmt.Errorf("geometry %q", g.Type)
		}
		if layer != nil && layer.Upper != nil {
			u := *layer.Upper
			if layer.Uom != nil && *layer.Uom == ed318.UomFeet {
				u *= core.FeetToMetres
			}
			p.UpperM = &u
			p.UpperRef = layer.UpperReference
		}
		out = append(out, p)
	}
	return out, nil
}
