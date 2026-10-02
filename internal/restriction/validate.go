package restriction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
)

// ReasonAGL is the D3 refusal of an AGL limit, word for word.
const ReasonAGL = "AGL is not supported for a dynamic restriction in this release"

// MaxReasonChars bounds reason_text: it becomes the feature's name and
// message, ED-318 textShortType (200 characters).
const MaxReasonChars = MaxTextChars

// MaxVertices bounds a polygon's vertices (F3548 CstrMaxVertices; the
// closing position repeats the first and is not counted).
const MaxVertices = f3548.CstrMaxVertices

// MaxAreaM2 bounds the area (F3548 CstrMaxAreaKm2), in square metres as
// PostGIS ST_Area on geography gives it.
const MaxAreaM2 = float64(f3548.CstrMaxAreaKm2) * 1e6

// Refusal is a refused operation with its problem type: the handler
// writes it as the RFC 9457 body (M28) with errors[] from Fields.
type Refusal struct { //nolint:errname // the refusal is the problem body, apierr.Problem's sibling
	Status     int
	Slug       string
	Detail     string
	Fields     []*core.FieldError
	RetryAfter time.Duration
}

func (r *Refusal) Error() string {
	if len(r.Fields) > 0 {
		return r.Slug + ": " + r.Detail + ": " + r.Fields[0].Error()
	}
	return r.Slug + ": " + r.Detail
}

// The problem slugs of this package (docs/PLAN.md section 6).
const (
	SlugInvalid            = "restriction_invalid"
	SlugChainRequired      = "chain_required"
	SlugOutsideUSpace      = "outside_uspace_airspace"
	SlugReferenceMismatch  = "reference_mismatch"
	SlugCISStale           = "cis_stale"
	SlugGeoidUnavailable   = "geoid_unavailable"
	SlugIllegalTransition  = "illegal_transition"
	SlugIdempotency        = "idempotency_conflict"
	SlugNotFound           = "not_found"
	SlugRequestDecided     = "request_decided"
	SlugTooManyRequests    = "too_many_open_requests"
	SlugIdentifiersSpent   = "identifiers_exhausted"
	SlugRestrictionsLocked = "unavailable"
)

func refuse(status int, slug, detail string, fields ...*core.FieldError) *Refusal {
	return &Refusal{Status: status, Slug: slug, Detail: detail, Fields: fields}
}

func invalid(fields ...*core.FieldError) *Refusal {
	return refuse(400, SlugInvalid, "the restriction is refused; nothing was stored", fields...)
}

// Input is a restriction to plan, as the console or a request gives it.
type Input struct {
	// UspaceAirspaceID names the USPACE feature it lies in; empty asks
	// the service to infer it (a restriction request).
	UspaceAirspaceID string
	// ZoneType is PROHIBITED or REQ_AUTHORIZATION; empty takes the
	// policy's default_zone_type.
	ZoneType   core.ZoneType
	Shape      Shape
	LowerM     float64
	LowerRef   core.VerticalRef
	UpperM     float64
	UpperRef   core.VerticalRef
	StartsAt   time.Time
	EndsAt     time.Time
	ReasonText string
}

// Window is one restriction's [StartsAt, EndsAt).
type Window struct {
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

// Wire geometry (RFC 7946) as the API takes it.
type wireGeometry struct {
	Type        string          `json:"type"`
	Coordinates json.RawMessage `json:"coordinates"`
}

// ParseShape reads the API's geometry (a GeoJSON Polygon with one outer
// ring, or a Point with radius_m) into a Shape. Every problem is named
// by its path; nothing is repaired. The bounds are the F3548 constraint
// limits (CstrMaxVertices) and core's ring and circle checks.
func ParseShape(raw json.RawMessage, radiusM *float64) (Shape, []*core.FieldError) {
	var g wireGeometry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return Shape{}, []*core.FieldError{core.Fieldf("geometry", "is required: a GeoJSON Polygon, or a Point with radius_m")}
	}
	if err := dec.Decode(&g); err != nil {
		return Shape{}, []*core.FieldError{core.Fieldf("geometry", "is not a GeoJSON Polygon or Point")}
	}
	switch g.Type {
	case "Polygon":
		if radiusM != nil {
			return Shape{}, []*core.FieldError{core.Fieldf("radius_m", "belongs to a Point (a circle), not a Polygon")}
		}
		var rings [][][]float64
		if err := json.Unmarshal(g.Coordinates, &rings); err != nil {
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates", "is not a list of rings of [lng, lat] positions")}
		}
		switch {
		case len(rings) == 0:
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates", "has no ring")}
		case len(rings) > 1:
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates", "has %d rings; a restriction has one outer ring and no holes in this release", len(rings))}
		}
		ring := make(geodesy.Ring, 0, len(rings[0]))
		if len(rings[0]) > MaxVertices+1 {
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates[0]", "has %d vertices; at most %d (F3548 CstrMaxVertices)", len(rings[0])-1, MaxVertices)}
		}
		for i, p := range rings[0] {
			if len(p) != 2 {
				return Shape{}, []*core.FieldError{core.Fieldf(fmt.Sprintf("geometry.coordinates[0][%d]", i), "is not a [lng, lat] position")}
			}
			ring = append(ring, core.LatLon{LatDeg: p[1], LonDeg: p[0]})
		}
		if err := geodesy.ValidRing(ring, MaxVertices+1); err != nil {
			var fe *core.FieldError
			if errors.As(err, &fe) {
				return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates[0]"+strings.TrimPrefix(fe.Field, "ring"), "%s", fe.Reason)}
			}
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates[0]", "%s", err.Error())}
		}
		return Shape{Ring: ring}, nil
	case "Point":
		var p []float64
		if err := json.Unmarshal(g.Coordinates, &p); err != nil || len(p) != 2 {
			return Shape{}, []*core.FieldError{core.Fieldf("geometry.coordinates", "is not a [lng, lat] position")}
		}
		c := core.LatLon{LatDeg: p[1], LonDeg: p[0]}
		var errs []*core.FieldError
		if !c.Valid() {
			errs = append(errs, core.Fieldf("geometry.coordinates", "is not a valid WGS84 position"))
		}
		switch {
		case radiusM == nil:
			errs = append(errs, core.Fieldf("radius_m", "is required with a Point: the circle's radius in metres"))
		case !core.IsFinite(*radiusM) || *radiusM <= 0:
			errs = append(errs, core.Fieldf("radius_m", "must be a positive number of metres"))
		case *radiusM > ed318.MaxCircleRadiusM:
			errs = append(errs, core.Fieldf("radius_m", "is more than %d m", ed318.MaxCircleRadiusM))
		}
		if len(errs) > 0 {
			return Shape{}, errs
		}
		return Shape{Center: &c, RadiusM: *radiusM}, nil
	}
	return Shape{}, []*core.FieldError{core.Fieldf("geometry.type", "%q is not Polygon or Point", g.Type)}
}

// Validate checks in against the rules that need no database: zone
// type, limits and their references (D3, D-01), the window against the
// F3548 limits at now (the database's clock), reason_text, and the
// shape as ED-318 holds it (ed318.Parse of the feature it would make:
// the antimeridian, ring and circle rules live there). Every problem is
// reported, none repaired. A window longer than MaxDuration but
// otherwise valid is not a problem here: it is returned as the chain of
// re-issues it would make (Chain), for the supervisor to confirm.
func Validate(in Input, now time.Time) (chain []Window, errs []*core.FieldError) {
	switch in.ZoneType {
	case core.ZoneProhibited, core.ZoneReqAuthorization:
	case core.ZoneConditional, core.ZoneNoRestriction, core.ZoneUSpace:
		errs = append(errs, core.Fieldf("zone_type", "%q is not PROHIBITED or REQ_AUTHORIZATION (D4)", string(in.ZoneType)))
	default:
		errs = append(errs, core.Fieldf("zone_type", "%q is not PROHIBITED or REQ_AUTHORIZATION (D4)", string(in.ZoneType)))
	}
	errs = append(errs, verticalErrors(in)...)
	if n := utf8.RuneCountInString(in.ReasonText); n == 0 || strings.TrimSpace(in.ReasonText) == "" {
		errs = append(errs, core.Fieldf("reason_text", "is required: why, as the supervisor states it (N4)"))
	} else if n > MaxReasonChars {
		errs = append(errs, core.Fieldf("reason_text", "has %d characters; at most %d (ED-318 message)", n, MaxReasonChars))
	}
	chain, werrs := windowErrors(in.StartsAt, in.EndsAt, now)
	errs = append(errs, werrs...)
	errs = append(errs, shapeErrors(in)...)
	return chain, errs
}

func verticalErrors(in Input) []*core.FieldError {
	var errs []*core.FieldError
	ref := func(field string, r core.VerticalRef) bool {
		switch r {
		case RefAMSL, RefWGS84:
			return true
		case "":
			errs = append(errs, core.Fieldf(field, "is required: a limit without its reference is refused (D-01)"))
		case core.RefAGL:
			errs = append(errs, core.Fieldf(field, "%s", ReasonAGL))
		default:
			errs = append(errs, core.Fieldf(field, "%q is not AMSL or WGS84", string(r)))
		}
		return false
	}
	okLower := ref("lower_ref", in.LowerRef)
	okUpper := ref("upper_ref", in.UpperRef)
	if !core.IsFinite(in.LowerM) {
		errs = append(errs, core.Fieldf("lower_m", "is not a finite number of metres"))
		okLower = false
	}
	if !core.IsFinite(in.UpperM) {
		errs = append(errs, core.Fieldf("upper_m", "is not a finite number of metres"))
		okUpper = false
	}
	if okLower && okUpper && in.LowerRef == in.UpperRef && in.LowerM >= in.UpperM {
		errs = append(errs, core.Fieldf("upper_m", "%v is not above lower_m %v", in.UpperM, in.LowerM))
	}
	return errs
}

// windowErrors checks the window at now and returns the chain a window
// longer than MaxDuration would make.
func windowErrors(start, end, now time.Time) ([]Window, []*core.FieldError) {
	var errs []*core.FieldError
	if start.IsZero() {
		errs = append(errs, core.Fieldf("starts_at", "is required"))
	}
	if end.IsZero() {
		errs = append(errs, core.Fieldf("ends_at", "is required"))
	}
	if len(errs) > 0 {
		return nil, errs
	}
	if !start.Before(end) {
		return nil, []*core.FieldError{core.Fieldf("ends_at", "%s is not after starts_at %s", stamp(end), stamp(start))}
	}
	if start.Before(now.Add(-StartLead)) {
		errs = append(errs, core.Fieldf("starts_at", "%s is in the past (now %s); an immediate restriction starts now", stamp(start), stamp(now)))
	}
	if start.After(now.Add(MaxHorizon)) {
		errs = append(errs, core.Fieldf("starts_at", "%s is more than %v ahead of now %s (F3548 CstrMaxPlanningHorizonDays)", stamp(start), MaxHorizon, stamp(now)))
	}
	if !end.After(now) {
		errs = append(errs, core.Fieldf("ends_at", "%s is not after now %s", stamp(end), stamp(now)))
	}
	if len(errs) > 0 || end.Sub(start) <= MaxDuration {
		return nil, errs
	}
	chain := Chain(start, end)
	for i, w := range chain {
		if w.StartsAt.After(now.Add(MaxHorizon)) {
			return nil, []*core.FieldError{core.Fieldf("ends_at", "re-issue %d of the chain would start at %s, more than %v ahead of now (F3548 CstrMaxPlanningHorizonDays)", i, stamp(w.StartsAt), MaxHorizon)}
		}
	}
	return chain, nil
}

// Chain splits [start, end) into consecutive windows of at most
// MaxDuration: the re-issues of a restriction longer than F3548 allows
// one constraint to be.
func Chain(start, end time.Time) []Window {
	var out []Window
	for s := start; s.Before(end); s = s.Add(MaxDuration) {
		e := s.Add(MaxDuration)
		if e.After(end) {
			e = end
		}
		out = append(out, Window{StartsAt: s.UTC(), EndsAt: e.UTC()})
	}
	return out
}

// shapeErrors builds the feature in would make and parses it with
// ed318.Parse, so that the geometry rules ED-318 and core hold (a shape
// across the antimeridian, a ring that is not closed, a circle's radius)
// are judged once, by core.
func shapeErrors(in Input) []*core.FieldError {
	if !in.Shape.IsCircle() && len(in.Shape.Ring) == 0 {
		return []*core.FieldError{core.Fieldf("geometry", "is required")}
	}
	probe := Restriction{
		ID: "00000000000000000000000000", AnspRef: "probe", Identifier: IdentifierPrefix + "0000", UspaceAirspaceID: "probe",
		ZoneType: core.ZoneProhibited, Shape: in.Shape, LowerM: 0, LowerRef: RefWGS84, UpperM: 1, UpperRef: RefWGS84,
		StartsAt: time.Unix(0, 0), EndsAt: time.Unix(3600, 0), ReasonText: "probe",
	}
	_, err := Feature(probe, FeatureConfig{Country: "GEO", AuthorityName: "probe"})
	if err == nil {
		return nil
	}
	var out []*core.FieldError
	for _, fe := range fieldErrors(err) {
		if strings.HasPrefix(fe.Field, "geometry") {
			out = append(out, core.Fieldf("geometry", "%s", fe.Reason))
		}
	}
	if len(out) == 0 {
		out = append(out, core.Fieldf("geometry", "is not an ED-318 restriction shape: %s", err.Error()))
	}
	return out
}

// fieldErrors flattens a joined error of field errors.
func fieldErrors(err error) []*core.FieldError {
	var out []*core.FieldError
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			out = append(out, fieldErrors(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return []*core.FieldError{fe}
	}
	return nil
}
