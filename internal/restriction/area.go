package restriction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// AreaBody is the wire form of api/openapi.yaml's RestrictionArea plus
// the members of RestrictionCreate (zone_type, confirm_chain) and of
// RestrictionRequestCreate (client_ref, case_ref). Numbers are float64:
// the generated types use float32, which cannot hold a WGS84 position to
// the metre.
type AreaBody struct {
	UspaceAirspaceID *string         `json:"uspace_airspace_id,omitempty"`
	ZoneType         *string         `json:"zone_type,omitempty"`
	Geometry         json.RawMessage `json:"geometry"`
	RadiusM          *float64        `json:"radius_m,omitempty"`
	LowerM           *float64        `json:"lower_m"`
	LowerRef         *string         `json:"lower_ref"`
	UpperM           *float64        `json:"upper_m"`
	UpperRef         *string         `json:"upper_ref"`
	StartsAt         *string         `json:"starts_at"`
	EndsAt           *string         `json:"ends_at"`
	ReasonText       *string         `json:"reason_text"`
	ConfirmChain     *bool           `json:"confirm_chain,omitempty"`
	ClientRef        *string         `json:"client_ref,omitempty"`
	CaseRef          *string         `json:"case_ref,omitempty"`
}

// The bodies' kinds: which members each admits.
const (
	BodyCreate  = "create"
	BodyRequest = "request"
)

// MaxRefChars bounds client_ref and case_ref (api/openapi.yaml).
const MaxRefChars = 128

// DecodeArea reads a restriction body strictly: one JSON object, no
// unknown member (a misspelt ends_at must not read as an absent one),
// nothing after it. kind is BodyCreate or BodyRequest. Every problem
// is named by its path; the Input is valid to Validate only when errs is
// empty.
func DecodeArea(raw []byte, kind string) (AreaBody, Input, []*core.FieldError) {
	var b AreaBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, Input{}, []*core.FieldError{decodeError(err)}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return b, Input{}, []*core.FieldError{core.Fieldf("body", "has content after the JSON object")}
	}
	var errs []*core.FieldError
	switch kind {
	case BodyCreate:
		if b.ClientRef != nil {
			errs = append(errs, core.Fieldf("client_ref", "belongs to a restriction request; a restriction takes the Idempotency-Key header"))
		}
		if b.CaseRef != nil {
			errs = append(errs, core.Fieldf("case_ref", "belongs to a restriction request"))
		}
		if b.UspaceAirspaceID == nil {
			errs = append(errs, core.Fieldf("uspace_airspace_id", "is required: the current USPACE feature the restriction lies in (M9)"))
		}
	case BodyRequest:
		if b.ZoneType != nil {
			errs = append(errs, core.Fieldf("zone_type", "is the supervisor's choice at accept, not the requester's"))
		}
		if b.ConfirmChain != nil {
			errs = append(errs, core.Fieldf("confirm_chain", "is the supervisor's choice, not the requester's"))
		}
		switch {
		case b.ClientRef == nil || *b.ClientRef == "":
			errs = append(errs, core.Fieldf("client_ref", "is required: the requester's reference makes the call idempotent"))
		case len(*b.ClientRef) > MaxRefChars:
			errs = append(errs, core.Fieldf("client_ref", "is longer than %d characters", MaxRefChars))
		}
		if b.CaseRef != nil && len(*b.CaseRef) > MaxRefChars {
			errs = append(errs, core.Fieldf("case_ref", "is longer than %d characters", MaxRefChars))
		}
	}
	in := Input{}
	if b.UspaceAirspaceID != nil {
		in.UspaceAirspaceID = *b.UspaceAirspaceID
		if in.UspaceAirspaceID == "" || len(in.UspaceAirspaceID) > 7 {
			errs = append(errs, core.Fieldf("uspace_airspace_id", "is not an ED-318 identifier (1 to 7 characters)"))
		}
	}
	if b.ZoneType != nil {
		in.ZoneType = core.ZoneType(*b.ZoneType)
	}
	shape, serrs := ParseShape(b.Geometry, b.RadiusM)
	errs = append(errs, serrs...)
	in.Shape = shape
	num := func(field string, v *float64) float64 {
		if v == nil {
			errs = append(errs, core.Fieldf(field, "is required"))
			return 0
		}
		return *v
	}
	str := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}
	in.LowerM = num("lower_m", b.LowerM)
	in.UpperM = num("upper_m", b.UpperM)
	in.LowerRef = core.VerticalRef(str(b.LowerRef))
	in.UpperRef = core.VerticalRef(str(b.UpperRef))
	in.ReasonText = str(b.ReasonText)
	in.StartsAt = instant("starts_at", b.StartsAt, &errs)
	in.EndsAt = instant("ends_at", b.EndsAt, &errs)
	return b, in, errs
}

// instant reads an RFC 3339 instant with an offset (T-09), to the
// millisecond the wire carries (02 section 1). A missing one is left
// zero for Validate to name.
func instant(field string, v *string, errs *[]*core.FieldError) time.Time {
	if v == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, *v)
	if err != nil {
		*errs = append(*errs, core.Fieldf(field, "is not an RFC 3339 instant with an offset"))
		return time.Time{}
	}
	if t.Truncate(time.Millisecond) != t {
		*errs = append(*errs, core.Fieldf(field, "has more than millisecond precision (02 section 1)"))
	}
	return t.UTC()
}

// decodeError names the member a JSON error is about, never echoing the
// value sent.
func decodeError(err error) *core.FieldError {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) && ute.Field != "" {
		return core.Fieldf(ute.Field, "is not of the type the operation takes")
	}
	if msg := err.Error(); strings.HasPrefix(msg, "json: unknown field ") {
		name := strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`)
		if len(name) > 64 {
			name = name[:64]
		}
		return core.Fieldf(name, "is not a member of this body")
	}
	return core.Fieldf("body", "is not the JSON object this operation takes")
}

// ReasonBody is api/openapi.yaml's ReasonRequest and ExtendRequest, and
// AcceptRequest's members.
type ReasonBody struct {
	Reason   *string `json:"reason,omitempty"`
	EndsAt   *string `json:"ends_at,omitempty"`
	ZoneType *string `json:"zone_type,omitempty"`
}

// MaxChangeReasonChars bounds a transition's reason (api/openapi.yaml
// ReasonRequest).
const MaxChangeReasonChars = 500

// DecodeReason reads a transition body strictly. required says whether
// reason must be given; allowEnd and allowZone admit ends_at (extend)
// and zone_type (accept). An empty raw is an absent body.
func DecodeReason(raw []byte, required, allowEnd, allowZone bool) (ReasonBody, []*core.FieldError) {
	var b ReasonBody
	if len(bytes.TrimSpace(raw)) == 0 {
		if required {
			return b, []*core.FieldError{core.Fieldf("reason", "is required: why (the N4 record)")}
		}
		return b, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, []*core.FieldError{decodeError(err)}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return b, []*core.FieldError{core.Fieldf("body", "has content after the JSON object")}
	}
	var errs []*core.FieldError
	switch {
	case b.Reason == nil || strings.TrimSpace(*b.Reason) == "":
		if required {
			errs = append(errs, core.Fieldf("reason", "is required: why (the N4 record)"))
		}
	case len([]rune(*b.Reason)) > MaxChangeReasonChars:
		errs = append(errs, core.Fieldf("reason", "is longer than %d characters", MaxChangeReasonChars))
	}
	if b.EndsAt != nil && !allowEnd {
		errs = append(errs, core.Fieldf("ends_at", "belongs to an extend"))
	}
	if b.EndsAt == nil && allowEnd {
		errs = append(errs, core.Fieldf("ends_at", "is required: the new end of the window"))
	}
	if b.ZoneType != nil && !allowZone {
		errs = append(errs, core.Fieldf("zone_type", "belongs to an accept"))
	}
	return b, errs
}

// EndOf is an extend body's new ends_at.
func (b ReasonBody) EndOf() (time.Time, []*core.FieldError) {
	var errs []*core.FieldError
	t := instant("ends_at", b.EndsAt, &errs)
	return t, errs
}

// ReasonOr is the body's reason, or def when none was given.
func (b ReasonBody) ReasonOr(def string) string {
	if b.Reason == nil || strings.TrimSpace(*b.Reason) == "" {
		return def
	}
	return *b.Reason
}

// String renders a window for a refusal.
func (w Window) String() string { return fmt.Sprintf("%s to %s", stamp(w.StartsAt), stamp(w.EndsAt)) }
