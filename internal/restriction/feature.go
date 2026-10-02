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
	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// The fixed members of a restriction's feature (D4, spec 02 F2).
const (
	// ReasonDAR is the feature's one reason.
	ReasonDAR = "DAR"
	// VariantCommon is the feature's variant.
	VariantCommon = "COMMON"
	// FeatureLang is the language of the texts built from reason_text.
	FeatureLang = "en"
	// PurposeInformation is the zone authority's purpose: the ANSP
	// informs; it does not authorise flights (that is the USSP's).
	PurposeInformation = "INFORMATION"
	// ExtendedKey is this system's member of extendedProperties.
	ExtendedKey = "ansp"
	// MaxTextChars bounds every text built from reason_text: ED-318's
	// textShortType (ed269.DefaultLimits NameMax and MessageMax, 200).
	MaxTextChars = 200
)

// FeatureConfig is what the feature takes from configuration and policy:
// the country (ansp_policy.country) and the zone authority
// (ANSP_AUTHORITY_*; branding is configuration).
type FeatureConfig struct {
	Country          string
	AuthorityName    string
	AuthorityService string
	AuthorityEmail   string
	AuthorityPhone   string
}

// Extended is extendedProperties.ansp: the members that stay the same in
// every version of a restriction. ansp_version and state are not here:
// an extend republishes the feature to the CISP, which refuses one that
// differs from the published feature anywhere but the period's
// endDateTime (uspace-cisp PLAN section 15 Q36, 409 feature_changed);
// they travel beside the feature, in cis/restriction/v1 and in
// restriction/state/v1.
type Extended struct {
	AnspRef          string `json:"ansp_ref"`
	RestrictionID    string `json:"restriction_id"`
	UspaceAirspaceID string `json:"uspace_airspace_id"`
}

// Feature is the ED-318 feature of r (D4): identifier DAR plus 4
// base-36 characters, the configured country, name and message from
// reason_text, type r.ZoneType, variant COMMON, reason [DAR], one
// limitedApplicability period from starts_at to ends_at (UTC, Z), one
// zone authority with purpose INFORMATION, extendedProperties.ansp
// (Extended) and the geometry with its layer in metres. The feature is
// checked with ed318.Export and ed318.Parse before it is returned (Z-01:
// what leaves is a valid ED-318 document); a refusal names the member
// by its path in the feature.
func Feature(r Restriction, cfg FeatureConfig) (*ed318.Feature, error) {
	if !ValidIdentifier(r.Identifier) {
		return nil, core.Fieldf("identifier", "%q is not DAR plus 4 base-36 characters (D4)", r.Identifier)
	}
	if cfg.AuthorityName == "" {
		return nil, core.Fieldf("zoneAuthority", "no authority name is configured (ANSP_AUTHORITY_NAME)")
	}
	ext, err := json.Marshal(Extended{AnspRef: r.AnspRef, RestrictionID: r.ID, UspaceAirspaceID: r.UspaceAirspaceID})
	if err != nil {
		return nil, err
	}
	id, err := json.Marshal(r.Identifier)
	if err != nil {
		return nil, err
	}
	text := cutRunes(r.ReasonText, MaxTextChars)
	auth := ed318.Authority{Name: texts(cfg.AuthorityName), Purpose: PurposeInformation}
	if cfg.AuthorityService != "" {
		auth.Service = texts(cfg.AuthorityService)
	}
	if cfg.AuthorityEmail != "" {
		e := cfg.AuthorityEmail
		auth.Email = &e
	}
	if cfg.AuthorityPhone != "" {
		p := cfg.AuthorityPhone
		auth.Phone = &p
	}
	f := &ed318.Feature{
		Type: "Feature",
		ID:   id,
		Geometry: geometry(r.Shape, &ed318.Layer{
			Upper: ptr(r.UpperM), UpperReference: r.UpperRef,
			Lower: ptr(r.LowerM), LowerReference: r.LowerRef,
			Uom: ptr(ed318.UomMetres),
		}),
		Properties: ed318.UASZone{
			Identifier:           r.Identifier,
			Country:              cfg.Country,
			Name:                 texts(text),
			Type:                 r.ZoneType,
			Variant:              VariantCommon,
			Reason:               []string{ReasonDAR},
			Message:              texts(text),
			ExtendedProperties:   map[string]json.RawMessage{ExtendedKey: ext},
			LimitedApplicability: []ed318.TimePeriod{period(r.StartsAt, r.EndsAt)},
			ZoneAuthority:        []ed318.Authority{auth},
		},
	}
	if _, err := CheckFeature(f); err != nil {
		return nil, err
	}
	return f, nil
}

// WithEnd is f with its one period ending at end, everything else
// unchanged: the feature of an extend (uspace-cisp Q36: an extend may
// change the period's endDateTime and nothing else).
func WithEnd(f *ed318.Feature, end time.Time) (*ed318.Feature, error) {
	if f == nil || len(f.Properties.LimitedApplicability) != 1 {
		return nil, core.Fieldf("properties.limitedApplicability", "a restriction's feature has exactly one period")
	}
	out := *f
	tp := f.Properties.LimitedApplicability[0]
	tp.EndDateTime = dateTime(end)
	out.Properties.LimitedApplicability = []ed318.TimePeriod{tp}
	if _, err := CheckFeature(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ParseFeature reads one stored feature (restriction_versions.feature)
// back through ed318.Parse.
func ParseFeature(raw json.RawMessage) (*ed318.Feature, error) {
	fc, probs := ed318.Parse(collection(raw), ed318.Limits{})
	if probs != nil {
		return nil, problemsError(probs)
	}
	if len(fc.Features) != 1 {
		return nil, errors.New("a stored restriction feature is not one feature")
	}
	return &fc.Features[0], nil
}

// CheckFeature exports f as a one-feature collection, parses it back
// with ed318.Parse and returns the exported feature: the bytes that are
// stored and published. A refusal is the parse's first problem, its path
// relative to the feature.
func CheckFeature(f *ed318.Feature) (json.RawMessage, error) {
	raw, err := ed318.Export(&ed318.FeatureCollection{Type: "FeatureCollection", Features: []ed318.Feature{*f}})
	if err != nil {
		return nil, err
	}
	if _, probs := ed318.Parse(raw, ed318.Limits{}); probs != nil {
		return nil, problemsError(probs)
	}
	var fc struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(raw, &fc); err != nil || len(fc.Features) != 1 {
		return nil, errors.New("the exported collection is not one feature")
	}
	return fc.Features[0], nil
}

// FeatureCollection is the ED-318 collection of the given features
// (what GET /v1/restrictions/{id} can serve to a receiver's pull_url in
// the degraded path, WP-8), with core's metadata members issued and
// provider (M15: never creationDateTime or originator).
func FeatureCollection(features []json.RawMessage, issued time.Time, provider string) ([]byte, error) {
	fc := &ed318.FeatureCollection{Type: "FeatureCollection", Metadata: &ed318.Metadata{Issued: dateTime(issued), Provider: texts(provider)}}
	for i, raw := range features {
		f, err := ParseFeature(raw)
		if err != nil {
			return nil, fmt.Errorf("features[%d]: %w", i, err)
		}
		fc.Features = append(fc.Features, *f)
	}
	out, err := ed318.Export(fc)
	if err != nil {
		return nil, err
	}
	if _, probs := ed318.Parse(out, ed318.Limits{}); probs != nil {
		return nil, problemsError(probs)
	}
	return out, nil
}

// problemsError is the first problem of a parse as a field error, its
// path made relative to the one feature ("features[0].geometry" ->
// "geometry").
func problemsError(p *ed269.Problems) error {
	if p == nil || len(p.List) == 0 {
		return errors.New("refused by ed318.Parse")
	}
	errs := make([]error, 0, len(p.List))
	for _, pr := range p.List {
		field := pr.Field
		if rest, ok := strings.CutPrefix(field, "features[0]."); ok {
			field = rest
		}
		errs = append(errs, core.Fieldf(field, "%s", pr.Reason))
	}
	return errors.Join(errs...)
}

func collection(feature json.RawMessage) []byte {
	var b bytes.Buffer
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	b.Write(feature)
	b.WriteString(`]}`)
	return b.Bytes()
}

func geometry(s Shape, layer *ed318.Layer) ed318.Geometry {
	if s.IsCircle() {
		c := *s.Center
		r := s.RadiusM
		return ed318.Geometry{Type: ed318.GeometryPoint, Center: &c, RadiusM: &r, Layer: layer}
	}
	ring := make([]core.LatLon, len(s.Ring))
	copy(ring, s.Ring)
	return ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{ring}, Layer: layer}
}

func period(start, end time.Time) ed318.TimePeriod {
	return ed318.TimePeriod{StartDateTime: dateTime(start), EndDateTime: dateTime(end)}
}

func dateTime(t time.Time) *ed318.DateTime {
	u := t.UTC().Truncate(time.Millisecond)
	return &ed318.DateTime{Time: u, Text: u.Format(TimeFormat)}
}

func texts(s string) []ed318.Text {
	v := s
	return []ed318.Text{{Text: &v, Lang: FeatureLang}}
}

func ptr[T any](v T) *T { return &v }

// cutRunes bounds s to n characters.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for k := range s {
		if i == n {
			return s[:k]
		}
		i++
	}
	return s
}
