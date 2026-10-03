package coord

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
)

// SchemaAnnexV is the name of the body of POST /v1/coordination/notices
// (schemas/coordination/annex_v/v1.json, owned here: M14).
const SchemaAnnexV = "coordination/annex_v/v1"

// Bounds of a notice (E-10); the schema's maxLength and maxItems.
const (
	// MaxNoticeBytes bounds the body (06 T9: 1 MiB).
	MaxNoticeBytes = 1 << 20
	// MaxIntents bounds intents[] (the schema's maxItems).
	MaxIntents = 100
	// MaxVolumes bounds the volumes of one intent.
	MaxVolumes = 100
	// MaxNoticeRefBytes bounds notice_ref.
	MaxNoticeRefBytes = 128
	// MaxUSSPIDBytes bounds ussp_id.
	MaxUSSPIDBytes = 64
	// MaxAuthorisationBytes bounds an authorisation number.
	MaxAuthorisationBytes = 64
	// MaxRemarksBytes bounds remarks.
	MaxRemarksBytes = 1000
	// maxFieldErrors is where the refusal stops listing (apierr caps the
	// wire at 100 and says truncated).
	maxFieldErrors = 101
)

// Kind is a notice's kind (04 section 3.5).
type Kind string

// The kinds. nonconformance and contingent need a person's
// acknowledgement (Art. 13(2)); intent_notice and ended are
// informational.
const (
	KindIntentNotice   Kind = "intent_notice"
	KindNonconformance Kind = "nonconformance"
	KindContingent     Kind = "contingent"
	KindEnded          Kind = "ended"
)

// Kinds is every kind.
var Kinds = []Kind{KindIntentNotice, KindNonconformance, KindContingent, KindEnded}

// Valid reports whether k is a kind of the schema.
func (k Kind) Valid() bool {
	switch k {
	case KindIntentNotice, KindNonconformance, KindContingent, KindEnded:
		return true
	}
	return false
}

// AckRequired reports whether a notice of kind k needs a person's
// acknowledgement within notice_escalation_s, else it escalates.
func (k Kind) AckRequired() bool { return k == KindNonconformance || k == KindContingent }

// The nonconformance reasons (the schema's enum).
var nonconformanceReasons = []string{"threshold_exceeded", "constraint_breached", "lost_link", "other"}

// Intent is one intent of a notice as validated.
type Intent struct {
	IntentRef           string
	AuthorisationNumber string
	State               f3548.OperationalIntentState
	TimeStart, TimeEnd  time.Time
	Volumes             []f3548.Volume4D
}

// Decoded is a notice that passed every check: what is stored is the
// body as received (Raw) and these members.
type Decoded struct {
	NoticeRef string
	Kind      Kind
	USSPID    string
	SentAt    time.Time
	Intents   []Intent
	// Raw is the body as received; SHA256 the SHA-256 of its canonical
	// form (keys sorted, no insignificant space), which tells a repeat
	// of the same notice from a reused notice_ref.
	Raw    []byte
	SHA256 []byte
}

// IntentRefs are the intents' refs, once each, in order.
func (d Decoded) IntentRefs() []string {
	out := make([]string, 0, len(d.Intents))
	seen := map[string]bool{}
	for _, in := range d.Intents {
		if !seen[in.IntentRef] {
			seen[in.IntentRef] = true
			out = append(out, in.IntentRef)
		}
	}
	return out
}

// AuthorisationNumbers are the intents' authorisation numbers, once
// each, in order.
func (d Decoded) AuthorisationNumbers() []string {
	out := make([]string, 0, len(d.Intents))
	seen := map[string]bool{}
	for _, in := range d.Intents {
		if !seen[in.AuthorisationNumber] {
			seen[in.AuthorisationNumber] = true
			out = append(out, in.AuthorisationNumber)
		}
	}
	return out
}

// Box is the conservative horizontal box of one volume and its time
// window (uspace-core f3548.Volume4DToZonesEnvelope), in the JSON the
// store's intersection query reads. A box that crosses the antimeridian
// is split in two.
type Box struct {
	MinLon float64   `json:"min_lon"`
	MinLat float64   `json:"min_lat"`
	MaxLon float64   `json:"max_lon"`
	MaxLat float64   `json:"max_lat"`
	TStart time.Time `json:"t_start"`
	TEnd   time.Time `json:"t_end"`
}

// Boxes are the envelopes of every volume of d, each in its own window
// (the volume's times, else its intent's).
func (d Decoded) Boxes() []Box {
	var out []Box
	for _, in := range d.Intents {
		for _, v := range in.Volumes {
			bb, start, end, err := f3548.Volume4DToZonesEnvelope(v)
			if err != nil {
				// Checked at decoding; never reached for a Decoded.
				continue
			}
			if start.IsZero() {
				start = in.TimeStart
			}
			if end.IsZero() {
				end = in.TimeEnd
			}
			out = append(out, split(bb, start, end)...)
		}
	}
	return out
}

func split(bb geodesy.BBox, start, end time.Time) []Box {
	if bb.MinLon <= bb.MaxLon {
		return []Box{{MinLon: bb.MinLon, MinLat: bb.MinLat, MaxLon: bb.MaxLon, MaxLat: bb.MaxLat, TStart: start, TEnd: end}}
	}
	return []Box{
		{MinLon: bb.MinLon, MinLat: bb.MinLat, MaxLon: 180, MaxLat: bb.MaxLat, TStart: start, TEnd: end},
		{MinLon: -180, MinLat: bb.MinLat, MaxLon: bb.MaxLon, MaxLat: bb.MaxLat, TStart: start, TEnd: end},
	}
}

// errs collects field errors up to maxFieldErrors.
type errs struct{ list []*core.FieldError }

func (e *errs) add(field, format string, args ...any) {
	if len(e.list) < maxFieldErrors {
		e.list = append(e.list, core.Fieldf(field, format, args...))
	}
}

func (e *errs) full() bool { return len(e.list) >= maxFieldErrors }

// DecodeNotice reads a coordination/annex_v/v1 body from untrusted bytes
// and checks it member by member: the schema name, notice_ref, kind,
// ussp_id, sent_at, every intent (its F3548 entity id as a UUID, its
// authorisation number, its DSS state, its times in order, and each
// volume through uspace-core's f3548 envelope and altitude checks), the
// nonconformance member a nonconformance notice carries, and remarks.
// Unknown members are accepted and kept (02 section 1, additive). A
// refusal lists every member at fault (at most 101; the problem says
// truncated past 100) and never panics.
func DecodeNotice(body []byte) (Decoded, []*core.FieldError) {
	var e errs
	if len(body) > MaxNoticeBytes {
		e.add("body", "is %d bytes; at most %d", len(body), MaxNoticeBytes)
		return Decoded{}, e.list
	}
	if !utf8.Valid(body) {
		e.add("body", "is not valid UTF-8")
		return Decoded{}, e.list
	}
	var top map[string]json.RawMessage
	if err := strictObject(body, &top); err != nil {
		e.add("body", "is not one JSON object")
		return Decoded{}, e.list
	}
	d := Decoded{Raw: body}
	if s, ok := str(&e, top, "schema", 64); ok && s != SchemaAnnexV {
		e.add("schema", "is %q; this operation takes %s", clipText(s, 64), SchemaAnnexV)
	}
	d.NoticeRef, _ = str(&e, top, "notice_ref", MaxNoticeRefBytes)
	if k, ok := str(&e, top, "kind", 32); ok {
		if !Kind(k).Valid() {
			e.add("kind", "%q is not intent_notice, nonconformance, contingent or ended", clipText(k, 32))
		} else {
			d.Kind = Kind(k)
		}
	}
	d.USSPID, _ = str(&e, top, "ussp_id", MaxUSSPIDBytes)
	d.SentAt, _ = timestamp(&e, top, "sent_at", "sent_at", true)
	d.Intents = intents(&e, top["intents"])
	if d.Kind == KindNonconformance || top["nonconformance"] != nil {
		nonconformance(&e, top["nonconformance"], d.Kind == KindNonconformance)
	}
	if raw, ok := top["remarks"]; ok && !isNull(raw) {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			e.add("remarks", "must be a string")
		} else if len(s) > MaxRemarksBytes {
			e.add("remarks", "is longer than %d bytes", MaxRemarksBytes)
		}
	}
	if len(e.list) > 0 {
		return Decoded{}, e.list
	}
	sum, err := canonicalSHA256(body)
	if err != nil {
		e.add("body", "is not one JSON object")
		return Decoded{}, e.list
	}
	d.SHA256 = sum
	return d, nil
}

// strictObject decodes one JSON object and nothing after it.
func strictObject(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if v, ok := v.(*map[string]json.RawMessage); ok && *v == nil {
		return errors.New("null")
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data")
	}
	return nil
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// str reads a required, non-empty string member of at most maxLen
// bytes.
func str(e *errs, obj map[string]json.RawMessage, name string, maxLen int) (string, bool) {
	return strAt(e, obj, name, name, maxLen)
}

func strAt(e *errs, obj map[string]json.RawMessage, name, path string, maxLen int) (string, bool) {
	raw, ok := obj[name]
	if !ok || isNull(raw) {
		e.add(path, "is required")
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		e.add(path, "must be a string")
		return "", false
	}
	if s == "" || len(s) > maxLen {
		e.add(path, "must be 1 to %d bytes", maxLen)
		return "", false
	}
	return s, true
}

// timestamp reads an RFC 3339 instant (a string member).
func timestamp(e *errs, obj map[string]json.RawMessage, name, path string, required bool) (time.Time, bool) {
	raw, ok := obj[name]
	if !ok || isNull(raw) {
		if required {
			e.add(path, "is required")
		}
		return time.Time{}, false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		e.add(path, "must be an RFC 3339 string")
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		e.add(path, "is not an RFC 3339 instant")
		return time.Time{}, false
	}
	return t.UTC(), true
}

func intents(e *errs, raw json.RawMessage) []Intent {
	if raw == nil || isNull(raw) {
		e.add("intents", "is required")
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		e.add("intents", "must be an array")
		return nil
	}
	switch {
	case len(list) == 0:
		e.add("intents", "is empty; at least one intent")
		return nil
	case len(list) > MaxIntents:
		e.add("intents", "has %d intents; at most %d", len(list), MaxIntents)
		return nil
	}
	out := make([]Intent, 0, len(list))
	for i, r := range list {
		if e.full() {
			break
		}
		if in, ok := intent(e, r, fmt.Sprintf("intents[%d]", i)); ok {
			out = append(out, in)
		}
	}
	return out
}

func intent(e *errs, raw json.RawMessage, path string) (Intent, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		e.add(path, "must be an object")
		return Intent{}, false
	}
	n := len(e.list)
	var in Intent
	if ref, ok := strAt(e, obj, "intent_ref", path+".intent_ref", 64); ok {
		if !isUUID(ref) {
			e.add(path+".intent_ref", "is not a UUID")
		}
		in.IntentRef = strings.ToLower(ref)
	}
	in.AuthorisationNumber, _ = strAt(e, obj, "authorisation_number", path+".authorisation_number", MaxAuthorisationBytes)
	if st, ok := strAt(e, obj, "state", path+".state", 32); ok {
		in.State = f3548.OperationalIntentState(st)
		if !in.State.Valid() {
			e.add(path+".state", "%q is not Accepted, Activated, Nonconforming or Contingent", clipText(st, 32))
		}
	}
	start, okS := timestamp(e, obj, "time_start", path+".time_start", true)
	end, okE := timestamp(e, obj, "time_end", path+".time_end", true)
	if okS && okE && end.Before(start) {
		e.add(path+".time_end", "is before time_start")
	}
	in.TimeStart, in.TimeEnd = start, end
	in.Volumes = volumes(e, obj["volumes"], path+".volumes")
	return in, len(e.list) == n
}

// isUUID reports whether s is a UUID in its canonical 36-character form.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	_, err := uuid.Parse(s)
	return err == nil
}

func volumes(e *errs, raw json.RawMessage, path string) []f3548.Volume4D {
	if raw == nil || isNull(raw) {
		e.add(path, "is required")
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		e.add(path, "must be an array")
		return nil
	}
	switch {
	case len(list) == 0:
		e.add(path, "is empty; at least one volume")
		return nil
	case len(list) > MaxVolumes:
		e.add(path, "has %d volumes; at most %d", len(list), MaxVolumes)
		return nil
	}
	out := make([]f3548.Volume4D, 0, len(list))
	for i, r := range list {
		if e.full() {
			break
		}
		here := fmt.Sprintf("%s[%d]", path, i)
		var v f3548.Volume4D
		if err := json.Unmarshal(r, &v); err != nil {
			e.add(here, "is not an F3548 Volume4D: %s", typeReason(err))
			continue
		}
		// The F3548 checks are uspace-core's (CLAUDE.md rule 3): the
		// outline, the times and the altitudes' reference and units.
		if _, _, _, err := f3548.Volume4DToZonesEnvelope(v); err != nil {
			e.add(here+"."+fieldOf(err), "%s", reasonOf(err))
			continue
		}
		lo, okLo := altitude(e, v.Volume.AltitudeLower, here+".volume.altitude_lower")
		hi, okHi := altitude(e, v.Volume.AltitudeUpper, here+".volume.altitude_upper")
		if okLo && okHi && lo > hi {
			e.add(here+".volume.altitude_upper", "is below altitude_lower")
		}
		out = append(out, v)
	}
	return out
}

func altitude(e *errs, a *f3548.Altitude, path string) (float64, bool) {
	if a == nil {
		return 0, false
	}
	v, err := a.HAEM()
	if err != nil {
		e.add(path+"."+fieldOf(err), "%s", reasonOf(err))
		return 0, false
	}
	return v, true
}

// fieldOf and reasonOf split core's field error.
func fieldOf(err error) string {
	var fe *core.FieldError
	if errors.As(err, &fe) && fe.Field != "" {
		return fe.Field
	}
	return "value"
}

func reasonOf(err error) string {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return fe.Reason
	}
	return clipText(err.Error(), 200)
}

// typeReason names a JSON type error without echoing the value sent.
func typeReason(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return te.Field + " must be " + te.Type.String()
	}
	return "malformed"
}

func nonconformance(e *errs, raw json.RawMessage, required bool) {
	const path = "nonconformance"
	if raw == nil || isNull(raw) {
		if required {
			e.add(path, "is required for a nonconformance notice")
		}
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		e.add(path, "must be an object")
		return
	}
	if ref, ok := strAt(e, obj, "intent_ref", path+".intent_ref", 64); ok && !isUUID(ref) {
		e.add(path+".intent_ref", "is not a UUID")
	}
	_, _ = strAt(e, obj, "authorisation_number", path+".authorisation_number", MaxAuthorisationBytes)
	_, _ = timestamp(e, obj, "detected_at", path+".detected_at", true)
	if r, ok := strAt(e, obj, "reason", path+".reason", 32); ok && !contains(nonconformanceReasons, r) {
		e.add(path+".reason", "%q is not threshold_exceeded, constraint_breached, lost_link or other", clipText(r, 32))
	}
	for _, name := range []string{"distance_outside_m", "height_over_m"} {
		if raw, ok := obj[name]; ok && !isNull(raw) {
			var v float64
			if json.Unmarshal(raw, &v) != nil || !core.IsFinite(v) || v < 0 {
				e.add(path+"."+name, "must be a number of metres, at least 0")
			}
		}
	}
	if raw, ok := obj["position"]; ok && !isNull(raw) {
		var p struct {
			Lat *float64 `json:"lat"`
			Lng *float64 `json:"lng"`
		}
		if json.Unmarshal(raw, &p) != nil || p.Lat == nil || p.Lng == nil ||
			!(core.LatLon{LatDeg: *p.Lat, LonDeg: *p.Lng}).Valid() {
			e.add(path+".position", "must be {lat, lng} in WGS84 degrees")
		}
	}
	if raw, ok := obj["alt_wgs84_m"]; ok && !isNull(raw) {
		var v float64
		if json.Unmarshal(raw, &v) != nil || !core.IsFinite(v) {
			e.add(path+".alt_wgs84_m", "must be a number of metres")
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// clipText bounds a value echoed in a reason.
func clipText(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// canonicalSHA256 is the SHA-256 of b's canonical JSON: decoded and
// encoded again (encoding/json sorts the keys of a map and writes no
// insignificant space), with numbers kept as written.
func canonicalSHA256(b []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	c, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return sum[:], nil
}
