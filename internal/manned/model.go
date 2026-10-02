package manned

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// The constants of track/manned/v1 (schemas/track/manned/v1.json, owned
// here; spec 04 §2, §3.1).
const (
	// SchemaTrack is the schema name of a manned track.
	SchemaTrack = "track/manned/v1"
	// SourceANSPFeed is the adapter type of every manned track (04 §2).
	SourceANSPFeed = "ansp_feed"
	// StateLive is the only state an adapter publishes; manned-feed ages
	// a track into stale or source_disabled (WP-6).
	StateLive = "live"
	// Producer names this process in the envelope (`<system>/<process>`).
	Producer = "ansp/manned-adapter"
)

// The surveillance source classes (02 F4; the schema's enum).
const (
	SourceClassADSB    = "ads_b"
	SourceClassModeS   = "mode_s"
	SourceClassSSR     = "ssr"
	SourceClassATMFeed = "atm_feed"
	SourceClassADSL    = "ads_l"
)

// SourceClasses is every source class, in the schema's order.
var SourceClasses = []string{SourceClassADSB, SourceClassModeS, SourceClassSSR, SourceClassATMFeed, SourceClassADSL}

// ValidSourceClass reports whether c is one of SourceClasses.
func ValidSourceClass(c string) bool {
	for _, s := range SourceClasses {
		if s == c {
			return true
		}
	}
	return false
}

var (
	icao24Pattern   = regexp.MustCompile(`^[0-9a-f]{6}$`)
	squawkPattern   = regexp.MustCompile(`^[0-7]{4}$`)
	instancePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	callsignPattern = regexp.MustCompile(`^[\x21-\x7e]( ?[\x21-\x7e])*$`)
)

// MaxCallsignLen is the schema's maxLength of callsign.
const MaxCallsignLen = 8

// MaxInstanceLen is the schema's maxLength of source_instance.
const MaxInstanceLen = 64

// ValidInstance reports whether id is a valid adapter instance id: the
// schema's source_instance pattern, at most 64 characters. It is also a
// single NATS subject token.
func ValidInstance(id string) bool {
	return len(id) <= MaxInstanceLen && instancePattern.MatchString(id)
}

// Track is one manned aircraft as the adapter hands it to U-space
// (track/manned/v1). Altitudes are kept by definition, never converted
// into each other (D-03): AltPressureM is barometric (ISA 1013.25 hPa)
// and never an AMSL value, AltWGS84M is geometric height above the
// ellipsoid when the feed gives one.
type Track struct {
	Schema   string
	MsgID    string
	Producer string
	// Times: TS is the feed's clock (nil when the feed gives none),
	// RxTS the adapter's clock at read, CapturedAt the placement.
	Times          core.Times
	Trust          core.Trust
	Source         string
	SourceInstance string
	ICAO24         string
	Callsign       *string
	Position       core.LatLon
	AltPressureM   *float64
	AltWGS84M      *float64
	GSMS           *float64
	TrackDeg       *float64
	VRateMS        *float64
	Emergency      *bool
	SPI            *bool
	Squawk         *string
	SourceClass    string
	// Quality is the feed's quality block as received (NIC, NACp, ...),
	// bounded by Policy.MaxQualityKeys.
	Quality       map[string]any
	PolicyVersion uint64
}

// Validate is ValidateWith under the default policy.
func (t *Track) Validate() error {
	d := Defaults()
	return t.ValidateWith(&d)
}

// ValidateWith checks every member against track/manned/v1 and the
// bounds of pol. The error joins one *core.FieldError per problem, each
// naming the member by its JSON name.
func (t *Track) ValidateWith(pol *Policy) error {
	var errs []error
	add := func(field, format string, args ...any) { errs = append(errs, core.Fieldf(field, format, args...)) }
	if t.Schema != SchemaTrack {
		add("schema", "must be %s", SchemaTrack)
	}
	if t.MsgID == "" {
		add("msg_id", "required")
	}
	if t.Producer == "" {
		add("producer", "required")
	}
	if t.Times.RxTS.IsZero() || t.Times.CapturedAt.IsZero() {
		add("captured_at", "rx_ts and captured_at are required")
	}
	if t.Trust != core.TrustSurveillance {
		add("trust", "must be surveillance")
	}
	if t.Source != SourceANSPFeed {
		add("source", "must be %s", SourceANSPFeed)
	}
	if !ValidInstance(t.SourceInstance) {
		add("source_instance", "must match ^[a-z][a-z0-9]*(-[a-z0-9]+)*$, at most 64 characters")
	}
	if !icao24Pattern.MatchString(t.ICAO24) {
		add("icao24", "must be six lower-case hex digits")
	}
	if !t.Position.Valid() {
		add("position", "latitude and longitude must be finite and in range")
	}
	if t.Callsign != nil && !ValidCallsign(*t.Callsign) {
		add("callsign", "must be 1-8 printable characters")
	}
	if t.Squawk != nil && !squawkPattern.MatchString(*t.Squawk) {
		add("squawk", "must be four octal digits")
	}
	if !ValidSourceClass(t.SourceClass) {
		add("source_class", "unknown source class")
	}
	for _, f := range t.numbers(pol) {
		if f.v == nil {
			continue
		}
		if !core.IsFinite(*f.v) || *f.v < f.lo || *f.v > f.hi || (f.openHi && *f.v == f.hi) {
			add(f.name, "%s is outside its bounds", strconv.FormatFloat(*f.v, 'g', -1, 64))
		}
	}
	if len(t.Quality) > pol.MaxQualityKeys {
		add("quality", "more than %d members", pol.MaxQualityKeys)
	}
	return errors.Join(errs...)
}

// ValidCallsign reports whether c is a callsign as the schema allows it:
// 1-8 printable ASCII characters, trimmed.
func ValidCallsign(c string) bool {
	return len(c) <= MaxCallsignLen && callsignPattern.MatchString(c)
}

// ValidSquawk reports whether s is four octal digits.
func ValidSquawk(s string) bool { return squawkPattern.MatchString(s) }

// ValidICAO24 reports whether s is six lower-case hex digits.
func ValidICAO24(s string) bool { return icao24Pattern.MatchString(s) }

type numberField struct {
	name   string
	v      *float64
	lo, hi float64
	openHi bool
}

// numbers are the optional numeric members with their bounds.
func (t *Track) numbers(pol *Policy) []numberField {
	return []numberField{
		{name: "alt_pressure_m", v: t.AltPressureM, lo: pol.MinAltM, hi: pol.MaxAltM},
		{name: "alt_wgs84_m", v: t.AltWGS84M, lo: pol.MinAltM, hi: pol.MaxAltM},
		{name: "gs_ms", v: t.GSMS, lo: 0, hi: pol.MaxGSMS},
		{name: "track_deg", v: t.TrackDeg, lo: 0, hi: 360, openHi: true},
		{name: "vrate_ms", v: t.VRateMS, lo: -pol.MaxVRateMS, hi: pol.MaxVRateMS},
	}
}

// Subject is the NATS subject of t: man.v1.<adapter>.<icao24> (D2).
func (t *Track) Subject(prefix string) string {
	return prefix + t.SourceInstance + "." + t.ICAO24
}

// FormatTime is the envelope's timestamp: RFC 3339 UTC with Z and
// millisecond precision (02 §1).
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
