package manned_test

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
)

// One test per conversion constant (WP-4), each against an exact
// definition: 1 ft = 0.3048 m, 1 kt = 1852 m / 3600 s, 1 ft/min =
// 0.3048 m / 60 s.
func TestFeetToMetres(t *testing.T) {
	if manned.FeetToMetres != 0.3048 || manned.FeetToM(10000) != 3048 {
		t.Fatal(manned.FeetToM(10000))
	}
}

func TestKnotsToMetresPerSecond(t *testing.T) {
	if got := manned.KnotsToMS(3600); math.Abs(got-1852) > 1e-9 {
		t.Fatal(got)
	}
	if got := manned.KnotsToMS(140); math.Abs(got-72.0222222) > 1e-6 {
		t.Fatal(got)
	}
}

func TestFeetPerMinuteToMetresPerSecond(t *testing.T) {
	if got := manned.FeetPerMinToMS(60); math.Abs(got-0.3048) > 1e-12 {
		t.Fatal(got)
	}
	if got := manned.FeetPerMinToMS(-1000); math.Abs(got+5.08) > 1e-12 {
		t.Fatal(got)
	}
}

func validTrack() manned.Track {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return manned.Track{
		Schema: manned.SchemaTrack, MsgID: manned.ULIDWithEntropy(at, [10]byte{1}), Producer: manned.Producer,
		Times: core.Times{TS: manned.T(at), RxTS: at.Add(180 * time.Millisecond), CapturedAt: at, Source: core.TimeSourceClock},
		Trust: core.TrustSurveillance, Source: manned.SourceANSPFeed, SourceInstance: "adsb-tbs",
		ICAO24: "f0a001", Callsign: manned.S("SYN001"), Position: core.LatLon{LatDeg: 41.721, LonDeg: 44.793},
		AltPressureM: manned.F(1524), AltWGS84M: manned.F(1561), GSMS: manned.F(72.5), TrackDeg: manned.F(134),
		VRateMS: manned.F(-2.5), Emergency: manned.B(false), Squawk: manned.S("4521"), SourceClass: manned.SourceClassADSB,
		Quality: map[string]any{"nic": 8.0}, PolicyVersion: 3,
	}
}

func TestValidateAcceptsAValidTrack(t *testing.T) {
	tr := validTrack()
	if err := tr.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every member the schema bounds is refused by name (E-01 twin of the
// valid track above).
func TestValidateRefusesEachMemberByName(t *testing.T) {
	cases := map[string]func(*manned.Track){
		"schema":          func(tr *manned.Track) { tr.Schema = "track/manned/v2" },
		"msg_id":          func(tr *manned.Track) { tr.MsgID = "" },
		"producer":        func(tr *manned.Track) { tr.Producer = "" },
		"captured_at":     func(tr *manned.Track) { tr.Times.CapturedAt = time.Time{} },
		"trust":           func(tr *manned.Track) { tr.Trust = core.TrustSimulated },
		"source":          func(tr *manned.Track) { tr.Source = "sitl" },
		"source_instance": func(tr *manned.Track) { tr.SourceInstance = "ADSB" },
		"icao24":          func(tr *manned.Track) { tr.ICAO24 = "F0A001" },
		"position":        func(tr *manned.Track) { tr.Position.LatDeg = math.NaN() },
		"callsign":        func(tr *manned.Track) { tr.Callsign = manned.S("TOOLONG123") },
		"squawk":          func(tr *manned.Track) { tr.Squawk = manned.S("7800") },
		"source_class":    func(tr *manned.Track) { tr.SourceClass = "radar" },
		"alt_pressure_m":  func(tr *manned.Track) { tr.AltPressureM = manned.F(math.Inf(1)) },
		"alt_wgs84_m":     func(tr *manned.Track) { tr.AltWGS84M = manned.F(99999) },
		"gs_ms":           func(tr *manned.Track) { tr.GSMS = manned.F(-1) },
		"track_deg":       func(tr *manned.Track) { tr.TrackDeg = manned.F(360) },
		"vrate_ms":        func(tr *manned.Track) { tr.VRateMS = manned.F(-500) },
		"quality": func(tr *manned.Track) {
			tr.Quality = map[string]any{}
			for i := range 40 {
				tr.Quality[strings.Repeat("k", i+1)] = 1.0
			}
		},
	}
	for field, edit := range cases {
		t.Run(field, func(t *testing.T) {
			tr := validTrack()
			edit(&tr)
			err := tr.Validate()
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != field {
				t.Fatalf("got %v, want a refusal of %s", err, field)
			}
		})
	}
}

// The wire form validates against schemas/track/manned/v1.json, ts
// present and absent; and the schema refuses what Validate refuses, so
// the check is not vacuous (E-01).
func TestEnvelopeValidatesAgainstTheSchema(t *testing.T) {
	sch := schematest.Compile(t, schematest.TrackManned)
	tr := validTrack()
	raw, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := schematest.Validate(t, sch, raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	tr.Times.TS, tr.Times.Source = nil, core.TimeSystem
	tr.Callsign, tr.AltPressureM, tr.GSMS, tr.Quality = nil, nil, nil, nil
	raw, _ = json.Marshal(&tr)
	if err := schematest.Validate(t, sch, raw); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if !strings.Contains(string(raw), `"ts":null`) || !strings.Contains(string(raw), `"alt_pressure_m":null`) {
		t.Fatalf("absent members are not null: %s", raw)
	}
	tr.ICAO24 = "F0A001"
	raw, _ = json.Marshal(&tr)
	if err := schematest.Validate(t, sch, raw); err == nil {
		t.Fatal("the schema accepted an upper-case icao24")
	}
}

func TestEnvelopeFields(t *testing.T) {
	tr := validTrack()
	e := tr.Envelope()
	body := e.Body.(manned.TrackBody)
	if e.Schema != "track/manned/v1" || e.Producer != "ansp/manned-adapter" || *e.TS != "2026-10-02T12:00:00.000Z" ||
		e.RxTS != "2026-10-02T12:00:00.180Z" || e.TimeSource != "source_clock" || e.Backlog ||
		body.State != "live" || body.Trust != "surveillance" || body.Source != "ansp_feed" || body.PolicyVersion != "3" ||
		body.Position.Lat != 41.721 || body.Position.Lng != 44.793 {
		t.Fatalf("%+v %+v", e, body)
	}
	if got := tr.Subject("man.v1."); got != "man.v1.adsb-tbs.f0a001" {
		t.Fatal(got)
	}
}

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func TestULID(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	a, b := manned.NewULID(at), manned.NewULID(at.Add(time.Millisecond))
	if !ulidPattern.MatchString(a) || !ulidPattern.MatchString(b) || a[:10] >= b[:10] {
		t.Fatalf("%s %s", a, b)
	}
	if a == manned.NewULID(at) {
		t.Fatal("two ULIDs of the same millisecond are equal")
	}
	// The time part encodes milliseconds since the epoch.
	if got := manned.ULIDWithEntropy(time.UnixMilli(0), [10]byte{}); got != strings.Repeat("0", 26) {
		t.Fatal(got)
	}
	if got := manned.ULIDWithEntropy(time.UnixMilli(1), [10]byte{}); got != "0000000001"+strings.Repeat("0", 16) {
		t.Fatal(got)
	}
	for _, edge := range []time.Time{time.Unix(-5, 0), time.Date(20000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if got := manned.ULIDWithEntropy(edge, [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); !ulidPattern.MatchString(got) {
			t.Fatalf("%v: %s", edge, got)
		}
	}
}

func TestPolicyDefaultsValidate(t *testing.T) {
	p := manned.Defaults()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.StallAfterS != 5 || p.DedupeWindowS != 2 || p.StatusPeriodS != 2 || p.PollPeriodS != 1 || p.MaxSpacingS != 120 {
		t.Fatalf("%+v", p)
	}
}

func TestPolicyRefusesADisarmingValue(t *testing.T) {
	for field, edit := range map[string]func(*manned.Policy){
		"stall_after_s":   func(p *manned.Policy) { p.StallAfterS = 0 },
		"dedupe_window_s": func(p *manned.Policy) { p.DedupeWindowS = math.NaN() },
		"max_aircraft":    func(p *manned.Policy) { p.MaxAircraft = 0 },
		"min_alt_m":       func(p *manned.Policy) { p.MinAltM = p.MaxAltM },
		"reconnect_min_s": func(p *manned.Policy) { p.ReconnectMinS = p.ReconnectMaxS + 1 },
	} {
		p := manned.Defaults()
		edit(&p)
		err := p.Validate()
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != field {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestSeconds(t *testing.T) {
	for in, want := range map[float64]time.Duration{
		1.5: 1500 * time.Millisecond, 0: 0, -3: 0, math.NaN(): 0, 1e12: 24 * time.Hour, 0.0000004: 0,
	} {
		if got := manned.Seconds(in); got != want {
			t.Errorf("Seconds(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestStaticPolicy(t *testing.T) {
	p, v := manned.StaticPolicy{Policy: manned.Defaults(), Version: 7}.Current()
	if v != 7 || p.StallAfterS != 5 {
		t.Fatal(v, p)
	}
}

// Logged once per aircraft per period (presence: the first and the one
// after the period; absence: the one inside it), bounded memory.
func TestRefusalLimiter(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	l := manned.NewRefusalLimiter(time.Minute, 2)
	if !l.Allow("a", at) || l.Allow("a", at.Add(59*time.Second)) || !l.Allow("a", at.Add(time.Minute)) {
		t.Fatal("once per minute per aircraft")
	}
	if !l.Allow("b", at) {
		t.Fatal("another aircraft is logged")
	}
	if l.Allow("c", at.Add(time.Second)) {
		t.Fatal("a full limiter whose entries are all recent logged a third aircraft")
	}
	if !l.Allow("c", at.Add(3*time.Minute)) {
		t.Fatal("a full limiter did not forget old entries")
	}
	if !manned.NewRefusalLimiter(time.Minute, 0).Allow("x", at) {
		t.Fatal("a zero bound is one")
	}
}

func TestSourceClasses(t *testing.T) {
	for _, c := range manned.SourceClasses {
		if !manned.ValidSourceClass(c) {
			t.Fatal(c)
		}
	}
	if manned.ValidSourceClass("radar") || !manned.ValidInstance("adsb-tbs") || manned.ValidInstance("adsb.tbs") ||
		manned.ValidInstance(strings.Repeat("a", 65)) {
		t.Fatal("instance or class check")
	}
}
