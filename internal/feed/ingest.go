package feed

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// MaxMessageBytes bounds one message read from the bus (E-10): a
// track/manned/v1 sample or a source/status/v1 body.
const MaxMessageBytes = 16 << 10

// wireTrack is track/manned/v1 as the adapter publishes it on
// man.v1.<adapter>.<icao24> (manned.Track.Envelope; schemas/track/
// manned/v1.json). Unknown members are ignored within the major (04 §4).
type wireTrack struct {
	Schema     string         `json:"schema"`
	MsgID      string         `json:"msg_id"`
	Producer   string         `json:"producer"`
	TS         *string        `json:"ts"`
	RxTS       string         `json:"rx_ts"`
	CapturedAt string         `json:"captured_at"`
	TimeSource string         `json:"time_source"`
	Backlog    *bool          `json:"backlog"`
	Body       *wireTrackBody `json:"body"`
}

type wireTrackBody struct {
	ICAO24   string  `json:"icao24"`
	Callsign *string `json:"callsign"`
	Position *struct {
		Lat *float64 `json:"lat"`
		Lng *float64 `json:"lng"`
	} `json:"position"`
	AltPressureM   *float64       `json:"alt_pressure_m"`
	AltWGS84M      *float64       `json:"alt_wgs84_m"`
	GSMS           *float64       `json:"gs_ms"`
	TrackDeg       *float64       `json:"track_deg"`
	VRateMS        *float64       `json:"vrate_ms"`
	Emergency      *bool          `json:"emergency"`
	SPI            *bool          `json:"spi"`
	Squawk         *string        `json:"squawk"`
	SourceClass    string         `json:"source_class"`
	Quality        map[string]any `json:"quality"`
	Trust          string         `json:"trust"`
	Source         string         `json:"source"`
	SourceInstance string         `json:"source_instance"`
	State          string         `json:"state"`
	PolicyVersion  string         `json:"policy_version"`
}

var timeSources = map[string]core.TimeSource{
	string(core.TimeSourceClock): core.TimeSourceClock,
	string(core.TimeBroadcast):   core.TimeBroadcast,
	string(core.TimeReceiver):    core.TimeReceiver,
	string(core.TimeProvider):    core.TimeProvider,
	string(core.TimeSystem):      core.TimeSystem,
}

func parseTime(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, core.Fieldf(field, "not an RFC 3339 UTC timestamp")
	}
	return t.UTC(), nil
}

// DecodeTrack decodes one track/manned/v1 message from the bus and
// validates it against the schema and the bounds of pol (the adapter's,
// manned.Defaults). Only state live is taken: an adapter never publishes
// another (manned-feed ages tracks itself). It never panics; every
// refusal is a *core.FieldError naming the member.
func DecodeTrack(data []byte, pol *manned.Policy) (manned.Track, error) {
	if len(data) > MaxMessageBytes {
		return manned.Track{}, core.Fieldf("message", "longer than %d bytes", MaxMessageBytes)
	}
	var w wireTrack
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&w); err != nil {
		return manned.Track{}, core.Fieldf("message", "not a JSON object")
	}
	switch {
	case w.Schema != manned.SchemaTrack:
		return manned.Track{}, core.Fieldf("schema", "must be %s", manned.SchemaTrack)
	case w.Body == nil:
		return manned.Track{}, core.Fieldf("body", "required")
	case w.Body.Position == nil || w.Body.Position.Lat == nil || w.Body.Position.Lng == nil:
		return manned.Track{}, core.Fieldf("body.position", "lat and lng are required")
	case w.Backlog == nil:
		return manned.Track{}, core.Fieldf("backlog", "required")
	case w.Body.State != manned.StateLive:
		return manned.Track{}, core.Fieldf("body.state", "an adapter publishes live only")
	}
	ts, ok := timeSources[w.TimeSource]
	if !ok {
		return manned.Track{}, core.Fieldf("time_source", "unknown")
	}
	rx, err := parseTime("rx_ts", w.RxTS)
	if err != nil {
		return manned.Track{}, err
	}
	captured, err := parseTime("captured_at", w.CapturedAt)
	if err != nil {
		return manned.Track{}, err
	}
	b := w.Body
	t := manned.Track{
		Schema: w.Schema, MsgID: w.MsgID, Producer: w.Producer,
		Times: core.Times{RxTS: rx, CapturedAt: captured, Source: ts, Backlog: *w.Backlog},
		Trust: core.Trust(b.Trust), Source: b.Source, SourceInstance: b.SourceInstance, ICAO24: b.ICAO24,
		Callsign: b.Callsign, Position: core.LatLon{LatDeg: *b.Position.Lat, LonDeg: *b.Position.Lng},
		AltPressureM: b.AltPressureM, AltWGS84M: b.AltWGS84M, GSMS: b.GSMS, TrackDeg: b.TrackDeg, VRateMS: b.VRateMS,
		Emergency: b.Emergency, SPI: b.SPI, Squawk: b.Squawk, SourceClass: b.SourceClass, Quality: b.Quality,
	}
	if w.TS != nil {
		at, err := parseTime("ts", *w.TS)
		if err != nil {
			return manned.Track{}, err
		}
		t.Times.TS = &at
	}
	if b.PolicyVersion != "" {
		v, err := strconv.ParseUint(b.PolicyVersion, 10, 64)
		if err != nil {
			return manned.Track{}, core.Fieldf("body.policy_version", "not a version")
		}
		t.PolicyVersion = v
	}
	if !ulidLike(t.MsgID) {
		return manned.Track{}, core.Fieldf("msg_id", "not a ULID")
	}
	if err := t.ValidateWith(pol); err != nil {
		return manned.Track{}, err
	}
	return t, nil
}

// ulidLike is the envelope's msg_id pattern: Crockford base32, 26
// characters, the first 0-7.
func ulidLike(s string) bool {
	if len(s) != 26 || s[0] < '0' || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U':
		default:
			return false
		}
	}
	return true
}

// SubjectAdapter is the adapter instance of a man.v1.<adapter>.<icao24>
// or src.v1.manned.<adapter> subject, after prefix; "" when the subject
// has no such token.
func SubjectAdapter(subject, prefix string) string {
	rest, ok := strings.CutPrefix(subject, prefix)
	if !ok || rest == "" {
		return ""
	}
	inst, _, _ := strings.Cut(rest, ".")
	return inst
}
