package feed

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/picture"
)

// The schemas of the frames (M12, M29; schemas/common/console/*). There
// is no feed/status/v1.
const (
	SchemaStatus    = "console/status/v1"
	SchemaSnapshot  = "console/snapshot/v1"
	SchemaSubscribe = "console/subscribe/v1"
	// Producer names this process in every envelope it writes.
	Producer = "ansp/manned-feed"
)

// TrackBody is the body of a track/manned/v1 frame of this process: the
// adapter's members with the state the picture gives it, relevant (B-12)
// and age_s, the seconds since captured_at when the frame was written
// (B-13: an age is shown, never hidden).
type TrackBody struct {
	manned.TrackBody
	Relevant bool    `json:"relevant"`
	AgeS     float64 `json:"age_s"`
}

// TrackEnvelope is one entry as a track/manned/v1 message: the sample's
// own times and backlog flag (never restamped), a new msg_id and this
// process as producer.
func TrackEnvelope(e *picture.Entry, now time.Time) manned.Envelope {
	env := e.Track.Envelope()
	body, _ := env.Body.(manned.TrackBody)
	body.State = string(e.State)
	if e.State == picture.StateBacklogOnly {
		body.State = string(picture.StateStale)
	}
	env.MsgID = manned.NewULID(now)
	env.Producer = Producer
	env.Body = TrackBody{TrackBody: body, Relevant: e.Relevance.Relevant, AgeS: e.AgeS}
	return env
}

// systemEnvelope is a frame this process originates (status, snapshot):
// placed at now on its own clock, no source time.
func systemEnvelope(schema string, now time.Time, body any) manned.Envelope {
	at := manned.FormatTime(now)
	return manned.Envelope{Schema: schema, MsgID: manned.NewULID(now), Producer: Producer, RxTS: at, CapturedAt: at,
		TimeSource: string(core.TimeSystem), Body: body}
}

// StatusBody is the body of console/status/v1 with this system's extras
// (adapters, cis_version, cis_age_s, nats; M29) and relevance, the
// relevance filter's line (SC-22).
type StatusBody struct {
	ConnectionID  string            `json:"connection_id"`
	ServerTS      string            `json:"server_ts"`
	PolicyVersion string            `json:"policy_version"`
	StaleAfterS   float64           `json:"stale_after_s"`
	LiveMaxAgeS   float64           `json:"live_max_age_s"`
	DroppedFrames int64             `json:"dropped_frames"`
	Degraded      []string          `json:"degraded"`
	Sources       []json.RawMessage `json:"sources"`
	Adapters      []AdapterState    `json:"adapters"`
	CISVersion    string            `json:"cis_version,omitempty"`
	CISAgeS       *float64          `json:"cis_age_s,omitempty"`
	NATS          string            `json:"nats"`
	Relevance     string            `json:"relevance"`
}

// SnapshotBody is the body of console/snapshot/v1: tracks and alerts are
// always empty here (no UAS), manned holds the track/manned/v1 messages.
type SnapshotBody struct {
	Tracks       []json.RawMessage `json:"tracks"`
	Alerts       []json.RawMessage `json:"alerts"`
	Manned       []manned.Envelope `json:"manned"`
	ZonesVersion *string           `json:"zones_version"`
}

// MannedSnapshot is the answer of GET /v1/manned-traffic/snapshot: the
// snapshot body plus what is degraded, every adapter, the CIS version
// the relevance filter used and its age, the policy_version and when it
// was generated.
type MannedSnapshot struct {
	SnapshotBody
	Degraded      []string       `json:"degraded"`
	Adapters      []AdapterState `json:"adapters"`
	CISVersion    *string        `json:"cis_version"`
	CISAgeS       *float64       `json:"cis_age_s"`
	PolicyVersion string         `json:"policy_version"`
	GeneratedAt   string         `json:"generated_at"`
}

// Subscribe is the client's console/subscribe/v1 body.
type Subscribe struct {
	BBox   *geodesy.BBox
	Layers []string
}

// MaxClientFrameBytes bounds one client frame.
const MaxClientFrameBytes = 4 << 10

var layerNames = map[string]bool{"tracks": true, "manned": true, "alerts": true, "zones": true}

// DecodeSubscribe decodes a console/subscribe/v1 frame strictly (the
// pinned schema's members and enums), bounded.
func DecodeSubscribe(data []byte) (Subscribe, error) {
	if len(data) > MaxClientFrameBytes {
		return Subscribe{}, core.Fieldf("frame", "longer than %d bytes", MaxClientFrameBytes)
	}
	var f struct {
		Schema string `json:"schema"`
		MsgID  string `json:"msg_id"`
		Body   *struct {
			BBox   []float64 `json:"bbox"`
			Layers []string  `json:"layers"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return Subscribe{}, core.Fieldf("frame", "not a JSON object")
	}
	switch {
	case f.Schema != SchemaSubscribe:
		return Subscribe{}, core.Fieldf("schema", "must be %s", SchemaSubscribe)
	case f.MsgID != "" && !ulidLike(f.MsgID):
		return Subscribe{}, core.Fieldf("msg_id", "not a ULID")
	case f.Body == nil || f.Body.Layers == nil:
		return Subscribe{}, core.Fieldf("body", "bbox and layers are required")
	case len(f.Body.BBox) != 4:
		return Subscribe{}, core.Fieldf("body.bbox", "four numbers [west, south, east, north]")
	}
	box, err := bboxOf(f.Body.BBox[0], f.Body.BBox[1], f.Body.BBox[2], f.Body.BBox[3], "body.bbox")
	if err != nil {
		return Subscribe{}, err
	}
	seen := map[string]bool{}
	for _, l := range f.Body.Layers {
		if !layerNames[l] || seen[l] {
			return Subscribe{}, core.Fieldf("body.layers", "unknown or repeated layer")
		}
		seen[l] = true
	}
	return Subscribe{BBox: &box, Layers: f.Body.Layers}, nil
}

// ParseBBox parses the bbox query parameter: west,south,east,north in
// WGS84 degrees ([lng, lat], RFC 7946 section 5); west > east crosses
// the antimeridian. "" is no box.
func ParseBBox(s string) (*geodesy.BBox, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) > 96 {
		return nil, core.Fieldf("bbox", "longer than 96 characters")
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, core.Fieldf("bbox", "west,south,east,north")
	}
	var v [4]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return nil, core.Fieldf("bbox", "west,south,east,north in decimal degrees")
		}
		v[i] = f
	}
	box, err := bboxOf(v[0], v[1], v[2], v[3], "bbox")
	if err != nil {
		return nil, err
	}
	return &box, nil
}

func bboxOf(west, south, east, north float64, field string) (geodesy.BBox, error) {
	for _, lon := range []float64{west, east} {
		if !core.IsFinite(lon) || lon < -180 || lon > 180 {
			return geodesy.BBox{}, core.Fieldf(field, "longitude outside [-180, 180]")
		}
	}
	for _, lat := range []float64{south, north} {
		if !core.IsFinite(lat) || lat < -90 || lat > 90 {
			return geodesy.BBox{}, core.Fieldf(field, "latitude outside [-90, 90]")
		}
	}
	if south > north {
		return geodesy.BBox{}, core.Fieldf(field, "south is above north")
	}
	return geodesy.BBox{MinLat: south, MinLon: west, MaxLat: north, MaxLon: east}, nil
}
