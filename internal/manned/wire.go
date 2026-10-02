package manned

import (
	"encoding/json"
	"strconv"
)

// Envelope is the common envelope of spec 04 §2
// (schemas/common/envelope/v1/schema.json) around a body named by
// Schema. ts is null when the record carried none (T-12).
type Envelope struct {
	Schema     string  `json:"schema"`
	MsgID      string  `json:"msg_id"`
	Producer   string  `json:"producer"`
	TS         *string `json:"ts"`
	RxTS       string  `json:"rx_ts"`
	CapturedAt string  `json:"captured_at"`
	TimeSource string  `json:"time_source"`
	Backlog    bool    `json:"backlog"`
	Body       any     `json:"body"`
}

// PositionBody is the body's position (lat, lng; the schema's names).
type PositionBody struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

// TrackBody is the body of track/manned/v1. Members the schema requires
// are always present (null when unknown); relevant is manned-feed's
// judgement (WP-6, B-12) and never set here.
type TrackBody struct {
	ICAO24         string         `json:"icao24"`
	Callsign       *string        `json:"callsign"`
	Position       PositionBody   `json:"position"`
	AltPressureM   *float64       `json:"alt_pressure_m"`
	AltWGS84M      *float64       `json:"alt_wgs84_m"`
	GSMS           *float64       `json:"gs_ms"`
	TrackDeg       *float64       `json:"track_deg"`
	VRateMS        *float64       `json:"vrate_ms"`
	Emergency      *bool          `json:"emergency"`
	SPI            *bool          `json:"spi"`
	Squawk         *string        `json:"squawk"`
	SourceClass    string         `json:"source_class"`
	Quality        map[string]any `json:"quality,omitempty"`
	Trust          string         `json:"trust"`
	Source         string         `json:"source"`
	SourceInstance string         `json:"source_instance"`
	State          string         `json:"state"`
	PolicyVersion  string         `json:"policy_version"`
}

// Envelope is t on the wire, with state live.
func (t *Track) Envelope() Envelope {
	e := Envelope{
		Schema: t.Schema, MsgID: t.MsgID, Producer: t.Producer,
		RxTS: FormatTime(t.Times.RxTS), CapturedAt: FormatTime(t.Times.CapturedAt),
		TimeSource: string(t.Times.Source), Backlog: t.Times.Backlog,
		Body: TrackBody{
			ICAO24: t.ICAO24, Callsign: t.Callsign,
			Position:     PositionBody{Lat: t.Position.LatDeg, Lng: t.Position.LonDeg},
			AltPressureM: t.AltPressureM, AltWGS84M: t.AltWGS84M, GSMS: t.GSMS, TrackDeg: t.TrackDeg, VRateMS: t.VRateMS,
			Emergency: t.Emergency, SPI: t.SPI, Squawk: t.Squawk, SourceClass: t.SourceClass, Quality: t.Quality,
			Trust: string(t.Trust), Source: t.Source, SourceInstance: t.SourceInstance, State: StateLive,
			PolicyVersion: strconv.FormatUint(t.PolicyVersion, 10),
		},
	}
	if t.Times.TS != nil {
		ts := FormatTime(*t.Times.TS)
		e.TS = &ts
	}
	return e
}

// MarshalJSON encodes t as its envelope.
func (t *Track) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Envelope())
}
