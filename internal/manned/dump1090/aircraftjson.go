package dump1090

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

// AircraftJSON is aircraft.json as README-json.md describes it (SOURCE),
// with only the keys this adapter reads; every name is the document's.
type AircraftJSON struct {
	// Now is "the time this file was generated, in seconds since Jan 1
	// 1970 00:00:00 GMT".
	Now      *float64       `json:"now"`
	Aircraft []AircraftItem `json:"aircraft"`
}

// AircraftItem is one entry of "aircraft". Keys "will be omitted if
// data is not available": every member is a pointer.
type AircraftItem struct {
	Hex  *string `json:"hex"`
	Type *string `json:"type"`
	// Flight is the callsign, "8 chars" (space padded).
	Flight *string `json:"flight"`
	// AltBaro is feet, or the string "ground" (net_io.c line 1769).
	AltBaro   json.RawMessage `json:"alt_baro"`
	AltGeom   *float64        `json:"alt_geom"`
	GS        *float64        `json:"gs"`
	Track     *float64        `json:"track"`
	BaroRate  *float64        `json:"baro_rate"`
	GeomRate  *float64        `json:"geom_rate"`
	Squawk    *string         `json:"squawk"`
	Emergency *string         `json:"emergency"`
	Lat       *float64        `json:"lat"`
	Lon       *float64        `json:"lon"`
	NIC       *float64        `json:"nic"`
	RC        *float64        `json:"rc"`
	SeenPos   *float64        `json:"seen_pos"`
	Version   *float64        `json:"version"`
	NICBaro   *float64        `json:"nic_baro"`
	NACP      *float64        `json:"nac_p"`
	NACV      *float64        `json:"nac_v"`
	SIL       *float64        `json:"sil"`
	SILType   *string         `json:"sil_type"`
	GVA       *float64        `json:"gva"`
	SDA       *float64        `json:"sda"`
	MLAT      []string        `json:"mlat"`
	TISB      []string        `json:"tisb"`
	Seen      *float64        `json:"seen"`
}

// altBaroGround is the value of alt_baro for an aircraft on the ground.
const altBaroGround = "ground"

// emergencyNone is the emergency value that is not an emergency
// (emergency_enum_string).
const emergencyNone = "none"

// ParseAircraftJSON decodes one aircraft.json document of at most
// maxBytes. It refuses with a *core.FieldError; it never panics.
func ParseAircraftJSON(doc []byte, maxBytes int) (AircraftJSON, error) {
	var out AircraftJSON
	if len(doc) > maxBytes {
		return out, core.Fieldf("aircraft.json", "larger than %d bytes", maxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&out); err != nil {
		return AircraftJSON{}, core.Fieldf("aircraft.json", "not the documented object: %s", firstLine(err.Error()))
	}
	if out.Now == nil || !core.IsFinite(*out.Now) || *out.Now < 0 || *out.Now > 1e11 {
		return AircraftJSON{}, core.Fieldf("now", "absent or not seconds since the epoch")
	}
	return out, nil
}

func firstLine(s string) string {
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// epoch converts seconds since the epoch (the document's unit) to a
// time, rounded to the millisecond.
func epoch(s float64) time.Time {
	return time.UnixMilli(int64(math.Round(s * 1000))).UTC()
}

// Sample is the sample of one aircraft of a document generated at now
// (the feed's clock), or ok false when it has no position (a Mode S
// aircraft without one is not refused, there is nothing to place). The
// position's feed time is now - seen_pos; a position older than
// max_age_s is backlog.
func (a *AircraftItem) Sample(now time.Time, pol *manned.Policy) (s manned.RawSample, ok bool) {
	if a.Lat == nil || a.Lon == nil {
		return manned.RawSample{}, false
	}
	feedNow := now
	s = manned.RawSample{FeedNow: &feedNow, Position: &manned.LatLonSample{LatDeg: *a.Lat, LonDeg: *a.Lon}}
	if a.Hex != nil {
		s.ICAO24 = *a.Hex
	}
	if a.SeenPos != nil && core.IsFinite(*a.SeenPos) && *a.SeenPos >= 0 && *a.SeenPos < 86400 {
		ts := now.Add(-manned.Seconds(*a.SeenPos))
		s.FeedTS = &ts
		s.Backlog = *a.SeenPos > pol.MaxAgeS
	}
	if a.Flight != nil {
		s.Callsign = manned.S(strings.TrimSpace(*a.Flight))
	}
	q := map[string]any{}
	if len(a.AltBaro) > 0 {
		var ft float64
		var word string
		switch {
		case json.Unmarshal(a.AltBaro, &ft) == nil:
			s.AltPressureM = manned.F(manned.FeetToM(ft))
		case json.Unmarshal(a.AltBaro, &word) == nil && word == altBaroGround:
			q["alt_baro"] = altBaroGround
		}
	}
	s.AltWGS84M = convert(a.AltGeom, manned.FeetToM)
	s.GSMS = convert(a.GS, manned.KnotsToMS)
	s.TrackDeg = convert(a.Track, func(v float64) float64 { return v })
	// The vertical rate is barometric when the feed gives it, else
	// geometric; which one is in the quality block.
	switch {
	case a.BaroRate != nil:
		s.VRateMS = convert(a.BaroRate, manned.FeetPerMinToMS)
		q["vertical_rate_geometric"] = false
	case a.GeomRate != nil:
		s.VRateMS = convert(a.GeomRate, manned.FeetPerMinToMS)
		q["vertical_rate_geometric"] = true
	}
	s.Squawk = a.Squawk
	if a.Emergency != nil {
		s.Emergency = manned.B(*a.Emergency != emergencyNone)
		q["emergency"] = *a.Emergency
	}
	for k, v := range map[string]*float64{
		"nic": a.NIC, "rc": a.RC, "version": a.Version, "nic_baro": a.NICBaro, "nac_p": a.NACP,
		"nac_v": a.NACV, "sil": a.SIL, "gva": a.GVA, "sda": a.SDA,
	} {
		if v != nil {
			q[k] = *v
		}
	}
	for k, v := range map[string]*string{"sil_type": a.SILType, "type": a.Type} {
		if v != nil {
			q[k] = *v
		}
	}
	if len(a.MLAT) > 0 {
		q["mlat"] = a.MLAT
	}
	if len(a.TISB) > 0 {
		q["tisb"] = a.TISB
	}
	if len(q) > 0 {
		s.Quality = q
	}
	return s, true
}

// JSONConfig configures the aircraft.json adapter.
type JSONConfig struct {
	// URL is where aircraft.json is served (http or https).
	URL string
	// Client is the HTTP client; nil is one with a timeout of the poll
	// period plus a second.
	Client *http.Client
}

// JSONAdapter polls aircraft.json at poll_period_s (1 Hz). It sends
// GET requests only.
type JSONAdapter struct {
	cfg JSONConfig
}

// NewJSONAdapter checks cfg.
func NewJSONAdapter(cfg JSONConfig) (*JSONAdapter, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: dump1090_json: %q is not an http(s) URL", adapter.ErrPermanent, cfg.URL)
	}
	return &JSONAdapter{cfg: cfg}, nil
}

// Kind is dump1090_json.
func (*JSONAdapter) Kind() string { return adapter.KindDump1090JSON }

// Counters of the aircraft.json reader.
const (
	RefusedJSONDocument = "json_document" // refused_json_document: not the documented object, or too large
	CounterPolls        = "polls"
)

// Run polls until a poll fails (the runner reconnects) or ctx ends. The
// feed is connected from the first poll that answers 200.
func (a *JSONAdapter) Run(ctx context.Context, sink adapter.Sink) error {
	pol := sink.Policy()
	client := a.cfg.Client
	if client == nil {
		client = &http.Client{Timeout: manned.Seconds(pol.PollPeriodS) + time.Second}
	}
	connected := false
	for {
		pol = sink.Policy()
		started := sink.Now()
		body, err := a.poll(ctx, client, pol.MaxJSONBytes)
		if err != nil && !errors.Is(err, errTooLarge) {
			return err
		}
		if !connected {
			sink.Connected()
			connected = true
		}
		sink.Heard()
		sink.Count(CounterPolls)
		var doc AircraftJSON
		if err == nil {
			doc, err = ParseAircraftJSON(body, pol.MaxJSONBytes)
		}
		if err != nil {
			sink.Refuse(RefusedJSONDocument)
		} else if err := a.emit(ctx, &doc, sink, &pol); err != nil {
			return err
		}
		wait := manned.Seconds(pol.PollPeriodS) - sink.Now().Sub(started)
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

var errTooLarge = errors.New("aircraft.json larger than max_json_bytes")

// poll GETs the document, at most maxBytes of it.
func (a *JSONAdapter) poll(ctx context.Context, client *http.Client, maxBytes int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("dump1090_json: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dump1090_json: poll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dump1090_json: poll: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("dump1090_json: read: %w", err)
	}
	if len(body) > maxBytes {
		return nil, errTooLarge
	}
	return body, nil
}

// emit queues the samples of doc.
func (*JSONAdapter) emit(ctx context.Context, doc *AircraftJSON, sink adapter.Sink, pol *manned.Policy) error {
	now := epoch(*doc.Now)
	for i := range doc.Aircraft {
		s, ok := doc.Aircraft[i].Sample(now, pol)
		if !ok {
			sink.Count(CounterSkippedNoPosition)
			continue
		}
		if err := sink.Sample(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
