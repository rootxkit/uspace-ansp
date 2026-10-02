package dump1090_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/dump1090"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/sinktest"
)

func aircraftDoc(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/aircraft-from-writer-format.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Golden: aircraft.json (README-json.md, section "aircraft.json"):
//   - "now": 1790942400.0 s since the epoch = 2026-10-02T12:00:00Z, the
//     feed's "now" of every sample;
//   - f0a001 "seen_pos": 0.4 ("how long ago (in seconds before now) the
//     position was last updated") -> ts 11:59:59.600; "alt_baro": 4975
//     ("barometric altitude in feet") -> alt_pressure_m 1516.38;
//     "alt_geom": 5100 ("geometric ... referenced to the WGS84
//     ellipsoid") -> alt_wgs84_m 1554.48; "gs": 141 knots; "track": 134
//     ("true track over ground in degrees"); "baro_rate": -512
//     ("feet/minute"); "squawk": "4521"; "emergency": "none" -> false;
//     "flight" "SYN001  " ("8 chars") -> SYN001; nic, rc, nac_p ... as
//     received in quality;
//   - f0a002: "alt_baro": "ground" (net_io.c line 1769) -> no pressure
//     altitude, quality alt_baro ground; "seen_pos" 45 > max_age_s 30 ->
//     backlog; "geom_rate" 64 ft/min (no baro_rate) -> vrate, geometric;
//   - ~f0a003: a non-ICAO address ("may start with '~'") -> sampled,
//     then refused by the normaliser (icao24);
//   - f0a004: no lat/lon -> no sample, counted.
func TestGoldenAircraftJSON(t *testing.T) {
	pol := manned.Defaults()
	doc, err := dump1090.ParseAircraftJSON(aircraftDoc(t), pol.MaxJSONBytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var samples []manned.RawSample
	skipped := 0
	for i := range doc.Aircraft {
		s, ok := doc.Aircraft[i].Sample(now, &pol)
		if !ok {
			skipped++
			continue
		}
		samples = append(samples, s)
	}
	if len(samples) != 3 || skipped != 1 {
		t.Fatalf("%d samples, %d skipped", len(samples), skipped)
	}
	a := samples[0]
	if a.ICAO24 != "f0a001" || !a.FeedTS.Equal(now.Add(-400*time.Millisecond)) || !a.FeedNow.Equal(now) || a.Backlog ||
		!near(*a.AltPressureM, 1516.38) || !near(*a.AltWGS84M, 1554.48) || !near(*a.GSMS, 141*1852.0/3600) ||
		*a.TrackDeg != 134 || !near(*a.VRateMS, -512*0.3048/60) || *a.Squawk != "4521" || *a.Emergency ||
		*a.Callsign != "SYN001" || a.Quality["nac_p"] != 9.0 || a.Quality["sil_type"] != "perhour" ||
		a.Quality["vertical_rate_geometric"] != false {
		t.Fatalf("%+v %v", a, a.Quality)
	}
	g := samples[1]
	if g.AltPressureM != nil || g.Quality["alt_baro"] != "ground" || !g.Backlog || !near(*g.VRateMS, 64*0.3048/60) ||
		g.Quality["vertical_rate_geometric"] != true {
		t.Fatalf("%+v %v", g, g.Quality)
	}
	if samples[2].ICAO24 != "~f0a003" || samples[2].Quality["type"] != "tisb_other" {
		t.Fatalf("%+v", samples[2])
	}

	n := manned.NewNormaliser("adsb-json", manned.SourceClassADSB, manned.StaticPolicy{Policy: pol, Version: 1}, nil)
	n.Now = func() time.Time { return now.Add(time.Second) }
	tracks := n.Take(samples, now.Add(200*time.Millisecond))
	if len(tracks) != 2 || n.Counters().Get("refused_icao24") != 1 {
		t.Fatalf("%d tracks, %v", len(tracks), n.Counters().Snapshot())
	}
	// Placed against the feed's own "now": 400 ms before the read.
	if !tracks[0].Times.CapturedAt.Equal(now.Add(-200*time.Millisecond)) || !tracks[1].Times.Backlog {
		t.Fatalf("%+v", tracks[0].Times)
	}
	sch := schematest.Compile(t, schematest.TrackManned)
	for i := range tracks {
		raw, _ := json.Marshal(&tracks[i])
		if err := schematest.Validate(t, sch, raw); err != nil {
			t.Fatalf("%v\n%s", err, raw)
		}
	}
	// An emergency other than none is an emergency.
	e := doc.Aircraft[3]
	e.Lat, e.Lon = manned.F(41), manned.F(44)
	if s, _ := e.Sample(now, &pol); !*s.Emergency || s.Quality["emergency"] != "general" || s.FeedTS != nil {
		t.Fatalf("%+v", s)
	}
}

func TestParseAircraftJSONRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":   `nope`,
		"no now":     `{"aircraft":[]}`,
		"bad now":    `{"now":-1,"aircraft":[]}`,
		"wrong type": `{"now":1,"aircraft":{"hex":"x"}}`,
		"too large":  `{"now":1,"aircraft":[` + strings.Repeat(`{},`, 100) + `{}]}`,
	} {
		_, err := dump1090.ParseAircraftJSON([]byte(doc), 200)
		var fe *core.FieldError
		if !errors.As(err, &fe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The adapter polls over HTTP: a good document gives samples and the
// feed is connected; a document too large is refused and counted while
// the feed stays connected; a 500 ends the session for the runner to
// reconnect (E-01, E-10).
func TestJSONAdapterPolls(t *testing.T) {
	var mode atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		switch mode.Load() {
		case 0:
			_, _ = w.Write(aircraftDoc(t))
		case 1:
			_, _ = w.Write([]byte(`{"now":1790942401,"aircraft":[` + strings.Repeat(`{"hex":"f0a009"},`, 400) + `{}]}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	a, err := dump1090.NewJSONAdapter(dump1090.JSONConfig{URL: srv.URL + "/data/aircraft.json"})
	if err != nil || a.Kind() != adapter.KindDump1090JSON {
		t.Fatal(err)
	}
	sink := sinktest.New(func(p *manned.Policy) { p.PollPeriodS = 0.02; p.MaxJSONBytes = 4000 })
	done := make(chan error, 1)
	go func() { done <- a.Run(context.Background(), sink) }()
	waitUntil(t, func() bool { return len(sink.Samples()) >= 3 })
	if sink.Connections() != 1 || sink.Counters.Get(dump1090.CounterSkippedNoPosition) < 1 {
		t.Fatal(sink.Counters.Snapshot())
	}
	mode.Store(1)
	waitUntil(t, func() bool { return sink.Counters.Get("refused_json_document") > 0 })
	mode.Store(2)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "status 500") {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a 500 did not end the session")
	}
	if _, err := dump1090.NewJSONAdapter(dump1090.JSONConfig{URL: "ftp://x/aircraft.json"}); !errors.Is(err, adapter.ErrPermanent) {
		t.Fatal(err)
	}
}

// A document that is not aircraft.json is refused and counted, the
// polling goes on; ctx ends the session.
func TestJSONAdapterRefusesAndStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"aircraft":[]}`))
	}))
	defer srv.Close()
	a, _ := dump1090.NewJSONAdapter(dump1090.JSONConfig{URL: srv.URL, Client: srv.Client()})
	sink := sinktest.New(func(p *manned.Policy) { p.PollPeriodS = 0.01 })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, sink) }()
	waitUntil(t, func() bool { return sink.Counters.Get("refused_json_document") >= 2 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	srv.Close()
	if err := a.Run(context.Background(), sinktest.New(nil)); err == nil {
		t.Fatal("a closed server was polled without error")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
