package replay_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
	"github.com/rootxkit/uspace-ansp/internal/manned/replay"
)

// update regenerates testdata/replay/*.ndjson:
//
//	go test ./internal/manned/replay -run TestReplayFilesAreCurrent -update
var update = flag.Bool("update", false, "regenerate testdata/replay")

const replayDir = "../../../testdata/replay"

// epoch is the synthetic start of every file.
var epoch = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// leg is one synthetic aircraft: a callsign, an address, a position as
// a function of the second, a pressure altitude, and the seconds it is
// heard.
type leg struct {
	icao, callsign string
	squawk         string
	pos            func(s float64) core.LatLon
	altPressureM   float64
	geoidOffsetM   float64
	heard          func(s int) bool
}

// line is a straight path from a to b over d seconds.
func line(a, b core.LatLon, d float64) func(float64) core.LatLon {
	return func(s float64) core.LatLon {
		f := s / d
		return core.LatLon{LatDeg: a.LatDeg + (b.LatDeg-a.LatDeg)*f, LonDeg: a.LonDeg + (b.LonDeg-a.LonDeg)*f}
	}
}

// circle is a loop of the given radius in degrees of latitude around c
// once every period seconds.
func circle(c core.LatLon, radiusDeg, period float64) func(float64) core.LatLon {
	return func(s float64) core.LatLon {
		a := 2 * math.Pi * s / period
		return core.LatLon{
			LatDeg: c.LatDeg + radiusDeg*math.Sin(a),
			LonDeg: c.LonDeg + radiusDeg*math.Cos(a)/math.Cos(c.LatDeg*math.Pi/180),
		}
	}
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// file is one synthetic replay file: the header, then one record per
// heard second per leg, in time order. Speed and track come from
// uspace-core geodesy between consecutive positions (no geodesy here).
func file(t *testing.T, description string, seconds int, legs []leg) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr, _ := json.Marshal(replay.Header{Schema: replay.HeaderSchema, Synthetic: true, SourceClass: manned.SourceClassADSB, Description: description})
	buf.Write(hdr)
	buf.WriteByte('\n')
	n := uint64(0)
	for s := range seconds {
		for _, l := range legs {
			if !l.heard(s) {
				continue
			}
			p := l.pos(float64(s))
			p = core.LatLon{LatDeg: round(p.LatDeg, 6), LonDeg: round(p.LonDeg, 6)}
			next := l.pos(float64(s) + 1)
			dist, bearing, _, err := geodesy.Inverse(p, next)
			if err != nil {
				t.Fatal(err)
			}
			if bearing < 0 {
				bearing += 360
			}
			ts := epoch.Add(time.Duration(s) * time.Second)
			var entropy [10]byte
			n++
			binary.BigEndian.PutUint64(entropy[2:], n)
			tr := manned.Track{
				Schema: manned.SchemaTrack, MsgID: manned.ULIDWithEntropy(ts, entropy), Producer: manned.Producer,
				Times: core.Times{TS: &ts, RxTS: ts, CapturedAt: ts, Source: core.TimeSourceClock},
				Trust: core.TrustSurveillance, Source: manned.SourceANSPFeed, SourceInstance: "replay",
				ICAO24: l.icao, Callsign: manned.S(l.callsign), Position: p,
				AltPressureM: manned.F(l.altPressureM), AltWGS84M: manned.F(l.altPressureM + l.geoidOffsetM),
				GSMS: manned.F(round(dist, 1)), TrackDeg: manned.F(math.Mod(round(bearing, 1), 360)), VRateMS: manned.F(0),
				Emergency: manned.B(false), Squawk: manned.S(l.squawk), SourceClass: manned.SourceClassADSB,
				Quality: map[string]any{"nic": 8.0, "nac_p": 9.0}, PolicyVersion: 0,
			}
			raw, err := json.Marshal(&tr)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(raw)
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

func always(int) bool { return true }

// files are the three replay files of WP-4. All synthetic: made-up
// addresses in f0a0xx, made-up callsigns SYNxxx, straight lines and a
// circle near Tbilisi, no real traffic.
func files(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"two-aircraft-converging.ndjson": file(t,
			"SYNTHETIC, never real traffic. Two aircraft on reciprocal tracks at the same pressure altitude, 55 m apart laterally at closest approach near t=120 s (the USSP's CPA scenario).",
			240, []leg{
				{icao: "f0a001", callsign: "SYN001", squawk: "4521", altPressureM: 900, geoidOffsetM: 25, heard: always,
					pos: line(core.LatLon{LatDeg: 41.7000, LonDeg: 44.70}, core.LatLon{LatDeg: 41.7000, LonDeg: 44.90}, 240)},
				{icao: "f0a002", callsign: "SYN002", squawk: "4522", altPressureM: 900, geoidOffsetM: 25, heard: always,
					pos: line(core.LatLon{LatDeg: 41.7005, LonDeg: 44.90}, core.LatLon{LatDeg: 41.7005, LonDeg: 44.70}, 240)},
			}),
		"helicopter-near-uspace.ndjson": file(t,
			"SYNTHETIC, never real traffic. A helicopter circling at 150 m pressure altitude, radius about 1.1 km, one turn every 300 s.",
			300, []leg{
				{icao: "f0a003", callsign: "SYNHELI", squawk: "7000", altPressureM: 150, geoidOffsetM: 25, heard: always,
					pos: circle(core.LatLon{LatDeg: 41.69, LonDeg: 44.80}, 0.01, 300)},
			}),
		"stale-then-resume.ndjson": file(t,
			"SYNTHETIC, never real traffic. One aircraft heard for 30 s, silent for 30 s, heard again for 30 s (SC-15: the picture shows it stale, then live).",
			90, []leg{
				{icao: "f0a004", callsign: "SYN004", squawk: "4524", altPressureM: 1200, geoidOffsetM: 25,
					heard: func(s int) bool { return s < 30 || s >= 60 },
					pos:   line(core.LatLon{LatDeg: 41.65, LonDeg: 44.75}, core.LatLon{LatDeg: 41.65, LonDeg: 44.85}, 90)},
			}),
	}
}

// The committed files are what the generator writes, and every record
// is valid track/manned/v1 (E-03: the shape is this repo's schema).
func TestReplayFilesAreCurrent(t *testing.T) {
	sch := schematest.Compile(t, schematest.TrackManned)
	for name, want := range files(t) {
		path := filepath.Join(replayDir, name)
		if *update {
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s is not what the generator writes; run with -update", name)
		}
		recs := bytes.Split(bytes.TrimSpace(got), []byte("\n"))
		if _, err := replay.ParseHeader(recs[0]); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, r := range recs[1:] {
			if err := schematest.Validate(t, sch, r); err != nil {
				t.Fatalf("%s: %v\n%s", name, err, r)
			}
		}
		t.Logf("%s: %d records", name, len(recs)-1)
	}
}
