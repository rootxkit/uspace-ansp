package feed

import (
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

func TestDecodeTrackTakesWhatTheAdapterPublishes(t *testing.T) {
	pol := manned.Defaults()
	in := sample("4ca7b5", "adsb-tbs", 41.721, 44.793, t0)
	got, err := DecodeTrack(wireOf(t, in), &pol)
	if err != nil {
		t.Fatal(err)
	}
	if got.ICAO24 != in.ICAO24 || got.SourceInstance != "adsb-tbs" || !got.Times.CapturedAt.Equal(t0) || got.Times.TS == nil ||
		!got.Times.RxTS.Equal(in.Times.RxTS) || *got.AltPressureM != 1524 || got.PolicyVersion != 1 || got.MsgID != in.MsgID ||
		got.Quality["nic"] != 8.0 || got.Times.Backlog {
		t.Fatalf("decoded %+v", got)
	}
	// ts null (T-12) and backlog true are taken as said.
	in.Times.TS = nil
	in.Times.Backlog = true
	got, err = DecodeTrack(wireOf(t, in), &pol)
	if err != nil || got.Times.TS != nil || !got.Times.Backlog {
		t.Fatalf("ts null: %+v %v", got, err)
	}
}

func TestDecodeTrackRefusesNamingTheMember(t *testing.T) {
	pol := manned.Defaults()
	good := string(wireOf(t, sample("4ca7b5", "adsb-tbs", 41.721, 44.793, t0)))
	for name, c := range map[string]struct{ in, field string }{
		"not json":         {`{`, "message"},
		"schema":           {strings.Replace(good, `"schema":"track/manned/v1"`, `"schema":"track/manned/v2"`, 1), "schema"},
		"no body":          {`{"schema":"track/manned/v1","backlog":false}`, "body"},
		"no position":      {strings.Replace(good, `"position":{"lat":41.721,"lng":44.793}`, `"position":null`, 1), "body.position"},
		"state stale":      {strings.Replace(good, `"state":"live"`, `"state":"stale"`, 1), "body.state"},
		"no backlog":       {strings.Replace(good, `"backlog":false,`, ``, 1), "backlog"},
		"time source":      {strings.Replace(good, `"time_source":"receiver"`, `"time_source":"guess"`, 1), "time_source"},
		"rx_ts":            {strings.Replace(good, `"rx_ts":"2026-10-02T12:00:00.100Z"`, `"rx_ts":"yesterday"`, 1), "rx_ts"},
		"captured_at zone": {strings.Replace(good, `"captured_at":"2026-10-02T12:00:00.000Z"`, `"captured_at":"2026-10-02T16:00:00+04:00"`, 1), "captured_at"},
		"ts":               {strings.Replace(good, `"ts":"2026-10-02T12:00:00.000Z"`, `"ts":"x"`, 1), "ts"},
		"policy version":   {strings.Replace(good, `"policy_version":"1"`, `"policy_version":"v1"`, 1), "body.policy_version"},
		"msg id":           {strings.Replace(good, `"msg_id":"`, `"msg_id":"x`, 1), "msg_id"},
		"icao24":           {strings.Replace(good, `"icao24":"4ca7b5"`, `"icao24":"4CA7B5"`, 1), "icao24"},
		"trust":            {strings.Replace(good, `"trust":"surveillance"`, `"trust":"simulated"`, 1), "trust"},
		"long":             {good + strings.Repeat(" ", MaxMessageBytes), "message"},
	} {
		_, err := DecodeTrack([]byte(c.in), &pol)
		if err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSubjectAdapter(t *testing.T) {
	for subject, want := range map[string]string{
		"man.v1.adsb-tbs.4ca7b5":      "adsb-tbs",
		"src.v1.manned.adsb-tbs":      "",
		"man.v1.":                     "",
		"other.adsb-tbs.4ca7b5":       "",
		"man.v1.replay-1.4ca7b5.more": "replay-1",
	} {
		if got := SubjectAdapter(subject, "man.v1."); got != want {
			t.Errorf("%s: %q", subject, got)
		}
	}
	if got := SubjectAdapter("src.v1.manned.adsb-tbs", "src.v1.manned."); got != "adsb-tbs" {
		t.Fatal(got)
	}
}

func TestULIDLike(t *testing.T) {
	if !ulidLike(manned.NewULID(t0)) || ulidLike("8ZZZZZZZZZZZZZZZZZZZZZZZZZ") || ulidLike("01K6N5SXS5AA819X9YP981068I") || ulidLike("short") {
		t.Fatal("ulidLike")
	}
}

func FuzzDecodeTrack(f *testing.F) {
	f.Add(wireOf(f, sample("4ca7b5", "adsb-tbs", 41.721, 44.793, t0)))
	f.Add([]byte(`{"schema":"track/manned/v1","backlog":false,"body":{"position":{"lat":1,"lng":2},"state":"live"}}`))
	f.Add([]byte(`null`))
	pol := manned.Defaults()
	f.Fuzz(func(t *testing.T, b []byte) {
		tr, err := DecodeTrack(b, &pol)
		if err == nil && tr.Validate() != nil {
			t.Fatal("an invalid track was taken")
		}
	})
}

func FuzzDecodeSubscribe(f *testing.F) {
	f.Add([]byte(`{"schema":"console/subscribe/v1","body":{"bbox":[44.6,41.6,45,41.9],"layers":["manned"]}}`))
	f.Add([]byte(`{"schema":"console/subscribe/v1","body":{"bbox":[1e999,0,0,0],"layers":[]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeSubscribe(b)
		if err == nil && s.BBox == nil {
			t.Fatal("a subscription without a box was taken")
		}
	})
}

func TestDecodeSubscribe(t *testing.T) {
	s, err := DecodeSubscribe([]byte(`{"schema":"console/subscribe/v1","msg_id":"` + manned.NewULID(t0) + `","body":{"bbox":[44.6,41.6,45.0,41.9],"layers":["manned","zones"]}}`))
	if err != nil || s.BBox.MinLon != 44.6 || s.BBox.MaxLat != 41.9 || len(s.Layers) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	for name, in := range map[string]string{
		"schema":     `{"schema":"console/subscribe/v2","body":{"bbox":[0,0,1,1],"layers":[]}}`,
		"no body":    `{"schema":"console/subscribe/v1"}`,
		"no layers":  `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,1,1]}}`,
		"bbox 3":     `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,1],"layers":[]}}`,
		"lat":        `{"schema":"console/subscribe/v1","body":{"bbox":[0,-91,1,1],"layers":[]}}`,
		"lon":        `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,181,1],"layers":[]}}`,
		"south>nort": `{"schema":"console/subscribe/v1","body":{"bbox":[0,2,1,1],"layers":[]}}`,
		"layer":      `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,1,1],"layers":["all"]}}`,
		"repeated":   `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,1,1],"layers":["manned","manned"]}}`,
		"msg id":     `{"schema":"console/subscribe/v1","msg_id":"x","body":{"bbox":[0,0,1,1],"layers":[]}}`,
		"not json":   `[`,
		"long":       `{"schema":"console/subscribe/v1","body":{"bbox":[0,0,1,1],"layers":[]}}` + strings.Repeat(" ", MaxClientFrameBytes),
	} {
		if _, err := DecodeSubscribe([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseBBox(t *testing.T) {
	b, err := ParseBBox("44.60,41.60,45.00,41.90")
	if err != nil || b.MinLon != 44.6 || b.MinLat != 41.6 || b.MaxLon != 45 || b.MaxLat != 41.9 {
		t.Fatalf("%+v %v", b, err)
	}
	if b, err := ParseBBox(""); b != nil || err != nil {
		t.Fatal("empty")
	}
	// Across the antimeridian: west > east.
	if b, err := ParseBBox("179,10,-179,11"); err != nil || b.MinLon != 179 || b.MaxLon != -179 {
		t.Fatalf("antimeridian %+v %v", b, err)
	}
	for _, in := range []string{"1,2,3", "a,1,2,3", "0,91,1,92", "-181,0,1,1", "0,2,1,1", strings.Repeat("1", 97)} {
		if _, err := ParseBBox(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	_ = time.Second
}
