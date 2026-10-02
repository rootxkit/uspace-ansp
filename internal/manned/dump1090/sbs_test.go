package dump1090_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/dump1090"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/sinktest"
)

func lines(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/sbs-from-writer-format.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("\r\n")) {
		t.Fatal("the sample lost the writer's CRLF line endings (.gitattributes)")
	}
	var out [][]byte
	for l := range bytes.SplitSeq(raw, []byte("\r\n")) {
		out = append(out, l)
	}
	return out[:len(out)-1] // after the last CRLF
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// Golden: the pinned writer's columns (net_io.c modesSendSBSOutput,
// SOURCE) of the sample's position line of F0A001, after the lines
// before it were merged. Expected values from the column comments and
// README-json.md's units (SOURCE assumption 1):
//   - column 5 "%06X" ICAO F0A001 -> icao24 f0a001 (lower-cased later);
//   - columns 7-8 reception time 12:00:01.000 (UTC configured) -> ts;
//   - columns 9-10 current time 12:00:01.050 -> the batch's feed "now";
//   - column 12 "4975", no H -> barometric 4975 ft = 1516.38 m pressure
//     altitude (D-03), never alt_wgs84_m;
//   - column 13 "141" knots (MSG,4) -> 141 x 1852 / 3600 m/s;
//   - column 14 "134" ground track degrees;
//   - column 17 "-512" ft/min, no H -> -512 x 0.3048 / 60 m/s;
//   - column 11 "SYN001" (MSG,1); column 18 squawk "7700" and column 20
//     "-1" Squawk Emergency (MSG,6); column 21 "0" Ident -> spi false.
func TestGoldenSBSPositionLine(t *testing.T) {
	m := dump1090.NewMerger()
	pol := manned.Defaults()
	var samples []manned.RawSample
	for _, l := range lines(t) {
		if len(l) == 0 {
			continue
		}
		parsed, err := dump1090.ParseSBSLine(l, time.UTC)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		if s, ok, _ := m.Take(&parsed, &pol); ok {
			samples = append(samples, s)
		}
	}
	if len(samples) != 2 {
		t.Fatalf("%d position samples, want 2", len(samples))
	}
	s := samples[0]
	want := time.Date(2026, 10, 2, 12, 0, 1, 0, time.UTC)
	if s.ICAO24 != "F0A001" || !s.FeedTS.Equal(want) || !s.FeedNow.Equal(want.Add(50*time.Millisecond)) ||
		s.Position.LatDeg != 41.721 || s.Position.LonDeg != 44.793 {
		t.Fatalf("%+v", s)
	}
	if !near(*s.AltPressureM, 1516.38) || s.AltWGS84M != nil || !near(*s.GSMS, 141*1852.0/3600) || *s.TrackDeg != 134 ||
		!near(*s.VRateMS, -512*0.3048/60) || *s.Callsign != "SYN001" || *s.Squawk != "7700" || !*s.Emergency || *s.SPI {
		t.Fatalf("%+v alt %v gs %v vrate %v", s, *s.AltPressureM, *s.GSMS, *s.VRateMS)
	}
	if s.Quality["sbs_message_type"] != 3.0 || s.Quality["on_the_ground"] != false {
		t.Fatal(s.Quality)
	}
	// F0A002: "5100H" is the geometric altitude (SOURCE assumption 2),
	// so alt_wgs84_m; the barometric "2500" of its MSG,5 stays the
	// pressure altitude, the two never written into each other (D-03);
	// "1024H" is a geometric rate.
	g := samples[1]
	if !near(*g.AltPressureM, 2500*0.3048) || !near(*g.AltWGS84M, 5100*0.3048) || !near(*g.VRateMS, 1024*0.3048/60) ||
		g.Quality["vertical_rate_geometric"] != true {
		t.Fatalf("%+v", g)
	}

	// Normalised, the track is valid track/manned/v1.
	n := manned.NewNormaliser("adsb-tbs", manned.SourceClassADSB, manned.StaticPolicy{Policy: pol, Version: 1}, nil)
	n.Now = func() time.Time { return want.Add(time.Second) }
	tracks := n.Take(samples, want.Add(100*time.Millisecond))
	if len(tracks) != 2 || tracks[0].ICAO24 != "f0a001" {
		t.Fatal(tracks)
	}
	sch := schematest.Compile(t, schematest.TrackManned)
	for i := range tracks {
		raw, _ := json.Marshal(&tracks[i])
		if err := schematest.Validate(t, sch, raw); err != nil {
			t.Fatalf("%v\n%s", err, raw)
		}
	}
}

// Fields older than held_field_max_age_s on the feed's clock are not
// merged into a position; fresher ones are (E-01).
func TestMergerHeldFieldAge(t *testing.T) {
	pol := manned.Defaults()
	pol.HeldFieldMaxAgeS = 5
	m := dump1090.NewMerger()
	parse := func(s string) dump1090.SBSLine {
		l, err := dump1090.ParseSBSLine([]byte(s), time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	id := parse("MSG,1,1,1,F0A001,1,2026/10/02,12:00:00.000,2026/10/02,12:00:00.000,SYN001,,,,,,,,,,,0")
	m.Take(&id, &pol)
	pos := parse("MSG,3,1,1,F0A001,1,2026/10/02,12:00:04.000,2026/10/02,12:00:04.000,,4975,,,41.72100,44.79300,,,,,,0")
	s, ok, _ := m.Take(&pos, &pol)
	if !ok || s.Callsign == nil {
		t.Fatal("a fresh field was not merged")
	}
	late := parse("MSG,3,1,1,F0A001,1,2026/10/02,12:00:06.000,2026/10/02,12:00:06.000,,4975,,,41.72200,44.79300,,,,,,0")
	s, ok, _ = m.Take(&late, &pol)
	if !ok || s.Callsign != nil || s.AltPressureM == nil {
		t.Fatalf("an old field was merged: %+v", s)
	}
}

// E-10: the held set is bounded by max_aircraft, eviction reported.
func TestMergerEviction(t *testing.T) {
	pol := manned.Defaults()
	pol.MaxAircraft = 1
	m := dump1090.NewMerger()
	a, _ := dump1090.ParseSBSLine([]byte("MSG,1,1,1,F0A001,1,2026/10/02,12:00:00.000,2026/10/02,12:00:00.000,SYN001,,,,,,,,,,,0"), time.UTC)
	b, _ := dump1090.ParseSBSLine([]byte("MSG,1,1,1,F0A002,1,2026/10/02,12:00:00.000,2026/10/02,12:00:00.000,SYN002,,,,,,,,,,,0"), time.UTC)
	if _, _, ev := m.Take(&a, &pol); ev {
		t.Fatal("evicted at the bound")
	}
	if _, _, ev := m.Take(&b, &pol); !ev || m.Held() != 1 {
		t.Fatal("not evicted past the bound")
	}
}

// Every column the parser reads is refused by number when it is not the
// writer's shape; the sample lines are accepted (E-01).
func TestParseSBSLineRefusals(t *testing.T) {
	good := "MSG,3,1,1,F0A001,1,2026/10/02,12:00:01.000,2026/10/02,12:00:01.050,,4975,,,41.72100,44.79300,,,,,,0"
	if _, err := dump1090.ParseSBSLine([]byte(good), time.UTC); err != nil {
		t.Fatal(err)
	}
	set := func(col int, v string) string {
		c := strings.Split(good, ",")
		c[col-1] = v
		return strings.Join(c, ",")
	}
	for name, tc := range map[string]struct{ line, field string }{
		"short":      {strings.TrimSuffix(good, ",0"), "columns"},
		"long":       {good + ",1", "columns"},
		"not MSG":    {set(1, "SEL"), "column_1"},
		"type 9":     {set(2, "9"), "column_2"},
		"icao":       {set(5, "F0A00G"), "column_5"},
		"icao short": {set(5, "F0A0"), "column_5"},
		"rx date":    {set(7, "2026-10-02"), "column_7"},
		"now time":   {set(10, "12:00"), "column_9"},
		"altitude":   {set(12, "49x5"), "column_12"},
		"alt huge":   {set(12, "99999999999999999"), "column_12"},
		"vrate":      {set(17, "H"), "column_17"},
		"gs":         {set(13, "fast"), "column_13"},
		"gs hex":     {set(13, "0x10"), "column_13"},
		"gs nan":     {set(13, "NaN"), "column_13"},
		"gs inf":     {set(13, "1e999"), "column_13"},
		"gs long":    {set(13, strings.Repeat("1", 30)), "column_13"},
		"lat only":   {set(16, ""), "column_15"},
		"alert":      {set(19, "1"), "column_19"},
		"ground":     {set(22, "yes"), "column_22"},
	} {
		_, err := dump1090.ParseSBSLine([]byte(tc.line), time.UTC)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%s: %v, want %s", name, err, tc.field)
		}
	}
}

// SOURCE assumption 3: the time columns are in the configured zone.
func TestParseSBSLineZone(t *testing.T) {
	tbs := time.FixedZone("UTC+4", 4*3600)
	l, err := dump1090.ParseSBSLine([]byte("MSG,3,1,1,F0A001,1,2026/10/02,16:00:01.000,2026/10/02,16:00:01.050,,4975,,,41.72100,44.79300,,,,,,0"), tbs)
	if err != nil || !l.RxAt.Equal(time.Date(2026, 10, 2, 12, 0, 1, 0, time.UTC)) {
		t.Fatal(l.RxAt, err)
	}
}

// serve is a TCP server that writes payload to the first client, then
// holds the connection until hold is closed (nil: closes at once).
func serve(t *testing.T, payload []byte, hold chan struct{}) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write(payload)
				if hold != nil {
					<-hold
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// The adapter over TCP: the sample file's lines arrive as samples, the
// heartbeat is counted, a line too long and a line that does not parse
// are refused and counted; nothing panics; the connection is never
// written to (the server would see bytes; it reads none).
func TestSBSAdapterOverTCP(t *testing.T) {
	raw, _ := os.ReadFile("testdata/sbs-from-writer-format.txt")
	payload := append([]byte{}, raw...)
	payload = append(payload, []byte(strings.Repeat("X", 600)+"\r\nMSG,garbage\r\n")...)
	hold := make(chan struct{})
	addr := serve(t, payload, hold)
	a, err := dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind() != adapter.KindDump1090SBS {
		t.Fatal(a.Kind())
	}
	sink := sinktest.New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, sink) }()
	deadline := time.Now().Add(5 * time.Second)
	for sink.Counters.Get("refused_sbs_line") == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := len(sink.Samples()); got != 2 || sink.Connections() != 1 || sink.Counters.Get(dump1090.CounterHeartbeats) != 1 ||
		sink.Counters.Get("refused_line_too_long") != 1 || sink.Counters.Get("refused_sbs_line") != 1 ||
		sink.Counters.Get(dump1090.CounterMergedLines) != 4 {
		t.Fatalf("samples %d, %v", got, sink.Counters.Snapshot())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(hold)
}

// The feed closing the connection ends Run with an error the runner
// reconnects on; silence past feed_idle_timeout_s ends it too, counted.
func TestSBSAdapterFeedGoneAndIdle(t *testing.T) {
	addr := serve(t, []byte("\r\n"), nil)
	a, _ := dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: addr})
	err := a.Run(context.Background(), sinktest.New(nil))
	if err == nil || !strings.Contains(err.Error(), "closed the connection") {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	defer close(hold)
	addr = serve(t, nil, hold)
	a, _ = dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: addr})
	sink := sinktest.New(func(p *manned.Policy) { p.FeedIdleTimeoutS = 0.1 })
	err = a.Run(context.Background(), sink)
	if err == nil || sink.Counters.Get(dump1090.CounterFeedIdleTimeouts) != 1 {
		t.Fatal(err, sink.Counters.Snapshot())
	}
	if _, err := dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: "no-port"}); !errors.Is(err, adapter.ErrPermanent) {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	_ = ln.Close()
	a, _ = dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: closed, DialTimeout: time.Second})
	if err := a.Run(context.Background(), sinktest.New(nil)); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatal(err)
	}
}

// The runner reconnects a dump1090 feed that went away and publishes
// again (B-08), end to end over TCP.
func TestSBSRunnerReconnects(t *testing.T) {
	raw, _ := os.ReadFile("testdata/sbs-from-writer-format.txt")
	addr := serve(t, raw, nil) // every connection gets the lines, then is closed
	a, _ := dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: addr})
	pub := &pubRecorder{}
	p := manned.Defaults()
	p.ReconnectMinS, p.ReconnectMaxS = 0.02, 0.05
	r := &adapter.Runner{Adapter: a, Instance: "adsb-tbs", SourceClass: manned.SourceClassADSB, Publisher: pub,
		Policy: manned.StaticPolicy{Policy: p}, Counters: &core.Counters{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for r.Counters.Get(adapter.CounterReconnects) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	// Each session replays the same feed times: the first session's
	// tracks are published, the repeats are duplicates, never re-sent.
	if pub.count() != 2 || r.Counters.Get(adapter.CounterFeedLost) < 2 || r.Counters.Get(manned.CounterDuplicates) < 2 {
		t.Fatalf("published %d, %v", pub.count(), r.Counters.Snapshot())
	}
}

type pubRecorder struct {
	mu sync.Mutex
	n  int
}

func (p *pubRecorder) Publish(subject string, _ []byte) error {
	if strings.HasPrefix(subject, "man.v1.") {
		p.mu.Lock()
		p.n++
		p.mu.Unlock()
	}
	return nil
}

func (p *pubRecorder) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// BenchmarkParseSBSLine is one position line.
func BenchmarkParseSBSLine(b *testing.B) {
	line := []byte("MSG,3,1,1,F0A001,1,2026/10/02,12:00:01.000,2026/10/02,12:00:01.050,,4975,,,41.72100,44.79300,,,,,,0")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := dump1090.ParseSBSLine(line, time.UTC); err != nil {
			b.Fatal(err)
		}
	}
}
