package replay_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/sinktest"
	"github.com/rootxkit/uspace-ansp/internal/manned/replay"
)

func stale() string { return filepath.Join(replayDir, "stale-then-resume.ndjson") }

// Replay never runs unless allowed (06 T11); a bad speed, a missing
// file or a file that does not say it is synthetic refuses to start
// (permanent: the process stops and says why). Allowed, it builds
// (E-01).
func TestNewRefusals(t *testing.T) {
	ok := replay.Config{File: stale(), Allowed: true, Speed: 1}
	a, err := replay.New(ok)
	if err != nil || a.Kind() != adapter.KindReplay || a.Header().SourceClass != "ads_b" || !a.Header().Synthetic {
		t.Fatal(err)
	}
	dir := t.TempDir()
	notSynthetic := filepath.Join(dir, "real.ndjson")
	_ = os.WriteFile(notSynthetic, []byte(`{"schema":"replay/header/v1","synthetic":false,"source_class":"ads_b","description":"x"}`+"\n"), 0o600)
	noHeader := filepath.Join(dir, "none.ndjson")
	_ = os.WriteFile(noHeader, []byte(`{"schema":"track/manned/v1"}`+"\n"), 0o600)
	badClass := filepath.Join(dir, "class.ndjson")
	_ = os.WriteFile(badClass, []byte(`{"schema":"replay/header/v1","synthetic":true,"source_class":"radar","description":"x"}`+"\n"), 0o600)
	for name, cfg := range map[string]replay.Config{
		"not allowed":   {File: stale(), Speed: 1},
		"speed 0":       {File: stale(), Allowed: true},
		"speed huge":    {File: stale(), Allowed: true, Speed: 5000},
		"missing file":  {File: filepath.Join(dir, "missing"), Allowed: true, Speed: 1},
		"not synthetic": {File: notSynthetic, Allowed: true, Speed: 1},
		"no header":     {File: noHeader, Allowed: true, Speed: 1},
		"bad class":     {File: badClass, Allowed: true, Speed: 1},
	} {
		if _, err := replay.New(cfg); !errors.Is(err, adapter.ErrPermanent) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The file replays with its own times as the feed's clock, keeps the
// spacing at the configured speed (the 30 s silence is a silence), and
// a replay without a loop stays connected and silent at the end.
func TestReplayStaleThenResume(t *testing.T) {
	a, err := replay.New(replay.Config{File: stale(), Allowed: true, Speed: 300})
	if err != nil {
		t.Fatal(err)
	}
	sink := sinktest.New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- a.Run(ctx, sink) }()
	waitUntil(t, func() bool { return sink.Counters.Get(replay.CounterReplayEnded) == 1 })
	elapsed := time.Since(start)
	s := sink.Samples()
	if len(s) != 60 || sink.Connections() != 1 {
		t.Fatal(len(s))
	}
	first := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if !s[0].FeedTS.Equal(first) || !s[59].FeedTS.Equal(first.Add(89*time.Second)) || s[0].ICAO24 != "f0a004" ||
		s[0].Position == nil || *s[0].AltPressureM != 1200 || *s[0].Callsign != "SYN004" || s[0].Quality["nic"] != 8.0 {
		t.Fatalf("%+v", s[0])
	}
	// 89 s of file at 300x is about 0.3 s, the 30 s gap about 0.1 s.
	gap := s[30].ReadAt.Sub(s[29].ReadAt)
	if elapsed < 250*time.Millisecond || gap < 80*time.Millisecond {
		t.Fatalf("elapsed %v gap %v", elapsed, gap)
	}
	select {
	case err := <-done:
		t.Fatalf("a finished replay ended the session: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// In a loop the times move forward every pass, so the replayed clock
// never runs backwards (no out_of_order after a loop).
func TestReplayLoopShiftsTimes(t *testing.T) {
	a, _ := replay.New(replay.Config{File: stale(), Allowed: true, Speed: 1000, Loop: true})
	sink := sinktest.New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, sink) }()
	waitUntil(t, func() bool { return len(sink.Samples()) >= 130 })
	cancel()
	<-done
	s := sink.Samples()
	for i := 1; i < len(s); i++ {
		if !s[i].FeedTS.After(*s[i-1].FeedTS) {
			t.Fatalf("record %d at %v after %v", i, s[i].FeedTS, s[i-1].FeedTS)
		}
	}
	if sink.Counters.Get(replay.CounterLoops) < 2 || !s[60].FeedTS.Equal(s[0].FeedTS.Add(90*time.Second)) {
		t.Fatalf("%v %v", sink.Counters.Snapshot(), s[60].FeedTS)
	}
}

// A record that is not track/manned/v1, a bad ts or a line beyond the
// bound is refused and counted; a record without ts is replayed with no
// feed time; the rest goes on (E-10).
func TestReplayRefusesBadRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.ndjson")
	body := strings.Join([]string{
		`{"schema":"replay/header/v1","synthetic":true,"source_class":"mode_s","description":"synthetic test"}`,
		`{"schema":"track/manned/v2","ts":"2026-01-01T12:00:00.000Z","body":{}}`,
		`not json`,
		`{"schema":"track/manned/v1","ts":"yesterday","body":{"icao24":"f0a001"}}`,
		`{"schema":"track/manned/v1","ts":"2026-01-01T12:00:00.000Z","body":{"icao24":"` + strings.Repeat("a", 200) + `"}}`,
		``,
		`{"schema":"track/manned/v1","ts":null,"body":{"icao24":"f0a001","position":{"lat":41.7,"lng":44.8}}}`,
		`{"schema":"track/manned/v1","ts":"2026-01-01T12:00:01.000Z","body":{"icao24":"f0a001","position":{"lat":41.7,"lng":44.8}}}`,
	}, "\n")
	_ = os.WriteFile(path, []byte(body), 0o600)
	a, err := replay.New(replay.Config{File: path, Allowed: true, Speed: 1000})
	if err != nil {
		t.Fatal(err)
	}
	sink := sinktest.New(func(p *manned.Policy) { p.MaxRecordBytes = 128 })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, sink) }()
	waitUntil(t, func() bool { return sink.Counters.Get(replay.CounterReplayEnded) == 1 })
	cancel()
	<-done
	s := sink.Samples()
	if sink.Counters.Get("refused_replay_record") != 4 || len(s) != 2 || s[0].FeedTS != nil || s[1].FeedTS == nil {
		t.Fatalf("%v %d", sink.Counters.Snapshot(), len(s))
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
