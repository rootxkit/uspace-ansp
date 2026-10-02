//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

type seen struct {
	mu       sync.Mutex
	tracks   []time.Time
	statuses []adapter.StatusBody
	last     map[string]any
}

func (s *seen) trackCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tracks)
}

func (s *seen) tracksAfter(t time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, at := range s.tracks {
		if at.After(t) {
			n++
		}
	}
	return n
}

func (s *seen) lastStatus() (adapter.StatusBody, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return adapter.StatusBody{}, false
	}
	return s.statuses[len(s.statuses)-1], true
}

func waitIntegration(t *testing.T, what string, d time.Duration, cond func() bool) time.Time {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Now()
}

// The process against a real NATS: a replayed track arrives on
// man.v1.<adapter>.<icao24> in the envelope, src.v1.manned.<adapter>
// says live; the switch is turned off in KV source_control and
// publishing stops within one status tick (2 s) while the status says
// who and why; it is turned on again by the ctl.sources push and
// publishing resumes within one tick (B-11, E-01, E-02).
func TestIntegrationPublishAndSwitch(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, CredsFile: os.Getenv("ANSP_NATS_CREDS"), Name: "it-adapter"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	kv, err := b.JetStream().KeyValue(ctx, bus.BucketSourceControl)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("it-%d", time.Now().UnixNano()%1_000_000)
	got := &seen{}
	sub, err := b.Conn().Subscribe(bus.SubjectMannedPrefix+id+".>", func(m *nats.Msg) {
		var e map[string]any
		_ = json.Unmarshal(m.Data, &e)
		got.mu.Lock()
		got.tracks = append(got.tracks, time.Now())
		got.last = e
		got.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	ssub, err := b.Conn().Subscribe(bus.SubjectSourceStatusPrefix+id, func(m *nats.Msg) {
		var e struct {
			Body adapter.StatusBody `json:"body"`
		}
		_ = json.Unmarshal(m.Data, &e)
		got.mu.Lock()
		got.statuses = append(got.statuses, e.Body)
		got.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ssub.Unsubscribe() }()

	env := []string{
		"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_HTTP_ADDR=127.0.0.1:0",
		"ANSP_NATS_URL=" + url, "ANSP_NATS_CREDS=" + os.Getenv("ANSP_NATS_CREDS"),
		"ANSP_ADAPTER_KIND=replay", "ANSP_ADAPTER_ID=" + id, "ANSP_ADAPTER_SOURCE_CLASS=ads_b",
		"ANSP_ADAPTER_REPLAY_FILE=" + filepath.Join("..", "..", "testdata", "replay", "two-aircraft-converging.ndjson"),
		"ANSP_ADAPTER_REPLAY_ALLOWED=true", "ANSP_ADAPTER_REPLAY_SPEED=4", "ANSP_ADAPTER_REPLAY_LOOP=true",
	}
	pctx, stop := context.WithCancel(ctx)
	done := make(chan int, 1)
	out := &syncBuffer{}
	go func() { done <- run(pctx, nil, env, out) }()

	waitIntegration(t, "a track", 20*time.Second, func() bool { return got.trackCount() > 0 })
	got.mu.Lock()
	last := got.last
	got.mu.Unlock()
	body, _ := last["body"].(map[string]any)
	if last["schema"] != "track/manned/v1" || last["producer"] != "ansp/manned-adapter" || last["time_source"] != "source_clock" ||
		body["source_instance"] != id || body["state"] != "live" || body["trust"] != "surveillance" || body["source_class"] != "ads_b" {
		t.Fatalf("envelope %v", last)
	}
	waitIntegration(t, "a live status", 10*time.Second, func() bool {
		s, ok := got.lastStatus()
		return ok && s.State == "live" && s.Enabled && s.Counters["accepted"] > 0
	})

	// Off, by instance, in KV.
	epoch := fmt.Sprintf("it-epoch-%s", id)
	off := adapter.ControlDoc{Version: 1, Epoch: epoch, Controls: []adapter.ControlRow{
		{SourceType: "manned", InstanceID: &id, Enabled: false, Actor: "it-admin", Reason: "integration test", ChangedAt: time.Now().UTC()},
	}}
	raw, _ := json.Marshal(off)
	if _, err := kv.Put(ctx, adapter.KVKey, raw); err != nil {
		t.Fatal(err)
	}
	switched := time.Now()
	tick := 2 * time.Second
	waitIntegration(t, "a disabled status", 3*tick, func() bool {
		s, ok := got.lastStatus()
		return ok && s.State == "disabled"
	})
	time.Sleep(2 * tick)
	if n := got.tracksAfter(switched.Add(tick)); n != 0 {
		t.Fatalf("%d tracks published more than one tick after the switch went off", n)
	}
	s, _ := got.lastStatus()
	if s.Enabled || s.DisabledBy == nil || *s.DisabledBy != "instance" || *s.DisabledByWho != "it-admin" ||
		*s.Reason != "disabled by it-admin: integration test (instance switch)" || s.Counters["refused_disabled"] == 0 {
		t.Fatalf("disabled status %+v", s)
	}
	t.Logf("switch off at %s; last track %v after it; status %q", switched.Format(time.RFC3339Nano),
		func() time.Duration {
			got.mu.Lock()
			defer got.mu.Unlock()
			return got.tracks[len(got.tracks)-1].Sub(switched)
		}(), *s.Reason)

	// On again, by the ctl.sources push.
	on := off
	on.Version = 2
	on.Controls[0].Enabled = true
	raw, _ = json.Marshal(on)
	if err := b.Conn().Publish(bus.SubjectControlSources, raw); err != nil {
		t.Fatal(err)
	}
	resumed := time.Now()
	at := waitIntegration(t, "publishing to resume", tick, func() bool { return got.tracksAfter(resumed) > 0 })
	t.Logf("switch on by ctl.sources; first track %v later", at.Sub(resumed))
	_ = kv.Delete(ctx, adapter.KVKey)

	stop()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d; log:\n%s", code, out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no drain")
	}
}
