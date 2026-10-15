//go:build integration

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/feed"
)

// The picture's count against real NATS, with manned-feed started
// without ANSP_SESSION_PUBLIC_KEY_FILE, so it verifies no console
// session, and the count still reaches api over the bus. It
// answers ctl.manned.summary empty with adapters_silent, then two live
// aircraft of a live adapter, each reply in the shape api decodes and
// naming no aircraft, and counts what it answered.
func TestIntegrationFeedSummary(t *testing.T) {
	p := startFeed(t)
	ask := func() (feed.MannedSummary, string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		m, err := p.b.Conn().RequestWithContext(ctx, bus.SubjectMannedSummary, nil)
		if err != nil {
			return feed.MannedSummary{}, "", err
		}
		s, err := feed.DecodeSummary(m.Data)
		return s, string(m.Data), err
	}
	deadline := time.Now().Add(20 * time.Second)
	var (
		s   feed.MannedSummary
		raw string
		err error
	)
	for {
		if s, raw, err = ask(); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || s.Total != 0 || !strings.Contains(strings.Join(s.Degraded, ","), feed.DegradedAdaptersSilent) {
		t.Fatalf("empty: %v %s; log:\n%s", err, raw, p.out.String())
	}
	adapter := fmt.Sprintf("replay-sum-%d", time.Now().UnixNano()%100000)
	p.status(t, adapter, "live")
	now := time.Now().UTC()
	p.publish(t, liveSample(adapter, "a1b2c1", 41.70, 44.80, now))
	p.publish(t, liveSample(adapter, "a1b2c2", 41.71, 44.80, now))
	deadline = time.Now().Add(20 * time.Second)
	for {
		s, raw, err = ask()
		if err == nil && s.Total == 2 && s.ByState.Live == 2 && !strings.Contains(strings.Join(s.Degraded, ","), feed.DegradedAdaptersSilent) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("two live aircraft not counted: %v %s", err, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(raw, "a1b2c1") {
		t.Fatalf("the summary names an aircraft: %s", raw)
	}
	if !strings.Contains(get200(t, "http://"+p.addr+"/metrics"), counterSummaryAnswered) {
		t.Fatalf("%s is not exported", counterSummaryAnswered)
	}
}

// get200 is the body of a GET that answered 200.
func get200(t *testing.T, url string) string {
	t.Helper()
	code, body := get(t, url)
	if code != 200 {
		t.Fatalf("GET %s: %d", url, code)
	}
	return body
}
