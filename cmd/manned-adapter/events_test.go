package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// Every event is logged at its level; a refusal once per aircraft per
// period, never per frame.
func TestEventLogger(t *testing.T) {
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "debug"})
	log := eventLogger(logger, manned.NewRefusalLimiter(time.Minute, 10))
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, e := range []adapter.Event{
		{Kind: adapter.EventConnected},
		{Kind: adapter.EventLost, Err: errors.New("connection reset")},
		{Kind: adapter.EventRefused, At: at, ICAO24: "f0a001", Field: "position", Reason: "absent"},
		{Kind: adapter.EventRefused, At: at.Add(time.Second), ICAO24: "f0a001", Field: "position", Reason: "absent"},
		{Kind: adapter.EventStall, Gap: 30 * time.Second, Samples: 30},
		{Kind: adapter.EventDisabled, Reason: "disabled by admin-1: maintenance (instance switch)"},
		{Kind: adapter.EventEnabled},
	} {
		log(e)
	}
	s := out.String()
	for _, want := range []string{
		`"msg":"feed connected"`, `"msg":"feed lost; reconnecting"`, `"error":"connection reset"`, `"msg":"sample refused"`,
		`"icao24":"f0a001","field":"position","reason":"absent"`, `"msg":"feed stalled"`, `"samples":30`, `"msg":"publishing stopped"`,
		`"reason":"disabled by admin-1: maintenance (instance switch)"`, `"msg":"publishing resumed"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("log lacks %s:\n%s", want, s)
		}
	}
	if strings.Count(s, "sample refused") != 1 {
		t.Fatalf("a refusal was logged per frame:\n%s", s)
	}
}

// The policy is the WP-4 defaults with the followed row's liveness and
// version; before any row, version 0 and the compiled liveness.
func TestPolicySource(t *testing.T) {
	f := policy.NewFollower(nil)
	p, v := policySource{f}.Current()
	if v != 0 || p.SourceLivenessS != 15 || p.StallAfterS != 5 {
		t.Fatal(v, p)
	}
	th := policy.Defaults()
	th.SourceLivenessS = 20
	if !f.Apply(policy.Policy{Version: 7, Thresholds: th}) {
		t.Fatal("not applied")
	}
	p, v = policySource{f}.Current()
	if v != 7 || p.SourceLivenessS != 20 {
		t.Fatal(v, p)
	}
}
