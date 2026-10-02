package sinktest_test

import (
	"context"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/sinktest"
)

func TestRecorder(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	r := sinktest.New(func(p *manned.Policy) { p.StallAfterS = 9 })
	r.Clock = func() time.Time { return at }
	var heard int
	r.OnSample = func(manned.RawSample) { heard++ }
	r.Connected()
	<-r.ConnectedC()
	r.Heard()
	if err := r.Sample(context.Background(), manned.RawSample{ICAO24: "f0a001"}); err != nil {
		t.Fatal(err)
	}
	r.Refuse("x")
	r.Count("y")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Sample(ctx, manned.RawSample{}); err == nil {
		t.Fatal("a cancelled sample was recorded")
	}
	s := r.Samples()
	if len(s) != 1 || !s[0].ReadAt.Equal(at) || heard != 1 || r.Connections() != 1 || r.Reads() != 1 ||
		r.Counters.Get("refused_x") != 1 || r.Counters.Get("refused") != 1 || r.Counters.Get("y") != 1 ||
		r.Policy().StallAfterS != 9 || !r.Now().Equal(at) {
		t.Fatal(s, r.Counters.Snapshot())
	}
	if sinktest.New(nil).Now().IsZero() {
		t.Fatal("no clock")
	}
}
