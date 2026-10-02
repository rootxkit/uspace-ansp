package adapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/internal/schematest"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// recorder is a Publisher that keeps every message.
type recorder struct {
	mu   sync.Mutex
	msgs []msg
	fail bool
}

type msg struct {
	subject string
	data    []byte
}

func (r *recorder) Publish(subject string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("nats: connection closed")
	}
	r.msgs = append(r.msgs, msg{subject, append([]byte(nil), data...)})
	return nil
}

// tracks are the published track messages.
func (r *recorder) tracks() []msg {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []msg
	for _, m := range r.msgs {
		if strings.HasPrefix(m.subject, "man.v1.") {
			out = append(out, m)
		}
	}
	return out
}

func (r *recorder) statuses() []msg {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []msg
	for _, m := range r.msgs {
		if strings.HasPrefix(m.subject, "src.v1.manned.") {
			out = append(out, m)
		}
	}
	return out
}

// fake is an Adapter driven by the test: each session connects, then
// runs script with the sink, then ends with the script's error.
type fake struct {
	mu       sync.Mutex
	sessions int
	script   func(ctx context.Context, sink adapter.Sink, session int) error
}

func (f *fake) Kind() string { return adapter.KindReplay }

func (f *fake) Run(ctx context.Context, sink adapter.Sink) error {
	f.mu.Lock()
	f.sessions++
	n := f.sessions
	f.mu.Unlock()
	return f.script(ctx, sink, n)
}

// switchable is a Switch the test flips.
type switchable struct {
	mu sync.Mutex
	d  adapter.Decision
}

func (s *switchable) Decide() adapter.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d
}

func (s *switchable) set(d adapter.Decision) {
	s.mu.Lock()
	s.d = d
	s.mu.Unlock()
}

func on() adapter.Decision { return adapter.Decision{Enabled: true, Known: true} }

func off() adapter.Decision {
	w := sources.WhyInstance
	return adapter.Decision{Enabled: false, Why: &w, Actor: "admin-1", Reason: "receiver maintenance", Known: true}
}

func sample(icao string, ts *time.Time, lat float64) manned.RawSample {
	return manned.RawSample{
		FeedTS: ts, FeedNow: ts, ICAO24: icao, Position: &manned.LatLonSample{LatDeg: lat, LonDeg: 44.8},
		AltPressureM: manned.F(900),
	}
}

func newRunner(pub *recorder, sw adapter.Switch, edit func(*manned.Policy)) *adapter.Runner {
	p := manned.Defaults()
	if edit != nil {
		edit(&p)
	}
	return &adapter.Runner{
		Adapter: &fake{}, Instance: "adsb-tbs", SourceClass: manned.SourceClassADSB, Publisher: pub, Switch: sw,
		Policy: manned.StaticPolicy{Policy: p, Version: 2}, Counters: &core.Counters{},
	}
}

// burst is n samples of one aircraft one second apart on the feed's
// clock, all read at rx after a gap.
func burst(n int, withTime bool, rx time.Time, gap time.Duration) []manned.RawSample {
	out := make([]manned.RawSample, n)
	for i := range out {
		var ts *time.Time
		if withTime {
			ts = manned.T(t0.Add(time.Duration(i) * time.Second))
		}
		out[i] = sample("f0a001", ts, 41.70+float64(i)/1000)
		out[i].ReadAt = rx
		out[i].AfterGap = gap
	}
	return out
}

// No stall: one fresh read after a short gap is published as live, no
// stall counted (E-01 twin of the two stall cases below).
func TestNoStall(t *testing.T) {
	pub := &recorder{}
	r := newRunner(pub, adapter.AlwaysOn{}, nil)
	rx := time.Now()
	r.Handle(burst(1, true, rx, time.Second), false)
	if len(pub.tracks()) != 1 || r.Counters.Get(manned.CounterStalledReads) != 0 || r.Counters.Get(manned.CounterBacklogSamples) != 0 {
		t.Fatal(r.Counters.Snapshot())
	}
}

// SC-15 with a time base: 30 s of input buffered by the feed and read at
// once after a 30 s gap is placed by the feed's time (the oldest 29 s
// before the read, never stamped as now), not backlog, and the stall is
// counted.
func TestStallPlacedByFeedTime(t *testing.T) {
	pub := &recorder{}
	r := newRunner(pub, adapter.AlwaysOn{}, nil)
	rx := time.Now()
	r.Handle(burst(30, true, rx, 30*time.Second), true)
	got := pub.tracks()
	if len(got) != 30 {
		t.Fatal(len(got))
	}
	var first, last manned.Envelope
	_ = json.Unmarshal(got[0].data, &first)
	_ = json.Unmarshal(got[29].data, &last)
	if first.CapturedAt != manned.FormatTime(rx.Add(-29*time.Second)) || last.CapturedAt != manned.FormatTime(rx) ||
		first.Backlog || first.TimeSource != "source_clock" {
		t.Fatalf("first %+v last %+v", first, last)
	}
	if r.Counters.Get(manned.CounterStalledReads) != 1 || r.Counters.Get(adapter.CounterSuspectedStalls) != 1 {
		t.Fatal(r.Counters.Snapshot())
	}
	t.Logf("SC-15 (time base): 30 samples read at %s after a 30 s gap: captured_at %s .. %s, backlog false, stalled_reads %d",
		manned.FormatTime(rx), first.CapturedAt, last.CapturedAt, r.Counters.Get(manned.CounterStalledReads))
}

// SC-15 without a time base: the same burst is backlog, placed at its
// read (time_source system), and both counters move.
func TestStallWithoutTimeBaseIsBacklog(t *testing.T) {
	pub := &recorder{}
	r := newRunner(pub, adapter.AlwaysOn{}, nil)
	rx := time.Now()
	b := burst(30, false, rx, 30*time.Second)
	for i := range b {
		b[i].Position.LonDeg += float64(i) / 1000 // distinct positions: no dedupe
	}
	r.Handle(b, true)
	got := pub.tracks()
	if len(got) != 30 {
		t.Fatal(len(got))
	}
	for _, m := range got {
		var e manned.Envelope
		_ = json.Unmarshal(m.data, &e)
		if !e.Backlog || e.TS != nil || e.TimeSource != "system" {
			t.Fatalf("%+v", e)
		}
	}
	if r.Counters.Get(manned.CounterStalledReads) != 1 || r.Counters.Get(manned.CounterBacklogSamples) != 30 {
		t.Fatal(r.Counters.Snapshot())
	}
	t.Logf("SC-15 (no time base): 30 samples after a 30 s gap: backlog true on all 30, stalled_reads %d, backlog_samples %d",
		r.Counters.Get(manned.CounterStalledReads), r.Counters.Get(manned.CounterBacklogSamples))
}

// A quiet sky that resumes is not a stall: the read after the gap spans
// nothing on the feed's clock (lesson: a quiet table must not produce a
// false gap).
func TestQuietFeedResumingIsNotAStall(t *testing.T) {
	pub := &recorder{}
	r := newRunner(pub, adapter.AlwaysOn{}, nil)
	r.Handle(burst(1, true, time.Now(), 10*time.Minute), true)
	if r.Counters.Get(adapter.CounterSuspectedStalls) != 1 || r.Counters.Get(manned.CounterStalledReads) != 0 || len(pub.tracks()) != 1 {
		t.Fatal(r.Counters.Snapshot())
	}
}

// B-11: disabled, nothing is published and every track is counted
// refused_disabled; the status says who and why; enabled again, the
// next batch is published (E-01).
func TestSwitchEnabledDisabledResumed(t *testing.T) {
	pub := &recorder{}
	sw := &switchable{d: on()}
	r := newRunner(pub, sw, nil)
	var events []adapter.Event
	r.OnEvent = func(e adapter.Event) { events = append(events, e) }
	rx := time.Now()
	r.Handle([]manned.RawSample{sample("f0a001", manned.T(t0), 41.7)}, false)
	if len(pub.tracks()) != 1 {
		t.Fatal("enabled did not publish")
	}
	sw.set(off())
	r.Handle([]manned.RawSample{sample("f0a001", manned.T(t0.Add(time.Second)), 41.71)}, false)
	if len(pub.tracks()) != 1 || r.Counters.Get(adapter.CounterRefusedDisabled) != 1 {
		t.Fatalf("disabled published: %v", r.Counters.Snapshot())
	}
	st := r.Status(rx)
	if st.State != "disabled" || st.Enabled || *st.DisabledBy != "instance" || *st.DisabledByWho != "admin-1" ||
		*st.Reason != "disabled by admin-1: receiver maintenance (instance switch)" {
		t.Fatalf("%+v", st)
	}
	sw.set(on())
	r.Handle([]manned.RawSample{sample("f0a001", manned.T(t0.Add(2*time.Second)), 41.72)}, false)
	if len(pub.tracks()) != 2 {
		t.Fatal("re-enabled did not resume")
	}
	kinds := []string{}
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "disabled,enabled" {
		t.Fatal(kinds)
	}
}

// A publish NATS refuses is counted, never accepted.
func TestPublishFailureCounted(t *testing.T) {
	pub := &recorder{fail: true}
	r := newRunner(pub, nil, nil)
	r.Handle([]manned.RawSample{sample("f0a001", manned.T(t0), 41.7)}, false)
	r.PublishStatus()
	if r.Counters.Get(adapter.CounterPublishFailed) != 1 || r.Counters.Get(manned.CounterAccepted) != 0 ||
		r.Counters.Get(adapter.CounterStatusPublishFailed) != 1 {
		t.Fatal(r.Counters.Snapshot())
	}
	var none adapter.Runner
	none.Adapter, none.Instance, none.SourceClass = &fake{}, "x", manned.SourceClassADSB
	none.Handle([]manned.RawSample{sample("f0a001", manned.T(t0), 41.7)}, false)
	if none.Counters.Get(adapter.CounterPublishFailed) != 1 {
		t.Fatal("a runner without a publisher did not count")
	}
}

// waitFor polls cond for up to 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// E-02: a clean run's status is read field by field; then the feed goes
// away: the status and readiness say "reconnecting since T", feed_lost
// counts it, and the reconnection resumes publishing.
func TestStatusHealthyThenFeedLostThenResumed(t *testing.T) {
	pub := &recorder{}
	release := make(chan struct{})
	f := &fake{}
	f.script = func(ctx context.Context, sink adapter.Sink, session int) error {
		sink.Connected()
		base := t0.Add(time.Duration(session) * time.Minute)
		for i := range 3 {
			sink.Heard()
			if err := sink.Sample(ctx, sample(fmt.Sprintf("f0a00%d", i+1), manned.T(base), 41.7)); err != nil {
				return err
			}
		}
		if session == 1 {
			<-release
			return errors.New("feed closed the connection")
		}
		<-ctx.Done()
		return ctx.Err()
	}
	r := newRunner(pub, adapter.AlwaysOn{}, func(p *manned.Policy) {
		p.StatusPeriodS, p.ReconnectMinS, p.ReconnectMaxS = 0.05, 0.05, 0.05
	})
	r.Adapter = f
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "three tracks", func() bool { return len(pub.tracks()) == 3 })

	now := time.Now()
	st := r.Status(now)
	if st.Source != "ansp_feed" || st.SourceInstance != "adsb-tbs" || st.State != "live" || st.AgeS == nil || *st.AgeS > 5 ||
		st.DisabledBy != nil || st.DisabledByWho != nil || st.Counters["accepted"] != 3 || st.Counters["refused"] != 0 ||
		st.Kind != "replay" || st.Replay || !st.Enabled || !st.Connected || st.Feed != "connected" || st.LastFrameAt == nil ||
		st.AircraftSeen != 3 || st.PolicyVersion != "2" || st.Stalled || st.FeedClock != "present" || st.Reason != nil {
		t.Fatalf("healthy status: %+v", st)
	}
	if rep := (&obs.Health{}).Check(ctx, r.Check()); rep.Status != obs.StatusReady || rep.Summary[0] != "feed: ok" {
		t.Fatalf("%+v", rep)
	}
	sch := schematest.Compile(t, schematest.SourceStatus)
	waitFor(t, "a status", func() bool { return len(pub.statuses()) > 0 })
	for _, m := range pub.statuses()[:1] {
		if m.subject != "src.v1.manned.adsb-tbs" {
			t.Fatal(m.subject)
		}
		if err := schematest.Validate(t, sch, m.data); err != nil {
			t.Fatalf("%v\n%s", err, m.data)
		}
	}

	close(release)
	waitFor(t, "the feed lost", func() bool { return r.Counters.Get(adapter.CounterFeedLost) == 1 })
	st = r.Status(time.Now())
	if !strings.HasPrefix(st.Feed, "reconnecting since ") && r.Counters.Get(adapter.CounterReconnects) == 0 {
		t.Fatalf("feed lost: %+v", st)
	}
	waitFor(t, "the reconnection publishing again", func() bool { return len(pub.tracks()) == 6 })
	if r.Counters.Get(adapter.CounterReconnects) < 1 {
		t.Fatal(r.Counters.Snapshot())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// While the feed cannot be reached, the status and the readiness say
// reconnecting since T, and the state is down (E-02, degraded output).
func TestFeedDownSaysReconnectingSince(t *testing.T) {
	pub := &recorder{}
	f := &fake{script: func(context.Context, adapter.Sink, int) error { return errors.New("connection refused") }}
	r := newRunner(pub, adapter.AlwaysOn{}, func(p *manned.Policy) { p.ReconnectMinS, p.ReconnectMaxS = 0.01, 0.02 })
	r.Adapter = f
	var lost int
	var mu sync.Mutex
	r.OnEvent = func(e adapter.Event) {
		if e.Kind == adapter.EventLost {
			mu.Lock()
			lost++
			mu.Unlock()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "reconnect attempts", func() bool { return r.Counters.Get(adapter.CounterReconnects) >= 3 })
	st := r.Status(time.Now())
	if st.State != "down" || st.Connected || !strings.HasPrefix(st.Feed, "reconnecting since 20") || r.Counters.Get(adapter.CounterFeedLost) != 0 {
		t.Fatalf("%+v %v", st, r.Counters.Snapshot())
	}
	rep := (&obs.Health{}).Check(ctx, r.Check())
	if rep.Status != obs.StatusNotReady || !strings.HasPrefix(rep.Summary[0], "feed: down (reconnecting since ") {
		t.Fatalf("%+v", rep)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if lost < 3 {
		t.Fatal(lost)
	}
}

// A permanent adapter error stops the runner with that error; it is not
// retried.
func TestPermanentErrorStops(t *testing.T) {
	f := &fake{script: func(context.Context, adapter.Sink, int) error { return adapter.ErrDeferred }}
	r := newRunner(&recorder{}, nil, nil)
	r.Adapter = f
	err := r.Run(context.Background())
	if !errors.Is(err, adapter.ErrPermanent) || f.sessions != 1 {
		t.Fatal(err, f.sessions)
	}
}

// The runner drains a burst after a suspected stall into one batch, and
// takes samples queued behind a gap as the start of the next batch.
func TestRunnerBatchesBurstAfterGap(t *testing.T) {
	pub := &recorder{}
	f := &fake{}
	f.script = func(ctx context.Context, sink adapter.Sink, _ int) error {
		sink.Connected()
		sink.Heard()
		_ = sink.Sample(ctx, sample("f0a001", manned.T(t0), 41.70))
		time.Sleep(300 * time.Millisecond) // longer than stall_after_s below
		sink.Heard()
		for i := 1; i <= 10; i++ {
			_ = sink.Sample(ctx, sample("f0a001", manned.T(t0.Add(time.Duration(i)*time.Second)), 41.70+float64(i)/1000))
		}
		<-ctx.Done()
		return ctx.Err()
	}
	r := newRunner(pub, nil, func(p *manned.Policy) { p.StallAfterS, p.BurstSettleS = 0.1, 0.05 })
	r.Adapter = f
	var stall adapter.Event
	var mu sync.Mutex
	r.OnEvent = func(e adapter.Event) {
		if e.Kind == adapter.EventStall {
			mu.Lock()
			stall = e
			mu.Unlock()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "eleven tracks", func() bool { return len(pub.tracks()) == 11 })
	if st := r.Status(time.Now()); st.Stalled {
		t.Fatal("stalled right after a read")
	}
	if st := r.Status(time.Now().Add(time.Second)); !st.Stalled {
		t.Fatal("not stalled after a second of silence")
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if r.Counters.Get(manned.CounterStalledReads) != 1 || stall.Samples != 10 || stall.Gap < 250*time.Millisecond {
		t.Fatalf("%v %+v", r.Counters.Snapshot(), stall)
	}
}

func TestStatusStaleAndUnknown(t *testing.T) {
	sw := &switchable{d: adapter.Decision{Enabled: true}}
	r := newRunner(&recorder{}, sw, nil)
	f := &fake{script: func(ctx context.Context, sink adapter.Sink, _ int) error {
		sink.Connected()
		<-ctx.Done()
		return ctx.Err()
	}}
	r.Adapter = f
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitFor(t, "connected", func() bool { return r.Status(time.Now()).Connected })
	if st := r.Status(time.Now()); st.State != "unknown" || st.AgeS != nil || st.FeedClock != "unknown" {
		t.Fatalf("%+v", st)
	}
	sw.set(on())
	st := r.Status(time.Now())
	if st.State != "stale" {
		t.Fatalf("%+v", st)
	}
	sch := schematest.Compile(t, schematest.SourceStatus)
	raw, _ := json.Marshal(r.StatusEnvelope(time.Now()))
	if err := schematest.Validate(t, sch, raw); err != nil {
		t.Fatal(err)
	}
	sw.set(off())
	raw, _ = json.Marshal(r.StatusEnvelope(time.Now()))
	if err := schematest.Validate(t, sch, raw); err != nil {
		t.Fatalf("disabled status: %v\n%s", err, raw)
	}
	if rep := (&obs.Health{}).Check(ctx, r.Check()); rep.Checks[0].State != obs.StateDegraded {
		t.Fatalf("%+v", rep)
	}
	cancel()
	<-done
}

func TestRegistry(t *testing.T) {
	var reg adapter.Registry
	if _, err := reg.Build(adapter.KindReplay); err == nil {
		t.Fatal("built an unregistered kind")
	}
	if err := reg.Register("atm_api", nil); err == nil {
		t.Fatal("registered an unknown kind")
	}
	if err := reg.Register(adapter.KindReplay, func() (adapter.Adapter, error) { return &fake{}, nil }); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(adapter.KindReplay, nil); err == nil {
		t.Fatal("registered a kind twice")
	}
	a, err := reg.Build(adapter.KindReplay)
	if err != nil || a.Kind() != adapter.KindReplay || len(reg.Registered()) != 1 {
		t.Fatal(err)
	}
}

func TestDisabledText(t *testing.T) {
	if got := adapter.DisabledText(adapter.Decision{}); got != "disabled by unknown actor: no reason recorded" {
		t.Fatal(got)
	}
}
