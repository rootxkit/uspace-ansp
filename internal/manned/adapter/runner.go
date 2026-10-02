package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// Counters of the runner (E-09), beside the normaliser's.
const (
	CounterRefusedDisabled     = "refused_disabled"      // a track not published because the switch is off (B-11)
	CounterPublishFailed       = "publish_failed"        // NATS refused a track
	CounterStatusPublishFailed = "status_publish_failed" // NATS refused a status
	CounterReconnects          = "reconnects"            // the feed was opened again
	CounterFeedLost            = "feed_lost"             // a connected feed went away
	CounterSuspectedStalls     = "suspected_stalls"      // a read after a gap longer than stall_after_s
)

// ErrPermanent marks an adapter error the runner does not retry: the
// configuration can never work, so the process stops and says why.
var ErrPermanent = errors.New("permanent adapter error")

// Event is something the process may log: the runner never logs (a
// library package never does; the process decides).
type Event struct {
	Kind   string
	At     time.Time
	ICAO24 string
	Field  string
	Reason string
	Err    error
	// Gap and Samples describe a stall.
	Gap     time.Duration
	Samples int
}

// The kinds of Event.
const (
	EventConnected = "connected"
	EventLost      = "lost"
	EventRefused   = "refused"
	EventStall     = "stall"
	EventDisabled  = "disabled"
	EventEnabled   = "enabled"
)

// Publisher publishes on core NATS (a *nats.Conn).
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Runner runs one adapter: it reconnects the feed forever with backoff
// (B-08), places, judges and publishes what it reads, detects stalls
// (T-11), follows the switch (B-11) and publishes its status every
// status period on src.v1.manned.<instance>.
type Runner struct {
	Adapter     Adapter
	Instance    string
	SourceClass string
	Publisher   Publisher
	Switch      Switch
	Policy      manned.PolicySource
	Counters    *core.Counters
	// Clock is the adapter's clock; nil is time.Now.
	Clock func() time.Time
	// OnEvent hears what the process may log; nil ignores.
	OnEvent func(Event)
	// Replay says the feed is a replay; the status shows it (06 T11).
	Replay bool

	once  sync.Once
	norm  *manned.Normaliser
	queue chan manned.RawSample

	mu            sync.Mutex
	connected     bool
	feedSince     time.Time
	lastInput     time.Time
	gapBefore     time.Duration
	lastSample    time.Time
	feedClock     string
	state         string
	stateSince    time.Time
	lastEnabled   bool
	enabledKnown  bool
	lastDisableBy string
	pending       *manned.RawSample
}

func (r *Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r *Runner) emit(e Event) {
	if r.OnEvent != nil {
		if e.At.IsZero() {
			e.At = r.now()
		}
		r.OnEvent(e)
	}
}

// init builds the normaliser and the queue once.
func (r *Runner) init() {
	r.once.Do(func() {
		if r.Counters == nil {
			r.Counters = &core.Counters{}
		}
		if r.Switch == nil {
			r.Switch = AlwaysOn{}
		}
		if r.Publisher == nil {
			r.Publisher = noPublisher{}
		}
		if r.Policy == nil {
			r.Policy = manned.StaticPolicy{Policy: manned.Defaults()}
		}
		r.norm = manned.NewNormaliser(r.Instance, r.SourceClass, r.Policy, r.Counters)
		r.norm.Now = r.now
		r.norm.OnRefuse = func(f manned.Refusal) {
			r.emit(Event{Kind: EventRefused, ICAO24: f.ICAO24, Field: f.Field, Reason: f.Reason})
		}
		pol, _ := r.Policy.Current()
		r.queue = make(chan manned.RawSample, pol.MaxBatch)
		r.feedSince = r.now()
		r.feedClock = "unknown"
	})
}

// Normaliser is the runner's normaliser.
func (r *Runner) Normaliser() *manned.Normaliser {
	r.init()
	return r.norm
}

// Run runs the adapter until ctx ends. It returns nil then, or the
// adapter's error when the adapter failed permanently (ErrPermanent).
func (r *Runner) Run(ctx context.Context) error {
	r.init()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	fatal := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := r.feed(ctx); err != nil {
			fatal <- err
			cancel()
		}
	}()
	go func() {
		defer wg.Done()
		r.statusLoop(ctx)
	}()
	r.consume(ctx)
	cancel()
	wg.Wait()
	select {
	case err := <-fatal:
		return err
	default:
		return nil
	}
}

// feed runs the adapter, reconnecting with a doubling backoff between
// reconnect_min_s and reconnect_max_s, reset after a session that
// connected.
func (r *Runner) feed(ctx context.Context) error {
	sink := &runnerSink{r: r}
	var backoff time.Duration
	for {
		sink.connected = false
		err := r.Adapter.Run(ctx, sink)
		r.lost(err)
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if errors.Is(err, ErrPermanent) {
			return err
		}
		pol, _ := r.Policy.Current()
		lo, hi := manned.Seconds(pol.ReconnectMinS), manned.Seconds(pol.ReconnectMaxS)
		switch {
		case sink.connected || backoff == 0:
			backoff = lo
		default:
			backoff = min(2*backoff, hi)
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		r.Counters.Inc(CounterReconnects)
	}
}

func (r *Runner) lost(err error) {
	now := r.now()
	r.mu.Lock()
	was := r.connected
	r.connected = false
	if was {
		r.feedSince = now
	}
	r.mu.Unlock()
	if was {
		r.Counters.Inc(CounterFeedLost)
	}
	if was || err != nil {
		r.emit(Event{Kind: EventLost, At: now, Err: err})
	}
}

// runnerSink is the Sink of one adapter session.
type runnerSink struct {
	r         *Runner
	connected bool
}

// Connected marks the feed connected.
func (s *runnerSink) Connected() {
	now := s.r.now()
	s.connected = true
	s.r.mu.Lock()
	was := s.r.connected
	s.r.connected = true
	if !was {
		s.r.feedSince = now
	}
	s.r.mu.Unlock()
	if !was {
		s.r.emit(Event{Kind: EventConnected, At: now})
	}
}

// Heard records a read and the silence before it.
func (s *runnerSink) Heard() {
	now := s.r.now()
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	if s.r.lastInput.IsZero() {
		s.r.gapBefore = 0
	} else {
		s.r.gapBefore = now.Sub(s.r.lastInput)
	}
	s.r.lastInput = now
}

// Sample stamps and queues one sample.
func (s *runnerSink) Sample(ctx context.Context, smp manned.RawSample) error {
	if smp.ReadAt.IsZero() {
		smp.ReadAt = s.r.now()
	}
	s.r.mu.Lock()
	smp.AfterGap = s.r.gapBefore
	s.r.mu.Unlock()
	select {
	case s.r.queue <- smp:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refuse counts refused and refused_<name>.
func (s *runnerSink) Refuse(name string) {
	s.r.Counters.Inc(manned.CounterRefused)
	s.r.Counters.Inc(manned.RefusedPrefix + name)
}

// Count counts name.
func (s *runnerSink) Count(name string) { s.r.Counters.Inc(name) }

// Policy is the policy of the moment.
func (s *runnerSink) Policy() manned.Policy {
	p, _ := s.r.Policy.Current()
	return p
}

// Now is the runner's clock.
func (s *runnerSink) Now() time.Time { return s.r.now() }

// consume takes batches off the queue until ctx ends.
func (r *Runner) consume(ctx context.Context) {
	for {
		first, ok := r.next(ctx)
		if !ok {
			return
		}
		pol, _ := r.Policy.Current()
		stallAfter := manned.Seconds(pol.StallAfterS)
		suspect := first.AfterGap > stallAfter
		batch := []manned.RawSample{first}
		if suspect {
			batch = r.burst(ctx, batch, &pol)
		} else {
			batch = r.drain(batch, stallAfter, pol.MaxBatch)
		}
		r.Handle(batch, suspect)
	}
}

// next is the held-back sample or the next one off the queue.
func (r *Runner) next(ctx context.Context) (manned.RawSample, bool) {
	if r.pending != nil {
		s := *r.pending
		r.pending = nil
		return s, true
	}
	select {
	case <-ctx.Done():
		return manned.RawSample{}, false
	case s := <-r.queue:
		return s, true
	}
}

// drain adds what is already queued, up to maxBatch, and stops before a
// sample that follows a gap (it starts the next batch).
func (r *Runner) drain(batch []manned.RawSample, stallAfter time.Duration, maxBatch int) []manned.RawSample {
	for len(batch) < maxBatch {
		select {
		case s := <-r.queue:
			if s.AfterGap > stallAfter {
				r.pending = &s
				return batch
			}
			batch = append(batch, s)
		default:
			return batch
		}
	}
	return batch
}

// burst drains a suspected stall: everything that arrives until the
// queue is quiet for burst_settle_s, up to max_batch.
func (r *Runner) burst(ctx context.Context, batch []manned.RawSample, pol *manned.Policy) []manned.RawSample {
	settle := manned.Seconds(pol.BurstSettleS)
	t := time.NewTimer(settle)
	defer t.Stop()
	for len(batch) < pol.MaxBatch {
		select {
		case <-ctx.Done():
			return batch
		case <-t.C:
			return batch
		case s := <-r.queue:
			batch = append(batch, s)
			if !t.Stop() {
				<-t.C
			}
			t.Reset(settle)
		}
	}
	return batch
}

// Handle judges and publishes one batch. suspect says the batch is the
// burst read after a gap longer than stall_after_s. The stall is
// confirmed when the burst spans more than stall_after_s on the feed's
// own clock (the feed buffered), or when the feed gives no time base
// (a silent feed and a stalled one cannot then be told apart, and the
// burst is taken as history); a quiet sky that resumes is not a stall
// (one fresh sample spans nothing). In a confirmed stall, samples with a
// feed time are placed by it and samples without one are backlog (T-11,
// SC-15).
func (r *Runner) Handle(batch []manned.RawSample, suspect bool) {
	r.init()
	if len(batch) == 0 {
		return
	}
	pol, _ := r.Policy.Current()
	rxTS := batch[0].ReadAt
	for i := range batch {
		if batch[i].ReadAt.After(rxTS) {
			rxTS = batch[i].ReadAt
		}
	}
	if rxTS.IsZero() {
		rxTS = r.now()
	}
	if suspect {
		r.Counters.Inc(CounterSuspectedStalls)
		spread, hasTS := feedSpread(batch)
		if !hasTS || spread > manned.Seconds(pol.StallAfterS) {
			r.Counters.Inc(manned.CounterStalledReads)
			for i := range batch {
				if batch[i].FeedTS == nil {
					batch[i].Backlog = true
				}
			}
			r.emit(Event{Kind: EventStall, Gap: batch[0].AfterGap, Samples: len(batch)})
		}
	}
	tracks := r.norm.Take(batch, rxTS)
	dec := r.Switch.Decide()
	r.noteSwitch(dec)
	for i := range tracks {
		if !dec.Enabled {
			r.Counters.Inc(manned.CounterRefused)
			r.Counters.Inc(CounterRefusedDisabled)
			continue
		}
		data, err := json.Marshal(&tracks[i])
		if err == nil {
			err = r.Publisher.Publish(tracks[i].Subject(bus.SubjectMannedPrefix), data)
		}
		if err != nil {
			r.Counters.Inc(CounterPublishFailed)
			continue
		}
		r.Counters.Inc(manned.CounterAccepted)
	}
	clock := "absent"
	for i := range batch {
		if batch[i].FeedTS != nil {
			clock = "present"
			break
		}
	}
	r.mu.Lock()
	r.lastSample = rxTS
	r.feedClock = clock
	r.mu.Unlock()
}

// feedSpread is newest - oldest feed time of the batch, and whether any
// sample had one.
func feedSpread(batch []manned.RawSample) (time.Duration, bool) {
	var lo, hi time.Time
	has := false
	for i := range batch {
		ts := batch[i].FeedTS
		if ts == nil {
			continue
		}
		if !has || ts.Before(lo) {
			lo = *ts
		}
		if !has || ts.After(hi) {
			hi = *ts
		}
		has = true
	}
	return hi.Sub(lo), has
}

// noteSwitch emits a transition of the switch once.
func (r *Runner) noteSwitch(d Decision) {
	by := ""
	if !d.Enabled {
		by = DisabledText(d)
	}
	r.mu.Lock()
	changed := !r.enabledKnown || r.lastEnabled != d.Enabled || r.lastDisableBy != by
	first := !r.enabledKnown
	r.lastEnabled, r.enabledKnown, r.lastDisableBy = d.Enabled, true, by
	r.mu.Unlock()
	switch {
	case !changed:
	case !d.Enabled:
		r.emit(Event{Kind: EventDisabled, Reason: by})
	case !first:
		r.emit(Event{Kind: EventEnabled})
	}
}

// DisabledText is "disabled by <actor>: <reason>" (B-11), with the kind
// of the deciding row when known.
func DisabledText(d Decision) string {
	actor := d.Actor
	if actor == "" {
		actor = "unknown actor"
	}
	reason := d.Reason
	if reason == "" {
		reason = "no reason recorded"
	}
	text := fmt.Sprintf("disabled by %s: %s", actor, reason)
	if d.Why != nil {
		text += " (" + string(*d.Why) + " switch)"
	}
	return text
}

// statusLoop publishes the status every status period until ctx ends.
func (r *Runner) statusLoop(ctx context.Context) {
	for {
		r.PublishStatus()
		pol, _ := r.Policy.Current()
		t := time.NewTimer(manned.Seconds(pol.StatusPeriodS))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// PublishStatus publishes one status on src.v1.manned.<instance>.
func (r *Runner) PublishStatus() {
	r.init()
	env := r.StatusEnvelope(r.now())
	data, err := json.Marshal(env)
	if err == nil {
		err = r.Publisher.Publish(bus.SubjectSourceStatusPrefix+r.Instance, data)
	}
	if err != nil {
		r.Counters.Inc(CounterStatusPublishFailed)
	}
}

// Check is the readiness check of the feed, named feed and required:
// ok while connected (degraded when the switch is off), down with
// "reconnecting since T" otherwise.
func (r *Runner) Check() obs.Check {
	return obs.Check{Name: "feed", Required: true, Probe: func(context.Context) (obs.State, string) {
		r.init()
		r.mu.Lock()
		connected, since := r.connected, r.feedSince
		r.mu.Unlock()
		if !connected {
			return obs.StateDown, "reconnecting since " + manned.FormatTime(since)
		}
		if d := r.Switch.Decide(); !d.Enabled {
			return obs.StateDegraded, DisabledText(d)
		}
		return obs.StateOK, ""
	}}
}
