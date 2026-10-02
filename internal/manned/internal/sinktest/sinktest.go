// Package sinktest is a recording adapter.Sink for the readers' tests:
// it keeps every sample and counts everything else. Imported by tests
// only.
package sinktest

import (
	"context"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// Recorder records what an adapter reports. Safe for concurrent use.
type Recorder struct {
	Pol      manned.Policy
	Counters core.Counters
	// Clock is the clock; nil is time.Now.
	Clock func() time.Time
	// OnSample, when set, is called with every sample.
	OnSample func(manned.RawSample)

	mu         sync.Mutex
	samples    []manned.RawSample
	connected  int
	heard      int
	connectedC chan struct{}
}

// New is a recorder with the default policy changed by edit (may be nil).
func New(edit func(*manned.Policy)) *Recorder {
	p := manned.Defaults()
	if edit != nil {
		edit(&p)
	}
	return &Recorder{Pol: p, connectedC: make(chan struct{}, 64)}
}

// Connected counts a connection.
func (r *Recorder) Connected() {
	r.mu.Lock()
	r.connected++
	r.mu.Unlock()
	select {
	case r.connectedC <- struct{}{}:
	default:
	}
}

// ConnectedC receives once per connection (best effort, 64 buffered).
func (r *Recorder) ConnectedC() <-chan struct{} { return r.connectedC }

// Heard counts a read.
func (r *Recorder) Heard() {
	r.mu.Lock()
	r.heard++
	r.mu.Unlock()
}

// Sample records s.
func (r *Recorder) Sample(ctx context.Context, s manned.RawSample) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ReadAt.IsZero() {
		s.ReadAt = r.Now()
	}
	r.mu.Lock()
	r.samples = append(r.samples, s)
	f := r.OnSample
	r.mu.Unlock()
	if f != nil {
		f(s)
	}
	return nil
}

// Refuse counts refused and refused_<name>.
func (r *Recorder) Refuse(name string) {
	r.Counters.Inc(manned.CounterRefused)
	r.Counters.Inc(manned.RefusedPrefix + name)
}

// Count counts name.
func (r *Recorder) Count(name string) { r.Counters.Inc(name) }

// Policy is Pol.
func (r *Recorder) Policy() manned.Policy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Pol
}

// Now is the clock.
func (r *Recorder) Now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// Samples is a copy of the samples so far.
func (r *Recorder) Samples() []manned.RawSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]manned.RawSample(nil), r.samples...)
}

// Connections and Reads are the counts of Connected and Heard.
func (r *Recorder) Connections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

// Reads is the count of Heard.
func (r *Recorder) Reads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.heard
}
