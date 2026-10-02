package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
)

// MaxDocBytes bounds a policy document read from KV or a push.
const MaxDocBytes = 64 << 10

// Follower holds the policy the hot path judges with. It applies only a
// higher, valid version than the one it holds, so a late or replayed
// value cannot roll it back and a bad value cannot disarm a check. With
// none applied it serves Defaults() and says so (Status). Safe for
// concurrent use.
type Follower struct {
	counters *core.Counters

	mu      sync.RWMutex
	current Policy
	have    bool
}

// NewFollower is a follower that holds no policy yet; counters may be
// nil.
func NewFollower(counters *core.Counters) *Follower {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Follower{counters: counters}
}

// Counters are the follower's counters.
func (f *Follower) Counters() *core.Counters { return f.counters }

// Apply offers p and reports whether it replaced the held policy. An
// equal version (a re-read) is ignored silently, a lower one is ignored
// and counted, an invalid one refused and counted.
func (f *Follower) Apply(p Policy) bool {
	if p.Version <= 0 || p.Validate() != nil {
		f.counters.Inc(CounterInvalidRefused)
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.have && p.Version <= f.current.Version {
		if p.Version < f.current.Version {
			f.counters.Inc(CounterOlderIgnored)
		}
		return false
	}
	f.current, f.have = p, true
	f.counters.Inc(CounterApplied)
	return true
}

// ApplyJSON decodes a KV value or ctl.policy push and applies it.
func (f *Follower) ApplyJSON(doc []byte) bool {
	if len(doc) > MaxDocBytes {
		f.counters.Inc(CounterUndecodable)
		return false
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		f.counters.Inc(CounterUndecodable)
		return false
	}
	return f.Apply(p)
}

// Current is the held policy, or with none the compiled defaults at
// version 0; fromKV says which.
func (f *Follower) Current() (p Policy, fromKV bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.have {
		return Policy{Thresholds: Defaults()}, false
	}
	return f.current, true
}

// Version is the held policy_version, 0 while serving the defaults.
func (f *Follower) Version() int64 {
	p, _ := f.Current()
	return p.Version
}

// Status is the follower's line for the process log and status: the
// version it applies, or that it serves the defaults because KV gave it
// nothing (E-02: defaults never look like a stored policy).
func (f *Follower) Status() string {
	p, fromKV := f.Current()
	if !fromKV {
		return "policy: defaults, KV empty"
	}
	return fmt.Sprintf("policy: version %d", p.Version)
}

// Run watches the KV bucket policy and applies every value of KVKey
// until ctx ends. It returns ctx's error, or the watcher's when the
// watch cannot start.
func (f *Follower) Run(ctx context.Context, kv jetstream.KeyValue) error {
	w, err := kv.Watch(ctx, KVKey)
	if err != nil {
		return fmt.Errorf("policy: watch: %w", err)
	}
	defer func() { _ = w.Stop() }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-w.Updates():
			if !ok {
				return ctx.Err()
			}
			// A nil entry marks the end of the initial values.
			if e != nil && e.Operation() == jetstream.KeyValuePut {
				f.ApplyJSON(e.Value())
			}
		}
	}
}
