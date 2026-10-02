package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/sources"
)

// SourceType is the source type of every adapter in the source-control
// state (04 §3.6; docs/PLAN.md section 6 PUT /v1/sources/{type}/{instance}).
const SourceType = "manned"

// Decision is whether this adapter may publish, and if not who switched
// it off, why, and by which row (B-11: disabled is never silent).
type Decision struct {
	Enabled bool
	// Why is nil exactly when Enabled.
	Why *sources.Why
	// Actor and Reason are the deciding row's, empty when no row decided.
	Actor  string
	Reason string
	// Known is false while the switch has not read any control state
	// (04 §3.6 state "unknown"); it is then enabled (B-09: a follower
	// never fails closed).
	Known bool
}

// Switch decides whether the adapter publishes.
type Switch interface {
	Decide() Decision
}

// AlwaysOn is a Switch that is always enabled and known (tests, and a
// process configured without a bus).
type AlwaysOn struct{}

// Decide is enabled.
func (AlwaysOn) Decide() Decision { return Decision{Enabled: true, Known: true} }

// ControlDoc is the source-control state as this adapter reads it from
// the KV bucket source_control (key KVKey) and the ctl.sources push.
//
// Proposed by WP-4, not yet confirmed (docs/PLAN.md section 15 gap 26):
// WP-6 owns internal/sources, the writer and the follower of this state,
// and had not landed when WP-4 needed a switch. The document mirrors the
// columns of WP-1's source_controls table and uspace-core's
// sources.State, so the writer has nothing to invent; when WP-6 lands,
// the adapter takes its Follower and this decoder goes.
type ControlDoc struct {
	Version     uint64       `json:"version"`
	Epoch       string       `json:"epoch"`
	DefaultDeny bool         `json:"default_deny"`
	Controls    []ControlRow `json:"controls"`
}

// ControlRow is one row of source_controls.
type ControlRow struct {
	SourceType string    `json:"source_type"`
	InstanceID *string   `json:"instance_id"`
	Enabled    bool      `json:"enabled"`
	Reason     string    `json:"reason"`
	Actor      string    `json:"actor"`
	ChangedAt  time.Time `json:"changed_at"`
}

// KVKey is the key of the state in the bucket source_control.
const KVKey = "current"

// MaxControlDocBytes bounds a control document (E-10).
const MaxControlDocBytes = 256 << 10

// Counters of the switch.
const (
	CounterControlUndecodable = "control_undecodable"
	CounterControlApplied     = "control_applied"
	CounterControlIgnored     = "control_ignored_older"
)

type rowKey struct {
	sourceType string
	instance   string
	whole      bool
}

// KVSwitch follows the source-control state for one adapter instance on
// uspace-core's sources.Follower (version within epoch, B-09). Safe for
// concurrent use.
type KVSwitch struct {
	instance string
	counters *core.Counters
	follower *sources.Follower

	mu    sync.RWMutex
	rows  map[rowKey]ControlRow
	known bool
}

// NewKVSwitch follows the switch of (manned, instance).
func NewKVSwitch(instance string, counters *core.Counters) *KVSwitch {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &KVSwitch{instance: instance, counters: counters, follower: sources.NewFollower(), rows: map[rowKey]ControlRow{}}
}

// MarkKnown says the control state has been read and is empty (the KV
// key does not exist): everything is enabled, and that is known.
func (s *KVSwitch) MarkKnown() {
	s.mu.Lock()
	s.known = true
	s.mu.Unlock()
}

// ApplyJSON decodes a KV value or push and applies it when it moves the
// state forward; it reports whether it did.
func (s *KVSwitch) ApplyJSON(doc []byte) bool {
	if len(doc) > MaxControlDocBytes {
		s.counters.Inc(CounterControlUndecodable)
		return false
	}
	var d ControlDoc
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || d.Epoch == "" {
		s.counters.Inc(CounterControlUndecodable)
		return false
	}
	st := sources.State{DefaultDeny: d.DefaultDeny, Version: d.Version, Epoch: d.Epoch}
	rows := make(map[rowKey]ControlRow, len(d.Controls))
	for _, c := range d.Controls {
		st.Controls = append(st.Controls, sources.Control{SourceType: c.SourceType, InstanceID: c.InstanceID, Enabled: c.Enabled})
		k := rowKey{sourceType: c.SourceType, whole: c.InstanceID == nil}
		if c.InstanceID != nil {
			k.instance = *c.InstanceID
		}
		rows[k] = c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.follower.Apply(st) {
		s.counters.Inc(CounterControlIgnored)
		return false
	}
	s.rows, s.known = rows, true
	s.counters.Inc(CounterControlApplied)
	return true
}

// Decide is the decision for this instance, with the deciding row's
// actor and reason.
func (s *KVSwitch) Decide() Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst := s.instance
	d := s.follower.Query(SourceType, &inst)
	out := Decision{Enabled: d.Enabled, Why: d.WhyDisabled, Known: s.known}
	if d.WhyDisabled != nil {
		var row ControlRow
		switch *d.WhyDisabled {
		case sources.WhyType:
			row = s.rows[rowKey{sourceType: SourceType, whole: true}]
		case sources.WhyInstance:
			row = s.rows[rowKey{sourceType: SourceType, instance: inst}]
		case sources.WhyDefaultDeny:
			row = ControlRow{Actor: "default_deny", Reason: "no row for this instance and the state denies by default"}
		}
		out.Actor, out.Reason = row.Actor, row.Reason
	}
	return out
}

// Watch follows the bucket's key until ctx ends: every put is applied,
// the end of the initial values with no key marks the state known and
// empty. It returns ctx's error, or the watcher's when the watch cannot
// start.
func (s *KVSwitch) Watch(ctx context.Context, kv jetstream.KeyValue) error {
	w, err := kv.Watch(ctx, KVKey)
	if err != nil {
		return fmt.Errorf("source control: watch: %w", err)
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
			switch {
			case e == nil:
				s.MarkKnown()
			case e.Operation() == jetstream.KeyValuePut:
				s.ApplyJSON(e.Value())
			}
		}
	}
}
