package feed

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// MaxAdapters bounds the adapters remembered from src.v1 (E-10); a new
// one past it is refused, counted.
const MaxAdapters = 64

// The states of an adapter (source/status/v1, AdapterState).
const (
	AdapterLive     = "live"
	AdapterStale    = "stale"
	AdapterDisabled = "disabled"
	AdapterDown     = "down"
	AdapterUnknown  = "unknown"
)

// Counters of the adapter registry.
const (
	CounterStatusRefused = "adapter_status_refused"
	CounterStatusFull    = "adapter_status_refused_full"
)

// AdapterState is one adapter as the snapshot and the status frame say
// it (api/openapi.yaml AdapterState).
type AdapterState struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	Enabled     bool     `json:"enabled"`
	LastFrameAt *string  `json:"last_frame_at"`
	AgeS        *float64 `json:"age_s"`
}

// statusBody is the part of source/status/v1 the registry reads.
type statusBody struct {
	Source         string   `json:"source"`
	SourceInstance *string  `json:"source_instance"`
	State          string   `json:"state"`
	Since          string   `json:"since"`
	AgeS           *float64 `json:"age_s"`
	Enabled        *bool    `json:"enabled"`
	LastFrameAt    *string  `json:"last_frame_at"`
	Counters       *struct {
		Accepted *uint64 `json:"accepted"`
		Refused  *uint64 `json:"refused"`
	} `json:"counters"`
}

type heard struct {
	body  json.RawMessage
	state string
	// enabled is the adapter's own word, as it published it.
	enabled     bool
	lastFrameAt *string
	at          time.Time
}

// Adapters remembers the last source/status/v1 of every adapter. Safe
// for concurrent use.
type Adapters struct {
	counters core.Counters
	mu       sync.RWMutex
	byID     map[string]*heard
}

// NewAdapters is an empty registry.
func NewAdapters() *Adapters { return &Adapters{byID: map[string]*heard{}} }

// Counters are the registry's counters.
func (a *Adapters) Counters() *core.Counters { return &a.counters }

// Observe takes one src.v1.manned.<adapter> message heard at at. The
// envelope must be source/status/v1 with the adapter's instance; the
// body is kept as published for sources[] of the status frame.
func (a *Adapters) Observe(subjectInstance string, data []byte, at time.Time) bool {
	if len(data) > MaxMessageBytes || !manned.ValidInstance(subjectInstance) {
		a.counters.Inc(CounterStatusRefused)
		return false
	}
	var env struct {
		Schema string          `json:"schema"`
		Body   json.RawMessage `json:"body"`
	}
	if json.Unmarshal(data, &env) != nil || env.Schema != "source/status/v1" || len(env.Body) == 0 {
		a.counters.Inc(CounterStatusRefused)
		return false
	}
	var b statusBody
	if json.NewDecoder(bytes.NewReader(env.Body)).Decode(&b) != nil || b.SourceInstance == nil ||
		*b.SourceInstance != subjectInstance || b.Source != manned.SourceANSPFeed || !validAdapterState(b.State) ||
		b.Counters == nil || b.Counters.Accepted == nil || b.Counters.Refused == nil {
		a.counters.Inc(CounterStatusRefused)
		return false
	}
	h := &heard{body: env.Body, state: b.State, enabled: b.State != AdapterDisabled, lastFrameAt: b.LastFrameAt, at: at}
	if b.Enabled != nil {
		h.enabled = *b.Enabled
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.byID[subjectInstance]; !ok && len(a.byID) >= MaxAdapters {
		a.counters.Inc(CounterStatusFull)
		return false
	}
	a.byID[subjectInstance] = h
	return true
}

func validAdapterState(s string) bool {
	switch s {
	case AdapterLive, AdapterStale, AdapterDisabled, AdapterDown, AdapterUnknown:
		return true
	}
	return false
}

// States are the adapters at now, by id. An adapter whose last status
// is older than livenessS is down (its process is silent since then),
// whatever that status said.
func (a *Adapters) States(now time.Time, livenessS float64) []AdapterState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]AdapterState, 0, len(a.byID))
	for id, h := range a.byID {
		s := AdapterState{ID: id, State: h.state, Enabled: h.enabled, LastFrameAt: h.lastFrameAt}
		silent := now.Sub(h.at)
		if silent > manned.Seconds(livenessS) {
			s.State = AdapterDown
		}
		if h.lastFrameAt != nil {
			if at, err := time.Parse(time.RFC3339Nano, *h.lastFrameAt); err == nil {
				age := math.Max(0, now.Sub(at).Seconds())
				s.AgeS = &age
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Sources are the last source/status/v1 bodies, by id, for sources[] of
// the status frame.
func (a *Adapters) Sources() []json.RawMessage {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ids := make([]string, 0, len(a.byID))
	for id := range a.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		out = append(out, a.byID[id].body)
	}
	return out
}

// Silent is whether no adapter is live at now: none heard, or every one
// down, stale, disabled or unknown (degraded adapters_silent).
func (a *Adapters) Silent(now time.Time, livenessS float64) bool {
	for _, s := range a.States(now, livenessS) {
		if s.State == AdapterLive {
			return false
		}
	}
	return true
}
