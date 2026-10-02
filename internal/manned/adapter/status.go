package adapter

import (
	"errors"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
)

// SchemaSourceStatus is the schema of the status (04 §3.6, consumed
// from uspace-lab, schemas/common/source/status/v1).
const SchemaSourceStatus = "source/status/v1"

// The states of source/status/v1.
const (
	StateLive     = "live"
	StateStale    = "stale"
	StateDisabled = "disabled"
	StateDown     = "down"
	StateUnknown  = "unknown"
)

// StatusBody is the body of source/status/v1 (the members the schema
// names) plus this adapter's members of WP-4 (enabled, connected, feed,
// last_frame_at, aircraft_seen, policy_version, stalled, feed_clock,
// kind, replay, reason), which the schema's open body allows.
type StatusBody struct {
	Source         string            `json:"source"`
	SourceInstance string            `json:"source_instance"`
	State          string            `json:"state"`
	Since          string            `json:"since"`
	AgeS           *float64          `json:"age_s"`
	DisabledBy     *string           `json:"disabled_by"`
	DisabledByWho  *string           `json:"disabled_by_who"`
	Counters       map[string]uint64 `json:"counters"`

	Kind          string  `json:"kind"`
	Replay        bool    `json:"replay"`
	Enabled       bool    `json:"enabled"`
	Connected     bool    `json:"connected"`
	Feed          string  `json:"feed"`
	LastFrameAt   *string `json:"last_frame_at"`
	AircraftSeen  int     `json:"aircraft_seen"`
	PolicyVersion string  `json:"policy_version"`
	Stalled       bool    `json:"stalled"`
	FeedClock     string  `json:"feed_clock"`
	Reason        *string `json:"reason"`
}

// Status is the status at now. The state is, in order: disabled when
// the switch is off; down when the feed is not connected; unknown while
// the switch has read no control state (treated as enabled, 04 §3.6);
// stale when connected without a sample for source_liveness_s; live.
// stalled is true while a connected feed has delivered no input for
// stall_after_s: a silent feed and a stalled one look alike until the
// next read, and stalled_reads counts the confirmed ones.
func (r *Runner) Status(now time.Time) StatusBody {
	r.init()
	dec := r.Switch.Decide()
	pol, version := r.Policy.Current()
	r.mu.Lock()
	defer r.mu.Unlock()
	state := StateLive
	switch {
	case !dec.Enabled:
		state = StateDisabled
	case !r.connected:
		state = StateDown
	case !dec.Known:
		state = StateUnknown
	case r.lastSample.IsZero() || now.Sub(r.lastSample) > manned.Seconds(pol.SourceLivenessS):
		state = StateStale
	}
	if state != r.state || r.stateSince.IsZero() {
		r.state, r.stateSince = state, now
	}
	counters := r.Counters.Snapshot()
	for _, k := range []string{manned.CounterAccepted, manned.CounterRefused} {
		if _, ok := counters[k]; !ok {
			counters[k] = 0
		}
	}
	b := StatusBody{
		Source: manned.SourceANSPFeed, SourceInstance: r.Instance, State: state, Since: manned.FormatTime(r.stateSince),
		Counters: counters, Kind: r.Adapter.Kind(), Replay: r.Replay, Enabled: dec.Enabled, Connected: r.connected,
		AircraftSeen: r.norm.AircraftSeen(now, manned.Seconds(pol.SourceLivenessS)), PolicyVersion: strconv.FormatUint(version, 10),
		FeedClock: r.feedClock, Feed: "connected",
	}
	if !r.connected {
		b.Feed = "reconnecting since " + manned.FormatTime(r.feedSince)
	}
	if !r.lastSample.IsZero() {
		age := max(now.Sub(r.lastSample).Seconds(), 0)
		b.AgeS = &age
		at := manned.FormatTime(r.lastSample)
		b.LastFrameAt = &at
	}
	if !dec.Enabled {
		why := "instance"
		if dec.Why != nil {
			why = string(*dec.Why)
		}
		b.DisabledBy = &why
		who := dec.Actor
		b.DisabledByWho = &who
		text := DisabledText(dec)
		b.Reason = &text
	}
	ref := r.lastInput
	if r.feedSince.After(ref) {
		ref = r.feedSince
	}
	b.Stalled = r.connected && now.Sub(ref) > manned.Seconds(pol.StallAfterS)
	return b
}

// StatusEnvelope is the status in the common envelope: placed at now on
// this system's clock (time_source system, no source time).
func (r *Runner) StatusEnvelope(now time.Time) manned.Envelope {
	at := manned.FormatTime(now)
	return manned.Envelope{
		Schema: SchemaSourceStatus, MsgID: manned.NewULID(now), Producer: manned.Producer,
		RxTS: at, CapturedAt: at, TimeSource: string(core.TimeSystem), Body: r.Status(now),
	}
}

// errNoPublisher is the error of a runner without a publisher.
var errNoPublisher = errors.New("no publisher: the bus is not configured")

type noPublisher struct{}

// Publish refuses: there is no bus.
func (noPublisher) Publish(string, []byte) error { return errNoPublisher }
