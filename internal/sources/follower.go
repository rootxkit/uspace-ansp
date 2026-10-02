package sources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
)

// Defaults of Follow (docs/PLAN.md section 7: three attempts at start,
// then degraded; a re-read every 60 s repairs a lost push).
const (
	DefaultStartAttempts = 3
	DefaultStartBackoff  = 500 * time.Millisecond
	RereadPeriod         = 60 * time.Second
	readTimeout          = 5 * time.Second
)

// Counters of the follower (core's applied, ignored_older_version and
// new_epoch are CoreCounters).
const (
	CounterUndecodable = "source_control_undecodable"
	CounterReadFailed  = "source_control_read_failed"
	CounterReread      = "source_control_reread"
)

// KV is the part of a jetstream.KeyValue the follower reads.
type KV interface {
	Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error)
}

// Decision is whether a source may be used and, when not, who switched
// it off, when, why and by which rule (B-11: disabled is never silent).
type Decision struct {
	Enabled bool
	// Why is core's reason, nil exactly when Enabled.
	Why *coresources.Why
	// Actor, Reason and ChangedAt are the deciding row's; empty when no
	// row decided (default deny says so in Reason).
	Actor     string
	Reason    string
	ChangedAt time.Time
	// Known is false while no state has been read (04 §3.6 unknown): the
	// source is then enabled (B-09).
	Known bool
}

type rowKey struct {
	sourceType string
	instance   string
	whole      bool
}

func keyOf(sourceType string, instance *string) rowKey {
	if instance == nil {
		return rowKey{sourceType: sourceType, whole: true}
	}
	return rowKey{sourceType: sourceType, instance: *instance}
}

// Follower holds the last source-control state applied. Safe for
// concurrent use.
type Follower struct {
	counters *core.Counters

	mu    sync.RWMutex
	core  *coresources.Follower
	doc   *Doc
	rows  map[rowKey]Row
	known bool
	// failed is when the current run of failed reads began; zero after
	// a read that worked.
	failed time.Time
}

// NewFollower is a follower with no state: every source is enabled and
// the state is unknown. counters may be nil.
func NewFollower(counters *core.Counters) *Follower {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Follower{counters: counters, core: coresources.NewFollower(), rows: map[rowKey]Row{}}
}

// Counters are this follower's counters.
func (f *Follower) Counters() *core.Counters { return f.counters }

// CoreCounters are uspace-core's follower counters (applied,
// ignored_older_version, new_epoch).
func (f *Follower) CoreCounters() *core.Counters { return f.core.Counters() }

// Apply offers d; it is taken when core's follower takes it (a higher
// version within the epoch, or a new epoch), and reports whether it was.
func (f *Follower) Apply(d Doc) bool {
	if err := d.Validate(); err != nil {
		f.counters.Inc(CounterUndecodable)
		return false
	}
	rows := make(map[rowKey]Row, len(d.Controls))
	for _, r := range d.Controls {
		rows[keyOf(r.SourceType, r.InstanceID)] = r
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.known = true
	if !f.core.Apply(d.State()) {
		return false
	}
	cp := d
	f.doc, f.rows = &cp, rows
	return true
}

// ApplyJSON decodes a KV value or a ctl.sources push and applies it.
func (f *Follower) ApplyJSON(b []byte) bool {
	d, err := DecodeDoc(b)
	if err != nil {
		f.counters.Inc(CounterUndecodable)
		return false
	}
	return f.Apply(d)
}

// MarkKnown records that the bucket was read and holds no state: every
// source is enabled, and that is known.
func (f *Follower) MarkKnown() {
	f.mu.Lock()
	f.known = true
	f.mu.Unlock()
}

// Decision is core's decision for (sourceType, instance) with the
// deciding row; a nil instance asks about the whole type.
func (f *Follower) Decision(sourceType string, instance *string) Decision {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d := f.core.Query(sourceType, instance)
	out := Decision{Enabled: d.Enabled, Why: d.WhyDisabled, Known: f.known}
	if d.WhyDisabled == nil {
		return out
	}
	var row Row
	switch *d.WhyDisabled {
	case coresources.WhyType:
		row = f.rows[keyOf(sourceType, nil)]
	case coresources.WhyInstance:
		row = f.rows[keyOf(sourceType, instance)]
	case coresources.WhyDefaultDeny:
		row = Row{Actor: "default_deny", Reason: "no switch for this instance and the state denies by default"}
	}
	out.Actor, out.Reason, out.ChangedAt = row.Actor, row.Reason, row.ChangedAt
	return out
}

// Doc is a copy of the state held, false when none has been applied.
func (f *Follower) Doc() (Doc, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.doc == nil {
		return Doc{}, false
	}
	cp := *f.doc
	cp.Controls = append([]Row(nil), f.doc.Controls...)
	return cp, true
}

// Version is the held state's version and epoch; known is false while
// nothing has been read.
func (f *Follower) Version() (version uint64, epoch string, known bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.doc == nil {
		return 0, "", f.known
	}
	return f.doc.Version, f.doc.Epoch, f.known
}

// Status is the follower's line for the process status and readiness
// (E-02: an unknown or unread state never looks like a stored one).
func (f *Follower) Status() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var s string
	switch {
	case f.doc != nil:
		s = fmt.Sprintf("version %d", f.doc.Version)
	case f.known:
		s = "empty (every source enabled)"
	default:
		s = "unknown, nothing read (every source enabled)"
	}
	if !f.failed.IsZero() {
		s += ", KV unreachable since " + f.failed.UTC().Format(time.RFC3339)
	}
	return s
}

// Read reads the bucket once and applies what it holds; a missing key
// is an empty state, which is known.
func (f *Follower) Read(ctx context.Context, kv KV) error {
	if kv == nil {
		return errors.New("source control: no KV bucket")
	}
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	e, err := kv.Get(rctx, KVKey)
	now := time.Now()
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		f.MarkKnown()
	case err != nil:
		f.markFailed(now)
		return fmt.Errorf("source control: read %s: %w", KVKey, err)
	default:
		f.ApplyJSON(e.Value())
	}
	f.mu.Lock()
	f.failed = time.Time{}
	f.mu.Unlock()
	return nil
}

// markFailed counts a failed read and remembers when the failures began.
func (f *Follower) markFailed(now time.Time) {
	f.counters.Inc(CounterReadFailed)
	f.mu.Lock()
	if f.failed.IsZero() {
		f.failed = now
	}
	f.mu.Unlock()
}

// FollowOptions tune Follow; zero values take the defaults.
type FollowOptions struct {
	StartAttempts int
	StartBackoff  time.Duration
	Reread        time.Duration
	// OnError receives a failed read (the process logs it).
	OnError func(error)
}

// Follow reads the bucket at start (StartAttempts tries, the backoff
// doubling), then again every Reread until ctx ends. The caller applies
// the ctl.sources push with ApplyJSON. kv may be resolved late: get is
// called before every read and may fail (the bucket not created yet).
func (f *Follower) Follow(ctx context.Context, get func(ctx context.Context) (KV, error), o FollowOptions) {
	if o.StartAttempts <= 0 {
		o.StartAttempts = DefaultStartAttempts
	}
	if o.StartBackoff <= 0 {
		o.StartBackoff = DefaultStartBackoff
	}
	if o.Reread <= 0 {
		o.Reread = RereadPeriod
	}
	read := func() error {
		kv, err := get(ctx)
		if err != nil {
			f.markFailed(time.Now())
			return err
		}
		return f.Read(ctx, kv)
	}
	backoff := o.StartBackoff
	for attempt := 1; attempt <= o.StartAttempts; attempt++ {
		err := read()
		if err == nil {
			break
		}
		if o.OnError != nil {
			o.OnError(fmt.Errorf("attempt %d of %d: %w", attempt, o.StartAttempts, err))
		}
		if attempt == o.StartAttempts {
			break
		}
		if !sleep(ctx, backoff) {
			return
		}
		backoff *= 2
	}
	t := time.NewTicker(o.Reread)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.counters.Inc(CounterReread)
			if err := read(); err != nil && o.OnError != nil && ctx.Err() == nil {
				o.OnError(err)
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
