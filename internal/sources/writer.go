package sources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
)

// SubjectControl is the core subject of the push (docs/PLAN.md section 7).
const SubjectControl = "ctl.sources"

// RepublishPeriod is how often the api writes the database's state to
// KV again (B-09: a lost put is repaired within one period).
const RepublishPeriod = 60 * time.Second

// maxCASAttempts bounds the compare-and-set loop of one put.
const maxCASAttempts = 5

// Counters of the writer.
const (
	CounterSet             = "source_control_set"
	CounterKVUnavailable   = "source_kv_unavailable"
	CounterKVPutFailed     = "source_kv_put_failed"
	CounterKVPut           = "source_kv_put"
	CounterKVNewerKept     = "source_kv_newer_kept"
	CounterPushFailed      = "source_push_failed"
	CounterRepublished     = "source_republished"
	CounterRepublishFailed = "source_republish_failed"
)

// ErrKVUnavailable is the bucket not answering before a change: nothing
// was changed (503 with Retry-After).
var ErrKVUnavailable = errors.New("the source_control bucket cannot be reached; nothing was changed")

// Change is one switch to set.
type Change struct {
	SourceType string
	// InstanceID is nil for the whole type.
	InstanceID *string
	Enabled    bool
	Reason     string
	// Actor is the account that sets it.
	Actor string
}

// Validate refuses a change source_controls would refuse, naming the
// field.
func (c *Change) Validate() error {
	var errs []error
	if !ValidSourceType(c.SourceType) {
		errs = append(errs, core.Fieldf("type", "not a source type"))
	}
	if c.InstanceID != nil && !ValidInstance(*c.InstanceID) {
		errs = append(errs, core.Fieldf("instance", "1 to 64 of A-Z a-z 0-9 . _ -, or * for the whole type"))
	}
	reason := strings.TrimSpace(c.Reason)
	switch {
	case reason == "":
		errs = append(errs, core.Fieldf("reason", "required: every switch says why"))
	case len(c.Reason) > MaxReasonLen || !utf8.ValidString(c.Reason):
		errs = append(errs, core.Fieldf("reason", "valid UTF-8 of at most %d bytes", MaxReasonLen))
	}
	if c.Actor == "" || len(c.Actor) > MaxActorLen {
		errs = append(errs, core.Fieldf("actor", "required"))
	}
	return errors.Join(errs...)
}

// Repo is the source_controls table (store.SourcesRepo).
type Repo interface {
	// Set upserts one switch under the writers' advisory lock with the
	// next version, records the audit event, commits, and returns the
	// row as set and the whole committed state.
	Set(ctx context.Context, c Change) (Row, Doc, error)
	// Load reads the whole state.
	Load(ctx context.Context) (Doc, error)
}

// WriteKV is the part of a jetstream.KeyValue the writer uses.
type WriteKV interface {
	KV
	Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error)
	Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error)
}

// Publisher pushes on a core subject (nats.Conn).
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Writer is the api's side: the row first, KV and the push after the
// commit. Repo and KV are required; Push may be nil (no bus push).
type Writer struct {
	Repo     Repo
	KV       WriteKV
	Push     Publisher
	counters core.Counters
}

// Counters are the writer's counters.
func (w *Writer) Counters() *core.Counters { return &w.counters }

// Set changes one switch. The bucket is asked first: when it cannot
// answer, nothing is written (ErrKVUnavailable). Then the row is
// committed, and the committed state is put and pushed. A put that fails
// after the commit is counted and returned as putErr beside the row: the
// switch is set, and Republish repairs KV.
func (w *Writer) Set(ctx context.Context, c Change) (row Row, doc Doc, putErr, err error) {
	if err := c.Validate(); err != nil {
		return Row{}, Doc{}, nil, err
	}
	if w.Repo == nil || w.KV == nil {
		w.counters.Inc(CounterKVUnavailable)
		return Row{}, Doc{}, nil, ErrKVUnavailable
	}
	if _, err := w.current(ctx); err != nil {
		w.counters.Inc(CounterKVUnavailable)
		return Row{}, Doc{}, nil, fmt.Errorf("%w: %w", ErrKVUnavailable, err)
	}
	row, doc, err = w.Repo.Set(ctx, c)
	if err != nil {
		return Row{}, Doc{}, nil, err
	}
	w.counters.Inc(CounterSet)
	if _, err := w.publish(ctx, doc); err != nil {
		w.counters.Inc(CounterKVPutFailed)
		return row, doc, err, nil
	}
	return row, doc, nil, nil
}

// Republish writes the database's state to KV and the push when KV does
// not already hold it or a newer state of the same epoch; it reports
// whether it wrote.
func (w *Writer) Republish(ctx context.Context) (bool, error) {
	if w.Repo == nil || w.KV == nil {
		return false, ErrKVUnavailable
	}
	doc, err := w.Repo.Load(ctx)
	if err != nil {
		w.counters.Inc(CounterRepublishFailed)
		return false, err
	}
	wrote, err := w.publish(ctx, doc)
	if err != nil {
		w.counters.Inc(CounterRepublishFailed)
		return false, err
	}
	if wrote {
		w.counters.Inc(CounterRepublished)
	}
	return wrote, nil
}

// Run republishes every period until ctx ends, passing failures to
// onError.
func (w *Writer) Run(ctx context.Context, period time.Duration, onError func(error)) {
	if period <= 0 {
		period = RepublishPeriod
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		if _, err := w.Republish(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// current reads what KV holds: nil when the key does not exist.
func (w *Writer) current(ctx context.Context) (jetstream.KeyValueEntry, error) {
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	e, err := w.KV.Get(rctx, KVKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, nil
	}
	return e, err
}

// publish puts doc unless KV holds it or a newer state of its epoch (a
// compare-and-set on the key's revision, so a concurrent writer is never
// overwritten by an older state), then pushes it.
func (w *Writer) publish(ctx context.Context, doc Doc) (bool, error) {
	b, err := doc.Encode()
	if err != nil {
		return false, err
	}
	for attempt := 0; attempt < maxCASAttempts; attempt++ {
		e, err := w.current(ctx)
		if err != nil {
			return false, err
		}
		pctx, cancel := context.WithTimeout(ctx, readTimeout)
		if e == nil {
			_, err = w.KV.Create(pctx, KVKey, b)
		} else {
			if held, derr := DecodeDoc(e.Value()); derr == nil && !newer(&doc, &held) {
				cancel()
				if held.Version > doc.Version {
					w.counters.Inc(CounterKVNewerKept)
				}
				return false, nil
			}
			_, err = w.KV.Update(pctx, KVKey, b, e.Revision())
		}
		cancel()
		if err == nil {
			w.counters.Inc(CounterKVPut)
			if w.Push != nil {
				if perr := w.Push.Publish(SubjectControl, b); perr != nil {
					// The followers re-read KV within RereadPeriod.
					w.counters.Inc(CounterPushFailed)
				}
			}
			return true, nil
		}
		if !casConflict(err) {
			return false, err
		}
	}
	return false, fmt.Errorf("source control: the KV key kept changing during %d attempts", maxCASAttempts)
}

// casConflict reports whether err is a lost compare-and-set (another
// writer moved the key), which is retried.
func casConflict(err error) bool {
	if errors.Is(err, jetstream.ErrKeyExists) {
		return true
	}
	var apiErr *jetstream.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence
}
