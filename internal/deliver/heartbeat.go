package deliver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// The heartbeat's states.
const (
	HeartbeatUnknown     = "unknown"
	HeartbeatOK          = "ok"
	HeartbeatUnreachable = "unreachable"
)

// Heartbeat sends POST {cisp}/v1/publishers/heartbeat {sent_at,
// active_refs} every cisp_heartbeat_s (M3; the CISP flags this publisher
// stale after 60 s, three misses). It is not a job of the work queue: a
// heartbeat carries no change and is never retried, the next one
// replaces it. A failed heartbeat is counted and shown as "unreachable
// since T" in readiness, never as data loss (C-12). The first success,
// and every success after a failure, runs OnRecover (the reconciliation).
type Heartbeat struct {
	CISP   *CISP
	Repo   Repo
	Policy Policy
	// Period is cisp_heartbeat_s of the ansp_policy row.
	Period    func(ctx context.Context) time.Duration
	OnRecover func(ctx context.Context)
	Logger    *slog.Logger
	Counters  *core.Counters
	// Now is the sent_at clock; After waits (a test's fake clock).
	Now   func() time.Time
	After func(d time.Duration) <-chan time.Time

	mu         sync.Mutex
	state      string
	since      time.Time
	lastStatus int
	lastErr    string
	lastAt     time.Time
}

func (h *Heartbeat) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Heartbeat) log() *slog.Logger {
	if h.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return h.Logger
}

func (h *Heartbeat) count(name string) {
	if h.Counters != nil {
		h.Counters.Inc(name)
	}
}

// Beat sends one heartbeat and records its outcome.
func (h *Heartbeat) Beat(ctx context.Context) Response {
	refs, err := h.Repo.ActiveRefs(ctx, h.Policy.MaxActiveRefs+1)
	if err != nil {
		// The CISP is still told this system is alive; without the refs
		// it compares nothing (active_refs is optional).
		h.log().Warn("deliver: the active restrictions could not be read; the heartbeat carries no active_refs", slog.String("error", err.Error()))
		refs = nil
	}
	if len(refs) > h.Policy.MaxActiveRefs {
		h.count(CounterRefsTruncated)
		h.log().Error("deliver: more active restrictions than a heartbeat carries; the CISP sees the first",
			slog.Int("bound", h.Policy.MaxActiveRefs))
		refs = refs[:h.Policy.MaxActiveRefs]
	}
	sentAt := h.now()
	resp := h.CISP.Heartbeat(ctx, sentAt, refs)
	h.record(ctx, sentAt, resp, len(refs))
	return resp
}

func (h *Heartbeat) record(ctx context.Context, at time.Time, r Response, refs int) {
	ok := r.Status == http.StatusNoContent || (r.Status >= 200 && r.Status < 300)
	h.mu.Lock()
	prev := h.state
	h.lastStatus, h.lastErr, h.lastAt = r.Status, r.Err, at
	switch {
	case ok:
		if h.state != HeartbeatOK {
			h.since = at
		}
		h.state = HeartbeatOK
	case h.state != HeartbeatUnreachable:
		h.state, h.since = HeartbeatUnreachable, at
	}
	since := h.since
	h.mu.Unlock()
	attrs := []any{slog.Int("status_code", r.Status), slog.Int("active_refs", refs), slog.String("sent_at", restriction.Stamp(at))}
	if ok {
		h.count(CounterHeartbeatOK)
		h.log().Info("deliver: cisp heartbeat", attrs...)
		if prev != HeartbeatOK && h.OnRecover != nil {
			if prev == HeartbeatUnreachable {
				h.log().Info("deliver: the CISP is reachable again; reconciling the unpublished restrictions")
			}
			h.OnRecover(ctx)
		}
		return
	}
	h.count(CounterHeartbeatFailed)
	if r.Err != "" {
		attrs = append(attrs, slog.String("error", r.Err))
	}
	h.log().Warn("deliver: cisp heartbeat not answered with 204; the CISP is unreachable since "+restriction.Stamp(since), attrs...)
}

// Status is the readiness of the publisher channel: ok with the last
// heartbeat, unreachable since T with the last answer, or not yet sent.
func (h *Heartbeat) Status() (obs.State, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch h.state {
	case HeartbeatOK:
		return obs.StateOK, fmt.Sprintf("ok (last heartbeat %d at %s)", h.lastStatus, restriction.Stamp(h.lastAt))
	case HeartbeatUnreachable:
		why := h.lastErr
		if h.lastStatus != 0 {
			why = fmt.Sprintf("HTTP %d", h.lastStatus)
		}
		return obs.StateDown, fmt.Sprintf("unreachable since %s (%s); publications are queued and retried", restriction.Stamp(h.since), why)
	}
	return obs.StateDegraded, "no heartbeat answered yet"
}

// Run sends a heartbeat at once and then every Period until ctx ends.
func (h *Heartbeat) Run(ctx context.Context) {
	after := h.After
	if after == nil {
		after = time.After
	}
	for {
		h.Beat(ctx)
		period := 15 * time.Second
		if h.Period != nil {
			period = h.Period(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-after(period):
		}
	}
}

// Reconciler re-queues, when the CISP returns, every active restriction
// whose published version is below its current one: the queued job is
// made due now, an abandoned one is reopened with a new window, and a
// version with no job gets one.
type Reconciler struct {
	Repo     Repo
	Outbox   *Outbox
	Policy   Policy
	Logger   *slog.Logger
	Counters *core.Counters
}

// Reconcile runs once.
func (r *Reconciler) Reconcile(ctx context.Context) (int, error) {
	list, err := r.Repo.Unpublished(ctx, r.Policy.MaxBatch)
	if err != nil {
		r.Outbox.count(CounterReconcileFailed)
		return 0, err
	}
	n := 0
	for _, u := range list {
		var ps []Pending
		var how string
		err := r.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
			var err error
			if ps, err = tx.Expedite(ctx, KindCISPPublish, u.RestrictionID); err != nil || len(ps) > 0 {
				how = "expedited"
				return err
			}
			p, ok, err := tx.Requeue(ctx, KindCISPPublish, u.RestrictionID, u.AnspVersion, r.Policy.MaxAttempts(), r.Policy.Window)
			if err != nil {
				return err
			}
			if ok {
				how, ps = "reopened", []Pending{p}
				return nil
			}
			v, err := r.Repo.Version(ctx, u.RestrictionID, u.AnspVersion)
			if err != nil {
				return err
			}
			id, ok, err := r.Outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: u.RestrictionID, AnspRef: u.AnspRef,
				AnspVersion: u.AnspVersion, Op: OpOfVersion(v), Target: TargetCISP})
			if err == nil && ok {
				how, ps = "enqueued", []Pending{{ID: id, Kind: KindCISPPublish}}
			}
			return err
		})
		if err != nil {
			r.Outbox.count(CounterReconcileFailed)
			r.log().Warn("deliver: reconciliation of a restriction failed; the next recovery or scan repeats it",
				slog.String("restriction_id", u.RestrictionID), slog.String("error", err.Error()))
			continue
		}
		if len(ps) == 0 {
			continue
		}
		n++
		r.Outbox.count(CounterReconciled)
		r.log().Info("deliver: reconciliation re-queued the CISP publication", slog.String("restriction_id", u.RestrictionID),
			slog.Int64("ansp_version", u.AnspVersion), slog.String("how", how))
		r.Outbox.PublishAll(ctx, ps)
	}
	return n, nil
}

func (r *Reconciler) log() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}
