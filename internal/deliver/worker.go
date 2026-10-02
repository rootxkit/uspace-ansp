package deliver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Msg is a JetStream message (jetstream.Msg) as the worker uses it.
type Msg interface {
	Data() []byte
	Ack() error
	NakWithDelay(delay time.Duration) error
	Term() error
}

// Worker runs the attempts of the DELIVER work queue: it leases the
// row, sends, records the outcome on the row and acknowledges the
// message only after the row is updated (explicit ack). A retry is a
// Nak with the backoff as delay; the row's next_retry_at says the same
// on the database clock.
type Worker struct {
	Repo   Repo
	CISP   *CISP
	Direct *Direct
	Events *Events
	Policy Policy
	Logger *slog.Logger
	// Counters are the outbox's (shared with Outbox).
	Counters *core.Counters
	// Clock times the attempts (the log's duration_ms); nil is time.Now.
	Clock func() time.Time
}

func (w *Worker) count(name string) {
	if w.Counters != nil {
		w.Counters.Inc(name)
	}
}

func (w *Worker) log() *slog.Logger {
	if w.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return w.Logger
}

func (w *Worker) clock() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

// Run takes messages from next and handles at most Policy.InFlight at
// once (E-10) until ctx ends; it then waits for the attempts in flight.
// next blocks until a message arrives or ctx ends.
func (w *Worker) Run(ctx context.Context, next func(ctx context.Context) (Msg, error)) {
	sem := make(chan struct{}, w.Policy.InFlight)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		m, err := next(ctx)
		if err != nil {
			<-sem
			if ctx.Err() != nil {
				return
			}
			w.log().Warn("deliver: the work queue did not answer; trying again", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			w.Handle(ctx, m)
		}()
	}
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Handle runs one message: claim, prepare, send, record, then Ack, or
// Nak with the wait until the row is due.
func (w *Worker) Handle(ctx context.Context, m Msg) {
	msg, err := DecodeMessage(m.Data())
	if err != nil {
		w.count(CounterMalformed)
		w.log().Error("deliver: a deliver.v1 message is malformed; terminated", slog.String("error", err.Error()))
		_ = m.Term()
		return
	}
	log := w.log().With(slog.String("delivery_id", msg.ID), slog.String("kind", string(msg.Kind)))
	token := newToken()
	c, err := w.Repo.Claim(ctx, msg.ID, token, w.Policy.Lease)
	if err != nil {
		w.count(CounterStoreFailed)
		log.Warn("deliver: the job could not be claimed; the message comes back", slog.String("error", err.Error()))
		_ = m.NakWithDelay(w.Policy.BackoffMin)
		return
	}
	switch c.Outcome {
	case Gone:
		w.count(CounterOrphan)
		log.Warn("deliver: a message names no delivery row; acknowledged")
		_ = m.Ack()
		return
	case Settled:
		// A replayed or repeated message after the row settled: the job
		// is not sent again (the idempotency of the outbox).
		w.count(CounterReplayIgnored)
		log.Info("deliver: the job is settled; the message is acknowledged without a request", slog.String("state", string(c.Delivery.State)))
		_ = m.Ack()
		return
	case Leased, NotDue, Blocked:
		w.count(CounterDeferred)
		wait := c.Until.Sub(c.Now)
		_ = m.NakWithDelay(min(max(wait, 100*time.Millisecond), w.Policy.BackoffMax))
		return
	case Claimed:
	}
	d := c.Delivery
	log = log.With(slog.String("restriction_id", d.RestrictionID), slog.Int64("ansp_version", d.AnspVersion),
		slog.String("op", d.Op), slog.String("target", d.Target), slog.Int("attempt", d.Attempt))
	a := Attempt{ID: d.ID, Token: token, Attempt: d.Attempt}
	if d.Attempt > d.MaxAttempts || c.Now.After(d.WindowEndsAt) {
		a.State, a.Outcome, a.Error = StateAbandoned, "abandoned",
			fmt.Sprintf("not sent: %d attempts of at most %d, or the window ended at %s", d.Attempt-1, d.MaxAttempts, restriction.Stamp(d.WindowEndsAt))
		w.finish(ctx, m, log, d, a, c.Now)
		return
	}
	start := w.clock()
	resp, cancel, err := w.send(ctx, &d, token)
	a.Duration = w.clock().Sub(start)
	switch {
	case err != nil:
		// A local failure (the version cannot be read, a body cannot be
		// built): never a request; failed with the reason and an alarm.
		a.State, a.Outcome, a.Error = StateFailed, "failed", clip(err.Error(), 1000)
	case cancel != "":
		a.State, a.Outcome, a.CancelReason = StateCancelled, "cancelled", cancel
	default:
		w.count(CounterAttempts)
		a.StatusCode, a.Excerpt, a.Error = statusPtr(resp.Status), clip(resp.Excerpt, 2000), clip(resp.Err, 1000)
		switch Judge(resp) {
		case Sent:
			a.State, a.Outcome = StateSent, "sent"
		case Permanent:
			a.State, a.Outcome = StateFailed, "failed"
		case Retry:
			wait := max(w.Policy.Backoff(d.Attempt), resp.RetryAfter)
			a.RetryAt = c.Now.Add(a.Duration).Add(wait)
			if d.Attempt >= d.MaxAttempts || a.RetryAt.After(d.WindowEndsAt) {
				a.State, a.Outcome = StateAbandoned, "abandoned"
			} else {
				a.State, a.Outcome = StateQueued, "retry"
			}
		}
	}
	w.finish(ctx, m, log, d, a, c.Now)
}

func statusPtr(s int) *int {
	if s == 0 {
		return nil
	}
	return &s
}

// send prepares the request at the first attempt and sends it. cancel,
// when set, says the job is not sent and why.
func (w *Worker) send(ctx context.Context, d *Delivery, token string) (Response, string, error) {
	switch d.Kind {
	case KindCISPPublish:
		if d.Method == "" {
			v, err := w.Repo.Version(ctx, d.RestrictionID, d.AnspVersion)
			if err != nil {
				return Response{}, "", fmt.Errorf("the version cannot be read: %w", err)
			}
			pub, err := BuildPublication(v, d.Op)
			if err != nil {
				return Response{}, "", err
			}
			if pub.Cancel != "" {
				return Response{}, pub.Cancel, nil
			}
			if len(pub.Body) > w.Policy.MaxBodyBytes {
				return Response{}, "", fmt.Errorf("the publication is %d bytes; the CISP takes at most %d", len(pub.Body), w.Policy.MaxBodyBytes)
			}
			p, err := w.Repo.Prepare(ctx, d.ID, token, pub.Method, pub.Path, pub.Body)
			if err != nil {
				return Response{}, "", fmt.Errorf("the request cannot be recorded: %w", err)
			}
			*d = p
		}
		if w.CISP == nil {
			return Response{Err: "no CISP configured (ANSP_CISP_URL)"}, "", nil
		}
		return w.CISP.Publish(ctx, d.Method, d.URL, d.Body, d.IdempotencyKey), "", nil
	case KindDirect:
		if d.Method == "" {
			p, err := w.Repo.Prepare(ctx, d.ID, token, "POST", strings.TrimRight(d.Target, "/")+PathNotifications, d.Body)
			if err != nil {
				return Response{}, "", fmt.Errorf("the request cannot be recorded: %w", err)
			}
			*d = p
		}
		if w.Direct == nil {
			return Response{Err: "no degraded direct path configured"}, "", nil
		}
		return w.Direct.Send(ctx, d.Target, d.RestrictionID, d.ID, d.Body), "", nil
	case KindCISPHeartbeat, KindDSSPut, KindDSSDelete, KindUSSNotify, KindOccurrence:
	}
	return Response{}, "", fmt.Errorf("no sender for kind %s in this build", d.Kind)
}

// finish records a in one transaction with what it implies (the CISP's
// confirmation, the direct path superseded, the alarm cleared or a
// failure alarm raised), then answers the message and tells the bus.
func (w *Worker) finish(ctx context.Context, m Msg, log *slog.Logger, d Delivery, a Attempt, now time.Time) {
	var held bool
	var cancelled []Cancelled
	var raised, cleared *Alarm
	var ps PublishedState
	err := w.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		cancelled, raised, cleared = nil, nil, nil
		var err error
		if held, err = tx.Finish(ctx, a); err != nil || !held {
			return err
		}
		switch {
		case a.State == StateSent && d.Kind == KindCISPPublish:
			if ps, err = tx.MarkPublishedVersion(ctx, d.RestrictionID, d.AnspVersion); err != nil {
				return err
			}
			if cancelled, err = tx.CancelQueued(ctx, KindDirect, d.RestrictionID, d.AnspVersion, CancelSupersededByCISP); err != nil {
				return err
			}
			if ps.PublishedVersion >= ps.AnspVersion {
				al, ok, err := tx.ClearCISPAlarm(ctx, d.RestrictionID, "published")
				if err != nil {
					return err
				}
				if ok {
					cleared = &al
				}
			}
		case a.State == StateFailed || a.State == StateAbandoned:
			kind, verb := AlarmFailed, "failed"
			if a.State == StateAbandoned {
				kind, verb = AlarmAbandoned, "abandoned after "+fmt.Sprint(d.Attempt)+" attempts"
			}
			detail := fmt.Sprintf("%s to %s (%s of version %d) %s: %s", d.Kind, d.Target, d.Op, d.AnspVersion, verb, describe(a))
			al, ok, err := tx.RaiseAlarm(ctx, Alarm{ID: restriction.NewULID(now), Kind: kind, RestrictionID: d.RestrictionID,
				AnspVersion: d.AnspVersion, DeliveryID: d.ID, Since: d.QueuedAt, Detail: clip(detail, 1000)})
			if err != nil {
				return err
			}
			if ok {
				raised = &al
			}
		}
		return nil
	})
	if err != nil {
		w.count(CounterStoreFailed)
		log.Error("deliver: the outcome of an attempt was not recorded; the message comes back and the attempt is repeated",
			slog.String("outcome", a.Outcome), slog.String("error", err.Error()))
		_ = m.NakWithDelay(w.Policy.BackoffMin)
		return
	}
	if !held {
		w.count(CounterLeaseLost)
		log.Warn("deliver: the lease was lost before the outcome was recorded; another attempt owns the job", slog.String("outcome", a.Outcome))
		_ = m.Ack()
		return
	}
	attrs := []any{slog.String("outcome", a.Outcome), slog.Int64("duration_ms", a.Duration.Milliseconds())}
	if a.StatusCode != nil {
		attrs = append(attrs, slog.Int("status_code", *a.StatusCode))
	}
	if a.Error != "" {
		attrs = append(attrs, slog.String("error", a.Error))
	}
	switch a.State {
	case StateSent:
		w.count(CounterSent)
		log.Info("deliver: sent", attrs...)
		_ = m.Ack()
	case StateQueued:
		w.count(CounterRetried)
		wait := a.RetryAt.Sub(now)
		log.Warn("deliver: not delivered; retried with backoff", append(attrs, slog.String("next_retry_at", restriction.Stamp(a.RetryAt)))...)
		_ = m.NakWithDelay(max(wait, 0))
	case StateFailed:
		w.count(CounterFailed)
		log.Error("deliver: failed; not retried, alarm raised", append(attrs, slog.String("response_excerpt", a.Excerpt))...)
		_ = m.Ack()
	case StateAbandoned:
		w.count(CounterAbandoned)
		log.Error("deliver: abandoned after its retries; alarm raised until a person acknowledges it", attrs...)
		_ = m.Ack()
	case StateCancelled:
		w.count(CounterCancelled)
		log.Info("deliver: cancelled; nothing sent", slog.String("cancel_reason", a.CancelReason))
		_ = m.Ack()
	}
	for _, c := range cancelled {
		w.count(CounterCancelled)
		log.Info("deliver: a degraded direct delivery still queued is cancelled: the CISP published the version",
			slog.String("cancelled_delivery_id", c.ID), slog.String("cancel_reason", CancelSupersededByCISP), slog.String("cancelled_target", c.Target))
	}
	if a.State == StateSent && d.Kind == KindCISPPublish {
		w.Events.Published(ctx, d.RestrictionID, d.AnspVersion)
	}
	if cleared != nil {
		w.count(CounterAlarmsCleared)
		log.Info("deliver: cisp_not_published cleared: published to the CISP", slog.String("alarm_id", cleared.ID),
			slog.Float64("duration_s", cleared.ClearedAt.Sub(cleared.Since).Seconds()))
		w.Events.Alarm(ctx, *cleared, "cleared")
	}
	if raised != nil {
		w.count(CounterAlarmsRaised)
		w.Events.Alarm(ctx, *raised, "raised")
	}
}

// describe is the alarm's account of an attempt: the status and the
// answer's excerpt, or the error.
func describe(a Attempt) string {
	if a.StatusCode != nil {
		return fmt.Sprintf("HTTP %d %s", *a.StatusCode, clip(a.Excerpt, 300))
	}
	if a.Error != "" {
		return a.Error
	}
	return "no answer"
}

// ErrStopped is returned by a next function whose source is closed.
var ErrStopped = errors.New("the work queue is closed")
