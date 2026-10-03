package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Counters of the outbox (E-09): each is a Prometheus counter of the
// same name and on the status line.
const (
	CounterEnqueued        = "deliver_enqueued"
	CounterEnqueueRepeated = "deliver_enqueue_repeated"
	CounterBusPublished    = "deliver_bus_published"
	CounterBusFailed       = "deliver_bus_publish_failed"
	CounterRepublished     = "deliver_republished"
	CounterStuck           = "deliver_republished_stuck"
	CounterScanFailed      = "deliver_scan_failed"
	CounterAttempts        = "deliver_attempts"
	CounterSent            = "deliver_sent"
	CounterRetried         = "deliver_retried"
	CounterFailed          = "deliver_failed"
	CounterAbandoned       = "deliver_abandoned"
	CounterCancelled       = "deliver_cancelled"
	CounterReplayIgnored   = "deliver_replay_ignored"
	CounterOrphan          = "deliver_message_orphan"
	CounterMalformed       = "deliver_message_malformed"
	CounterDeferred        = "deliver_deferred"
	CounterLeaseLost       = "deliver_lease_lost"
	CounterStoreFailed     = "deliver_store_failed"
	CounterEventFailed     = "deliver_event_publish_failed"
	CounterAlarmsRaised    = "deliver_alarms_raised"
	CounterAlarmsCleared   = "deliver_alarms_cleared"
	CounterAlarmsAcked     = "deliver_alarms_acknowledged"
	CounterDirectQueued    = "deliver_direct_queued"
	CounterDirectNoTargets = "deliver_direct_no_targets"
	CounterHeartbeatOK     = "deliver_cisp_heartbeat_ok"
	CounterHeartbeatFailed = "deliver_cisp_heartbeat_failed"
	CounterRefsTruncated   = "deliver_cisp_heartbeat_refs_truncated"
	CounterReconciled      = "deliver_reconciled"
	CounterReconcileFailed = "deliver_reconcile_failed"
	// CounterCISPConflict counts CISP 409 answers to a publication: the
	// pair with another body, or a lower ansp_version for the ansp_ref,
	// which no retry changes; each is failed at once with an alarm.
	CounterCISPConflict = "deliver_cisp_conflict"
	// CounterOccurrenceIntakeAbsent counts occurrence attempts the
	// authority answered 404, 405 or 501 (its intake is not served): the
	// report is held, queued, and tried again every OccurrenceHold.
	CounterOccurrenceIntakeAbsent = "deliver_occurrence_intake_unavailable"
)

// BusPublisher puts a message on JetStream with a message id (the
// stream drops a repeat of the id within its duplicate window).
type BusPublisher interface {
	Publish(ctx context.Context, subject, msgID string, data []byte) error
}

// Subject is deliver.v1.<kind>.
func Subject(k Kind) string { return bus.SubjectDeliverPrefix + string(k) }

// Message is a deliver.v1 message (docs/PLAN.md section 7): the job's
// id, kind, subject ref, idempotency key and publish sequence. The row
// is the truth; the message says which row to look at.
type Message struct {
	ID             string `json:"id"`
	Kind           Kind   `json:"kind"`
	SubjectRef     string `json:"subject_ref,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Seq            int    `json:"bus_seq"`
}

// MaxMessageBytes bounds a deliver.v1 message read from the bus.
const MaxMessageBytes = 4096

// DecodeMessage reads a deliver.v1 message: one JSON object, at most
// MaxMessageBytes, with a ULID id and a known kind. Unknown members are
// refused (a misspelt member must not read as an absent one).
func DecodeMessage(data []byte) (Message, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return Message{}, core.Fieldf("message", "empty or larger than %d bytes", MaxMessageBytes)
	}
	var m Message
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Message{}, core.Fieldf("message", "not a deliver.v1 message")
	}
	if dec.More() {
		return Message{}, core.Fieldf("message", "trailing data")
	}
	if !ulidPattern.MatchString(m.ID) {
		return Message{}, core.Fieldf("id", "not a ULID")
	}
	if !m.Kind.Valid() {
		return Message{}, core.Fieldf("kind", "not a delivery kind")
	}
	if m.Seq < 0 {
		return Message{}, core.Fieldf("bus_seq", "negative")
	}
	return m, nil
}

// ulidPattern is a ULID in Crockford base32 (the deliveries id check).
var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// MsgID is the JetStream message id of publish seq of a row.
func MsgID(id string, seq int) string { return id + "." + strconv.Itoa(seq) }

// Outbox writes jobs in the caller's transaction and publishes them
// after the commit; a scan every ScanEvery publishes what was not.
type Outbox struct {
	Repo     Repo
	Bus      BusPublisher
	Policy   Policy
	Logger   *slog.Logger
	Counters *core.Counters
}

func (o *Outbox) count(name string) {
	if o.Counters != nil {
		o.Counters.Inc(name)
	}
}

func (o *Outbox) log() *slog.Logger {
	if o.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return o.Logger
}

// Enqueue writes j as a queued row in tx (B-05: persisted before
// anything is published) and returns its id; inserted is false when the
// same job (kind, idempotency key, target) was queued before.
func (o *Outbox) Enqueue(ctx context.Context, tx Tx, j Job) (string, bool, error) {
	switch {
	case !j.Kind.Valid() || j.Target == "" || j.Op == "":
		return "", false, fmt.Errorf("an incomplete delivery job %+v", j)
	case j.OfRestriction() && (j.RestrictionID == "" || j.AnspVersion < 1 || j.AnspRef == ""):
		return "", false, fmt.Errorf("an incomplete delivery job %+v", j)
	case !j.OfRestriction() && (j.RestrictionID != "" || j.AnspVersion != 0 || j.Subject == "" || j.Key == ""):
		return "", false, fmt.Errorf("a job of no restriction needs its subject and key, and no version: %+v", j)
	}
	if len(j.Body) > o.Policy.MaxBodyBytes {
		return "", false, fmt.Errorf("the body is %d bytes, more than %d", len(j.Body), o.Policy.MaxBodyBytes)
	}
	if j.ID == "" {
		now, err := tx.Now(ctx)
		if err != nil {
			return "", false, err
		}
		j.ID = restriction.NewULID(now)
	}
	window := o.Policy.Window
	if j.Window > 0 {
		window = j.Window
	}
	ok, err := tx.Insert(ctx, j, o.Policy.MaxAttemptsIn(window), window)
	if err != nil {
		return "", false, err
	}
	if ok {
		o.count(CounterEnqueued)
	} else {
		o.count(CounterEnqueueRepeated)
	}
	return j.ID, ok, nil
}

// PublicationOp is the cisp_publish op of a restriction transition, ""
// for one the CISP is not told: an expiry, which the CISP judges on its
// own clock at ends_at (ended_by expiry).
func PublicationOp(op restriction.Op) string {
	switch op {
	case restriction.OpPlan:
		return OpCreate
	case restriction.OpActivate:
		return OpActivate
	case restriction.OpExtend:
		return OpExtend
	case restriction.OpEnd:
		return OpEnd
	case restriction.OpCancel:
		return OpCancel
	case restriction.OpExpire:
		return ""
	}
	return ""
}

// EnqueueVersion queues what version v made by op is delivered as, in
// the transaction that wrote v: its CISP publication (none for an
// expiry, which the CISP judges on its own clock) and, in parallel (D6),
// its DSS write (a put on an activation or extension, a delete on an end
// or expiry; WP-9), with the restriction's DSS standing set to pending.
func (o *Outbox) EnqueueVersion(ctx context.Context, tx Tx, v restriction.Version, op restriction.Op, policyVersion int64) error {
	if pop := PublicationOp(op); pop != "" {
		if _, _, err := o.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: v.RestrictionID, AnspRef: v.AnspRef,
			AnspVersion: v.Version, Op: pop, Target: TargetCISP, PolicyVersion: policyVersion}); err != nil {
			return err
		}
	}
	kind, dop := DSSOp(op)
	if kind == "" {
		return nil
	}
	if _, _, err := o.Enqueue(ctx, tx, Job{Kind: kind, RestrictionID: v.RestrictionID, AnspRef: v.AnspRef,
		AnspVersion: v.Version, Op: dop, Target: TargetDSS, PolicyVersion: policyVersion}); err != nil {
		return err
	}
	return tx.SettleDSS(ctx, v.RestrictionID, false)
}

// Committed publishes the queued rows of the committed versions; what it
// cannot publish the scan publishes later.
func (o *Outbox) Committed(ctx context.Context, vs []restriction.Version) {
	for i := range vs {
		v := &vs[i]
		ps, err := o.Repo.QueuedOf(ctx, v.RestrictionID, v.Version)
		if err != nil {
			o.count(CounterBusFailed)
			o.log().Warn("deliver: the jobs of a committed version were not read; the outbox scan publishes them",
				slog.String("restriction_id", v.RestrictionID), slog.Int64("ansp_version", v.Version), slog.String("error", err.Error()))
			continue
		}
		o.PublishAll(ctx, ps)
	}
}

// PublishAll publishes each pending row.
func (o *Outbox) PublishAll(ctx context.Context, ps []Pending) {
	for _, p := range ps {
		_ = o.Publish(ctx, p)
	}
}

// Publish puts the row's next message on the bus, then records it
// (compare-and-set on bus_seq: of two replicas publishing the same row
// one records; the stream drops the repeat of the message id).
func (o *Outbox) Publish(ctx context.Context, p Pending) error {
	if o.Bus == nil {
		o.count(CounterBusFailed)
		return errors.New("no bus")
	}
	seq := p.BusSeq + 1
	data, err := json.Marshal(Message{ID: p.ID, Kind: p.Kind, Seq: seq})
	if err != nil {
		return err
	}
	if err := o.Bus.Publish(ctx, Subject(p.Kind), MsgID(p.ID, seq), data); err != nil {
		o.count(CounterBusFailed)
		return err
	}
	won, err := o.Repo.MarkBusPublished(ctx, p.ID, seq)
	if err != nil {
		o.count(CounterBusFailed)
		return err
	}
	if won {
		o.count(CounterBusPublished)
	}
	return nil
}

// Scan publishes the rows never published (their publish after the
// commit was lost) and the rows whose message is overdue; each is
// counted, so a repaired gap is never silent.
func (o *Outbox) Scan(ctx context.Context) (int, error) {
	ps, err := o.Repo.Pending(ctx, o.Policy.PublishGrace, o.Policy.StuckGrace, o.Policy.MaxBatch)
	if err != nil {
		o.count(CounterScanFailed)
		return 0, err
	}
	n := 0
	for _, p := range ps {
		if err := o.Publish(ctx, p); err != nil {
			continue
		}
		n++
		if p.Stuck {
			o.count(CounterStuck)
			o.log().Warn("deliver: a job's message was overdue; published again", slog.String("delivery_id", p.ID), slog.String("kind", string(p.Kind)))
		} else {
			o.count(CounterRepublished)
			o.log().Warn("deliver: a job was never published after its commit; published by the outbox scan", slog.String("delivery_id", p.ID), slog.String("kind", string(p.Kind)))
		}
	}
	return n, nil
}

// RunScan runs Scan every ScanEvery until ctx ends.
func (o *Outbox) RunScan(ctx context.Context) {
	t := time.NewTicker(o.Policy.ScanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := o.Scan(ctx); err != nil && ctx.Err() == nil {
			o.log().Warn("deliver: outbox scan failed; it runs again next period", slog.String("error", err.Error()))
		}
	}
}

// Channel is one channel of a version's deliveries (api/openapi.yaml
// DeliveryChannel).
type Channel struct {
	State          string  `json:"state"`
	Attempts       int     `json:"attempts"`
	LastAttemptAt  *string `json:"last_attempt_at,omitempty"`
	LastStatusCode *int    `json:"last_status_code,omitempty"`
	NextRetryAt    *string `json:"next_retry_at,omitempty"`
}

// Summary is a version's deliveries (api/openapi.yaml DeliveriesSummary).
type Summary struct {
	CISP           Channel `json:"cisp"`
	DSS            Channel `json:"dss"`
	USSNotify      Channel `json:"uss_notify"`
	DirectDegraded Channel `json:"direct_degraded"`
}

// NoSummary is a version with nothing queued on any channel.
func NoSummary() Summary {
	n := Channel{State: "none"}
	return Summary{CISP: n, DSS: n, USSNotify: n, DirectDegraded: n}
}

// rank orders the states of one channel's jobs: the summary shows the
// one a person must look at first. A cancelled job is not shown.
var rank = map[State]int{StateFailed: 5, StateAbandoned: 4, StateQueued: 3, StateSent: 2}

// Summarise folds the rows of a version into its channels: per channel
// the most urgent state (failed, abandoned, queued, sent), the attempts
// summed, and the latest attempt.
func Summarise(rows []ChannelRow) Summary {
	s := NoSummary()
	for _, r := range rows {
		var c *Channel
		switch r.Kind {
		case KindCISPPublish:
			c = &s.CISP
		case KindDSSPut, KindDSSDelete:
			c = &s.DSS
		case KindUSSNotify:
			c = &s.USSNotify
		case KindDirect:
			c = &s.DirectDegraded
		case KindCISPHeartbeat, KindOccurrence:
			// Not a channel of a restriction version.
			continue
		default:
			continue
		}
		c.Attempts += r.Attempt
		if r.LastAttemptAt != nil && (c.LastAttemptAt == nil || restriction.Stamp(*r.LastAttemptAt) > *c.LastAttemptAt) {
			at := restriction.Stamp(*r.LastAttemptAt)
			c.LastAttemptAt, c.LastStatusCode = &at, r.StatusCode
		}
		if rank[r.State] > rank[State(c.State)] {
			c.State = string(r.State)
			if r.State == StateQueued {
				next := restriction.Stamp(r.NextRetryAt)
				c.NextRetryAt = &next
			} else {
				c.NextRetryAt = nil
			}
		}
	}
	return s
}

// clip bounds a text for a column.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utfStart(s) {
		s = s[:len(s)-1]
	}
	return s
}

func utfStart(s string) bool { return strings.ToValidUTF8(s, "") == s }

// RestrictionHook is the outbox as the restriction service's
// VersionHook: the CISP publication of a version is queued in the
// version's transaction and published after its commit.
type RestrictionHook struct {
	Outbox *Outbox
	// TxOf is the outbox's view of a restriction transaction
	// (store.DeliverTxOf).
	TxOf func(restriction.Tx) (Tx, bool)
}

var _ restriction.VersionHook = RestrictionHook{}

// Versioned queues v's publication in tx; a transaction the outbox
// cannot write in refuses the change (fail closed: a version is never
// committed without its delivery).
func (h RestrictionHook) Versioned(ctx context.Context, tx restriction.Tx, v restriction.Version, op restriction.Op) error {
	dtx, ok := h.TxOf(tx)
	if !ok {
		return errors.New("deliver: the outbox cannot write in this transaction")
	}
	return h.Outbox.EnqueueVersion(ctx, dtx, v, op, 0)
}

// Committed publishes the jobs of the committed versions.
func (h RestrictionHook) Committed(ctx context.Context, vs []restriction.Version) {
	h.Outbox.Committed(ctx, vs)
}
