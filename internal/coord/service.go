package coord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// SchemaNotice is the schema of a notice's frame on coord.v1 and on GET
// /v1/coordination/stream: the inbox item (CoordinationNotice of
// api/openapi.yaml) in the 04 section 2 envelope. It is not
// coordination/annex_v/v1, which is the USSP's request body: a frame's
// body is the message its schema names (envelope/v1), and the inbox item
// is not a request body (docs/PLAN.md section 15 row 24, settled here).
const SchemaNotice = "coordination/notice/v1"

// Counters of the inbox (E-09): each a Prometheus counter of the same
// name.
const (
	CounterReceived         = "notices_received"
	CounterReplayed         = "notices_replayed"
	CounterRefused          = "notices_refused"
	CounterSenderRefused    = "notices_sender_refused"
	CounterSenderUnverified = "notices_sender_unverified"
	CounterRefReused        = "notices_ref_reused"
	CounterEscalated        = "notices_escalated"
	CounterAcknowledged     = "notices_acknowledged"
	CounterBusFailed        = "notices_bus_publish_failed"
	CounterRepublished      = "notices_republished"
	CounterRestrictionsCut  = "notices_restriction_ids_truncated"
	CounterInboxViewed      = "notices_inbox_viewed"
	// CounterSenderQuota counts notices refused 429 at the sender's quota.
	CounterSenderQuota = "notices_sender_quota_refused"
)

// The refusal slugs of the inbox (problem type slugs, M28).
const (
	SlugInvalid        = "invalid_request"
	SlugSenderUnknown  = "sender_not_listed"
	SlugSenderMismatch = "sender_mismatch"
	SlugRefReused      = "notice_ref_reused"
	SlugAuditFailed    = "audit_unavailable"
	SlugRateLimited    = "rate_limited"
)

// Refusal is a refused request: the status, the problem slug, the detail
// and the members at fault.
type Refusal struct { //nolint:errname // the refusal is the problem body, as restriction.Refusal
	Status int
	Slug   string
	Detail string
	Fields []*core.FieldError
	// RetryAfter is set on a 503.
	RetryAfter time.Duration
}

func (r *Refusal) Error() string { return r.Slug + ": " + r.Detail }

// Policy is the inbox's timings and bounds in one place (CLAUDE.md rule
// 5). notice_escalation_s is the ansp_policy row's and is read from it;
// the rest have no column yet (docs/PLAN.md section 15 row 42) and are
// these defaults.
type Policy struct {
	// EscalationRepeat is how often an escalated notice is escalated
	// again until a person acknowledges it.
	EscalationRepeat time.Duration
	// TickEvery is the escalation and republish period (budget: the
	// escalation within 1 s of its due time).
	TickEvery time.Duration
	// MaxBatch bounds the notices one tick escalates or republishes.
	MaxBatch int
	// MaxRestrictionIDs bounds the restrictions recorded for a notice.
	MaxRestrictionIDs int
	// MaxListed bounds one inbox page.
	MaxListed int
	// OccurrenceAlarmAfter is when an undelivered occurrence report
	// raises occurrence_undelivered: 60 h after became_aware_at.
	OccurrenceAlarmAfter time.Duration
	// OccurrenceAlarmEvery is the occurrence monitor's period.
	OccurrenceAlarmEvery time.Duration
	// OccurrenceClockSkew is how far after now (the database clock) a
	// report's became_aware_at may be; later is refused, so a client's
	// clock never moves the 72 h deadline.
	OccurrenceClockSkew time.Duration
	// OccurrenceMaxAge is how far before now a report's occurred_at may
	// be; older is refused as a likely typo.
	OccurrenceMaxAge time.Duration
	// MaxSenderNotices bounds the notices one sender holds received
	// within SenderQuotaWindow or still awaiting a person's
	// acknowledgement; one more is refused 429 (ansp audit S-9).
	MaxSenderNotices  int
	SenderQuotaWindow time.Duration
}

// OccurrenceDeadline is 376/2014 Art. 4(8): a report within 72 h of
// becoming aware of the occurrence. A regulation, not a threshold.
const OccurrenceDeadline = 72 * time.Hour

// DefaultPolicy is the inbox's defaults.
func DefaultPolicy() Policy {
	return Policy{
		EscalationRepeat: 30 * time.Second, TickEvery: time.Second, MaxBatch: 100, MaxRestrictionIDs: 1000, MaxListed: 1000,
		OccurrenceAlarmAfter: 60 * time.Hour, OccurrenceAlarmEvery: 10 * time.Second,
		OccurrenceClockSkew: 5 * time.Minute, OccurrenceMaxAge: 365 * 24 * time.Hour,
		MaxSenderNotices: 500, SenderQuotaWindow: time.Hour,
	}
}

// Validate refuses a policy the inbox cannot run.
func (p Policy) Validate() error {
	var errs []error
	if p.EscalationRepeat <= 0 || p.TickEvery <= 0 || p.OccurrenceAlarmEvery <= 0 {
		errs = append(errs, core.Fieldf("periods", "must be positive"))
	}
	if p.MaxBatch < 1 || p.MaxRestrictionIDs < 1 || p.MaxListed < 1 || p.MaxSenderNotices < 1 || p.SenderQuotaWindow <= 0 {
		errs = append(errs, core.Fieldf("bounds", "must be at least 1"))
	}
	if p.OccurrenceAlarmAfter <= 0 || p.OccurrenceAlarmAfter >= OccurrenceDeadline {
		errs = append(errs, core.Fieldf("occurrence_alarm_after", "must be positive and before the 72 h deadline"))
	}
	if p.OccurrenceClockSkew <= 0 || p.OccurrenceMaxAge <= OccurrenceDeadline {
		errs = append(errs, core.Fieldf("occurrence_times", "the skew must be positive and the age longer than the 72 h deadline"))
	}
	return errors.Join(errs...)
}

// Clock is a source of now; the inbox's default is the database clock.
type Clock func(ctx context.Context) (time.Time, error)

// Service is the Annex V inbox: intake with receipts, the person's
// acknowledgement, the escalation of the silent ones, and the frames of
// the console stream. It never logs: its outcomes are returned and
// counted, and the process logs them.
type Service struct {
	Repo Repo
	// USSPs is the CIS USSP list projection: the ussp_ids listed and
	// whether a list is projected at all (WP-7).
	USSPs func() ([]string, bool)
	// Escalation is notice_escalation_s of the ansp_policy row and its
	// policy_version.
	Escalation func(ctx context.Context) (time.Duration, int64)
	// Bus puts coord.v1 on JetStream; nil leaves every change for the
	// ticker (counted, and the stream says the bus is not configured).
	Bus deliver.BusPublisher
	// Local relays a frame to this process's console stream at once, by
	// its dedupe key (the bus delivers it again; the stream drops it).
	Local    func(key string, frame []byte)
	Producer string
	Policy   Policy
	// Clock is now for the escalation; nil is the database clock.
	Clock Clock

	counters core.Counters
}

// Counters are the inbox's counters.
func (s *Service) Counters() *core.Counters { return &s.counters }

func (s *Service) now(ctx context.Context) (time.Time, error) {
	if s.Clock != nil {
		return s.Clock(ctx)
	}
	return s.Repo.Now(ctx)
}

// Receipt is the answer to a notice (M2): its ack_id, state received and
// when it was received.
type Receipt struct {
	AckID      string `json:"ack_id"`
	State      string `json:"state"`
	ReceivedAt string `json:"received_at"`
}

func receiptOf(n Notice) Receipt {
	return Receipt{AckID: n.AckID, State: string(StateReceived), ReceivedAt: restriction.Stamp(n.ReceivedAt)}
}

// SenderMatches reports whether a token's sub belongs to the USSP of
// ussp_id: the sub is the ussp_id, or the client id ussp-<ussp_id>-NN of
// the reconciliation's client ids (M24).
func SenderMatches(sub, usspID string) bool {
	if sub == "" || usspID == "" {
		return false
	}
	if sub == usspID {
		return true
	}
	rest, ok := strings.CutPrefix(sub, "ussp-"+usspID+"-")
	if !ok || len(rest) < 1 || len(rest) > 4 {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// listed is the ussp_id the sender belongs to, whether one does, and
// whether a list was there to judge by.
func (s *Service) listed(sub string) (string, bool, bool) {
	if s.USSPs == nil {
		return "", false, false
	}
	ids, projected := s.USSPs()
	if !projected {
		return "", false, false
	}
	for _, id := range ids {
		if SenderMatches(sub, id) {
			return id, true, true
		}
	}
	return "", false, true
}

// Submit takes a notice from the client sub (the token's sub). The
// sender must be on the CIS USSP list (403 and an audit row otherwise);
// with no list projected the notice is accepted and flagged
// sender_unverified, never refused for lack of this system's own data.
// The body is checked member by member (DecodeNotice); the restrictions
// its volumes intersect are recorded; the row and its audit event commit
// together and only then is the notice put on coord.v1 (B-05). A repeat
// of the same notice_ref with the same body answers the first receipt
// (replay true); with another body it is refused 409.
func (s *Service) Submit(ctx context.Context, sub string, body []byte) (Receipt, bool, error) {
	usspID, ok, projected := s.listed(sub)
	if projected && !ok {
		s.counters.Inc(CounterSenderRefused)
		return Receipt{}, false, s.refuseSender(ctx, sub, SlugSenderUnknown, "the sender is not a USSP on the CIS USSP list", body)
	}
	d, ferrs := DecodeNotice(body)
	if len(ferrs) > 0 {
		s.counters.Inc(CounterRefused)
		return Receipt{}, false, &Refusal{Status: http.StatusBadRequest, Slug: SlugInvalid, Detail: "the notice is refused; nothing was stored", Fields: ferrs}
	}
	if projected && d.USSPID != usspID {
		s.counters.Inc(CounterSenderRefused)
		return Receipt{}, false, s.refuseSender(ctx, sub, SlugSenderMismatch, "ussp_id is not the sending USSP's", body)
	}
	if !projected {
		s.counters.Inc(CounterSenderUnverified)
	}
	var stored Notice
	var replay bool
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		replay = false
		now, err := s.now(ctx)
		if err != nil {
			return err
		}
		if rf, err := s.quota(ctx, tx, sub, d.NoticeRef, now); err != nil || rf != nil {
			if rf != nil {
				return rf
			}
			return err
		}
		ids, err := tx.Intersecting(ctx, d.Boxes(), s.Policy.MaxRestrictionIDs+1)
		if err != nil {
			return err
		}
		if len(ids) > s.Policy.MaxRestrictionIDs {
			ids = ids[:s.Policy.MaxRestrictionIDs]
			s.counters.Inc(CounterRestrictionsCut)
		}
		n, inserted, err := tx.InsertNotice(ctx, NewNotice{
			AckID: restriction.NewULID(now), Kind: d.Kind, SenderClientID: sub, USSPID: d.USSPID, NoticeRef: d.NoticeRef,
			Payload: d.Raw, PayloadSHA256: d.SHA256, IntentRefs: d.IntentRefs(), AuthorisationNumbers: d.AuthorisationNumbers(),
			AckRequired: d.Kind.AckRequired(), SenderUnverified: !projected, RestrictionIDs: ids, ReceivedAt: now,
		})
		if err != nil {
			return err
		}
		if !inserted {
			first, err := tx.NoticeBySenderRef(ctx, sub, d.NoticeRef)
			if err != nil {
				return err
			}
			if !bytes.Equal(first.PayloadSHA256, d.SHA256) {
				return &Refusal{Status: http.StatusConflict, Slug: SlugRefReused,
					Detail: "notice_ref was used before by this sender for another notice; nothing was stored",
					Fields: []*core.FieldError{core.Fieldf("notice_ref", "was used before for another notice (ack_id %s)", first.AckID)}}
			}
			stored, replay = first, true
			return nil
		}
		stored = n
		return tx.Audit(ctx, audit.Event{
			ActorType: audit.ActorClient, ActorID: sub,
			Purpose:    "Annex V notice received (2021/664 Art. 13(2), Annex V)",
			EntityType: "coordination_notice", EntityID: n.AckID, EventType: "coordination_notice_received",
			Payload: map[string]any{"kind": n.Kind, "ussp_id": n.USSPID, "notice_ref": n.NoticeRef, "intent_refs": n.IntentRefs,
				"authorisation_numbers": n.AuthorisationNumbers, "sender_unverified": n.SenderUnverified,
				"restriction_ids": n.RestrictionIDs, "acknowledgement_required": n.AckRequired},
		})
	})
	if err != nil {
		var rf *Refusal
		if errors.As(err, &rf) && rf.Slug == SlugRefReused {
			s.counters.Inc(CounterRefReused)
		}
		if errors.As(err, &rf) && rf.Status == http.StatusTooManyRequests {
			s.counters.Inc(CounterSenderQuota)
		}
		return Receipt{}, false, err
	}
	if replay {
		s.counters.Inc(CounterReplayed)
		return receiptOf(stored), true, nil
	}
	s.counters.Inc(CounterReceived)
	s.publish(ctx, stored)
	return receiptOf(stored), false, nil
}

// quota refuses a new notice of a sender that holds MaxSenderNotices
// received within SenderQuotaWindow or awaiting acknowledgement: 429
// with Retry-After, nothing stored. A repeat of a notice it holds is
// not refused (its receipt is answered).
func (s *Service) quota(ctx context.Context, tx Tx, sub, ref string, now time.Time) (*Refusal, error) {
	n, err := tx.CountSenderNotices(ctx, sub, now.Add(-s.Policy.SenderQuotaWindow))
	if err != nil || n < int64(s.Policy.MaxSenderNotices) {
		return nil, err
	}
	if _, err := tx.NoticeBySenderRef(ctx, sub, ref); err == nil {
		return nil, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &Refusal{Status: http.StatusTooManyRequests, Slug: SlugRateLimited, RetryAfter: s.Policy.SenderQuotaWindow / 4,
		Detail: fmt.Sprintf("the sender holds %d notices received in the last %s or awaiting acknowledgement; at most %d; nothing was stored",
			n, s.Policy.SenderQuotaWindow, s.Policy.MaxSenderNotices)}, nil
}

// refuseSender records the refusal of a sender in the audit log, then
// refuses it 403; without the audit row it refuses 503 (fail closed).
func (s *Service) refuseSender(ctx context.Context, sub, slug, detail string, body []byte) error {
	ref := "unknown"
	var probe struct {
		NoticeRef string `json:"notice_ref"`
		USSPID    string `json:"ussp_id"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.NoticeRef != "" && len(probe.NoticeRef) <= MaxNoticeRefBytes && utf8.ValidString(probe.NoticeRef) {
		ref = probe.NoticeRef
	}
	usspID := probe.USSPID
	if len(usspID) > MaxUSSPIDBytes || !utf8.ValidString(usspID) {
		usspID = ""
	}
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		return tx.Audit(ctx, audit.Event{
			ActorType: audit.ActorClient, ActorID: clipText(sub, audit.MaxFieldBytes-8),
			Purpose:    "Annex V notice refused: " + detail,
			EntityType: "coordination_notice", EntityID: ref, EventType: "coordination_notice_refused",
			Payload: map[string]any{"reason": slug, "ussp_id": usspID},
		})
	})
	if err != nil {
		return &Refusal{Status: http.StatusServiceUnavailable, Slug: SlugAuditFailed, RetryAfter: 5 * time.Second,
			Detail: "the refusal could not be recorded; try again"}
	}
	return &Refusal{Status: http.StatusForbidden, Slug: slug, Detail: detail,
		Fields: []*core.FieldError{core.Fieldf("sub", "%s", detail)}}
}

// Get is a notice. A machine caller (sender non-empty) reads only the
// notices it sent; another's is not found.
func (s *Service) Get(ctx context.Context, ackID, sender string) (Notice, error) {
	n, err := s.Repo.Notice(ctx, ackID)
	if err != nil {
		return Notice{}, err
	}
	if sender != "" && n.SenderClientID != sender {
		return Notice{}, ErrNotFound
	}
	return n, nil
}

// Actor is a console user: the account id and its role.
type Actor struct {
	ID   string
	Role string
}

// Inbox is the inbox for a console user, newest first, at most limit,
// and whether more existed. Every view is audited (01 N4); a view that
// cannot be audited is refused.
func (s *Service) Inbox(ctx context.Context, actor Actor, f Filter) ([]Notice, bool, error) {
	limit := min(max(f.Limit, 1), s.Policy.MaxListed)
	f.Limit = limit + 1
	list, err := s.Repo.Notices(ctx, f)
	if err != nil {
		return nil, false, err
	}
	more := len(list) > limit
	if more {
		list = list[:limit]
	}
	payload := map[string]any{"state": f.State, "returned": len(list), "role": actor.Role}
	if f.Since != nil {
		payload["since"] = restriction.Stamp(*f.Since)
	}
	if err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: actor.ID, Purpose: "Annex V inbox viewed (01 N3)",
			EntityType: "coordination_inbox", EntityID: "inbox", EventType: "coordination_inbox_viewed", Payload: payload})
	}); err != nil {
		return nil, false, &Refusal{Status: http.StatusServiceUnavailable, Slug: SlugAuditFailed, RetryAfter: 5 * time.Second,
			Detail: "the view could not be recorded in the audit log; try again"}
	}
	s.counters.Inc(CounterInboxViewed)
	return list, more, nil
}

// MaxNoteBytes bounds an acknowledgement's note.
const MaxNoteBytes = 500

// DecodeAcknowledge reads the optional body {note}: absent or empty is
// no note; unknown members are ignored (02 section 1).
func DecodeAcknowledge(body []byte) (string, *core.FieldError) {
	if len(bytes.TrimSpace(body)) == 0 {
		return "", nil
	}
	var b struct {
		Note *string `json:"note"`
	}
	if err := strictObject(body, &b); err != nil {
		return "", core.Fieldf("body", "is not an object {note}")
	}
	if b.Note == nil {
		return "", nil
	}
	n := strings.TrimSpace(*b.Note)
	if len(n) > MaxNoteBytes || !utf8.ValidString(n) {
		return "", core.Fieldf("note", "is not valid UTF-8 of at most %d bytes", MaxNoteBytes)
	}
	return n, nil
}

// Acknowledge records the person's acknowledgement of notice ackID
// (Art. 13(2)) with an optional note, audited, and puts the change on
// coord.v1 after the commit. ErrNotFound for no such notice,
// ErrAcknowledged for one acknowledged already.
func (s *Service) Acknowledge(ctx context.Context, actor Actor, ackID, note string) (Notice, error) {
	var out Notice
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		n, ok, err := tx.Acknowledge(ctx, ackID, actor.Role, actor.ID, note)
		if err != nil {
			return err
		}
		if !ok {
			return ErrAcknowledged
		}
		out = n
		latency := 0.0
		if n.AcknowledgedAt != nil {
			latency = n.AcknowledgedAt.Sub(n.ReceivedAt).Seconds()
		}
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: actor.ID,
			Purpose:    "Annex V notice acknowledged (2021/664 Art. 13(2))",
			EntityType: "coordination_notice", EntityID: ackID, EventType: "coordination_notice_acknowledged",
			Payload: map[string]any{"kind": n.Kind, "role": actor.Role, "note": note, "escalations": n.Escalations,
				"seconds_after_receipt": latency, "ussp_id": n.USSPID}})
	})
	if errors.Is(err, ErrAcknowledged) {
		if _, gerr := s.Repo.Notice(ctx, ackID); errors.Is(gerr, ErrNotFound) {
			return Notice{}, ErrNotFound
		}
		return Notice{}, ErrAcknowledged
	}
	if err != nil {
		return Notice{}, err
	}
	s.counters.Inc(CounterAcknowledged)
	s.publish(ctx, out)
	return out, nil
}

// TickReport is what one tick did.
type TickReport struct {
	Escalated   []Notice
	Republished int
	Behind      int
}

// Tick escalates the notices due now (a nonconformance or contingent
// notice not acknowledged notice_escalation_s after receipt, and every
// EscalationRepeat after until a person acknowledges it), on the row so
// that a restart or another replica carries it on, and puts every change
// not yet on coord.v1 there.
func (s *Service) Tick(ctx context.Context) (TickReport, error) {
	var rep TickReport
	now, err := s.now(ctx)
	if err != nil {
		return rep, err
	}
	esc := 60 * time.Second
	if s.Escalation != nil {
		esc, _ = s.Escalation(ctx)
	}
	err = s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		rep.Escalated, err = tx.EscalateDue(ctx, now, esc, s.Policy.EscalationRepeat, s.Policy.MaxBatch)
		return err
	})
	if err != nil {
		return rep, err
	}
	for i := range rep.Escalated {
		s.counters.Inc(CounterEscalated)
		s.publish(ctx, rep.Escalated[i])
	}
	behind, err := s.Repo.BehindBus(ctx, s.Policy.MaxBatch)
	if err != nil {
		return rep, err
	}
	for i := range behind {
		if s.publishBus(ctx, behind[i]) {
			rep.Republished++
			s.counters.Inc(CounterRepublished)
		}
	}
	if c, err := s.Repo.CountBehindBus(ctx); err == nil {
		rep.Behind = c
	}
	return rep, nil
}

// Run runs Tick every TickEvery until ctx ends; report gets each
// outcome (the process logs it).
func (s *Service) Run(ctx context.Context, report func(TickReport, error)) {
	t := time.NewTicker(s.Policy.TickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := s.Tick(ctx)
		if report != nil && ctx.Err() == nil {
			report(rep, err)
		}
	}
}

// Subject is coord.v1.<kind>.<ack_id>.
func Subject(n Notice) string { return bus.SubjectCoordPrefix + string(n.Kind) + "." + n.AckID }

// Key is the dedupe key of a notice's change: <ack_id>.<event_seq>.
func Key(n Notice) string { return n.AckID + "." + strconv.Itoa(n.EventSeq) }

// publish relays n's change to the local stream and puts it on coord.v1.
func (s *Service) publish(ctx context.Context, n Notice) {
	frame := s.Frame(n)
	if s.Local != nil {
		s.Local(Key(n), frame)
	}
	s.publishFrame(ctx, n, frame)
}

func (s *Service) publishBus(ctx context.Context, n Notice) bool {
	return s.publishFrame(ctx, n, s.Frame(n))
}

// publishFrame puts the frame on coord.v1 with the change's message id,
// then records it; a failure is counted and left to the next tick.
func (s *Service) publishFrame(ctx context.Context, n Notice, frame []byte) bool {
	if s.Bus == nil {
		s.counters.Inc(CounterBusFailed)
		return false
	}
	if err := s.Bus.Publish(ctx, Subject(n), Key(n), frame); err != nil {
		s.counters.Inc(CounterBusFailed)
		return false
	}
	if err := s.Repo.MarkBus(ctx, n.AckID, n.EventSeq); err != nil {
		s.counters.Inc(CounterBusFailed)
		return false
	}
	return true
}

// Snapshot is the frames of the open notices (not acknowledged), newest
// first, at most limit, and whether more existed.
func (s *Service) Snapshot(ctx context.Context, limit int) ([]json.RawMessage, bool, error) {
	list, err := s.Repo.Notices(ctx, Filter{State: FilterOpen, Limit: limit + 1})
	if err != nil {
		return nil, false, err
	}
	more := len(list) > limit
	if more {
		list = list[:limit]
	}
	out := make([]json.RawMessage, 0, len(list))
	for i := range list {
		out = append(out, s.Frame(list[i]))
	}
	return out, more, nil
}

// Frame is n's coordination/notice/v1 frame: the inbox item with its
// payload (the console's view) in the envelope.
func (s *Service) Frame(n Notice) []byte {
	now := time.Now()
	at := restriction.Stamp(now)
	// BodyOf keeps the payload only when it is JSON, so this encodes.
	b, _ := json.Marshal(restriction.Envelope{
		Schema: SchemaNotice, MsgID: restriction.NewULID(now), Producer: s.Producer,
		Ts: at, RxTs: at, CapturedAt: at, TimeSource: restriction.TimeSourceSystem, Body: BodyOf(n, true),
	})
	return b
}

// NoticeBody is a notice on the wire (CoordinationNotice of
// api/openapi.yaml): acknowledged_by is the role of the person, never a
// name; the payload and the note are the console's only.
type NoticeBody struct {
	AckID                   string          `json:"ack_id"`
	Kind                    string          `json:"kind"`
	SenderClientID          string          `json:"sender_client_id"`
	USSPID                  string          `json:"ussp_id"`
	NoticeRef               string          `json:"notice_ref"`
	IntentRefs              []string        `json:"intent_refs"`
	AuthorisationNumbers    []string        `json:"authorisation_numbers"`
	ReceivedAt              string          `json:"received_at"`
	State                   string          `json:"state"`
	AcknowledgementRequired bool            `json:"acknowledgement_required"`
	SenderUnverified        bool            `json:"sender_unverified"`
	AcknowledgedBy          *string         `json:"acknowledged_by,omitempty"`
	AcknowledgedAt          *string         `json:"acknowledged_at,omitempty"`
	AcknowledgementNote     *string         `json:"acknowledgement_note,omitempty"`
	EscalatedAt             *string         `json:"escalated_at,omitempty"`
	LastEscalatedAt         *string         `json:"last_escalated_at,omitempty"`
	Escalations             int             `json:"escalations"`
	RestrictionIDs          []string        `json:"restriction_ids"`
	Payload                 json.RawMessage `json:"payload,omitempty"`
}

func stampPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := restriction.Stamp(*t)
	return &s
}

// BodyOf is n on the wire; console adds the payload and the note.
func BodyOf(n Notice, console bool) NoticeBody {
	b := NoticeBody{
		AckID: n.AckID, Kind: string(n.Kind), SenderClientID: n.SenderClientID, USSPID: n.USSPID, NoticeRef: n.NoticeRef,
		IntentRefs: nonNil(n.IntentRefs), AuthorisationNumbers: nonNil(n.AuthorisationNumbers),
		ReceivedAt: restriction.Stamp(n.ReceivedAt), State: string(n.State()), AcknowledgementRequired: n.AckRequired,
		SenderUnverified: n.SenderUnverified, AcknowledgedAt: stampPtr(n.AcknowledgedAt), EscalatedAt: stampPtr(n.EscalatedAt),
		LastEscalatedAt: stampPtr(n.LastEscalatedAt), Escalations: n.Escalations, RestrictionIDs: nonNil(n.RestrictionIDs),
	}
	if n.AcknowledgedBy != "" {
		role := n.AcknowledgedBy
		b.AcknowledgedBy = &role
	}
	if console {
		if json.Valid(n.Payload) {
			b.Payload = n.Payload
		}
		if n.AckNote != "" {
			note := n.AckNote
			b.AcknowledgementNote = &note
		}
	}
	return b
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// String names a tick for a log line.
func (r TickReport) String() string {
	return fmt.Sprintf("escalated %d, republished %d, behind %d", len(r.Escalated), r.Republished, r.Behind)
}
