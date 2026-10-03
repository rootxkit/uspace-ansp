package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/dss"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// The F3548 channel of the outbox (WP-9, D6): the constraint reference
// in the DSS (dss_put on an activation or extension, dss_delete on an
// end or expiry) and one uss_notify per subscriber the DSS names.

// TargetDSS is the target of a dss_put or dss_delete job (the DSS of
// ANSP_DSS_URL).
const TargetDSS = "dss"

// The ops of the DSS jobs and of the notifications they cause.
const (
	OpDSSPut    = "put"
	OpDSSDelete = "delete"
)

// The cancel reasons of the DSS channel.
const (
	// CancelNeverWritten: a delete of a constraint the DSS never held
	// (its put failed or was cancelled, and a read finds nothing).
	CancelNeverWritten = "dss_never_written"
	// CancelSupersededByNewer: a notification of an older version still
	// queued when the DSS named the subscriber for a newer one; the
	// newer carries the state (the subscriber sees the gap in
	// notification_index and reads the details).
	CancelSupersededByNewer = "superseded_by_newer"
)

// AlarmNotifyLate is a subscriber notification not delivered within
// CstrPublishedNotificationLatencySeconds of the DSS's answer: the miss
// is visible (02 F2, 02 F6), and the alarm stays open, acknowledged or
// not, until the notification is delivered, superseded or given up.
const AlarmNotifyLate AlarmKind = "uss_notify_late"

// The DSS states of a restriction (restrictions.dss_state).
const (
	DSSNone    = "none"
	DSSPending = "pending"
	DSSWritten = "written"
	DSSDeleted = "deleted"
	DSSFailed  = "failed"
)

// Counters of the DSS channel (E-09).
const (
	CounterDSSWritten            = "deliver_dss_written"
	CounterDSSDeleted            = "deliver_dss_deleted"
	CounterDSSOVNReread          = "deliver_dss_ovn_reread"
	CounterDSSConflict           = "deliver_dss_conflict_after_reread"
	CounterDSSSubscribersRefused = "deliver_dss_subscribers_refused"
	CounterDSSUnusable           = "deliver_dss_answer_unusable"
	CounterNotifyQueued          = "deliver_uss_notify_queued"
	CounterNotifyLate            = "deliver_uss_notify_late"
	CounterNotifySent            = "deliver_uss_notify_sent"
	CounterNotifySuperseded      = "deliver_uss_notify_superseded"
	// CounterNotifyTargetRefused counts notifications whose uss_base_url
	// is not https on a public address: failed at once, alarmed.
	CounterNotifyTargetRefused = "deliver_uss_notify_target_refused"
)

// DSSStatus is a restriction's standing in the DSS: the dss member of
// restriction/state/v1 and of the Restriction (pending since T while
// the DSS does not hold its current state; D6: never blocks the CISP).
type DSSStatus struct {
	State string `json:"state"`
	// Since is set while pending or failed.
	Since *string `json:"since,omitempty"`
	// AnspVersion is the version the DSS last accepted a put of.
	AnspVersion *int64 `json:"ansp_version,omitempty"`
	// DSSVersion is the DSS's version of the reference.
	DSSVersion *int64 `json:"dss_version,omitempty"`
}

// DSSInfo is what a DSS job reads at its attempt: the constraint id and
// ovn now, the restriction's state now, and the constraint document of
// the job's version ({details, derivation}, restriction_versions).
type DSSInfo struct {
	RestrictionID string
	AnspRef       string
	ConstraintID  string
	OVN           *string
	CurrentState  string
	Version       int64
	Constraint    json.RawMessage
}

// DSSWrite is what a DSS job did, recorded with its outcome in one
// transaction: the reference the DSS answered with (nil: a delete found
// nothing to delete) and the subscribers it named.
type DSSWrite struct {
	RestrictionID string
	AnspRef       string
	AnspVersion   int64
	DeliveryID    string
	Op            string
	ConstraintID  string
	Reference     *f3548.ConstraintReference
	Subscribers   []dss.Subscriber
}

// Notification is one dss_notifications row: a subscription the DSS
// named, carried by the uss_notify job DeliveryID.
type Notification struct {
	DeliveryID        string
	SubscriptionID    string
	NotificationIndex int32
	RestrictionID     string
	AnspVersion       int64
	ConstraintID      string
	Subscriber        string
	Op                string
}

// NotificationJob is what a uss_notify attempt reads to build its body
// at the first attempt: the write it reports and its subscriptions.
type NotificationJob struct {
	ConstraintID  string
	Op            string
	Reference     json.RawMessage
	Details       json.RawMessage
	Subscriptions []f3548.SubscriptionState
}

// Late is a uss_notify job still queued past the latency bound with no
// alarm yet.
type Late struct {
	DeliveryID    string
	RestrictionID string
	AnspVersion   int64
	Target        string
	QueuedAt      time.Time
}

// LateClearable is an open uss_notify_late alarm whose job is settled.
type LateClearable struct {
	AlarmID    string
	DeliveryID string
	State      State
}

// DSSOp is the DSS job of a restriction transition: a put on an
// activation or extension, a delete on an end or expiry, none on a plan
// or a cancel (a planned restriction is never in the DSS).
func DSSOp(op restriction.Op) (Kind, string) {
	switch op {
	case restriction.OpActivate, restriction.OpExtend:
		return KindDSSPut, OpDSSPut
	case restriction.OpEnd, restriction.OpExpire:
		return KindDSSDelete, OpDSSDelete
	case restriction.OpPlan, restriction.OpCancel:
	}
	return "", ""
}

// IsDSSKind reports whether k writes the DSS.
func IsDSSKind(k Kind) bool { return k == KindDSSPut || k == KindDSSDelete }

// DSS sends the F3548 jobs: the DSS writes through Client and the
// subscriber notifications through Notifier. USSBaseURL is
// ANSP_PUBLIC_BASE_URL, the uss_base_url of every reference.
type DSS struct {
	Client     *dss.Client
	Notifier   *dss.Notifier
	USSBaseURL string
	Logger     *slog.Logger
	Counters   *core.Counters
}

func (c *DSS) count(name string) {
	if c != nil && c.Counters != nil {
		c.Counters.Inc(name)
	}
}

func (c *DSS) log() *slog.Logger {
	if c == nil || c.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Logger
}

// sent is what one attempt of any kind did.
type sent struct {
	resp Response
	// cancel, when set, says the job is not sent and why.
	cancel string
	// verdict, when set, overrides Judge (an answer of the DSS's success
	// status that cannot be used is a failure, not a delivery).
	verdict *Verdict
	// write is a DSS write's outcome, recorded with the attempt.
	write *DSSWrite
}

func verdict(v Verdict) *Verdict { return &v }

// responseOf is a dss.Call as the attempt log keeps it.
func responseOf(c dss.Call) Response {
	return Response{Status: c.Status, Excerpt: c.Excerpt, RetryAfter: c.RetryAfter, Err: c.Err}
}

// failure is a failed DSS call as an attempt: unreachable is retried;
// a refusal, an unusable answer and a conflict that survived the re-read
// fail at once with an alarm (loudly).
func (c *DSS) failure(err error) sent {
	call := dss.CallOf(err)
	r := responseOf(call)
	if r.Err == "" {
		r.Err = clip(err.Error(), 1000)
	}
	switch {
	case errors.Is(err, dss.ErrUnavailable):
		return sent{resp: r, verdict: verdict(Retry)}
	case errors.Is(err, dss.ErrTooManySubscribers):
		c.count(CounterDSSSubscribersRefused)
		c.log().Error("dss: the DSS named more subscribers than the bound; the answer is refused and alarmed, never cut", slog.String("error", r.Err))
	case errors.Is(err, dss.ErrMalformed):
		c.count(CounterDSSUnusable)
	}
	return sent{resp: r, verdict: verdict(Permanent)}
}

// storedDetails is the details member of a version's constraint
// document (restriction.StoredConstraint).
func storedDetails(doc json.RawMessage) (f3548.ConstraintDetails, error) {
	var sc struct {
		Details f3548.ConstraintDetails `json:"details"`
	}
	if len(doc) == 0 || string(doc) == "null" {
		return f3548.ConstraintDetails{}, errors.New("the version has no F3548 constraint (no volumes were derived)")
	}
	if err := json.Unmarshal(doc, &sc); err != nil {
		return f3548.ConstraintDetails{}, fmt.Errorf("the stored constraint: %w", err)
	}
	if len(sc.Details.Volumes) == 0 {
		return f3548.ConstraintDetails{}, errors.New("the version's constraint has no volume")
	}
	return sc.Details, nil
}

// put writes the reference of d's version: extents are the version's
// F3548 volumes (WP-5's Volumes, the same volume as the ED-318 feature),
// uss_base_url this system's. A put of a restriction no longer active
// is cancelled (its delete follows in order). A 409 (a stale ovn, or a
// reference an earlier attempt created) is answered by one re-read of
// the reference and one retry with its ovn; a second 409 fails loudly.
func (c *DSS) put(ctx context.Context, repo Repo, d *Delivery, token string, maxBody int) (sent, error) {
	info, err := repo.DSSInfo(ctx, d.RestrictionID, d.AnspVersion)
	if err != nil {
		return sent{}, fmt.Errorf("the version cannot be read: %w", err)
	}
	if info.CurrentState != string(restriction.StateActive) {
		return sent{cancel: CancelNotActive}, nil
	}
	details, err := storedDetails(info.Constraint)
	if err != nil {
		return sent{}, err
	}
	if c.USSBaseURL == "" {
		return sent{resp: Response{Err: "no ANSP_PUBLIC_BASE_URL for the reference's uss_base_url"}, verdict: verdict(Retry)}, nil
	}
	body, err := dss.PutBody(details.Volumes, c.USSBaseURL)
	if err != nil {
		return sent{}, err
	}
	if len(body) > maxBody {
		return sent{}, fmt.Errorf("the reference is %d bytes; at most %d", len(body), maxBody)
	}
	if d.Method == "" {
		p, err := repo.Prepare(ctx, d.ID, token, http.MethodPut, dss.ReferencePath(info.ConstraintID, info.OVN), body)
		if err != nil {
			return sent{}, fmt.Errorf("the request cannot be recorded: %w", err)
		}
		*d = p
	}
	if c.Client == nil {
		return sent{resp: Response{Err: "no DSS configured (ANSP_DSS_URL)"}, verdict: verdict(Retry)}, nil
	}
	resp, call, err := c.Client.PutReference(ctx, info.ConstraintID, body, info.OVN)
	if errors.Is(err, dss.ErrConflict) || (info.OVN != nil && errors.Is(err, dss.ErrNotFound)) {
		c.count(CounterDSSOVNReread)
		ovn, rerr := c.reread(ctx, info.ConstraintID)
		if rerr != nil {
			return c.failure(rerr), nil
		}
		resp, call, err = c.Client.PutReference(ctx, info.ConstraintID, body, ovn)
		if errors.Is(err, dss.ErrConflict) {
			c.count(CounterDSSConflict)
			c.log().Error("dss: the reference's ovn was stale again after one re-read; failed, alarmed",
				slog.String("restriction_id", d.RestrictionID), slog.Int64("ansp_version", d.AnspVersion))
			s := c.failure(err)
			s.resp.Err = "409 again after one re-read of the reference: " + s.resp.Err
			return s, nil
		}
	}
	if err != nil {
		return c.failure(err), nil
	}
	ref := resp.ConstraintReference
	return sent{resp: responseOf(call), write: &DSSWrite{RestrictionID: d.RestrictionID, AnspRef: info.AnspRef, AnspVersion: d.AnspVersion,
		DeliveryID: d.ID, Op: OpDSSPut, ConstraintID: info.ConstraintID, Reference: &ref, Subscribers: dss.Subscribers(resp.Subscribers)}}, nil
}

// reread is the reference's current ovn: nil when the DSS holds none
// (the put creates it).
func (c *DSS) reread(ctx context.Context, id string) (*string, error) {
	ref, _, err := c.Client.GetReference(ctx, id)
	if errors.Is(err, dss.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if ref.Ovn == nil {
		return nil, &dss.Error{Kind: dss.ErrMalformed, Reason: "the DSS read the reference without its ovn; this system is its manager"}
	}
	return ref.Ovn, nil
}

// del deletes the reference at its ovn (read from the DSS when this
// system holds none: an earlier write's answer was lost). A 404 is done
// (an expired constraint needs no delete per F3548; one is sent anyway);
// a delete of a reference the DSS never held is cancelled.
func (c *DSS) del(ctx context.Context, repo Repo, d *Delivery, token string) (sent, error) {
	info, err := repo.DSSInfo(ctx, d.RestrictionID, d.AnspVersion)
	if err != nil {
		return sent{}, fmt.Errorf("the version cannot be read: %w", err)
	}
	if c.Client == nil {
		if d.Method == "" {
			if p, err := repo.Prepare(ctx, d.ID, token, http.MethodDelete, dss.ReferencePath(info.ConstraintID, info.OVN), nil); err == nil {
				*d = p
			}
		}
		return sent{resp: Response{Err: "no DSS configured (ANSP_DSS_URL)"}, verdict: verdict(Retry)}, nil
	}
	ovn := info.OVN
	if ovn == nil {
		if ovn, err = c.reread(ctx, info.ConstraintID); err != nil {
			return c.failure(err), nil
		}
		if ovn == nil {
			return sent{cancel: CancelNeverWritten}, nil
		}
	}
	if d.Method == "" {
		p, err := repo.Prepare(ctx, d.ID, token, http.MethodDelete, dss.ReferencePath(info.ConstraintID, ovn), nil)
		if err != nil {
			return sent{}, fmt.Errorf("the request cannot be recorded: %w", err)
		}
		*d = p
	}
	write := &DSSWrite{RestrictionID: d.RestrictionID, AnspRef: info.AnspRef, AnspVersion: d.AnspVersion, DeliveryID: d.ID,
		Op: OpDSSDelete, ConstraintID: info.ConstraintID}
	resp, call, err := c.Client.DeleteReference(ctx, info.ConstraintID, *ovn)
	if errors.Is(err, dss.ErrConflict) {
		c.count(CounterDSSOVNReread)
		conflict := dss.CallOf(err)
		if ovn, err = c.reread(ctx, info.ConstraintID); err != nil {
			return c.failure(err), nil
		}
		if ovn == nil {
			// Deleted in between (by an earlier attempt whose answer was
			// lost): done, nobody left to notify.
			r := responseOf(conflict)
			r.Err = "409, then the re-read found no reference: deleted already"
			return sent{resp: r, verdict: verdict(Sent), write: write}, nil
		}
		resp, call, err = c.Client.DeleteReference(ctx, info.ConstraintID, *ovn)
		if errors.Is(err, dss.ErrConflict) {
			c.count(CounterDSSConflict)
			c.log().Error("dss: the reference's ovn was stale again after one re-read; the delete failed, alarmed",
				slog.String("restriction_id", d.RestrictionID), slog.Int64("ansp_version", d.AnspVersion))
			return c.failure(err), nil
		}
	}
	if errors.Is(err, dss.ErrNotFound) {
		// Gone already: accepted as done, nobody to notify.
		r := responseOf(dss.CallOf(err))
		r.Err = ""
		return sent{resp: r, verdict: verdict(Sent), write: write}, nil
	}
	if err != nil {
		return c.failure(err), nil
	}
	ref := resp.ConstraintReference
	write.Reference, write.Subscribers = &ref, dss.Subscribers(resp.Subscribers)
	return sent{resp: responseOf(call), write: write}, nil
}

// notify sends a uss_notify job: its body is built at the first attempt
// from the write it reports and its subscriptions, then fixed (every
// retry sends the same bytes).
func (c *DSS) notify(ctx context.Context, repo Repo, d *Delivery, token string, maxBody int) (sent, error) {
	if d.Method == "" {
		n, err := repo.Notification(ctx, d.ID)
		if err != nil {
			return sent{}, fmt.Errorf("the notification cannot be read: %w", err)
		}
		body, err := NotificationBodyOf(n)
		if err != nil {
			return sent{}, err
		}
		if len(body) > maxBody {
			return sent{}, fmt.Errorf("the notification is %d bytes; at most %d", len(body), maxBody)
		}
		p, err := repo.Prepare(ctx, d.ID, token, http.MethodPost, strings.TrimRight(d.Target, "/")+dss.NotifyPath(), body)
		if err != nil {
			return sent{}, fmt.Errorf("the request cannot be recorded: %w", err)
		}
		*d = p
	}
	if c == nil || c.Notifier == nil {
		return sent{resp: Response{Err: "no subscriber notifier configured"}, verdict: verdict(Retry)}, nil
	}
	call := c.Notifier.Notify(ctx, d.Target, d.Body)
	r := responseOf(call)
	if call.Refused {
		// Not https on a public address: no retry changes that, and a
		// participant-written uss_base_url is never retried towards this
		// system's own network (ansp audit S-2). One failure, one alarm.
		c.count(CounterNotifyTargetRefused)
		c.log().Error("dss: a subscriber's uss_base_url is refused; the notification is failed and alarmed",
			slog.String("delivery_id", d.ID), slog.String("error", r.Err))
		return sent{resp: r, verdict: verdict(Permanent)}, nil
	}
	if r.Status == http.StatusConflict {
		// The standard's 409: the subscriber holds a newer notification
		// of the constraint; this one will never be taken.
		return sent{resp: r, verdict: verdict(Permanent)}, nil
	}
	return sent{resp: r}, nil
}

// NotificationBodyOf is the PutConstraintDetailsParameters of n: the
// full Constraint for a put (reference with its ovn, details), the
// constraint omitted for a delete.
func NotificationBodyOf(n NotificationJob) ([]byte, error) {
	if n.Op == OpDSSDelete {
		return dss.NotificationBody(n.ConstraintID, nil, n.Subscriptions)
	}
	var cons f3548.Constraint
	if err := json.Unmarshal(n.Reference, &cons.Reference); err != nil {
		return nil, fmt.Errorf("the written reference: %w", err)
	}
	details, err := storedDetails(json.RawMessage(`{"details":` + string(orNull(n.Details)) + `}`))
	if err != nil {
		return nil, err
	}
	cons.Details = details
	return dss.NotificationBody(n.ConstraintID, &cons, n.Subscriptions)
}

func orNull(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}

// LateDetail is the uss_notify_late alarm's text (C-12: never "lost").
func LateDetail(l Late, latency time.Duration) string {
	return fmt.Sprintf("the notification of subscriber %s of the constraint of restriction %s (version %d) is not delivered within %v of the DSS answer (queued at %s); it is retried",
		l.Target, l.RestrictionID, l.AnspVersion, latency, restriction.Stamp(l.QueuedAt))
}
