package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
)

// Kind is what a delivery does (docs/PLAN.md section 5.1 deliveries).
type Kind string

// The kinds of the deliveries table. WP-8 sends cisp_publish and
// direct_degraded; the DSS (WP-9) and occurrence (WP-10) kinds ride the
// same outbox.
const (
	KindCISPPublish   Kind = "cisp_publish"
	KindCISPHeartbeat Kind = "cisp_heartbeat"
	KindDSSPut        Kind = "dss_put"
	KindDSSDelete     Kind = "dss_delete"
	KindUSSNotify     Kind = "uss_notify"
	KindDirect        Kind = "direct_degraded"
	KindOccurrence    Kind = "occurrence"
)

// Kinds is every kind.
var Kinds = []Kind{KindCISPPublish, KindCISPHeartbeat, KindDSSPut, KindDSSDelete, KindUSSNotify, KindDirect, KindOccurrence}

// Valid reports whether k is a kind of the table.
func (k Kind) Valid() bool {
	for _, x := range Kinds {
		if k == x {
			return true
		}
	}
	return false
}

// State is a delivery's state.
type State string

// The states. cancelled is a job that will never be sent: its reason
// says why (superseded_by_cisp, never_published, restriction_not_active).
const (
	StateQueued    State = "queued"
	StateSent      State = "sent"
	StateFailed    State = "failed"
	StateAbandoned State = "abandoned"
	StateCancelled State = "cancelled"
)

// The cancel reasons.
const (
	// CancelSupersededByCISP: the CISP published the version, so the
	// degraded direct path stops (02 F2).
	CancelSupersededByCISP = "superseded_by_cisp"
	// CancelNeverPublished: an end or cancel of a restriction the CISP
	// never held; there is nothing there to change.
	CancelNeverPublished = "never_published"
	// CancelNotActive: a direct delivery queued for a restriction that is
	// no longer active here.
	CancelNotActive = "restriction_not_active"
)

// The ops of a cisp_publish job: the restriction transition it carries.
const (
	OpCreate   = "create"
	OpActivate = "activate"
	OpExtend   = "extend"
	OpEnd      = "end"
	OpCancel   = "cancel"
	// OpNotify is the op of a degraded direct delivery.
	OpNotify = "notify"
)

// TargetCISP is the target of a cisp_publish job (the configured CISP
// of record, ANSP_CISP_URL).
const TargetCISP = "cisp"

// Job is a delivery to enqueue.
type Job struct {
	// ID is the delivery id (a ULID); Enqueue mints one when empty. A
	// direct delivery's id is its jti and the msg_id of its body.
	ID            string
	Kind          Kind
	RestrictionID string
	AnspRef       string
	AnspVersion   int64
	Op            string
	Target        string
	// Body, when set, is fixed at enqueue (a direct delivery's change
	// record); otherwise the worker fixes it at the first attempt.
	Body          []byte
	PolicyVersion int64
}

// SubjectRef is "<restriction_id>.<version>".
func (j Job) SubjectRef() string {
	return j.RestrictionID + "." + strconv.FormatInt(j.AnspVersion, 10)
}

// IdempotencyKey is the pair (ansp_ref, ansp_version) (D5, M4) as one
// string; with the kind and the target it is unique.
func (j Job) IdempotencyKey() string {
	return IdempotencyKey(j.AnspRef, j.AnspVersion)
}

// IdempotencyKey renders the pair (ansp_ref, ansp_version).
func IdempotencyKey(anspRef string, version int64) string {
	return anspRef + "#" + strconv.FormatInt(version, 10)
}

// Delivery is one deliveries row.
type Delivery struct {
	ID             string
	Kind           Kind
	SubjectRef     string
	RestrictionID  string
	AnspVersion    int64
	Op             string
	Target         string
	IdempotencyKey string
	State          State
	Attempt        int
	MaxAttempts    int
	QueuedAt       time.Time
	WindowEndsAt   time.Time
	NextRetryAt    time.Time
	BusSeq         int
	LastAttemptAt  *time.Time
	SentAt         *time.Time
	StatusCode     *int
	Excerpt        string
	LastError      string
	Method         string
	URL            string
	Body           []byte
	CancelReason   string
}

// ClaimOutcome is what a claim found.
type ClaimOutcome int

// The outcomes of Repo.Claim.
const (
	// Claimed: the row is leased to this attempt.
	Claimed ClaimOutcome = iota
	// Gone: no such row (a message for a row that never committed).
	Gone
	// Settled: the row is no longer queued (sent, failed, abandoned or
	// cancelled): a replayed message does nothing.
	Settled
	// Leased: another attempt holds the lease until Until.
	Leased
	// NotDue: the row's next attempt is at Until.
	NotDue
	// Blocked: an earlier version of the same restriction to the same
	// target is still queued (until Until at the soonest); versions are
	// sent in order.
	Blocked
)

// Claim is the answer of Repo.Claim.
type Claim struct {
	Outcome  ClaimOutcome
	Delivery Delivery
	// Now is the database clock at the claim.
	Now   time.Time
	Until time.Time
}

// Pending is a row the outbox scan publishes (again).
type Pending struct {
	ID     string
	Kind   Kind
	BusSeq int
	// Stuck is true for a row whose message is overdue (published once
	// and not claimed since its next attempt was due); false for a row
	// never published.
	Stuck bool
}

// VersionInfo is a restriction version as a delivery needs it.
type VersionInfo struct {
	RestrictionID    string
	AnspRef          string
	Identifier       string
	UspaceAirspaceID string
	// CurrentState and CurrentVersion are the restriction's now.
	CurrentState     string
	CurrentVersion   int64
	PublishedVersion *int64
	Version          int64
	State            string
	StartsAt         time.Time
	EndsAt           time.Time
	Feature          json.RawMessage
	ChangedAt        time.Time
	// PrevState is the state of the version before, "" for the first.
	PrevState string
}

// OpOfVersion is the transition that made v, read from its state and
// the state before it: planned is a create, active after planned (or
// first) an activation, active after active an extension, ended an end
// and cancelled a cancel.
func OpOfVersion(v VersionInfo) string {
	switch v.State {
	case "planned":
		return OpCreate
	case "active":
		if v.PrevState == "active" {
			return OpExtend
		}
		return OpActivate
	case "ended":
		return OpEnd
	case "cancelled":
		return OpCancel
	}
	return ""
}

// Attempt is the outcome of one attempt, written by Tx.Finish.
type Attempt struct {
	ID      string
	Token   string
	Attempt int
	// State is the row's new state: queued (retry at RetryAt), sent,
	// failed, abandoned or cancelled.
	State        State
	RetryAt      time.Time
	StatusCode   *int
	Excerpt      string
	Error        string
	CancelReason string
	Duration     time.Duration
	// Outcome is the attempt row's: sent, retry, failed, abandoned,
	// cancelled.
	Outcome string
}

// PublishedState is a restriction after the CISP confirmed a version.
type PublishedState struct {
	State            string
	AnspVersion      int64
	PublishedVersion int64
}

// Cancelled is a job the outbox cancelled.
type Cancelled struct {
	ID          string
	Target      string
	AnspVersion int64
}

// AlarmKind is the kind of an alarm.
type AlarmKind string

// The alarms.
const (
	AlarmCISPNotPublished AlarmKind = "cisp_not_published"
	AlarmFailed           AlarmKind = "delivery_failed"
	AlarmAbandoned        AlarmKind = "delivery_abandoned"
)

// Alarm is one delivery_alarms row.
type Alarm struct {
	ID             string
	Kind           AlarmKind
	RestrictionID  string
	AnspVersion    int64
	DeliveryID     string
	RaisedAt       time.Time
	Since          time.Time
	Detail         string
	ClearedAt      *time.Time
	ClearReason    string
	AcknowledgedBy string
	AcknowledgedAt *time.Time
	AckReason      string
}

// Open reports whether the alarm is still shown as open: not cleared,
// and (for a failed or abandoned delivery) not acknowledged.
func (a Alarm) Open() bool { return a.ClearedAt == nil }

// Overdue is an active restriction whose current version is not
// published to the CISP, older than the alarm threshold.
type Overdue struct {
	RestrictionID string
	AnspVersion   int64
	ChangedAt     time.Time
	// AlarmID is the open alarm, when one exists (at an older version).
	AlarmID string
}

// Clearable is an open cisp_not_published alarm whose restriction is now
// published or no longer active.
type Clearable struct {
	AlarmID          string
	RestrictionID    string
	State            string
	AnspVersion      int64
	PublishedVersion int64
}

// Unpublished is an active restriction not published at its current
// version (the reconciliation's list).
type Unpublished struct {
	RestrictionID string
	AnspRef       string
	AnspVersion   int64
}

// ChannelRow is one delivery of a version, for the summary.
type ChannelRow struct {
	Kind          Kind
	State         State
	Attempt       int
	LastAttemptAt *time.Time
	StatusCode    *int
	NextRetryAt   time.Time
}

// Repo is the outbox's store (internal/store implements it on the
// relational database). Every instant is the database clock.
type Repo interface {
	Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	// Claim leases id to token for one attempt of at most lease.
	Claim(ctx context.Context, id, token string, lease time.Duration) (Claim, error)
	// Prepare fixes the request of a claimed row at its first attempt;
	// a row already prepared is left as it is and returned.
	Prepare(ctx context.Context, id, token, method, url string, body []byte) (Delivery, error)
	// Pending is the queued rows to publish: never published and older
	// than publishGrace, or stuck for stuckGrace.
	Pending(ctx context.Context, publishGrace, stuckGrace time.Duration, limit int) ([]Pending, error)
	// QueuedOf is the queued rows of a version not yet published.
	QueuedOf(ctx context.Context, restrictionID string, version int64) ([]Pending, error)
	// MarkBusPublished records the publish of seq (a compare-and-set
	// from seq-1); false when another publish won.
	MarkBusPublished(ctx context.Context, id string, seq int) (bool, error)
	// Version is a version of the restriction; 0 is its current one.
	Version(ctx context.Context, restrictionID string, version int64) (VersionInfo, error)
	Overdue(ctx context.Context, after time.Duration, limit int) ([]Overdue, error)
	Clearable(ctx context.Context, limit int) ([]Clearable, error)
	ActiveRefs(ctx context.Context, limit int) ([]string, error)
	Unpublished(ctx context.Context, limit int) ([]Unpublished, error)
	Alarms(ctx context.Context, all bool, limit int) ([]Alarm, error)
	Alarm(ctx context.Context, id string) (Alarm, error)
	Channels(ctx context.Context, restrictionID string, version int64) ([]ChannelRow, error)
	Attempts(ctx context.Context, id string) (int, error)
}

// Tx is one transaction of the outbox.
type Tx interface {
	Now(ctx context.Context) (time.Time, error)
	// Insert writes a queued row; false when the job (kind,
	// idempotency key, target) exists already.
	Insert(ctx context.Context, j Job, maxAttempts int, window time.Duration) (bool, error)
	// Finish writes the attempt row and, while token still holds the
	// lease, the row's new state; false when the lease was lost.
	Finish(ctx context.Context, a Attempt) (bool, error)
	MarkPublishedVersion(ctx context.Context, restrictionID string, version int64) (PublishedState, error)
	CancelQueued(ctx context.Context, kind Kind, restrictionID string, upTo int64, reason string) ([]Cancelled, error)
	// RaiseAlarm inserts a; false when an equal alarm is open (the open
	// one is returned).
	RaiseAlarm(ctx context.Context, a Alarm) (Alarm, bool, error)
	AdvanceAlarm(ctx context.Context, id string, version int64, detail string) error
	// ClearCISPAlarm clears the open cisp_not_published alarm of the
	// restriction; false when none is open.
	ClearCISPAlarm(ctx context.Context, restrictionID, reason string) (Alarm, bool, error)
	AcknowledgeAlarm(ctx context.Context, id, by, reason string) (Alarm, error)
	// Expedite makes the queued rows of kind for the restriction due now.
	Expedite(ctx context.Context, kind Kind, restrictionID string) ([]Pending, error)
	// Requeue reopens an abandoned row of the version with extra
	// attempts and a new window; false when there is none.
	Requeue(ctx context.Context, kind Kind, restrictionID string, version int64, extra int, window time.Duration) (Pending, bool, error)
	Audit(ctx context.Context, ev audit.Event) error
}

// ErrNotFound is a delivery or alarm that does not exist.
var ErrNotFound = errors.New("not found")
