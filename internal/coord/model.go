package coord

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
)

// State is a notice's state as the API shows it: received (the receipt),
// escalated (received, needing a person, and not acknowledged within
// notice_escalation_s) or acknowledged (by a person, Art. 13(2)). The
// store holds two states (received, acknowledged) and the escalation.
type State string

// The states.
const (
	StateReceived     State = "received"
	StateEscalated    State = "escalated"
	StateAcknowledged State = "acknowledged"
)

// Valid reports whether s is a state of the API.
func (s State) Valid() bool {
	return s == StateReceived || s == StateEscalated || s == StateAcknowledged
}

// Notice is a stored notice.
type Notice struct {
	AckID                string
	Kind                 Kind
	SenderClientID       string
	USSPID               string
	NoticeRef            string
	Payload              json.RawMessage
	PayloadSHA256        []byte
	IntentRefs           []string
	AuthorisationNumbers []string
	ReceivedAt           time.Time
	Acknowledged         bool
	AckRequired          bool
	SenderUnverified     bool
	// AcknowledgedBy is the role of the person who acknowledged (never a
	// name); AcknowledgedUser the account id, for the audit only.
	AcknowledgedBy   string
	AcknowledgedUser string
	AcknowledgedAt   *time.Time
	AckNote          string
	EscalatedAt      *time.Time
	LastEscalatedAt  *time.Time
	Escalations      int
	RestrictionIDs   []string
	CISVersion       string
	// EventSeq counts the notice's changes; BusSeq is the last one on
	// coord.v1.
	EventSeq int
	BusSeq   int
}

// State is n's state on the API.
func (n Notice) State() State {
	switch {
	case n.Acknowledged:
		return StateAcknowledged
	case n.EscalatedAt != nil:
		return StateEscalated
	}
	return StateReceived
}

// NewNotice is a notice to store.
type NewNotice struct {
	AckID                string
	Kind                 Kind
	SenderClientID       string
	USSPID               string
	NoticeRef            string
	Payload              []byte
	PayloadSHA256        []byte
	IntentRefs           []string
	AuthorisationNumbers []string
	AckRequired          bool
	SenderUnverified     bool
	RestrictionIDs       []string
	CISVersion           string
	ReceivedAt           time.Time
}

// Filter selects the inbox. State "" is every notice; open is every one
// not acknowledged (the console's snapshot).
type Filter struct {
	State string
	Since *time.Time
	Limit int
}

// FilterOpen is the Filter.State of the notices not acknowledged.
const FilterOpen = "open"

// NewOccurrence is an occurrence report to store.
type NewOccurrence struct {
	ID            string
	ReportRef     string
	Channel       string
	OccurredAt    time.Time
	BecameAwareAt time.Time
	Category      string
	Aircraft      json.RawMessage
	Manned        json.RawMessage
	IntentRefs    []string
	MinSeparation json.RawMessage
	Narrative     string
	// PersonRefSealed is the reporter's reference sealed under the
	// secrets key with KeyID; nil without a reporter reference.
	PersonRefSealed []byte
	KeyID           string
	CreatedBy       string
	DeliveryID      string
}

// Occurrence is a stored occurrence report.
type Occurrence struct {
	NewOccurrence
	CreatedAt  time.Time
	DeadlineAt time.Time
}

// Undelivered is a report not delivered OccurrenceAlarmAfter after its
// reporter became aware, without its alarm yet.
type Undelivered struct {
	ID            string
	ReportRef     string
	DeliveryID    string
	BecameAwareAt time.Time
	DeadlineAt    time.Time
	DeliveryState string
}

// AlarmRef is an open occurrence_undelivered alarm whose report is now
// delivered.
type AlarmRef struct {
	AlarmID    string
	DeliveryID string
}

// Repo is the inbox's store (internal/store implements it on the
// relational database).
type Repo interface {
	// Now is the database clock.
	Now(ctx context.Context) (time.Time, error)
	Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	Notice(ctx context.Context, ackID string) (Notice, error)
	Notices(ctx context.Context, f Filter) ([]Notice, error)
	// BehindBus is the notices whose latest change is not on coord.v1.
	BehindBus(ctx context.Context, limit int) ([]Notice, error)
	CountBehindBus(ctx context.Context) (int, error)
	// MarkBus records that change seq of the notice is on coord.v1.
	MarkBus(ctx context.Context, ackID string, seq int) error
	// OccurrenceByDelivery is the report a delivery carries.
	OccurrenceByDelivery(ctx context.Context, deliveryID string) (Occurrence, error)
	Undelivered(ctx context.Context, now time.Time, after time.Duration, limit int) ([]Undelivered, error)
	DeliveredAlarms(ctx context.Context, limit int) ([]AlarmRef, error)
}

// Tx is one transaction of the inbox.
type Tx interface {
	// InsertNotice stores n; false when the sender sent its notice_ref
	// before (nothing is written).
	InsertNotice(ctx context.Context, n NewNotice) (Notice, bool, error)
	NoticeBySenderRef(ctx context.Context, sender, noticeRef string) (Notice, error)
	// Intersecting is the planned or active restrictions any box
	// intersects in space and time, at most limit.
	Intersecting(ctx context.Context, boxes []Box, limit int) ([]string, error)
	// Acknowledge records the person's acknowledgement; false when the
	// notice is acknowledged already.
	Acknowledge(ctx context.Context, ackID, role, userID, note string) (Notice, bool, error)
	// EscalateDue escalates the notices due at now: not acknowledged
	// after escalation, then every repeat.
	EscalateDue(ctx context.Context, now time.Time, escalation, repeat time.Duration, limit int) ([]Notice, error)
	NextOccurrenceRef(ctx context.Context) (string, error)
	InsertOccurrence(ctx context.Context, o NewOccurrence) (Occurrence, error)
	// Outbox is the outbox's view of this transaction (the occurrence
	// job and its alarms commit with the report, B-05).
	Outbox() deliver.Tx
	Audit(ctx context.Context, ev audit.Event) error
}

// Errors of the inbox.
var (
	ErrNotFound = errors.New("no such notice or report")
	// ErrAcknowledged is an acknowledgement of a notice acknowledged
	// already.
	ErrAcknowledged = errors.New("the notice is acknowledged already")
)
