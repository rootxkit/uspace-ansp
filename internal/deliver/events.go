package deliver

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// AlarmBody is the alarm member of a restriction/state/v1 body
// (schemas/restriction/state/v1.json): an alarm raised, cleared (with how
// long it lasted) or acknowledged.
type AlarmBody struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	State          string   `json:"state"`
	RestrictionID  string   `json:"restriction_id,omitempty"`
	AnspVersion    int64    `json:"ansp_version,omitempty"`
	Since          string   `json:"since"`
	RaisedAt       string   `json:"raised_at"`
	Detail         string   `json:"detail"`
	DeliveryID     string   `json:"delivery_id,omitempty"`
	ClearedAt      string   `json:"cleared_at,omitempty"`
	ClearReason    string   `json:"clear_reason,omitempty"`
	DurationS      *float64 `json:"duration_s,omitempty"`
	AcknowledgedBy string   `json:"acknowledged_by,omitempty"`
	AcknowledgedAt string   `json:"acknowledged_at,omitempty"`
	AckReason      string   `json:"ack_reason,omitempty"`
}

// The alarm states of AlarmBody and of the API.
const (
	AlarmStateOpen         = "open"
	AlarmStateCleared      = "cleared"
	AlarmStateAcknowledged = "acknowledged"
)

// AlarmStateOf is a's state: cleared (by the publication, the end of the
// restriction or a person's acknowledgement of a failed or abandoned
// delivery), acknowledged (an open cisp_not_published a person has
// seen), or open.
func AlarmStateOf(a Alarm) string {
	switch {
	case a.ClearedAt != nil:
		return AlarmStateCleared
	case a.AcknowledgedAt != nil:
		return AlarmStateAcknowledged
	}
	return AlarmStateOpen
}

// BodyOf is a's wire form.
func BodyOf(a Alarm) AlarmBody {
	b := AlarmBody{ID: a.ID, Kind: string(a.Kind), State: AlarmStateOf(a), RestrictionID: a.RestrictionID, AnspVersion: a.AnspVersion,
		AckReason: a.AckReason, Since: restriction.Stamp(a.Since),
		RaisedAt: restriction.Stamp(a.RaisedAt), Detail: a.Detail, DeliveryID: a.DeliveryID,
		ClearReason: a.ClearReason, AcknowledgedBy: a.AcknowledgedBy}
	if a.ClearedAt != nil {
		b.ClearedAt = restriction.Stamp(*a.ClearedAt)
		d := math.Round(a.ClearedAt.Sub(a.Since).Seconds()*1000) / 1000
		b.DurationS = &d
	}
	if a.AcknowledgedAt != nil {
		b.AcknowledgedAt = restriction.Stamp(*a.AcknowledgedAt)
	}
	return b
}

// outcomeBody is restriction/state/v1 with the delivery outcome members.
type outcomeBody struct {
	restriction.StateBody
	Published  *bool      `json:"published,omitempty"`
	Alarm      *AlarmBody `json:"alarm,omitempty"`
	Deliveries *Summary   `json:"deliveries,omitempty"`
}

// Events puts delivery outcomes on restr.v1 (the console stream and the
// supervisor see them): the CISP's confirmation (published true) and
// alarms raised, cleared and acknowledged. A failed publish is counted
// and logged: the outcome is in the database and in GET
// /v1/delivery-alarms whatever the bus does.
type Events struct {
	Repo     Repo
	Bus      BusPublisher
	Producer string
	Logger   *slog.Logger
	Counters *core.Counters
	Now      func() time.Time
}

func (e *Events) count(name string) {
	if e.Counters != nil {
		e.Counters.Inc(name)
	}
}

// Published says the CISP confirmed version of rid.
func (e *Events) Published(ctx context.Context, rid string, version int64) {
	e.emit(ctx, rid, "published."+itoa(version), nil)
}

// Alarm says a changed (raised, cleared or acknowledged).
func (e *Events) Alarm(ctx context.Context, a Alarm, what string) {
	if a.RestrictionID == "" {
		return
	}
	b := BodyOf(a)
	e.emit(ctx, a.RestrictionID, "alarm."+a.ID+"."+what, &b)
}

// emit publishes the restriction's current version with the outcome:
// published says whether the CISP holds that version, deliveries what
// its channels did.
func (e *Events) emit(ctx context.Context, rid, suffix string, alarm *AlarmBody) {
	if e == nil || e.Bus == nil {
		return
	}
	v, err := e.Repo.Version(ctx, rid, 0)
	if err != nil {
		e.fail(rid, err)
		return
	}
	rows, err := e.Repo.Channels(ctx, rid, v.CurrentVersion)
	if err != nil {
		e.fail(rid, err)
		return
	}
	sum := Summarise(rows)
	published := v.PublishedVersion != nil && *v.PublishedVersion >= v.CurrentVersion
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	at := now.UTC().Format(restriction.TimeFormat)
	state := restriction.State(v.CurrentState)
	msg, err := json.Marshal(restriction.Envelope{
		Schema: restriction.SchemaState, MsgID: restriction.NewULID(now), Producer: e.Producer,
		Ts: at, RxTs: at, CapturedAt: at, TimeSource: restriction.TimeSourceSystem,
		Body: outcomeBody{StateBody: restriction.StateBody{
			RestrictionID: rid, AnspRef: v.AnspRef, State: state, StartsAt: restriction.Stamp(v.StartsAt),
			EndsAt: restriction.Stamp(v.EndsAt), AnspVersion: v.CurrentVersion, Feature: v.Feature,
		}, Published: &published, Alarm: alarm, Deliveries: &sum},
	})
	if err != nil {
		e.fail(rid, err)
		return
	}
	subject := restriction.Subject(restriction.Version{RestrictionID: rid, State: state})
	if err := e.Bus.Publish(ctx, subject, rid+"."+itoa(v.CurrentVersion)+"."+suffix, msg); err != nil {
		e.fail(rid, err)
	}
}

func (e *Events) fail(rid string, err error) {
	e.count(CounterEventFailed)
	if e.Logger != nil {
		e.Logger.Warn("deliver: a delivery outcome was not put on restr.v1; it is in the database and GET /v1/delivery-alarms",
			slog.String("restriction_id", rid), slog.String("error", err.Error()))
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
