package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/audit"
)

// MaxAckReasonBytes bounds the reason of an acknowledgement.
const MaxAckReasonBytes = 1000

// ErrAcknowledged is an acknowledgement of an alarm a person has
// acknowledged already, or one already cleared.
var ErrAcknowledged = errors.New("the alarm is acknowledged or cleared already")

// Actor is who acknowledges: the account id and its role.
type Actor struct {
	ID   string
	Role string
}

// Alarms lists the delivery alarms and takes a person's
// acknowledgement (audited). A failed or abandoned delivery's alarm is
// closed by it; a cisp_not_published alarm is marked acknowledged and
// stays open until the publication, so a live condition is never closed
// by a click (it is cleared only by what resolves it).
type Alarms struct {
	Repo     Repo
	Events   *Events
	Logger   *slog.Logger
	Counters *core.Counters
}

// List is the open alarms (all with all), newest first, at most limit,
// and whether more existed.
func (a *Alarms) List(ctx context.Context, all bool, limit int) ([]Alarm, bool, error) {
	out, err := a.Repo.Alarms(ctx, all, limit+1)
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// DecodeAcknowledge reads {"reason": "..."}: one JSON object, the reason
// required, valid UTF-8, at most MaxAckReasonBytes; unknown members are
// refused.
func DecodeAcknowledge(body []byte) (string, *core.FieldError) {
	var b struct {
		Reason *string `json:"reason"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return "", core.Fieldf("body", "not an object {reason}")
	}
	if b.Reason == nil || strings.TrimSpace(*b.Reason) == "" {
		return "", core.Fieldf("reason", "is required: why the alarm is acknowledged")
	}
	r := strings.TrimSpace(*b.Reason)
	if len(r) > MaxAckReasonBytes || !utf8.ValidString(r) {
		return "", core.Fieldf("reason", "is not valid UTF-8 of at most %d bytes", MaxAckReasonBytes)
	}
	return r, nil
}

// Acknowledge records actor's acknowledgement of alarm id with reason,
// and the audit event, in one transaction.
func (a *Alarms) Acknowledge(ctx context.Context, actor Actor, id, reason string) (Alarm, error) {
	var out Alarm
	err := a.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		if out, err = tx.AcknowledgeAlarm(ctx, id, actor.Role, reason); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: actor.ID,
			Purpose:    clip("delivery alarm acknowledged (02 F2): "+reason, audit.MaxPurposeBytes),
			EntityType: "delivery_alarm", EntityID: id, EventType: "delivery_alarm_acknowledged",
			Payload: map[string]any{"kind": out.Kind, "restriction_id": out.RestrictionID, "delivery_id": out.DeliveryID,
				"ansp_version": out.AnspVersion, "reason": reason, "role": actor.Role, "state": AlarmStateOf(out)}})
	})
	if err != nil {
		return Alarm{}, err
	}
	if a.Counters != nil {
		a.Counters.Inc(CounterAlarmsAcked)
	}
	if a.Logger != nil {
		a.Logger.Info("deliver: alarm acknowledged", slog.String("alarm_id", id), slog.String("kind", string(out.Kind)),
			slog.String("restriction_id", out.RestrictionID), slog.String("role", actor.Role))
	}
	a.Events.Alarm(ctx, out, "acknowledged")
	return out, nil
}
