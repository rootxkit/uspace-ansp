package restriction

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/bus"
)

// SchemaState is the schema of a restriction's state message (04
// section 3.4; schemas/restriction/state/v1.json, owned here).
const SchemaState = "restriction/state/v1"

// TimeSourceSystem is the envelope's time_source of a message this
// system makes on its own clock.
const TimeSourceSystem = "system"

// StateBody is the body of restriction/state/v1.
type StateBody struct {
	RestrictionID string          `json:"restriction_id"`
	AnspRef       string          `json:"ansp_ref"`
	State         State           `json:"state"`
	StartsAt      string          `json:"starts_at"`
	EndsAt        string          `json:"ends_at"`
	AnspVersion   int64           `json:"ansp_version"`
	Feature       json.RawMessage `json:"feature"`
}

// Envelope is the common envelope of 04 section 2 around a body.
type Envelope struct {
	Schema     string `json:"schema"`
	MsgID      string `json:"msg_id"`
	Producer   string `json:"producer"`
	Ts         string `json:"ts"`
	RxTs       string `json:"rx_ts"`
	CapturedAt string `json:"captured_at"`
	TimeSource string `json:"time_source"`
	Backlog    bool   `json:"backlog"`
	Body       any    `json:"body"`
}

// Subject is the bus subject of v: restr.v1.<state>.<restriction_id>.
func Subject(v Version) string {
	return bus.SubjectRestrictionPrefix + string(v.State) + "." + v.RestrictionID
}

// DedupeID is the JetStream message id of v (Nats-Msg-Id): the same for
// a version however often it is republished, so the stream holds it once.
func DedupeID(v Version) string {
	return v.RestrictionID + "." + strconv.FormatInt(v.Version, 10)
}

// StateMessage is v as restriction/state/v1 in its envelope, stamped at
// the version's changed_at. backlog marks a version republished after
// the moment it was made (the repair of a failed publish): history, not
// news.
func StateMessage(v Version, producer string, backlog bool) ([]byte, error) {
	if v.MsgID == "" || len(v.Feature) == 0 || !v.State.Valid() {
		return nil, errors.New("a version without msg_id, feature or state")
	}
	at := v.ChangedAt.UTC().Format(TimeFormat)
	return json.Marshal(Envelope{
		Schema: SchemaState, MsgID: v.MsgID, Producer: producer,
		Ts: at, RxTs: at, CapturedAt: at, TimeSource: TimeSourceSystem, Backlog: backlog,
		Body: StateBody{
			RestrictionID: v.RestrictionID, AnspRef: v.AnspRef, State: v.State,
			StartsAt: stamp(v.StartsAt), EndsAt: stamp(v.EndsAt), AnspVersion: v.Version, Feature: v.Feature,
		},
	})
}

// Stamp is t in the wire format (02 section 1).
func Stamp(t time.Time) string { return stamp(t) }
