package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// ActorType is who acted (docs/PLAN.md section 5.1 events.actor_type).
type ActorType string

// The actor types the table admits.
const (
	ActorUser   ActorType = "user"
	ActorClient ActorType = "client"
	ActorSystem ActorType = "system"
)

var actorTypes = []ActorType{ActorUser, ActorClient, ActorSystem}

// Event is one act to record. Every field is required; Payload is
// marshalled to a JSON object (nil records {}).
type Event struct {
	ActorType  ActorType
	ActorID    string
	Purpose    string
	EntityType string
	EntityID   string
	EventType  string
	Payload    any
}

// Bounds of one event (a write is always bounded).
const (
	MaxFieldBytes   = 256
	MaxPurposeBytes = 1000
	MaxPayloadBytes = 64 << 10
)

var eventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Validate refuses an event the log must not hold, naming every field
// at fault.
func (ev *Event) Validate() error {
	var errs []error
	if !slices.Contains(actorTypes, ev.ActorType) {
		errs = append(errs, core.Fieldf("actor_type", "must be user, client or system"))
	}
	for _, f := range []struct {
		name, v string
		limit   int
	}{
		{"actor_id", ev.ActorID, MaxFieldBytes},
		{"purpose", ev.Purpose, MaxPurposeBytes},
		{"entity_type", ev.EntityType, MaxFieldBytes},
		{"entity_id", ev.EntityID, MaxFieldBytes},
	} {
		switch {
		case f.v == "":
			errs = append(errs, core.Fieldf(f.name, "required"))
		case len(f.v) > f.limit:
			errs = append(errs, core.Fieldf(f.name, "longer than %d bytes", f.limit))
		}
	}
	if !eventTypePattern.MatchString(ev.EventType) {
		errs = append(errs, core.Fieldf("event_type", "must be snake_case, 1 to 64 characters"))
	}
	return errors.Join(errs...)
}

// Recorded is what Record wrote.
type Recorded struct {
	ID       int64
	TS       time.Time
	PrevHash string
	Hash     string
}

// Record writes ev inside the caller's transaction db (store.Tx), so the
// event commits or rolls back with the act it records. Its time is the
// database clock. Under the month's advisory lock it allocates the id,
// links to the previous row and stores
// hash = sha256(prev_hash || canonical JSON). An invalid event is
// refused before the database is touched.
func Record(ctx context.Context, db relational.DBTX, ev Event) (Recorded, error) {
	if err := ev.Validate(); err != nil {
		return Recorded{}, err
	}
	payload := []byte("{}")
	if ev.Payload != nil {
		b, err := json.Marshal(ev.Payload)
		if err != nil {
			return Recorded{}, core.Fieldf("payload", "cannot be encoded as JSON")
		}
		payload = b
	}
	if len(payload) > MaxPayloadBytes {
		return Recorded{}, core.Fieldf("payload", "longer than %d bytes", MaxPayloadBytes)
	}
	q := relational.New(db)
	now, err := q.DBNow(ctx)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: clock: %w", err)
	}
	ts := storedTime(now)
	month := MonthStart(ts)
	if err := q.AdvisoryXactLock(ctx, relational.LockKey(monthLockName(month))); err != nil {
		return Recorded{}, fmt.Errorf("audit: month lock: %w", err)
	}
	if _, err := q.EnsureEventsPartition(ctx, ts); err != nil {
		return Recorded{}, fmt.Errorf("audit: partition: %w", err)
	}
	prev, err := prevHash(ctx, q, month)
	if err != nil {
		return Recorded{}, err
	}
	id, err := q.NextEventID(ctx)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: next id: %w", err)
	}
	stored, err := q.NormalizeJSONB(ctx, payload)
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: payload: %w", err)
	}
	canonical, err := CanonicalPayload([]byte(stored))
	if err != nil {
		return Recorded{}, err
	}
	row := Row{
		ID: id, TS: ts, ActorType: string(ev.ActorType), ActorID: ev.ActorID, Purpose: ev.Purpose,
		EntityType: ev.EntityType, EntityID: ev.EntityID, EventType: ev.EventType,
		Payload: canonical, PrevHash: prev,
	}
	hash, err := Hash(&row)
	if err != nil {
		return Recorded{}, err
	}
	err = q.InsertEvent(ctx, relational.InsertEventParams{
		ID: row.ID, Ts: row.TS, ActorType: row.ActorType, ActorID: row.ActorID, Purpose: row.Purpose,
		EntityType: row.EntityType, EntityID: row.EntityID, EventType: row.EventType,
		Payload: canonical, PrevHash: prev, Hash: hash,
	})
	if err != nil {
		return Recorded{}, fmt.Errorf("audit: insert: %w", err)
	}
	return Recorded{ID: id, TS: ts, PrevHash: prev, Hash: hash}, nil
}

// prevHash is the hash the next row of month links to: the month's last
// row, or for the month's first row the last row before it in an
// earlier month (taking that month's lock too, so a writer still
// finishing it is waited for), or GenesisHash.
func prevHash(ctx context.Context, q *relational.Queries, month time.Time) (string, error) {
	last, err := q.LastEventInRange(ctx, relational.LastEventInRangeParams{FromTs: month, ToTs: month.AddDate(0, 1, 0)})
	if err == nil {
		return last.Hash, nil
	}
	if !isNoRows(err) {
		return "", fmt.Errorf("audit: last hash: %w", err)
	}
	if err := q.AdvisoryXactLock(ctx, relational.LockKey(monthLockName(month.AddDate(0, -1, 0)))); err != nil {
		return "", fmt.Errorf("audit: previous month lock: %w", err)
	}
	before, err := q.LastEventBefore(ctx, relational.LastEventBeforeParams{BeforeTs: month, BeforeID: maxID})
	if isNoRows(err) {
		return GenesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: previous month hash: %w", err)
	}
	return before.Hash, nil
}

// maxID bounds "written before" when the new row has no id yet.
const maxID = int64(^uint64(0) >> 1)

func rowFrom(e *relational.Event) Row {
	return Row{
		ID: e.ID, TS: e.Ts, ActorType: e.ActorType, ActorID: e.ActorID, Purpose: e.Purpose,
		EntityType: e.EntityType, EntityID: e.EntityID, EventType: e.EventType,
		Payload: e.Payload, PrevHash: e.PrevHash, Hash: e.Hash,
	}
}
