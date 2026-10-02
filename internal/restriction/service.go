package restriction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/geoid"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// ErrNotFound is a restriction, version or request that does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is a write that lost a race to another (the version moved
// between the read and the update); the caller retries the request.
var ErrConflict = errors.New("the restriction changed concurrently")

// ListFilter selects restrictions for GET /v1/restrictions.
type ListFilter struct {
	State *State
	At    *time.Time
	// BBox is west, south, east, north (west > east crosses the
	// antimeridian).
	BBox  *[4]float64
	Limit int
}

// Idempotency is the console's Idempotency-Key of a plan, per account.
type Idempotency struct {
	ActorID string
	Key     string
	SHA256  string
}

// Repo is the restrictions store (internal/store implements it on the
// relational database). Reads outside a transaction; every write in Tx.
type Repo interface {
	Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
	Get(ctx context.Context, id string) (Restriction, error)
	List(ctx context.Context, f ListFilter) ([]Restriction, bool, error)
	Versions(ctx context.Context, id string, limit int) ([]Version, error)
	Version(ctx context.Context, id string, version int64) (Version, error)
	Request(ctx context.Context, id string) (Request, error)
	// DueActivations and DueExpiries are judged on the database's clock.
	DueActivations(ctx context.Context, limit int) ([]string, error)
	DueExpiries(ctx context.Context, limit int) ([]string, error)
	// Unpublished is the versions not yet on the bus, oldest first.
	Unpublished(ctx context.Context, limit int) ([]Version, error)
	MarkPublished(ctx context.Context, id string, version int64) error
}

// Tx is one transaction of the restrictions store.
type Tx interface {
	Measurer
	// Now is the database's clock.
	Now(ctx context.Context) (time.Time, error)
	Policy(ctx context.Context) (policy.Policy, error)
	// MintIdentifier draws the next identifier (D4) from the sequence.
	MintIdentifier(ctx context.Context) (string, error)
	ByIdempotency(ctx context.Context, actorID, key string) (id, sha string, found bool, err error)
	Insert(ctx context.Context, r Restriction, idem *Idempotency) error
	// Lock reads a restriction FOR UPDATE.
	Lock(ctx context.Context, id string) (Restriction, error)
	// Update writes r if the stored version is still prev (ErrConflict
	// otherwise).
	Update(ctx context.Context, prev int64, r Restriction) error
	InsertVersion(ctx context.Context, v Version) error
	Audit(ctx context.Context, ev audit.Event) error
	// Successor is the planned re-issue that continues id, if any.
	Successor(ctx context.Context, id string) (string, bool, error)
	RequestByClientRef(ctx context.Context, requester, ref string) (Request, bool, error)
	CountOpenRequests(ctx context.Context, requester string) (int64, error)
	InsertRequest(ctx context.Context, q Request) error
	LockRequest(ctx context.Context, id string) (Request, error)
	DecideRequest(ctx context.Context, q Request) error
}

// Publisher puts a version on the bus (JetStream, subject Subject(v),
// message id DedupeID(v)).
type Publisher interface {
	Publish(ctx context.Context, subject, dedupeID string, data []byte) error
}

// Counters of the service (E-09).
const (
	CounterPlanned              = "restriction_planned"
	CounterTransitions          = "restriction_transitions"
	CounterRefused              = "restriction_refused"
	CounterScheduled            = "restriction_activation_scheduled"
	CounterScheduledActivations = "restriction_scheduled_activations"
	CounterActivationLate       = "restriction_activation_late"
	CounterExpiries             = "restriction_expiries"
	CounterTickFailed           = "restriction_tick_failed"
	CounterBusPublished         = "restriction_bus_published"
	CounterBusFailed            = "restriction_bus_publish_failed"
	CounterBusRepublished       = "restriction_bus_republished"
	CounterReissued             = "restriction_reissued"
	CounterRequests             = "restriction_requests_received"
	CounterRequestsRefused      = "restriction_requests_refused"
	CounterIdempotentReplays    = "restriction_idempotent_replays"
)

// MaxOpenRequests bounds the received (undecided) requests one requester
// may hold (E-10); past it a request is refused 429.
const MaxOpenRequests = 100

// MaxTickBatch bounds the activations, expiries or republished versions
// one tick handles; the rest wait for the next.
const MaxTickBatch = 100

// Service is the restriction state machine with its store, the CIS
// projection, the geoid and the bus.
type Service struct {
	Repo      Repo
	Airspaces Airspaces
	// Geoid makes AMSL limits HAE for the F3548 volumes; nil refuses
	// AMSL restrictions with geoid_unavailable (counted).
	Geoid geoid.Undulator
	// Bus publishes restr.v1; nil leaves every version unpublished, and
	// counted, until a bus is there (Tick republishes).
	Bus Publisher
	// Local is told every version committed by this process, as the
	// published message (the console stream); may be nil.
	Local func(v Version, msg []byte)
	// Feature is the zone authority; the country is the policy's.
	Feature FeatureConfig
	// ClientID prefixes ansp_ref ("ansp-01:<id>").
	ClientID string
	// Producer is the envelope producer ("ansp/api").
	Producer string

	counters core.Counters
}

// Counters are the service's counters.
func (s *Service) Counters() *core.Counters { return &s.counters }

// PlanOptions are the plan's request-level options.
type PlanOptions struct {
	Idempotency  *Idempotency
	ConfirmChain bool
	RequestID    *string
}

// Plan plans a restriction (state planned), or, with a window longer
// than MaxDuration and ConfirmChain, the chain of linked re-issues
// (the first is returned). With an Idempotency-Key it is idempotent per
// account: the same key and body answer the restriction first created
// (replay true), another body under the key is 409.
func (s *Service) Plan(ctx context.Context, actor Actor, in Input, opt PlanOptions) (Restriction, bool, error) {
	var first string
	var replay bool
	var pub []Version
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		pub = nil
		if opt.Idempotency != nil {
			id, sha, found, err := tx.ByIdempotency(ctx, opt.Idempotency.ActorID, opt.Idempotency.Key)
			if err != nil {
				return err
			}
			if found {
				if sha != opt.Idempotency.SHA256 {
					return refuse(409, SlugIdempotency, "this Idempotency-Key was used with another body",
						core.Fieldf("Idempotency-Key", "was used for restriction %s with another body; a new restriction needs a new key", id))
				}
				first, replay = id, true
				return nil
			}
		}
		id, vs, err := s.plan(ctx, tx, actor, in, opt)
		first, pub = id, vs
		return err
	})
	if err != nil {
		s.countRefusal(err)
		return Restriction{}, false, err
	}
	if replay {
		s.counters.Inc(CounterIdempotentReplays)
	}
	s.publish(ctx, pub, false)
	r, err := s.Repo.Get(ctx, first)
	return r, replay, err
}

// plan is Plan inside tx: validation, placement, the chain, the rows,
// the versions and the events. It returns the first restriction's id
// and the versions to publish after the commit.
func (s *Service) plan(ctx context.Context, tx Tx, actor Actor, in Input, opt PlanOptions) (string, []Version, error) {
	now, pol, err := s.clock(ctx, tx)
	if err != nil {
		return "", nil, err
	}
	if in.ZoneType == "" {
		in.ZoneType = core.ZoneType(pol.DefaultZoneType)
	}
	chain, errs := Validate(in, now)
	if len(errs) > 0 {
		return "", nil, invalid(errs...)
	}
	if len(chain) > 0 && !opt.ConfirmChain {
		fields := make([]*core.FieldError, 0, len(chain))
		for i, w := range chain {
			fields = append(fields, core.Fieldf(fmt.Sprintf("chain[%d]", i), "%s", w.String()))
		}
		return "", nil, refuse(400, SlugChainRequired,
			fmt.Sprintf("the window is longer than F3548 CstrMaxDurationHours (%v); it would be planned as %d linked re-issues: send confirm_chain true to plan them", MaxDuration, len(chain)),
			fields...)
	}
	snap, serr := s.Airspaces.Current(ctx)
	if _, err := cisAge(snap, serr, now, pol.CISStaleBoundS); err != nil {
		return "", nil, err
	}
	airspace, err := Place(ctx, in, snap, tx)
	if err != nil {
		return "", nil, err
	}
	area, err := tx.AreaM2(ctx, in.Shape)
	if err != nil {
		return "", nil, err
	}
	if area > MaxAreaM2 {
		return "", nil, invalid(core.Fieldf("geometry", "covers %.1f km2; at most %d km2 (F3548 CstrMaxAreaKm2)", area/1e6, int(MaxAreaM2/1e6)))
	}
	windows := chain
	if len(windows) == 0 {
		windows = []Window{{StartsAt: in.StartsAt, EndsAt: in.EndsAt}}
	}
	var first string
	var prev *string
	var pub []Version
	for i, w := range windows {
		r, v, err := s.newRestriction(ctx, tx, actor, in, w, airspace, snap.Version, pol, now, prev, opt.RequestID)
		if err != nil {
			return "", nil, err
		}
		var idem *Idempotency
		if i == 0 {
			first, idem = r.ID, opt.Idempotency
		}
		if err := tx.Insert(ctx, r, idem); err != nil {
			return "", nil, err
		}
		if err := tx.InsertVersion(ctx, v); err != nil {
			return "", nil, err
		}
		reason := "planned: " + in.ReasonText
		if i > 0 {
			reason = fmt.Sprintf("re-issue %d of the chain of %s", i, first)
		}
		if err := s.audit(ctx, tx, actor, r.ID, OpPlan, reason, nil, &r); err != nil {
			return "", nil, err
		}
		pub = append(pub, v)
		id := r.ID
		prev = &id
	}
	s.counters.Add(CounterPlanned, uint64(len(windows)))
	return first, pub, nil
}

// newRestriction is a planned restriction for w and its first version.
func (s *Service) newRestriction(ctx context.Context, tx Tx, actor Actor, in Input, w Window, airspace, cisVersion string,
	pol policy.Policy, now time.Time, supersedes, requestID *string,
) (Restriction, Version, error) {
	ident, err := tx.MintIdentifier(ctx)
	if err != nil {
		return Restriction{}, Version{}, err
	}
	id := NewULID(now)
	cv := cisVersion
	r := Restriction{
		ID: id, AnspRef: s.anspRef(id), Identifier: ident, UspaceAirspaceID: airspace, ZoneType: in.ZoneType,
		Shape: in.Shape, LowerM: in.LowerM, LowerRef: in.LowerRef, UpperM: in.UpperM, UpperRef: in.UpperRef,
		StartsAt: w.StartsAt.UTC(), EndsAt: w.EndsAt.UTC(), ReasonText: in.ReasonText, State: StatePlanned, AnspVersion: 1,
		CreatedBy: actor.Role, CreatedAt: now, RequestID: requestID, SupersedesID: supersedes,
		DSSConstraintID: uuid.NewString(), CISVersion: &cv,
	}
	f, err := Feature(r, s.featureConfig(pol))
	if err != nil {
		return Restriction{}, Version{}, err
	}
	raw, err := CheckFeature(f)
	if err != nil {
		return Restriction{}, Version{}, err
	}
	cons, err := s.constraint(r, f, true)
	if err != nil {
		return Restriction{}, Version{}, err
	}
	r.Feature, r.Constraint = raw, cons
	return r, s.version(r, actor, now, "planned: "+in.ReasonText), nil
}

func (s *Service) anspRef(id string) string {
	if s.ClientID == "" {
		return id
	}
	return s.ClientID + ":" + id
}

func (s *Service) featureConfig(pol policy.Policy) FeatureConfig {
	c := s.Feature
	c.Country = pol.Country
	return c
}

// constraint is the stored constraint document of r. With strict, a
// geoid that cannot answer refuses (503 geoid_unavailable); otherwise
// (end, cancel, expire: the restriction is going away) the version is
// written without one.
func (s *Service) constraint(r Restriction, f *ed318.Feature, strict bool) (json.RawMessage, error) {
	sc, err := Details(r, f, s.Geoid, &s.counters)
	if errors.Is(err, ErrGeoidUnavailable) {
		if !strict {
			return nil, nil
		}
		return nil, &Refusal{Status: 503, Slug: SlugGeoidUnavailable,
			Detail: "the geoid is not configured or cannot answer (ANSP_GEOID_FILE); an AMSL limit cannot be made W84 for the F3548 constraint, and a wrong altitude is never written", RetryAfter: 60 * time.Second}
	}
	if err != nil {
		if !strict {
			return nil, nil
		}
		return nil, err
	}
	return json.Marshal(sc)
}

func (s *Service) version(r Restriction, actor Actor, now time.Time, reason string) Version {
	return Version{
		RestrictionID: r.ID, Version: r.AnspVersion, State: r.State, StartsAt: r.StartsAt, EndsAt: r.EndsAt,
		MsgID: NewULID(now), Feature: r.Feature, Constraint: r.Constraint, ChangedBy: actor.Role, ChangedAt: now,
		ChangeReason: reason, AnspRef: r.AnspRef,
	}
}

// clock is the database's now, to the millisecond, and the policy.
func (s *Service) clock(ctx context.Context, tx Tx) (time.Time, policy.Policy, error) {
	now, err := tx.Now(ctx)
	if err != nil {
		return time.Time{}, policy.Policy{}, err
	}
	pol, err := tx.Policy(ctx)
	if err != nil {
		return time.Time{}, policy.Policy{}, err
	}
	return now.UTC().Truncate(time.Millisecond), pol, nil
}

// Apply runs op on restriction id by actor with reason (the N4 record).
// newEnd is an extend's new ends_at. An extend beyond MaxDuration from
// starts_at plans a linked re-issue from the current ends_at to newEnd
// and returns it.
func (s *Service) Apply(ctx context.Context, actor Actor, id string, op Op, reason string, newEnd *time.Time) (Restriction, error) {
	var out string
	var pub []Version
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		out, pub, err = s.apply(ctx, tx, actor, id, op, reason, newEnd)
		return err
	})
	if err != nil {
		s.countRefusal(err)
		return Restriction{}, err
	}
	s.publish(ctx, pub, false)
	return s.Repo.Get(ctx, out)
}

func (s *Service) apply(ctx context.Context, tx Tx, actor Actor, id string, op Op, reason string, newEnd *time.Time) (string, []Version, error) {
	now, pol, err := s.clock(ctx, tx)
	if err != nil {
		return "", nil, err
	}
	r, err := tx.Lock(ctx, id)
	if err != nil {
		return "", nil, err
	}
	if op == OpExtend && newEnd != nil && NeedsReissue(r, now, *newEnd) {
		return s.reissue(ctx, tx, actor, r, *newEnd, reason, now, pol)
	}
	ch, err := Transition(r, op, now, actor, newEnd)
	if err != nil {
		return "", nil, transitionRefusal(err)
	}
	if !ch.Versioned {
		if err := tx.Update(ctx, r.AnspVersion, ch.Next); err != nil {
			return "", nil, err
		}
		s.counters.Inc(CounterScheduled)
		return r.ID, nil, s.auditEvent(ctx, tx, actor, r.ID, "restriction_activation_scheduled", reason, &r, &ch.Next)
	}
	next := ch.Next
	if op == OpExtend {
		prev, err := ParseFeature(r.Feature)
		if err != nil {
			return "", nil, err
		}
		f, err := WithEnd(prev, next.EndsAt)
		if err != nil {
			return "", nil, err
		}
		if next.Feature, err = CheckFeature(f); err != nil {
			return "", nil, err
		}
	}
	feat, err := ParseFeature(next.Feature)
	if err != nil {
		return "", nil, err
	}
	strict := op == OpActivate || op == OpExtend
	if next.Constraint, err = s.constraint(next, feat, strict); err != nil {
		return "", nil, err
	}
	if err := tx.Update(ctx, r.AnspVersion, next); err != nil {
		return "", nil, err
	}
	v := s.version(next, actor, now, reason)
	if err := tx.InsertVersion(ctx, v); err != nil {
		return "", nil, err
	}
	if err := s.audit(ctx, tx, actor, r.ID, op, reason, &r, &next); err != nil {
		return "", nil, err
	}
	s.counters.Inc(CounterTransitions)
	pub := []Version{v}
	if op == OpExpire {
		// A chain continues: the re-issue planned to start at this
		// restriction's ends_at is activated (or scheduled) now.
		succ, ok, err := tx.Successor(ctx, r.ID)
		if err != nil {
			return "", nil, err
		}
		if ok {
			_, more, err := s.apply(ctx, tx, SystemActor, succ, OpActivate, "the chain continues: "+r.ID+" expired at its ends_at", nil)
			if err != nil {
				return "", nil, err
			}
			pub = append(pub, more...)
		}
	}
	return r.ID, pub, nil
}

// reissue plans the linked re-issue of an extend past MaxDuration.
func (s *Service) reissue(ctx context.Context, tx Tx, actor Actor, r Restriction, newEnd time.Time, reason string, now time.Time, pol policy.Policy) (string, []Version, error) {
	w := Window{StartsAt: r.EndsAt, EndsAt: newEnd.UTC()}
	if w.EndsAt.Sub(w.StartsAt) > MaxDuration {
		return "", nil, invalid(core.Fieldf("ends_at", "%s is more than F3548 CstrMaxDurationHours after the current ends_at %s; extend in steps of at most %v", stamp(w.EndsAt), stamp(w.StartsAt), MaxDuration))
	}
	if _, errs := windowErrors(w.StartsAt, w.EndsAt, now); len(errs) > 0 {
		return "", nil, invalid(errs...)
	}
	in := Input{UspaceAirspaceID: r.UspaceAirspaceID, ZoneType: r.ZoneType, Shape: r.Shape, LowerM: r.LowerM, LowerRef: r.LowerRef,
		UpperM: r.UpperM, UpperRef: r.UpperRef, StartsAt: w.StartsAt, EndsAt: w.EndsAt, ReasonText: r.ReasonText}
	snap, serr := s.Airspaces.Current(ctx)
	if _, err := cisAge(snap, serr, now, pol.CISStaleBoundS); err != nil {
		return "", nil, err
	}
	airspace, err := Place(ctx, in, snap, tx)
	if err != nil {
		return "", nil, err
	}
	id := r.ID
	n, v, err := s.newRestriction(ctx, tx, actor, in, w, airspace, snap.Version, pol, now, &id, r.RequestID)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Insert(ctx, n, nil); err != nil {
		return "", nil, err
	}
	if err := tx.InsertVersion(ctx, v); err != nil {
		return "", nil, err
	}
	if err := s.audit(ctx, tx, actor, n.ID, OpPlan, "re-issue of "+r.ID+" to extend it: "+reason, nil, &n); err != nil {
		return "", nil, err
	}
	if err := s.auditEvent(ctx, tx, actor, r.ID, "restriction_reissued", reason+" (continued by "+n.ID+")", &r, &r); err != nil {
		return "", nil, err
	}
	s.counters.Inc(CounterReissued)
	return n.ID, []Version{v}, nil
}

func transitionRefusal(err error) error {
	var te *TransitionError
	if errors.As(err, &te) {
		return refuse(409, SlugIllegalTransition, te.Error(), core.Fieldf("state", "is %s; %s", te.From, te.Error()))
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return invalid(fe)
	}
	return err
}

// auditSummary is what an event records of a restriction (before and
// after): who, why, when and until when (N4), never the geometry twice.
type auditSummary struct {
	State       State     `json:"state"`
	AnspVersion int64     `json:"ansp_version"`
	StartsAt    string    `json:"starts_at"`
	EndsAt      string    `json:"ends_at"`
	ActivateAt  *string   `json:"activate_at,omitempty"`
	Identifier  string    `json:"identifier"`
	Airspace    string    `json:"uspace_airspace_id"`
	ZoneType    string    `json:"zone_type"`
	Limits      [2]string `json:"limits"`
}

func summary(r *Restriction) *auditSummary {
	if r == nil {
		return nil
	}
	out := &auditSummary{State: r.State, AnspVersion: r.AnspVersion, StartsAt: stamp(r.StartsAt), EndsAt: stamp(r.EndsAt),
		Identifier: r.Identifier, Airspace: r.UspaceAirspaceID, ZoneType: string(r.ZoneType),
		Limits: [2]string{fmt.Sprintf("%v m %s", r.LowerM, r.LowerRef), fmt.Sprintf("%v m %s", r.UpperM, r.UpperRef)}}
	if r.ActivateAt != nil {
		a := stamp(*r.ActivateAt)
		out.ActivateAt = &a
	}
	return out
}

func (s *Service) audit(ctx context.Context, tx Tx, actor Actor, id string, op Op, reason string, before, after *Restriction) error {
	return s.auditEvent(ctx, tx, actor, id, op.EventType(), reason, before, after)
}

func (s *Service) auditEvent(ctx context.Context, tx Tx, actor Actor, id, event, reason string, before, after *Restriction) error {
	return tx.Audit(ctx, audit.Event{
		ActorType: audit.ActorType(actor.Type), ActorID: actor.ID, Purpose: cutRunes("dynamic airspace reconfiguration (N1, N4): "+reason, audit.MaxPurposeBytes/4),
		EntityType: "restriction", EntityID: id, EventType: event,
		Payload: map[string]any{"reason": reason, "role": actor.Role, "before": summary(before), "after": summary(after)},
	})
}

// publish puts each version on the bus and tells Local. A failure is
// counted and left for Tick to republish: the row says the version is
// not on the bus yet (bus_version), so nothing is lost.
func (s *Service) publish(ctx context.Context, vs []Version, backlog bool) {
	for i := range vs {
		v := vs[i]
		msg, err := StateMessage(v, s.Producer, backlog)
		if err != nil {
			s.counters.Inc(CounterBusFailed)
			continue
		}
		if s.Local != nil && !backlog {
			s.Local(v, msg)
		}
		if s.Bus == nil {
			s.counters.Inc(CounterBusFailed)
			continue
		}
		if err := s.Bus.Publish(ctx, Subject(v), DedupeID(v), msg); err != nil {
			s.counters.Inc(CounterBusFailed)
			continue
		}
		if err := s.Repo.MarkPublished(ctx, v.RestrictionID, v.Version); err != nil {
			s.counters.Inc(CounterBusFailed)
			continue
		}
		if backlog {
			s.counters.Inc(CounterBusRepublished)
		} else {
			s.counters.Inc(CounterBusPublished)
		}
	}
}

func (s *Service) countRefusal(err error) {
	var r *Refusal
	if errors.As(err, &r) {
		s.counters.Inc(CounterRefused)
	}
}

// TickReport is what one Tick did.
type TickReport struct {
	Activated, Expired, Republished, Failed int
	// MaxActivationLagS is the largest delay between a starts_at and its
	// activation in this tick.
	MaxActivationLagS float64
	// Unpublished is the versions still not on the bus after the tick.
	Unpublished int
}

// Tick activates the scheduled restrictions whose starts_at has come and
// expires the active ones whose ends_at has passed (both on the
// database's clock), then republishes versions the bus did not take. An
// activation later than late after its starts_at is counted
// (CounterActivationLate). Failures are counted and retried next tick.
func (s *Service) Tick(ctx context.Context, late time.Duration) (TickReport, error) {
	var rep TickReport
	var errs []error
	due, err := s.Repo.DueActivations(ctx, MaxTickBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, id := range due {
		r, err := s.Apply(ctx, SystemActor, id, OpActivate, "scheduled activation at starts_at", nil)
		if err != nil {
			rep.Failed++
			s.counters.Inc(CounterTickFailed)
			errs = append(errs, fmt.Errorf("activate %s: %w", id, err))
			continue
		}
		rep.Activated++
		s.counters.Inc(CounterScheduledActivations)
		if r.ActivatedAt != nil {
			lag := r.ActivatedAt.Sub(r.StartsAt)
			rep.MaxActivationLagS = max(rep.MaxActivationLagS, lag.Seconds())
			if lag > late {
				s.counters.Inc(CounterActivationLate)
			}
		}
	}
	exp, err := s.Repo.DueExpiries(ctx, MaxTickBatch)
	if err != nil {
		errs = append(errs, err)
	}
	for _, id := range exp {
		if _, err := s.Apply(ctx, SystemActor, id, OpExpire, "expired at ends_at", nil); err != nil {
			rep.Failed++
			s.counters.Inc(CounterTickFailed)
			errs = append(errs, fmt.Errorf("expire %s: %w", id, err))
			continue
		}
		rep.Expired++
		s.counters.Inc(CounterExpiries)
	}
	if s.Bus != nil {
		vs, err := s.Repo.Unpublished(ctx, MaxTickBatch)
		if err != nil {
			errs = append(errs, err)
		}
		before := s.counters.Get(CounterBusRepublished)
		s.publish(ctx, vs, true)
		rep.Republished = int(s.counters.Get(CounterBusRepublished) - before)
	}
	if left, err := s.Repo.Unpublished(ctx, MaxTickBatch); err == nil {
		rep.Unpublished = len(left)
	}
	return rep, errors.Join(errs...)
}

// Get is one restriction.
func (s *Service) Get(ctx context.Context, id string) (Restriction, error) {
	return s.Repo.Get(ctx, id)
}

// List is the restrictions matching f, newest first, and whether more
// existed than f.Limit.
func (s *Service) List(ctx context.Context, f ListFilter) ([]Restriction, bool, error) {
	return s.Repo.List(ctx, f)
}

// Versions is every version of id, oldest first (ErrNotFound when id
// does not exist).
func (s *Service) Versions(ctx context.Context, id string, limit int) ([]Version, error) {
	if _, err := s.Repo.Get(ctx, id); err != nil {
		return nil, err
	}
	return s.Repo.Versions(ctx, id, limit)
}

// Version is one version.
func (s *Service) Version(ctx context.Context, id string, v int64) (Version, error) {
	return s.Repo.Version(ctx, id, v)
}

// Snapshot is the current state message of every active and planned
// restriction (the console stream's snapshot), at most limit of each
// state; truncated says more existed (the stream says so, never hides
// it).
func (s *Service) Snapshot(ctx context.Context, limit int) (msgs [][]byte, truncated bool, err error) {
	for _, st := range []State{StateActive, StatePlanned} {
		state := st
		rs, more, err := s.Repo.List(ctx, ListFilter{State: &state, Limit: limit})
		if err != nil {
			return nil, false, err
		}
		truncated = truncated || more
		for i := range rs {
			v, err := s.Repo.Version(ctx, rs[i].ID, rs[i].AnspVersion)
			if err != nil {
				return nil, false, err
			}
			msg, err := StateMessage(v, s.Producer, false)
			if err != nil {
				return nil, false, err
			}
			msgs = append(msgs, msg)
		}
	}
	return msgs, truncated, nil
}

// Hash is the SHA-256 of a body, hex: the idempotency comparison.
func Hash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CreateRequest records a restriction request (F11) as received. The
// requester's client_ref makes it idempotent: the same ref and body
// answer the first request (replay true), another body is 409. A
// requester holds at most MaxOpenRequests undecided requests.
func (s *Service) CreateRequest(ctx context.Context, actor Actor, requester, source, clientRef string, payload []byte) (Request, bool, error) {
	var out Request
	var replay bool
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		sha := Hash(payload)
		q, found, err := tx.RequestByClientRef(ctx, requester, clientRef)
		if err != nil {
			return err
		}
		if found {
			if q.PayloadSHA256 != sha {
				return refuse(409, SlugIdempotency, "this client_ref was used with another body",
					core.Fieldf("client_ref", "was used for request %s with another body", q.ID))
			}
			out, replay = q, true
			return nil
		}
		n, err := tx.CountOpenRequests(ctx, requester)
		if err != nil {
			return err
		}
		if n >= MaxOpenRequests {
			return &Refusal{Status: 429, Slug: SlugTooManyRequests, Detail: fmt.Sprintf("the requester holds %d undecided requests; at most %d", n, MaxOpenRequests), RetryAfter: 60 * time.Second}
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		out = Request{ID: NewULID(now), Requester: requester, Source: source, ClientRef: clientRef, Payload: payload,
			PayloadSHA256: sha, ReceivedAt: now.UTC().Truncate(time.Millisecond), State: RequestReceived}
		if err := tx.InsertRequest(ctx, out); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorType(actor.Type), ActorID: actor.ID, Purpose: "restriction request received (F11)",
			EntityType: "restriction_request", EntityID: out.ID, EventType: "restriction_request_received",
			Payload: map[string]any{"requester": requester, "source": source, "client_ref": clientRef}})
	})
	if err != nil {
		s.counters.Inc(CounterRequestsRefused)
		return Request{}, false, err
	}
	if !replay {
		s.counters.Inc(CounterRequests)
	}
	return out, replay, nil
}

// Request is one restriction request.
func (s *Service) Request(ctx context.Context, id string) (Request, error) {
	return s.Repo.Request(ctx, id)
}

// Accept accepts a received request and plans the restriction it asks
// for, in one transaction: a refused plan leaves the request received.
// zoneType overrides the policy default when given.
func (s *Service) Accept(ctx context.Context, actor Actor, id string, zoneType core.ZoneType, reason string) (Request, error) {
	var out Request
	var pub []Version
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		pub = nil
		q, err := tx.LockRequest(ctx, id)
		if err != nil {
			return err
		}
		if q.State != RequestReceived {
			return refuse(409, SlugRequestDecided, "the request was decided already", core.Fieldf("state", "is %s", q.State))
		}
		_, in, errs := DecodeArea(q.Payload, BodyRequest)
		if len(errs) > 0 {
			return invalid(errs...)
		}
		in.ZoneType = zoneType
		rid := q.ID
		first, vs, err := s.plan(ctx, tx, actor, in, PlanOptions{RequestID: &rid})
		if err != nil {
			return err
		}
		pub = vs
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		role, at := actor.Role, now.UTC().Truncate(time.Millisecond)
		q.State, q.DecidedBy, q.DecidedAt, q.DecisionReason, q.RestrictionID = RequestAccepted, &role, &at, &reason, &first
		if err := tx.DecideRequest(ctx, q); err != nil {
			return err
		}
		out = q
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorType(actor.Type), ActorID: actor.ID, Purpose: cutRunes("restriction request accepted (F11): "+reason, 250),
			EntityType: "restriction_request", EntityID: q.ID, EventType: "restriction_request_accepted",
			Payload: map[string]any{"restriction_id": first, "reason": reason, "role": actor.Role}})
	})
	if err != nil {
		s.countRefusal(err)
		return Request{}, err
	}
	s.publish(ctx, pub, false)
	return out, nil
}

// Decline declines a received request with reason.
func (s *Service) Decline(ctx context.Context, actor Actor, id, reason string) (Request, error) {
	var out Request
	err := s.Repo.Tx(ctx, func(ctx context.Context, tx Tx) error {
		q, err := tx.LockRequest(ctx, id)
		if err != nil {
			return err
		}
		if q.State != RequestReceived {
			return refuse(409, SlugRequestDecided, "the request was decided already", core.Fieldf("state", "is %s", q.State))
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		role, at := actor.Role, now.UTC().Truncate(time.Millisecond)
		q.State, q.DecidedBy, q.DecidedAt, q.DecisionReason = RequestDeclined, &role, &at, &reason
		if err := tx.DecideRequest(ctx, q); err != nil {
			return err
		}
		out = q
		return tx.Audit(ctx, audit.Event{ActorType: audit.ActorType(actor.Type), ActorID: actor.ID, Purpose: cutRunes("restriction request declined (F11): "+reason, 250),
			EntityType: "restriction_request", EntityID: q.ID, EventType: "restriction_request_declined",
			Payload: map[string]any{"reason": reason, "role": actor.Role}})
	})
	if err != nil {
		s.countRefusal(err)
	}
	return out, err
}
