package restriction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

var supervisor = Actor{Type: "user", ID: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z", Role: "watch_supervisor"}

// box is a polygon inside the fixture U-space airspace.
func box() Shape {
	return Shape{Ring: []core.LatLon{
		{LatDeg: 41.70, LonDeg: 44.78}, {LatDeg: 41.70, LonDeg: 44.82}, {LatDeg: 41.73, LonDeg: 44.82}, {LatDeg: 41.73, LonDeg: 44.78}, {LatDeg: 41.70, LonDeg: 44.78},
	}}
}

func input(start, end time.Time) Input {
	return Input{UspaceAirspaceID: "GEOTU01", ZoneType: core.ZoneProhibited, Shape: box(), LowerM: 0, LowerRef: RefAMSL,
		UpperM: 120, UpperRef: RefAMSL, StartsAt: start, EndsAt: end, ReasonText: "Search and rescue (synthetic)"}
}

type fixture struct {
	repo *memRepo
	bus  *memBus
	svc  *Service
	seen []Version
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{repo: newMemRepo(t0), bus: &memBus{}}
	f.svc = &Service{
		Repo: f.repo, Bus: f.bus, Geoid: gridGeoid{}, ClientID: "ansp-01", Producer: "ansp/api",
		Airspaces: staticAirspaces{snap: Snapshot{Version: "42", FetchedAt: t0.Add(-10 * time.Second), Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefAMSL)}}},
		Feature:   FeatureConfig{AuthorityName: "Test ANSP", AuthorityService: "Watch", AuthorityEmail: "watch@example.test", AuthorityPhone: "+995000000"},
	}
	f.svc.Local = func(v Version, _ []byte) { f.seen = append(f.seen, v) }
	return f
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
	return r
}

func hasField(r *Refusal, field, reason string) bool {
	for _, f := range r.Fields {
		if f.Field == field && strings.Contains(f.Reason, reason) {
			return true
		}
	}
	return false
}

// The done-when lifecycle: planned, activated, extended and ended leave
// four versions, four events and four restr.v1 messages, in order, each
// version's feature the same but for the extend's endDateTime.
func TestLifecyclePlanActivateExtendEnd(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, replay, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(4*time.Hour)), PlanOptions{})
	if err != nil || replay {
		t.Fatalf("plan: %v %v", replay, err)
	}
	if r.State != StatePlanned || r.AnspVersion != 1 || !ValidIdentifier(r.Identifier) || r.AnspRef != "ansp-01:"+r.ID || r.UspaceAirspaceID != "GEOTU01" {
		t.Fatalf("planned: %+v", r)
	}
	if r, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "rescue helicopter on scene", nil); err != nil || r.State != StateActive || r.AnspVersion != 2 {
		t.Fatalf("activate: %+v %v", r, err)
	}
	f.repo.advance(time.Hour)
	end := t0.Add(6 * time.Hour)
	if r, err = f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "operation continues", &end); err != nil || r.AnspVersion != 3 || !r.EndsAt.Equal(end) {
		t.Fatalf("extend: %+v %v", r, err)
	}
	f.repo.advance(time.Hour)
	if r, err = f.svc.Apply(ctx, supervisor, r.ID, OpEnd, "rescue completed", nil); err != nil || r.State != StateEnded || r.AnspVersion != 4 || !r.EndsAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("end: %+v %v", r, err)
	}
	vs, _ := f.svc.Versions(ctx, r.ID, 10)
	if len(vs) != 4 {
		t.Fatalf("%d versions", len(vs))
	}
	var states []State
	for i, v := range vs {
		states = append(states, v.State)
		if v.Version != int64(i+1) || v.ChangedBy != "watch_supervisor" || v.MsgID == "" {
			t.Fatalf("version %d: %+v", i, v)
		}
	}
	if !slices.Equal(states, []State{StatePlanned, StateActive, StateActive, StateEnded}) {
		t.Fatalf("states %v", states)
	}
	var events []string
	for _, e := range f.repo.events {
		events = append(events, e.EventType)
		if e.ActorID != supervisor.ID || e.ActorType != "user" || e.EntityID != r.ID {
			t.Fatalf("event %+v", e)
		}
	}
	if !slices.Equal(events, []string{"restriction_plan", "restriction_activate", "restriction_extend", "restriction_end"}) {
		t.Fatalf("events %v", events)
	}
	if got := f.bus.subjects(); !slices.Equal(got, []string{"restr.v1.planned", "restr.v1.active", "restr.v1.active", "restr.v1.ended"}) {
		t.Fatalf("bus %v", got)
	}
	if len(f.seen) != 4 {
		t.Fatalf("local %d", len(f.seen))
	}
	// The feature never changes but for the extend's endDateTime.
	if !jsonEqual(t, vs[0].Feature, vs[1].Feature) || !jsonEqual(t, vs[2].Feature, vs[3].Feature) || jsonEqual(t, vs[1].Feature, vs[2].Feature) {
		t.Fatal("feature changed outside the extend, or not at it")
	}
	if !sameExceptEnd(t, vs[1].Feature, vs[2].Feature) {
		t.Fatal("the extend changed more than endDateTime")
	}
	// Every version is on the bus: nothing to republish.
	if left, _ := f.repo.Unpublished(ctx, 10); len(left) != 0 {
		t.Fatalf("unpublished %d", len(left))
	}
	if f.svc.Counters().Get(CounterBusPublished) != 4 || f.svc.Counters().Get(CounterTransitions) != 3 {
		t.Fatalf("counters %v", f.svc.Counters().Snapshot())
	}
}

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return bytes.Equal(ja, jb)
}

// sameExceptEnd is the CISP's extend rule (uspace-cisp
// restriction.SameExceptEnd): equal once the period's endDateTime is
// taken from the stored feature.
func sameExceptEnd(t *testing.T, stored, published json.RawMessage) bool {
	t.Helper()
	var s, p map[string]any
	_ = json.Unmarshal(stored, &s)
	_ = json.Unmarshal(published, &p)
	sp := s["properties"].(map[string]any)["limitedApplicability"].([]any)[0].(map[string]any)
	pp := p["properties"].(map[string]any)["limitedApplicability"].([]any)[0].(map[string]any)
	pp["endDateTime"] = sp["endDateTime"]
	a, _ := json.Marshal(s)
	b, _ := json.Marshal(p)
	return bytes.Equal(a, b)
}

// Every illegal transition is a 409 naming both states; the legal one
// from the same state is the presence pair (E-01).
func TestIllegalTransitionsRefused(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		state State
		bad   []Op
	}{
		{StatePlanned, []Op{OpExtend, OpEnd, OpExpire}},
		{StateActive, []Op{OpActivate, OpCancel}},
		{StateEnded, []Op{OpActivate, OpCancel, OpExtend, OpEnd, OpExpire}},
		{StateCancelled, []Op{OpActivate, OpCancel, OpExtend, OpEnd, OpExpire}},
	} {
		f := newFixture(t)
		r, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(4*time.Hour)), PlanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		switch tc.state {
		case StatePlanned:
		case StateActive:
			_, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "go", nil)
		case StateEnded:
			_, _ = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "go", nil)
			_, err = f.svc.Apply(ctx, supervisor, r.ID, OpEnd, "stop", nil)
		case StateCancelled:
			_, err = f.svc.Apply(ctx, supervisor, r.ID, OpCancel, "error", nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		before := len(f.repo.versions[r.ID])
		for _, op := range tc.bad {
			end := t0.Add(5 * time.Hour)
			_, err := f.svc.Apply(ctx, supervisor, r.ID, op, "try", &end)
			rf := refusalOf(t, err)
			if rf.Status != 409 || rf.Slug != SlugIllegalTransition || !strings.Contains(rf.Detail, string(op)) || !strings.Contains(rf.Detail, string(tc.state)) {
				t.Fatalf("%s from %s: %+v", op, tc.state, rf)
			}
		}
		if len(f.repo.versions[r.ID]) != before {
			t.Fatalf("%s: a refused transition wrote a version", tc.state)
		}
	}
	// Presence: cancel from planned is legal and versioned.
	f := newFixture(t)
	r, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if r, err := f.svc.Apply(ctx, supervisor, r.ID, OpCancel, "planned in error", nil); err != nil || r.State != StateCancelled || r.AnspVersion != 2 || *r.CancelledBy != "watch_supervisor" {
		t.Fatalf("cancel: %+v %v", r, err)
	}
	if _, err := f.svc.Apply(ctx, supervisor, "01K6P0A1B2C3D4E5F6G7H8J9KM", OpEnd, "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

// An activation asked for before starts_at is scheduled (no version, an
// event, activate_at set) and the ticker activates it at starts_at on the
// database clock, versioned and published; then expires it at ends_at.
// The absence pair: before starts_at the tick activates nothing.
func TestScheduledActivationAndExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	start := t0.Add(30 * time.Minute)
	r, _, err := f.svc.Plan(ctx, supervisor, input(start, start.Add(time.Hour)), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "at the start", nil)
	if err != nil || r.State != StatePlanned || r.ActivateAt == nil || !r.ActivateAt.Equal(start) || r.AnspVersion != 1 {
		t.Fatalf("scheduled: %+v %v", r, err)
	}
	if f.repo.events[len(f.repo.events)-1].EventType != "restriction_activation_scheduled" || f.svc.Counters().Get(CounterScheduled) != 1 {
		t.Fatal("no scheduling event")
	}
	f.repo.advance(29 * time.Minute)
	if rep, err := f.svc.Tick(ctx, 2*time.Second); err != nil || rep.Activated != 0 {
		t.Fatalf("early tick: %+v %v", rep, err)
	}
	f.repo.advance(time.Minute + 500*time.Millisecond)
	rep, err := f.svc.Tick(ctx, 2*time.Second)
	if err != nil || rep.Activated != 1 || rep.MaxActivationLagS != 0.5 {
		t.Fatalf("tick at starts_at: %+v %v", rep, err)
	}
	r, _ = f.svc.Get(ctx, r.ID)
	if r.State != StateActive || r.AnspVersion != 2 || r.ActivateAt != nil || *r.ActivatedBy != "watch_supervisor" {
		t.Fatalf("activated: %+v", r)
	}
	if v, _ := f.svc.Version(ctx, r.ID, 2); v.ChangedBy != RoleSystem {
		t.Fatalf("changed_by %q", v.ChangedBy)
	}
	if f.svc.Counters().Get(CounterActivationLate) != 0 {
		t.Fatal("counted late")
	}
	f.repo.advance(time.Hour)
	if rep, err = f.svc.Tick(ctx, 2*time.Second); err != nil || rep.Expired != 1 {
		t.Fatalf("expiry: %+v %v", rep, err)
	}
	r, _ = f.svc.Get(ctx, r.ID)
	if r.State != StateEnded || r.AnspVersion != 3 || !r.EndedAtActual.Equal(start.Add(time.Hour)) || *r.EndedBy != RoleSystem {
		t.Fatalf("expired: %+v", r)
	}
	if got := f.bus.subjects(); !slices.Equal(got, []string{"restr.v1.planned", "restr.v1.active", "restr.v1.ended"}) {
		t.Fatalf("bus %v", got)
	}
}

// A tick long after starts_at counts the activation late.
func TestLateActivationCounted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	start := t0.Add(time.Minute)
	r, _, _ := f.svc.Plan(ctx, supervisor, input(start, start.Add(time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "at the start", nil)
	f.repo.advance(2 * time.Minute)
	if rep, err := f.svc.Tick(ctx, 2*time.Second); err != nil || rep.Activated != 1 || f.svc.Counters().Get(CounterActivationLate) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// Idempotency-Key: the same key and body answer the first restriction
// (replay, nothing new); another body under the key is 409.
func TestPlanIdempotency(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	key := &Idempotency{ActorID: supervisor.ID, Key: "console-7f3a9c", SHA256: Hash([]byte("body-1"))}
	a, replay, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{Idempotency: key})
	if err != nil || replay {
		t.Fatal(err)
	}
	b, replay, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{Idempotency: key})
	if err != nil || !replay || b.ID != a.ID || len(f.repo.rs) != 1 || len(f.bus.msgs) != 1 {
		t.Fatalf("replay: %v %v %d", replay, err, len(f.repo.rs))
	}
	other := *key
	other.SHA256 = Hash([]byte("body-2"))
	_, _, err = f.svc.Plan(ctx, supervisor, input(t0, t0.Add(2*time.Hour)), PlanOptions{Idempotency: &other})
	if rf := refusalOf(t, err); rf.Status != 409 || rf.Slug != SlugIdempotency || !hasField(rf, "Idempotency-Key", a.ID) {
		t.Fatalf("conflict: %+v", rf)
	}
	if f.svc.Counters().Get(CounterIdempotentReplays) != 1 {
		t.Fatal("replay not counted")
	}
}

// A window over CstrMaxDurationHours: without confirm_chain the plan is
// refused with the chain it would make (30 h: two re-issues); with it the
// chain is planned, linked, and the successor is activated when the first
// expires.
func TestChainProposalAndConfirm(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	in := input(t0, t0.Add(30*time.Hour))
	_, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{})
	rf := refusalOf(t, err)
	if rf.Slug != SlugChainRequired || len(rf.Fields) != 2 || rf.Fields[0].Field != "chain[0]" ||
		!strings.Contains(rf.Fields[1].Reason, Stamp(t0.Add(24*time.Hour))+" to "+Stamp(t0.Add(30*time.Hour))) {
		t.Fatalf("proposal: %+v", rf)
	}
	if len(f.repo.rs) != 0 {
		t.Fatal("a proposal stored something")
	}
	first, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{ConfirmChain: true})
	if err != nil || len(f.repo.rs) != 2 || !first.EndsAt.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("chain: %v %d", err, len(f.repo.rs))
	}
	var second Restriction
	for _, r := range f.repo.rs {
		if r.SupersedesID != nil {
			second = r
		}
	}
	if *second.SupersedesID != first.ID || !second.StartsAt.Equal(first.EndsAt) || second.Identifier == first.Identifier {
		t.Fatalf("second: %+v", second)
	}
	if _, err := f.svc.Apply(ctx, supervisor, first.ID, OpActivate, "go", nil); err != nil {
		t.Fatal(err)
	}
	f.repo.advance(24 * time.Hour)
	if rep, err := f.svc.Tick(ctx, 2*time.Second); err != nil || rep.Expired != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if s, _ := f.svc.Get(ctx, second.ID); s.State != StateActive {
		t.Fatalf("the chain did not continue: %+v", s)
	}
}

// An extend beyond 24 h from starts_at plans a linked re-issue from the
// current ends_at; one beyond a further 24 h is refused.
func TestExtendReissue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(20*time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "go", nil)
	end := t0.Add(30 * time.Hour)
	n, err := f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "longer", &end)
	if err != nil || n.ID == r.ID || n.SupersedesID == nil || *n.SupersedesID != r.ID || !n.StartsAt.Equal(t0.Add(20*time.Hour)) || !n.EndsAt.Equal(end) {
		t.Fatalf("reissue: %+v %v", n, err)
	}
	if again, _ := f.svc.Get(ctx, r.ID); again.AnspVersion != 2 || !again.EndsAt.Equal(t0.Add(20*time.Hour)) {
		t.Fatalf("the original changed: %+v", again)
	}
	if f.svc.Counters().Get(CounterReissued) != 1 {
		t.Fatal("not counted")
	}
	far := t0.Add(50 * time.Hour)
	_, err = f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "much longer", &far)
	if rf := refusalOf(t, err); rf.Slug != SlugInvalid || !hasField(rf, "ends_at", "in steps") {
		t.Fatalf("too far: %+v", rf)
	}
	// An extend that does not move ends_at later is refused.
	same := t0.Add(20 * time.Hour)
	if _, err := f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "same", &same); !hasField(refusalOf(t, err), "ends_at", "not after the current") {
		t.Fatal(err)
	}
}

// A failed publish leaves the version unpublished, counted; the tick
// republishes it as backlog (E-02: take the bus away, then give it back).
func TestBusFailureRepublished(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.bus.fail = true
	r, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if f.svc.Counters().Get(CounterBusFailed) != 1 || len(f.seen) != 1 {
		t.Fatalf("counters %v local %d", f.svc.Counters().Snapshot(), len(f.seen))
	}
	rep, _ := f.svc.Tick(ctx, time.Second)
	if rep.Republished != 0 || rep.Unpublished != 1 {
		t.Fatalf("still down: %+v", rep)
	}
	f.bus.fail = false
	rep, err = f.svc.Tick(ctx, time.Second)
	if err != nil || rep.Republished != 1 || rep.Unpublished != 0 || len(f.bus.msgs) != 1 {
		t.Fatalf("back: %+v %v", rep, err)
	}
	var env Envelope
	_ = json.Unmarshal(f.bus.msgs[0].data, &env)
	if !env.Backlog || f.bus.msgs[0].id != r.ID+".1" {
		t.Fatalf("republished %+v %s", env, f.bus.msgs[0].id)
	}
	// Without a bus at all every version is counted unpublished.
	f.svc.Bus = nil
	if _, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{}); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.svc.Tick(ctx, time.Second); rep.Unpublished != 1 {
		t.Fatalf("no bus: %+v", rep)
	}
}

// AMSL limits need the geoid: without it a plan and an activation are
// refused 503 geoid_unavailable and counted; an end still succeeds (a
// restriction is never kept alive by a missing geoid), without a
// constraint. A WGS84 restriction needs no geoid (the presence pair).
func TestGeoidUnavailable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "go", nil)
	f.svc.Geoid = nil
	_, _, err = f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if rf := refusalOf(t, err); rf.Status != 503 || rf.Slug != SlugGeoidUnavailable || rf.RetryAfter == 0 {
		t.Fatalf("%+v", rf)
	}
	if f.svc.Counters().Get(CounterGeoidUnavailable) == 0 {
		t.Fatal("not counted")
	}
	end := t0.Add(2 * time.Hour)
	if _, err := f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "longer", &end); refusalOf(t, err).Slug != SlugGeoidUnavailable {
		t.Fatal("extend without geoid")
	}
	ended, err := f.svc.Apply(ctx, supervisor, r.ID, OpEnd, "stop", nil)
	if err != nil || ended.State != StateEnded || ended.Constraint != nil {
		t.Fatalf("end without geoid: %+v %v", ended, err)
	}
	in := input(t0, t0.Add(time.Hour))
	in.LowerRef, in.UpperRef = RefWGS84, RefWGS84
	f.svc.Airspaces = staticAirspaces{snap: Snapshot{Version: "43", FetchedAt: t0, Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefWGS84)}}}
	if _, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{}); err != nil {
		t.Fatalf("WGS84 without geoid: %v", err)
	}
}

// The plan refusals that need the service: the CIS projection, area,
// policy default zone type, and a database clock failure.
func TestPlanRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.Airspaces = NoProjection{}
	_, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if rf := refusalOf(t, err); rf.Status != 503 || rf.Slug != SlugCISStale || !strings.Contains(rf.Detail, "no CIS projection") {
		t.Fatalf("no projection: %+v", rf)
	}
	f.svc.Airspaces = staticAirspaces{snap: Snapshot{Version: "41", FetchedAt: t0.Add(-301 * time.Second), Airspaces: []ed318.Feature{uspaceFeature("GEOTU01", 1500, RefAMSL)}}}
	_, _, err = f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if rf := refusalOf(t, err); rf.Slug != SlugCISStale || !strings.Contains(rf.Detail, "301 s old") {
		t.Fatalf("stale: %+v", rf)
	}
	f.svc.Airspaces = staticAirspaces{err: errors.New("kv down")}
	if rf := refusalOf(t, func() error {
		_, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
		return err
	}()); rf.Slug != SlugCISStale {
		t.Fatalf("unreadable: %+v", rf)
	}

	f = newFixture(t)
	f.repo.areaM2 = MaxAreaM2 + 1
	_, _, err = f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	if rf := refusalOf(t, err); !hasField(rf, "geometry", "CstrMaxAreaKm2") {
		t.Fatalf("area: %+v", rf)
	}

	f = newFixture(t)
	in := input(t0, t0.Add(time.Hour))
	in.ZoneType = ""
	f.repo.pol.DefaultZoneType = "REQ_AUTHORIZATION"
	r, _, err := f.svc.Plan(ctx, supervisor, in, PlanOptions{})
	if err != nil || r.ZoneType != core.ZoneReqAuthorization {
		t.Fatalf("default zone type: %+v %v", r, err)
	}

	f = newFixture(t)
	f.repo.failNow = errors.New("db down")
	if _, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{}); err == nil || errors.As(err, new(*Refusal)) {
		t.Fatalf("db down: %v", err)
	}
	f.repo.failNow = nil
	f.repo.seqMax = 0
	if rf := refusalOf(t, func() error {
		_, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
		return err
	}()); rf.Slug != SlugIdentifiersSpent {
		t.Fatalf("identifiers: %+v", rf)
	}
	if f.svc.Counters().Get(CounterRefused) == 0 {
		t.Fatal("refusals not counted")
	}
}

// Restriction requests (F11): received, idempotent by client_ref,
// bounded per requester; accepted (plans the restriction, published) or
// declined; a decided request cannot be decided again; a refused plan
// leaves the request received.
func TestRestrictionRequests(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authority := Actor{Type: "client", ID: "authority-01", Role: "authority-01"}
	payload := []byte(`{"client_ref":"GCAA-1","uspace_airspace_id":"GEOTU01","geometry":{"type":"Polygon","coordinates":[[[44.78,41.70],[44.82,41.70],[44.82,41.73],[44.78,41.73],[44.78,41.70]]]},"lower_m":0,"lower_ref":"AMSL","upper_m":120,"upper_ref":"AMSL","starts_at":"2026-10-02T13:00:00.000Z","ends_at":"2026-10-02T15:00:00.000Z","reason_text":"Public event (synthetic)"}`)
	q, replay, err := f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-1", payload)
	if err != nil || replay || q.State != RequestReceived {
		t.Fatalf("create: %+v %v", q, err)
	}
	q2, replay, err := f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-1", payload)
	if err != nil || !replay || q2.ID != q.ID {
		t.Fatalf("replay: %v %v", replay, err)
	}
	_, _, err = f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-1", append(payload[:len(payload)-1:len(payload)-1], ' ', '}'))
	if rf := refusalOf(t, err); rf.Status != 409 || !hasField(rf, "client_ref", q.ID) {
		t.Fatalf("conflict: %+v", rf)
	}
	accepted, err := f.svc.Accept(ctx, supervisor, q.ID, core.ZoneReqAuthorization, "for the event")
	if err != nil || accepted.State != RequestAccepted || accepted.RestrictionID == nil || *accepted.DecidedBy != "watch_supervisor" {
		t.Fatalf("accept: %+v %v", accepted, err)
	}
	r, err := f.svc.Get(ctx, *accepted.RestrictionID)
	if err != nil || r.RequestID == nil || *r.RequestID != q.ID || r.ZoneType != core.ZoneReqAuthorization || len(f.bus.msgs) != 1 {
		t.Fatalf("restriction: %+v %v", r, err)
	}
	if _, err := f.svc.Decline(ctx, supervisor, q.ID, "late"); refusalOf(t, err).Slug != SlugRequestDecided {
		t.Fatal("decided twice")
	}
	if _, err := f.svc.Accept(ctx, supervisor, q.ID, "", "again"); refusalOf(t, err).Status != 409 {
		t.Fatal("accepted twice")
	}
	// A request whose plan is refused stays received.
	outside := []byte(strings.ReplaceAll(string(payload), "44.78", "43.00"))
	q3, _, _ := f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-2", outside)
	if _, err := f.svc.Accept(ctx, supervisor, q3.ID, "", "try"); refusalOf(t, err).Slug != SlugOutsideUSpace {
		t.Fatalf("outside: %v", err)
	}
	if again, _ := f.svc.Request(ctx, q3.ID); again.State != RequestReceived {
		t.Fatalf("state after a refused accept: %s", again.State)
	}
	if d, err := f.svc.Decline(ctx, supervisor, q3.ID, "outside U-space"); err != nil || d.State != RequestDeclined || *d.DecisionReason != "outside U-space" {
		t.Fatalf("decline: %+v %v", d, err)
	}
	if _, err := f.svc.Decline(ctx, supervisor, "01K6P2M3N4P5Q6R7S8T9V0W1X2", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// E-10: the 101st open request of a requester is refused 429.
	g := newFixture(t)
	for i := range MaxOpenRequests {
		if _, _, err := g.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "ref-"+Stamp(t0.Add(time.Duration(i)*time.Second)), payload); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = g.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "one-more", payload)
	if rf := refusalOf(t, err); rf.Status != 429 || rf.Slug != SlugTooManyRequests {
		t.Fatalf("bound: %+v", rf)
	}
	if _, _, err := g.svc.CreateRequest(ctx, authority, "authority-02", SourceAuthority, "one-more", payload); err != nil {
		t.Fatalf("another requester: %v", err)
	}
}

// The stream snapshot holds every planned and active restriction's
// current message and says when more existed.
func TestSnapshot(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	b, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, a.ID, OpActivate, "go", nil)
	c, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, c.ID, OpCancel, "no", nil)
	msgs, truncated, err := f.svc.Snapshot(ctx, 10)
	if err != nil || truncated || len(msgs) != 2 {
		t.Fatalf("%d %v %v", len(msgs), truncated, err)
	}
	if !strings.Contains(string(msgs[0]), a.ID) || !strings.Contains(string(msgs[1]), b.ID) || !strings.Contains(string(msgs[0]), `"ansp_version":2`) {
		t.Fatalf("%s", msgs)
	}
	if _, truncated, _ := f.svc.Snapshot(ctx, 0); !truncated {
		t.Fatal("not truncated")
	}
}
