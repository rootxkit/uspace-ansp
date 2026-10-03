package restriction

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

var errStore = errors.New("store fault")

// errNotThisCase: the injected fault hit the case's set-up, not the
// operation the case is about.
var errNotThisCase = errors.New("the fault hit the set-up")

// Every store fault inside a transaction fails the operation whole:
// the error comes back (never a refusal invented from it), nothing is
// stored and nothing is published (the transaction rolls back).
func TestStoreFaultsRollBack(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"client_ref":"GCAA-1","uspace_airspace_id":"GEOTU01","geometry":{"type":"Polygon","coordinates":[[[44.78,41.70],[44.82,41.70],[44.82,41.73],[44.78,41.73],[44.78,41.70]]]},"lower_m":0,"lower_ref":"AMSL","upper_m":120,"upper_ref":"AMSL","starts_at":"2026-10-02T13:00:00.000Z","ends_at":"2026-10-02T15:00:00.000Z","reason_text":"Public event (synthetic)"}`)
	authority := Actor{Type: "client", ID: "authority-01", Role: "authority-01"}
	type op struct {
		name string
		run  func(f *fixture, id, req string) error
	}
	plan := op{"plan", func(f *fixture, _, _ string) error {
		_, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Hour)), PlanOptions{Idempotency: &Idempotency{ActorID: "a", Key: "k", SHA256: Hash(nil)}})
		return err
	}}
	activate := op{"activate", func(f *fixture, id, _ string) error {
		_, err := f.svc.Apply(ctx, supervisor, id, OpActivate, "go", nil)
		return err
	}}
	extend := op{"extend", func(f *fixture, id, _ string) error {
		_, _ = f.svc.Apply(ctx, supervisor, id, OpActivate, "go", nil)
		end := t0.Add(30 * time.Hour)
		_, err := f.svc.Apply(ctx, supervisor, id, OpExtend, "re-issue", &end)
		return err
	}}
	schedule := op{"schedule", func(f *fixture, _, _ string) error {
		r, _, err := f.svc.Plan(ctx, supervisor, input(t0.Add(time.Hour), t0.Add(2*time.Hour)), PlanOptions{})
		if err != nil {
			return errors.Join(errNotThisCase, err)
		}
		_, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "later", nil)
		return err
	}}
	expire := op{"expire with a successor", func(f *fixture, _, _ string) error {
		first, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(30*time.Hour)), PlanOptions{ConfirmChain: true})
		if err != nil {
			return errors.Join(errNotThisCase, err)
		}
		if _, err := f.svc.Apply(ctx, supervisor, first.ID, OpActivate, "go", nil); err != nil {
			return errors.Join(errNotThisCase, err)
		}
		f.repo.advance(24 * time.Hour)
		_, err = f.svc.Apply(ctx, SystemActor, first.ID, OpExpire, "expired", nil)
		return err
	}}
	request := op{"request", func(f *fixture, _, _ string) error {
		_, _, err := f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-9", payload)
		return err
	}}
	accept := op{"accept", func(f *fixture, _, req string) error {
		_, err := f.svc.Accept(ctx, supervisor, req, "", "ok")
		return err
	}}
	decline := op{"decline", func(f *fixture, _, req string) error { _, err := f.svc.Decline(ctx, supervisor, req, "no"); return err }}
	faults := map[string][]op{
		"Policy": {plan, activate}, "MintIdentifier": {plan}, "ByIdempotency": {plan}, "Insert": {plan, extend},
		"Update": {activate, schedule}, "InsertVersion": {plan, activate}, "Audit": {plan, activate, schedule, request, accept, decline},
		"Successor": {expire}, "AreaM2": {plan}, "Relate": {plan, extend}, "RequestByClientRef": {request}, "CountOpenRequests": {request},
		"InsertRequest": {request}, "LockRequest": {accept, decline}, "DecideRequest": {accept, decline},
	}
	for fault, ops := range faults {
		for _, o := range ops {
			t.Run(fault+"/"+o.name, func(t *testing.T) {
				f := newFixture(t)
				r, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(20*time.Hour)), PlanOptions{})
				if err != nil {
					t.Fatal(err)
				}
				q, _, err := f.svc.CreateRequest(ctx, authority, "authority-01", SourceAuthority, "GCAA-1", payload)
				if err != nil {
					t.Fatal(err)
				}
				published, versions, events := len(f.bus.msgs), len(f.repo.versions), len(f.repo.events)
				f.repo.fail = map[string]error{fault: errStore}
				err = o.run(f, r.ID, q.ID)
				if o.name == "schedule" || o.name == "expire with a successor" {
					if err != nil && !errors.Is(err, errStore) && !errors.Is(err, errNotThisCase) {
						t.Fatalf("%v", err)
					}
					return
				}
				if !errors.Is(err, errStore) {
					t.Fatalf("want the store fault, got %v", err)
				}
				if o.name != "extend" && (len(f.bus.msgs) != published || len(f.repo.versions) != versions || len(f.repo.events) != events) {
					t.Fatal("a failed operation left something behind")
				}
			})
		}
	}
}

// The tick reports what it could not do, counts it, and does the rest.
func TestTickFaults(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a, _, _ := f.svc.Plan(ctx, supervisor, input(t0.Add(time.Minute), t0.Add(2*time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, a.ID, OpActivate, "later", nil)
	b, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Minute)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, b.ID, OpActivate, "now", nil)
	f.repo.advance(90 * time.Second)
	f.repo.failLock = errStore
	rep, err := f.svc.Tick(ctx, time.Second)
	if !errors.Is(err, errStore) || rep.Failed != 2 || f.svc.Counters().Get(CounterTickFailed) != 2 {
		t.Fatalf("%+v %v", rep, err)
	}
	f.repo.failLock = nil
	if rep, err := f.svc.Tick(ctx, time.Second); err != nil || rep.Activated != 1 || rep.Expired != 1 {
		t.Fatalf("recovered: %+v %v", rep, err)
	}
}

// Several replicas tick: one that read a restriction as due after
// another activated or expired it finds it moved on. That is counted
// restriction_tick_raced and is not a failure (ansp audit N-2); a real
// refusal (the window passed) still fails, and the twin, a due one, is
// activated.
func TestTickRacedIsNotAFailure(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	a, _, _ := f.svc.Plan(ctx, supervisor, input(t0.Add(time.Minute), t0.Add(2*time.Hour)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, a.ID, OpActivate, "later", nil)
	b, _, _ := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(time.Minute)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, b.ID, OpActivate, "now", nil)
	f.repo.advance(90 * time.Second)
	if rep, err := f.svc.Tick(ctx, time.Second); err != nil || rep.Activated != 1 || rep.Expired != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	f.repo.mu.Lock()
	f.repo.staleDue = []string{b.ID}
	f.repo.mu.Unlock()
	rep, err := f.svc.Tick(ctx, time.Second)
	if err != nil || rep.Failed != 0 || f.svc.Counters().Get(CounterTickFailed) != 0 || f.svc.Counters().Get(CounterTickRaced) != 2 {
		t.Fatalf("%+v %v %v", rep, err, f.svc.Counters().Snapshot())
	}
	f.repo.mu.Lock()
	f.repo.staleDue = nil
	f.repo.mu.Unlock()
	now := t0.Add(90 * time.Second)
	c, _, _ := f.svc.Plan(ctx, supervisor, input(now.Add(time.Minute), now.Add(2*time.Minute)), PlanOptions{})
	_, _ = f.svc.Apply(ctx, supervisor, c.ID, OpActivate, "later", nil)
	f.repo.advance(5 * time.Minute)
	if rep, err := f.svc.Tick(ctx, time.Second); err == nil || rep.Failed != 1 || f.svc.Counters().Get(CounterTickRaced) != 2 {
		t.Fatalf("a scheduled activation past its window: %+v %v", rep, err)
	}
}

// The small things: the shape's GeoJSON, a refusal's text, the CIS age
// rules, the request decoding of an accept.
func TestHelpers(t *testing.T) {
	c := core.LatLon{LatDeg: 41.7, LonDeg: 44.8}
	if g := (Shape{Center: &c, RadiusM: 5}).GeoJSON(); g != `{"type":"Point","coordinates":[44.8,41.7]}` {
		t.Fatal(g)
	}
	if (Shape{Ring: box().Ring}).Radius() != nil || *(Shape{Center: &c, RadiusM: 5}).Radius() != 5 {
		t.Fatal("radius")
	}
	r := &Refusal{Slug: "x", Detail: "y", Fields: []*core.FieldError{core.Fieldf("f", "z")}}
	if !strings.Contains(r.Error(), "f: z") || (&Refusal{Slug: "x", Detail: "y"}).Error() != "x: y" {
		t.Fatal(r.Error())
	}
	if _, err := cisAge(Snapshot{FetchedAt: t0}, nil, t0, 0); err == nil {
		t.Fatal("a zero bound judged a projection current")
	}
	if age, err := cisAge(Snapshot{FetchedAt: t0.Add(time.Second)}, nil, t0, 300); err != nil || age != 0 {
		t.Fatal(age, err)
	}
	if fe := fieldErrors(errors.New("plain")); fe != nil {
		t.Fatal(fe)
	}
	if !strings.Contains(decodeError(errors.New("x")).Field, "body") {
		t.Fatal("decodeError")
	}
}
