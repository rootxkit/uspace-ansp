package restriction

import (
	"context"
	"testing"
	"time"
)

// Local applicability (item 8 of the CISP expiry plan, spec 02 F3
// erratum 2026-10-16): this system's restriction ends at its own ends_at
// by its own ticker on the database clock. Nothing here waits for, or
// reads, the CISP's expiry version: the Service has no input from the
// CIS restrictions dataset at all, and the projection's install or hold
// of that version is bookkeeping (internal/cis). The absence half: one
// second before ends_at the tick expires nothing and the restriction is
// still active.
func TestExpiryIsLocalNotTheCISPs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	end := t0.Add(time.Hour)
	r, _, err := f.svc.Plan(ctx, supervisor, input(t0, end), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r, err = f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "now", nil); err != nil || r.State != StateActive {
		t.Fatalf("activate: %+v %v", r, err)
	}
	f.repo.advance(time.Hour - time.Second)
	if rep, err := f.svc.Tick(ctx, 2*time.Second); err != nil || rep.Expired != 0 {
		t.Fatalf("a second before ends_at: %+v %v", rep, err)
	}
	if got, _ := f.svc.Get(ctx, r.ID); got.State != StateActive {
		t.Fatalf("ended before its ends_at: %+v", got)
	}
	f.repo.advance(time.Second)
	rep, err := f.svc.Tick(ctx, 2*time.Second)
	if err != nil || rep.Expired != 1 {
		t.Fatalf("at ends_at: %+v %v", rep, err)
	}
	got, _ := f.svc.Get(ctx, r.ID)
	if got.State != StateEnded || got.EndedAtActual == nil || !got.EndedAtActual.Equal(end) || got.EndedBy == nil || *got.EndedBy != RoleSystem {
		t.Fatalf("not ended at its ends_at by the ticker: %+v", got)
	}
}
