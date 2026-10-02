package restriction

import (
	"context"
	"errors"
	"testing"
	"time"
)

// recordingHook is a VersionHook that records what it is told.
type recordingHook struct {
	versioned []Op
	committed []int64
	fail      error
}

func (h *recordingHook) Versioned(_ context.Context, _ Tx, _ Version, op Op) error {
	if h.fail != nil {
		return h.fail
	}
	h.versioned = append(h.versioned, op)
	return nil
}

func (h *recordingHook) Committed(_ context.Context, vs []Version) {
	for i := range vs {
		h.committed = append(h.committed, vs[i].Version)
	}
}

// Every version is told to the outbox in its transaction with the op
// that made it, and after its commit; a backlog republish is not a new
// commit (the absence); a hook that refuses rolls the change back.
func TestOutboxHook(t *testing.T) {
	f := newFixture(t)
	h := &recordingHook{}
	f.svc.Outbox = h
	ctx := context.Background()
	r, _, err := f.svc.Plan(ctx, supervisor, input(t0, t0.Add(2*time.Hour)), PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Apply(ctx, supervisor, r.ID, OpActivate, "go", nil); err != nil {
		t.Fatal(err)
	}
	end := t0.Add(3 * time.Hour)
	if _, err := f.svc.Apply(ctx, supervisor, r.ID, OpExtend, "longer", &end); err != nil {
		t.Fatal(err)
	}
	if len(h.versioned) != 3 || h.versioned[0] != OpPlan || h.versioned[1] != OpActivate || h.versioned[2] != OpExtend {
		t.Fatalf("versioned %v", h.versioned)
	}
	if len(h.committed) != 3 || h.committed[2] != 3 {
		t.Fatalf("committed %v", h.committed)
	}
	// The ticker's republish of a backlog is not a commit.
	f.svc.publish(ctx, []Version{{RestrictionID: r.ID, Version: 3}}, true)
	if len(h.committed) != 3 {
		t.Fatalf("a backlog republish told as a commit: %v", h.committed)
	}
	h.fail = errors.New("the outbox cannot write")
	if _, err := f.svc.Apply(ctx, supervisor, r.ID, OpEnd, "done", nil); err == nil {
		t.Fatal("a version committed without its delivery")
	}
	got, _ := f.svc.Get(ctx, r.ID)
	if got.State != StateActive || got.AnspVersion != 3 {
		t.Fatalf("the refused change stayed: %s %d", got.State, got.AnspVersion)
	}
}
