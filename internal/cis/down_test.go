package cis_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// E-02: kill the CISP; the follower keeps serving with its age and the
// status says down since T; bring it back and the next reconciliation
// recovers to ok.
func TestCISPDownThenRecovered(t *testing.T) {
	f := newProjection(t, func(c *cis.Config) { c.Policy = fixedPolicy(1) })
	f.stub.publishAll()
	f.pullAll(t)
	fol := cis.NewFollower(nil)
	for _, d := range cis.Datasets {
		fol.ApplyJSON(f.kv.value(string(d)))
	}
	if fol.Status(time.Now()) == cis.StatusNoProjection {
		t.Fatal("the follower took nothing")
	}

	f.stub.setDown(true)
	t0 := time.Now()
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, true); err == nil {
		t.Fatal("a pull from a dead CISP succeeded")
	}
	r := f.p.Status(context.Background(), time.Now())
	if r.State != cis.StateDown || r.Since.Before(t0.Add(-time.Second)) || !strings.HasPrefix(r.Line(), "down since ") ||
		!strings.Contains(r.Line(), "serving age") {
		t.Fatalf("status while down: %s", r.Line())
	}
	// The follower serves what it held, with its age.
	later := time.Now().Add(400 * time.Second)
	if age, ok := fol.Age(later); !ok || age < 399 || len(fol.USpaceVolumes()) != 1 || !strings.Contains(fol.Status(later), "age 4") {
		t.Fatalf("follower while the CISP is down: %v %v %s", age, ok, fol.Status(later))
	}
	// Past the stale bound the projection says stale... but down wins.
	if r := f.p.Status(context.Background(), later); r.State != cis.StateDown {
		t.Fatalf("down hidden by stale: %s", r.Line())
	}

	f.stub.setDown(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.p.Run(ctx)
	waitFor(t, 4*time.Second, "cisp: ok after the CISP returns", func() bool {
		return f.p.Status(context.Background(), time.Now()).State == cis.StateOK
	})
}

// Stale: no answer for longer than cis_stale_bound_s is stale with the
// age, and ok before it.
func TestStaleAfterBound(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	bound := policy.Defaults().CISStaleBoundS
	if r := f.p.Status(context.Background(), time.Now().Add(time.Duration(bound-1)*time.Second)); r.State != cis.StateOK {
		t.Fatalf("before the bound: %s", r.Line())
	}
	r := f.p.Status(context.Background(), time.Now().Add(time.Duration(bound+100)*time.Second))
	if r.State != cis.StateStale || !strings.HasPrefix(r.Line(), "stale (age 40") {
		t.Fatalf("past the bound: %s", r.Line())
	}
}
