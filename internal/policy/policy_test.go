package policy

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/bus"
)

func TestDefaultsArePositiveAndValid(t *testing.T) {
	d := Defaults()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, n := range d.numbers() {
		if n.value <= 0 {
			t.Fatalf("%s = %v", n.field, n.value)
		}
	}
	if d.FeedMarginLateralM != 5000 || d.FeedMarginVerticalM != 1500 || d.StaleAfterS != 15 || d.SourceLivenessS != 15 ||
		d.CISPAlarmAfterS != 10 || d.CISPHeartbeatS != 15 || d.CISReconcileS != 60 || d.CISStaleBoundS != 300 ||
		d.NoticeEscalationS != 60 || d.DefaultZoneType != ZoneProhibited || d.Country != "GEO" {
		t.Fatalf("defaults differ from docs/PLAN.md 5.1: %+v", d)
	}
}

// E-13: every numeric threshold names its unit (_m, _s, _hz) or is a
// count; numbers() lists every numeric field, so Validate checks them
// all.
func TestNumericFieldsNameTheirUnit(t *testing.T) {
	typ := reflect.TypeFor[Thresholds]()
	numeric := 0
	var d Thresholds
	listed := map[string]bool{}
	for _, n := range d.numbers() {
		listed[n.field] = true
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		name := f.Tag.Get("json")
		kind := f.Type.Kind()
		if kind >= reflect.Int && kind <= reflect.Float64 {
			numeric++
			ok := false
			for _, suffix := range []string{"_m", "_s", "_hz", "_count"} {
				ok = ok || strings.HasSuffix(name, suffix)
			}
			if !ok {
				t.Errorf("%s (%s) names no unit and is not a count", f.Name, name)
			}
			if !listed[name] {
				t.Errorf("%s is not validated (missing from numbers())", name)
			}
		}
	}
	if numeric != len(listed) || numeric == 0 {
		t.Fatalf("%d numeric fields, %d validated", numeric, len(listed))
	}
}

func TestValidateRefusesEachField(t *testing.T) {
	for _, v := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		d := Defaults()
		d.CISPHeartbeatS = v
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "cisp_heartbeat_s") {
			t.Fatalf("%v: %v", v, err)
		}
	}
	d := Defaults()
	d.FeedMarginLateralM, d.DefaultZoneType, d.Country = 0, "ALLOWED", "GE"
	err := d.Validate()
	for _, f := range []string{"feed_margin_lateral_m", "default_zone_type", "country"} {
		if err == nil || !strings.Contains(err.Error(), f) {
			t.Fatalf("missing %s in %v", f, err)
		}
	}
}

func pol(v int64) Policy { return Policy{Version: v, Thresholds: Defaults()} }

// With nothing from KV the follower serves the compiled defaults and
// says so; once a version arrives it says which (E-01 pair).
func TestFollowerDefaultsThenKV(t *testing.T) {
	f := NewFollower(nil)
	p, fromKV := f.Current()
	if fromKV || p.Version != 0 || p.Thresholds != Defaults() || f.Status() != "policy: defaults, KV empty" || f.Version() != 0 {
		t.Fatalf("empty: %+v %v %q", p, fromKV, f.Status())
	}
	q := pol(3)
	q.StaleAfterS = 30
	if !f.Apply(q) {
		t.Fatal("version 3 not applied")
	}
	p, fromKV = f.Current()
	if !fromKV || p.StaleAfterS != 30 || f.Status() != "policy: version 3" || f.Version() != 3 || f.Counters().Get(CounterApplied) != 1 {
		t.Fatalf("applied: %+v %q", p, f.Status())
	}
}

// A lower version is ignored and counted, an equal one ignored
// silently, an invalid one refused and counted; a higher one applies.
func TestFollowerOrder(t *testing.T) {
	counters := &core.Counters{}
	f := NewFollower(counters)
	f.Apply(pol(5))
	if f.Apply(pol(4)) || counters.Get(CounterOlderIgnored) != 1 {
		t.Fatal("lower version applied or not counted")
	}
	if f.Apply(pol(5)) || counters.Get(CounterOlderIgnored) != 1 {
		t.Fatal("equal version applied or counted")
	}
	bad := pol(9)
	bad.NoticeEscalationS = 0
	if f.Apply(bad) || f.Apply(pol(0)) || counters.Get(CounterInvalidRefused) != 2 {
		t.Fatal("invalid applied or not counted")
	}
	if !f.Apply(pol(6)) || f.Version() != 6 {
		t.Fatal("higher version not applied")
	}
}

func TestFollowerApplyJSON(t *testing.T) {
	f := NewFollower(nil)
	doc, _ := json.Marshal(pol(2))
	if !f.ApplyJSON(doc) || f.Version() != 2 {
		t.Fatalf("doc %s not applied", doc)
	}
	for _, bad := range [][]byte{[]byte(`{`), []byte(`{"policy_version":3,"surprise":1}`), make([]byte, MaxDocBytes+1)} {
		if f.ApplyJSON(bad) {
			t.Fatalf("%.40s applied", bad)
		}
	}
	if f.Counters().Get(CounterUndecodable) != 3 {
		t.Fatalf("undecodable %d", f.Counters().Get(CounterUndecodable))
	}
}

func TestFollowerConcurrent(t *testing.T) {
	f := NewFollower(nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for v := range 50 {
				f.Apply(pol(int64(i*50 + v + 1)))
				_, _ = f.Current()
				_ = f.Status()
			}
		})
	}
	wg.Wait()
	if f.Version() != 400 {
		t.Fatalf("version %d", f.Version())
	}
}

// fakeRepo emulates the transaction: within's error rolls the version
// back.
type fakeRepo struct {
	mu       sync.Mutex
	versions []Policy
	err      error
}

func (r *fakeRepo) Latest(context.Context) (Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Policy{}, r.err
	}
	return r.versions[len(r.versions)-1], nil
}

func (r *fakeRepo) Insert(ctx context.Context, actor Actor, t Thresholds, within func(context.Context, Policy) error) (Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Policy{}, r.err
	}
	p := Policy{Version: int64(len(r.versions) + 1), Thresholds: t, ChangedBy: actor.ID, ChangedAt: time.Now()}
	if err := within(ctx, p); err != nil {
		return Policy{}, err
	}
	r.versions = append(r.versions, p)
	return p, nil
}

type fakeKV struct {
	puts [][]byte
	err  error
}

func (k *fakeKV) Put(_ context.Context, key string, value []byte) (uint64, error) {
	if k.err != nil {
		return 0, k.err
	}
	if key != KVKey {
		return 0, errors.New("wrong key " + key)
	}
	k.puts = append(k.puts, value)
	return uint64(len(k.puts)), nil
}

type fakeNotify struct {
	subjects []string
	err      error
}

func (n *fakeNotify) Publish(subject string, _ []byte) error {
	n.subjects = append(n.subjects, subject)
	return n.err
}

func newService() (*Service, *fakeRepo, *fakeKV, *fakeNotify) {
	repo := &fakeRepo{versions: []Policy{{Version: 1, Thresholds: Defaults(), ChangedBy: "migration"}}}
	kv, n := &fakeKV{}, &fakeNotify{}
	return &Service{Repo: repo, KV: kv, Notify: n, Counters: &core.Counters{}}, repo, kv, n
}

// Update stores, puts into KV inside the transaction and pushes on
// ctl.policy; a follower fed the KV value applies it.
func TestUpdatePutsAndNotifies(t *testing.T) {
	s, repo, kv, n := newService()
	p := pol(0)
	p.StaleAfterS = 20
	v, err := s.Update(context.Background(), Actor{Type: "user", ID: "admin-1"}, p)
	if err != nil || v != 2 || len(repo.versions) != 2 || len(kv.puts) != 1 || len(n.subjects) != 1 || n.subjects[0] != bus.SubjectControlPolicy {
		t.Fatalf("v %d %v, %d versions, %d puts, %v", v, err, len(repo.versions), len(kv.puts), n.subjects)
	}
	f := NewFollower(nil)
	if !f.ApplyJSON(kv.puts[0]) || f.Version() != 2 {
		t.Fatalf("follower of %s: %s", kv.puts[0], f.Status())
	}
	if cur, _ := f.Current(); cur.StaleAfterS != 20 || cur.ChangedBy != "admin-1" {
		t.Fatalf("%+v", cur)
	}
	if got, err := s.Load(context.Background()); err != nil || got.Version != 2 {
		t.Fatalf("load %+v %v", got, err)
	}
}

// When KV cannot take the row, Update is refused with ErrKVUnavailable
// and the version is not recorded (B-09); with no KV at all likewise.
func TestUpdateRefusedWhenKVFails(t *testing.T) {
	s, repo, kv, n := newService()
	kv.err = errors.New("nats: timeout")
	_, err := s.Update(context.Background(), Actor{Type: "user", ID: "a"}, pol(0))
	if !errors.Is(err, ErrKVUnavailable) || !strings.Contains(err.Error(), "nats: timeout") || len(repo.versions) != 1 || len(n.subjects) != 0 ||
		s.Counters.Get(CounterKVRefused) != 1 {
		t.Fatalf("%v, %d versions, %v", err, len(repo.versions), n.subjects)
	}
	s.KV = nil
	if _, err := s.Update(context.Background(), Actor{Type: "user", ID: "a"}, pol(0)); !errors.Is(err, ErrKVUnavailable) || len(repo.versions) != 1 {
		t.Fatalf("no KV: %v", err)
	}
}

func TestUpdateRefusesInvalidAndRepoErrors(t *testing.T) {
	s, repo, kv, _ := newService()
	bad := pol(0)
	bad.CISReconcileS = -1
	if _, err := s.Update(context.Background(), Actor{}, bad); err == nil || len(kv.puts) != 0 {
		t.Fatalf("invalid: %v", err)
	}
	repo.err = errors.New("db down")
	if _, err := s.Update(context.Background(), Actor{}, pol(0)); err == nil {
		t.Fatal("repo error swallowed")
	}
	if _, err := s.Load(context.Background()); err == nil {
		t.Fatal("load error swallowed")
	}
	if _, err := s.Republish(context.Background()); err == nil {
		t.Fatal("republish error swallowed")
	}
}

// A failed push is counted, not a refusal: followers read KV.
func TestUpdateCountsAFailedPush(t *testing.T) {
	s, repo, _, n := newService()
	n.err = errors.New("nats: disconnected")
	if _, err := s.Update(context.Background(), Actor{Type: "user", ID: "a"}, pol(0)); err != nil || len(repo.versions) != 2 {
		t.Fatalf("%v", err)
	}
	if s.Counters.Get(CounterNotifyFailed) != 1 {
		t.Fatal("push failure not counted")
	}
	s.Notify, s.Counters = nil, nil
	if _, err := s.Update(context.Background(), Actor{Type: "user", ID: "a"}, pol(0)); err != nil || len(repo.versions) != 3 {
		t.Fatalf("no notifier: %v", err)
	}
}

// Republish puts the current version into KV again; a failing KV is
// reported.
func TestRepublish(t *testing.T) {
	s, _, kv, _ := newService()
	p, err := s.Republish(context.Background())
	if err != nil || p.Version != 1 || len(kv.puts) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	kv.err = errors.New("down")
	if _, err := s.Republish(context.Background()); !errors.Is(err, ErrKVUnavailable) {
		t.Fatalf("%v", err)
	}
}
