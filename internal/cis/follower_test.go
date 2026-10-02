package cis_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

func doc(t *testing.T, d cis.Dataset, v int64, at time.Time, body []byte) []byte {
	t.Helper()
	b, err := json.Marshal(cis.Doc{Dataset: d, Version: v, ETag: "e", FetchedAt: at, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SC-22: an empty follower says "no CIS projection", serves empty (not
// nil) volumes and USSPs, and has no age.
func TestFollowerEmpty(t *testing.T) {
	f := cis.NewFollower(nil)
	if f.Status(time.Now()) != cis.StatusNoProjection || f.Version() != "" || !f.FetchedAt().IsZero() {
		t.Fatal(f.Status(time.Now()))
	}
	if v := f.USpaceVolumes(); v == nil || len(v) != 0 {
		t.Fatal("volumes nil or not empty")
	}
	if u := f.USSPs(); u == nil || len(u) != 0 {
		t.Fatal("USSPs nil or not empty")
	}
	if _, ok := f.Age(time.Now()); ok {
		t.Fatal("an age without a projection")
	}
}

// Presence: a uspace_airspace doc gives its volumes, version and age; a
// ussp_list doc gives the USSPs; a restrictions doc is taken without a
// body. A newer version replaces, the same version moves fetched_at,
// an older one is ignored and counted.
func TestFollowerApply(t *testing.T) {
	f := cis.NewFollower(nil)
	t0 := time.Now().Add(-30 * time.Second).UTC()
	if !f.ApplyJSON(doc(t, cis.USpaceAirspace, 3, t0, fixture(t, cis.USpaceAirspace, 3))) {
		t.Fatal("not applied")
	}
	if f.Version() != "3" || len(f.USpaceVolumes()) != 1 || !f.FetchedAt().Equal(t0) {
		t.Fatalf("%s %d", f.Version(), len(f.USpaceVolumes()))
	}
	if age, ok := f.Age(t0.Add(12 * time.Second)); !ok || age != 12 {
		t.Fatalf("age %v", age)
	}
	if s := f.Status(t0.Add(12 * time.Second)); s != "CIS version 3, 1 volumes, age 12 s" {
		t.Fatal(s)
	}
	if !f.ApplyJSON(doc(t, cis.USSPList, 2, t0, fixture(t, cis.USSPList, 2))) || len(f.USSPs()) != 2 {
		t.Fatal("ussp_list")
	}
	if !f.ApplyJSON(doc(t, cis.Restrictions, 7, t0, nil)) {
		t.Fatal("restrictions")
	}
	t1 := t0.Add(10 * time.Second)
	if !f.ApplyJSON(doc(t, cis.USpaceAirspace, 3, t1, nil)) || !f.FetchedAt().Equal(t1) || len(f.USpaceVolumes()) != 1 {
		t.Fatal("the same version did not move fetched_at or lost the volumes")
	}
	if f.ApplyJSON(doc(t, cis.USpaceAirspace, 3, t0, nil)) || !f.FetchedAt().Equal(t1) {
		t.Fatal("an older fetched_at moved it back")
	}
	if f.ApplyJSON(doc(t, cis.USpaceAirspace, 2, t1.Add(time.Hour), fixture(t, cis.USpaceAirspace, 2))) || f.Version() != "3" {
		t.Fatal("rolled back")
	}
	if f.Counters().Get(cis.CounterFollowerOlder) != 1 || f.Counters().Get(cis.CounterFollowerTouched) != 1 || f.Counters().Get(cis.CounterFollowerApplied) != 3 {
		t.Fatalf("%v", f.Counters().Snapshot())
	}
	if !f.ApplyJSON(doc(t, cis.USpaceAirspace, 4, t1, fixture(t, cis.USpaceAirspace, 4))) || f.Version() != "4" {
		t.Fatal("newer not applied")
	}
}

// Absence: what does not decode, names no projected dataset, or whose
// body core refuses is ignored and counted; the state held stays.
func TestFollowerRefuses(t *testing.T) {
	f := cis.NewFollower(nil)
	t0 := time.Now().UTC()
	f.ApplyJSON(doc(t, cis.USpaceAirspace, 3, t0, fixture(t, cis.USpaceAirspace, 3)))
	for name, raw := range map[string][]byte{
		"garbage":         []byte("{"),
		"unknown member":  []byte(`{"dataset":"uspace_airspace","version":4,"etag":"e","fetched_at":"2026-10-02T00:00:00Z","x":1}`),
		"zones":           doc(t, "zones", 4, t0, nil),
		"version 0":       doc(t, cis.USpaceAirspace, 0, t0, nil),
		"no fetched_at":   doc(t, cis.USpaceAirspace, 4, time.Time{}, nil),
		"too large":       append([]byte(`{"dataset":"`), make([]byte, cis.MaxDocBytes)...),
		"refused by core": doc(t, cis.USpaceAirspace, 4, t0, []byte(strings.Replace(string(fixture(t, cis.USpaceAirspace, 4)), `"USPACE"`, `"X"`, 1))),
	} {
		if f.ApplyJSON(raw) {
			t.Fatalf("%s applied", name)
		}
	}
	if f.Version() != "3" || len(f.USpaceVolumes()) != 1 {
		t.Fatal("the held state moved")
	}
	if f.Counters().Get(cis.CounterFollowerUndecodable) != 6 || f.Counters().Get(cis.CounterFollowerRefused) != 1 {
		t.Fatalf("%v", f.Counters().Snapshot())
	}
}

// fakeEntry is a jetstream.KeyValueEntry.
type fakeEntry struct {
	key   string
	value []byte
	op    jetstream.KeyValueOp
}

func (e fakeEntry) Bucket() string                  { return "cis_current" }
func (e fakeEntry) Key() string                     { return e.key }
func (e fakeEntry) Value() []byte                   { return e.value }
func (e fakeEntry) Revision() uint64                { return 1 }
func (e fakeEntry) Created() time.Time              { return time.Now() }
func (e fakeEntry) Delta() uint64                   { return 0 }
func (e fakeEntry) Operation() jetstream.KeyValueOp { return e.op }

// fakeWatcher is a jetstream.KeyWatcher fed by the test.
type fakeWatcher struct{ ch chan jetstream.KeyValueEntry }

func (w *fakeWatcher) Updates() <-chan jetstream.KeyValueEntry { return w.ch }
func (w *fakeWatcher) Stop() error                             { return nil }

type fakeWatchKV struct {
	w   *fakeWatcher
	err error
}

func (k fakeWatchKV) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	if k.err != nil {
		return nil, k.err
	}
	return k.w, nil
}

// Run applies every put of the watch, skips deletes and the end-of-
// initial-values marker, and returns when the context ends, the watch
// cannot start, or it ends.
func TestFollowerRun(t *testing.T) {
	f := cis.NewFollower(nil)
	w := &fakeWatcher{ch: make(chan jetstream.KeyValueEntry, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx, fakeWatchKV{w: w}) }()
	w.ch <- nil
	w.ch <- fakeEntry{key: "uspace_airspace", op: jetstream.KeyValueDelete}
	w.ch <- fakeEntry{key: "uspace_airspace", value: doc(t, cis.USpaceAirspace, 3, time.Now().UTC(), fixture(t, cis.USpaceAirspace, 3)), op: jetstream.KeyValuePut}
	waitFor(t, time.Second, "the put", func() bool { return f.Version() == "3" })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := f.Run(context.Background(), fakeWatchKV{err: errors.New("no bucket")}); err == nil || !strings.Contains(err.Error(), "no bucket") {
		t.Fatal(err)
	}
	closed := &fakeWatcher{ch: make(chan jetstream.KeyValueEntry)}
	close(closed.ch)
	if err := f.Run(context.Background(), fakeWatchKV{w: closed}); err == nil || !strings.Contains(err.Error(), "ended") {
		t.Fatal(err)
	}
}
