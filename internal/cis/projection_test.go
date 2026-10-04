package cis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// fixtureProjection is a projection on the stub with the publishers'
// keys, a memory store and a memory KV.
type fixtureProjection struct {
	stub  *stub
	store *memStore
	kv    *memKV
	p     *cis.Projection
}

func newProjection(t *testing.T, mutate func(*cis.Config)) *fixtureProjection {
	t.Helper()
	s := newStub(t)
	f := &fixtureProjection{stub: s, store: newMemStore(), kv: newMemKV()}
	cfg := cis.Config{Client: s.client(t), Publishers: publisherVerifier(t), Store: f.store, KV: f.kv, Push: f.kv,
		Policy: fixedPolicy(60)}
	if mutate != nil {
		mutate(&cfg)
	}
	f.p = cis.New(cfg)
	return f
}

func (f *fixtureProjection) pullAll(t *testing.T) {
	t.Helper()
	for _, d := range cis.Datasets {
		if err := f.p.Pull(context.Background(), d, false); err != nil {
			t.Fatalf("pull %s: %v", d, err)
		}
	}
}

// The first pull stores the three datasets, puts them to KV and pushes
// them; a second pull is a 304 that only moves fetched_at.
func TestFirstPullThenNotModified(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	if got := f.p.Status(context.Background(), time.Now()); got.State != cis.StateNone || !strings.HasPrefix(got.Line(), cis.StatusNoProjection) {
		t.Fatalf("before the first pull: %+v", got)
	}
	f.pullAll(t)
	for d, want := range map[cis.Dataset]int64{cis.USpaceAirspace: 3, cis.USSPList: 2, cis.Restrictions: 7} {
		row, ok := f.store.row(d)
		if !ok || row.Version != want {
			t.Fatalf("%s stored: %+v", d, row)
		}
		var doc cis.Doc
		if err := json.Unmarshal(f.kv.value(string(d)), &doc); err != nil || doc.Version != want || !doc.FetchedAt.Equal(row.FetchedAt) {
			t.Fatalf("%s in KV: %v %+v", d, err, doc)
		}
		if (d == cis.Restrictions) != (len(doc.Body) == 0) {
			t.Fatalf("%s body in KV: %d bytes", d, len(doc.Body))
		}
		if f.p.Version(d) != want {
			t.Fatalf("%s version %d", d, f.p.Version(d))
		}
	}
	if got := f.kv.pushes(); len(got) != 3 || got[0] != bus.SubjectCISPrefix+"uspace_airspace" {
		t.Fatalf("pushes %v", got)
	}
	if n := len(f.stub.requests("GET", "/v1/uspace_airspace/versions/3")); n != 1 {
		t.Fatalf("the publisher's signature was read %d times", n)
	}
	for _, r := range f.stub.requests("GET", "") {
		if r.Auth != "Bearer test-token" {
			t.Fatalf("%s without the cis.read token", r.Path)
		}
	}
	if v, at, fs, err := f.p.USpaceAirspace(); err != nil || v != "3" || at.IsZero() || len(fs) != 1 {
		t.Fatalf("USpaceAirspace: %v %v %d %v", v, at, len(fs), err)
	}
	if len(f.p.USpaceVolumes()) != 1 || len(f.p.USSPs()) != 2 {
		t.Fatal("volumes or USSPs")
	}
	if got := f.p.Status(context.Background(), time.Now()); got.State != cis.StateOK || !strings.HasPrefix(got.Line(), "ok (age ") {
		t.Fatalf("after the pull: %s", got.Line())
	}

	before, _ := f.store.row(cis.USpaceAirspace)
	saves := f.store.saves
	time.Sleep(5 * time.Millisecond)
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	gets := f.stub.requests("GET", "/v1/uspace_airspace")
	if last := gets[len(gets)-1]; last.IfNoneMatch != `"uspace_airspace:3"` {
		t.Fatalf("If-None-Match %q", last.IfNoneMatch)
	}
	after, _ := f.store.row(cis.USpaceAirspace)
	if f.store.saves != saves || f.store.touchs != 1 || after.Version != 3 || !after.FetchedAt.After(before.FetchedAt) {
		t.Fatalf("304: saves %d->%d touches %d, %+v -> %+v", saves, f.store.saves, f.store.touchs, before.FetchedAt, after.FetchedAt)
	}
	if n := len(f.stub.requests("GET", "/v1/uspace_airspace/versions/3")); n != 1 {
		t.Fatal("a 304 read the version again")
	}
	if f.p.Counters().Get(cis.CounterNotModified) != 1 {
		t.Fatal("cis_not_modified")
	}
	var doc cis.Doc
	_ = json.Unmarshal(f.kv.value("uspace_airspace"), &doc)
	if !doc.FetchedAt.Equal(after.FetchedAt) {
		t.Fatal("KV did not move with the touch")
	}
}

// A changed ETag replaces the version and pushes cis.v1; the twin of
// the 304 above.
func TestChangedETagReplaces(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	pushes := len(f.kv.pushes())
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, true); err != nil {
		t.Fatal(err)
	}
	if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 4 || f.p.Version(cis.USpaceAirspace) != 4 {
		t.Fatalf("not replaced: %d", row.Version)
	}
	if got := f.kv.pushes(); len(got) != pushes+1 || got[len(got)-1] != "cis.v1.uspace_airspace" {
		t.Fatalf("pushes %v", got)
	}
	if f.p.Counters().Get(cis.CounterReconcileCatchups) != 1 {
		t.Fatal("a reconciliation that found a version is a catch-up")
	}
}

// A malformed dataset is refused and the old one kept, counted; the
// twin: the next good one is taken.
func TestMalformedRefusedThenGoodTaken(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	bad := strings.Replace(string(fixture(t, cis.USpaceAirspace, 4)), `"USPACE"`, `"NOT_A_TYPE"`, 1)
	f.stub.publish(cis.USpaceAirspace, 4, []byte(bad), "publisher")
	var rf *cis.RefusalError
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.As(err, &rf) {
		t.Fatalf("not refused: %v", err)
	}
	if f.p.Counters().Get(cis.CounterRefused) != 1 || f.p.Version(cis.USpaceAirspace) != 3 {
		t.Fatalf("refused %d, version %d", f.p.Counters().Get(cis.CounterRefused), f.p.Version(cis.USpaceAirspace))
	}
	if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 3 {
		t.Fatal("the refused version was stored")
	}
	if line := f.p.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "last read refused: uspace_airspace") {
		t.Fatalf("status %s", line)
	}
	f.stub.publish(cis.USpaceAirspace, 5, fixture(t, cis.USpaceAirspace, 5), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.USpaceAirspace) != 5 || strings.Contains(f.p.Status(context.Background(), time.Now()).Line(), "refused") {
		t.Fatal("the good version was not taken, or the refusal still shows")
	}
}

// A body past 20 MB is refused before it is parsed, counted; the
// version held stays.
func TestTooLargeRefused(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	f.stub.mu.Lock()
	f.stub.tooLarge = 21 << 20
	f.stub.mu.Unlock()
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err == nil {
		t.Fatal("21 MB taken")
	}
	if f.p.Counters().Get(cis.CounterTooLarge) != 1 || f.p.Version(cis.USpaceAirspace) != 3 {
		t.Fatal("not counted or the version moved")
	}
}

// A version whose publisher's signature does not verify (or is missing,
// or no keys are configured) is held: the version in use stays and the
// status names the hold. The twin: a correctly signed one is installed
// and the hold clears.
func TestUntrustedHeldThenSignedTaken(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	for _, sign := range []string{"other", "none"} {
		f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), sign)
		var ue *cis.UntrustedError
		if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.As(err, &ue) || ue.Version != 4 {
			t.Fatalf("%s: %v", sign, err)
		}
		if f.p.Version(cis.USpaceAirspace) != 3 {
			t.Fatalf("%s: the untrusted version is in use", sign)
		}
		if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 3 {
			t.Fatalf("%s: the untrusted version was stored", sign)
		}
		if line := f.p.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "uspace_airspace version 4 held") {
			t.Fatalf("%s: status %s", sign, line)
		}
	}
	if f.p.Counters().Get(cis.CounterUntrusted) != 2 {
		t.Fatal("cis_publisher_untrusted")
	}
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.USpaceAirspace) != 4 || strings.Contains(f.p.Status(context.Background(), time.Now()).Line(), "held") {
		t.Fatal("the signed version was not taken")
	}
}

// asPublished is a fixture as its publisher sends it: no top-level cis_*
// members (the CISP adds those).
func asPublished(t *testing.T, d cis.Dataset) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(fixture(t, d, 0), &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if strings.HasPrefix(k, "cis_") {
			delete(m, k)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// asServed is what the real CISP serves at GET /v1/{dataset} for a
// published collection (its getDataset contract): the same features with
// its own top-level cis_* members and metadata (issued = when it received
// the version, provider = the publishing client). edit, when set, alters
// the first feature's properties too.
func asServed(t *testing.T, published []byte, v int64, edit func(props map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(published, &m); err != nil {
		t.Fatal(err)
	}
	m["cis_dataset"] = "uspace_airspace"
	m["cis_version"] = v
	m["cis_updated_at"] = "2026-10-04T00:04:02.023404Z"
	m["metadata"] = map[string]any{"issued": "2026-10-04T00:04:02.023404Z",
		"provider": []any{map[string]any{"text": "authority-01", "lang": "en"}}}
	if edit != nil {
		f := m["features"].([]any)[0].(map[string]any)
		edit(f["properties"].(map[string]any))
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The signature covers the publisher's bytes at /versions/{n}; the CISP
// serves its own snapshot of them at the current path (cis_* members,
// its own metadata), as the droplet's CISP does. A current read whose
// features are not the signed ones (a CISP or a proxy that alters one
// path) is held, never installed; its twin, the CISP's snapshot of the
// same features, is installed with the bytes as served.
func TestCurrentBodyDifferentFromSignedHeld(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	published := asPublished(t, cis.USpaceAirspace)
	f.stub.publish(cis.USpaceAirspace, 4, published, "publisher")
	tampered := asServed(t, published, 4, func(props map[string]any) {
		props["name"] = []any{map[string]any{"text": "not what the authority signed", "lang": "en-GB"}}
	})
	f.stub.mu.Lock()
	f.stub.ds[cis.USpaceAirspace].current = tampered
	f.stub.mu.Unlock()
	var ue *cis.UntrustedError
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.As(err, &ue) || ue.Version != 4 {
		t.Fatalf("a current body other than the signed one: %v", err)
	}
	if f.p.Version(cis.USpaceAirspace) != 3 {
		t.Fatal("the unsigned current body is in use")
	}
	if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 3 {
		t.Fatal("the unsigned current body was stored")
	}
	if !strings.Contains(ue.Reason, "not the ones its publisher signed") {
		t.Fatalf("reason %q", ue.Reason)
	}

	served := asServed(t, published, 4, nil)
	if bytes.Equal(served, published) {
		t.Fatal("the snapshot must differ from the published bytes, or this twin proves nothing")
	}
	f.stub.mu.Lock()
	f.stub.ds[cis.USpaceAirspace].current = served
	f.stub.mu.Unlock()
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatalf("the CISP's snapshot of the signed features: %v", err)
	}
	if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 4 || !bytes.Equal(row.Body, served) {
		t.Fatal("the signed version was not installed with the bytes as served")
	}
}

// A restrictions version is signed over this system's request for one
// restriction, not over the collection the CISP serves: the request's
// feature must be in the collection, equal. Held when it differs;
// installed when it is there.
func TestRestrictionRequestBindsItsFeature(t *testing.T) {
	f := newProjection(t, nil)
	collection := fixture(t, cis.Restrictions, 7)
	var doc struct {
		Features []map[string]any `json:"features"`
	}
	if err := json.Unmarshal(collection, &doc); err != nil || len(doc.Features) == 0 {
		t.Fatalf("restrictions fixture: %v", err)
	}
	request := func(feature map[string]any) []byte {
		b, err := json.Marshal(map[string]any{"action": "create", "feature": feature})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	changed := map[string]any{}
	for k, v := range doc.Features[0] {
		changed[k] = v
	}
	props := map[string]any{}
	for k, v := range doc.Features[0]["properties"].(map[string]any) {
		props[k] = v
	}
	props["name"] = []any{map[string]any{"text": "a restriction the ANSP never requested", "lang": "en-GB"}}
	changed["properties"] = props

	f.stub.publish(cis.Restrictions, 7, request(changed), "publisher")
	f.stub.mu.Lock()
	f.stub.ds[cis.Restrictions].current = collection
	f.stub.mu.Unlock()
	var ue *cis.UntrustedError
	if err := f.p.Pull(context.Background(), cis.Restrictions, false); !errors.As(err, &ue) {
		t.Fatalf("a collection without the signed feature was taken: %v", err)
	}

	f.stub.publish(cis.Restrictions, 7, request(doc.Features[0]), "publisher")
	f.stub.mu.Lock()
	f.stub.ds[cis.Restrictions].current = collection
	f.stub.mu.Unlock()
	if err := f.p.Pull(context.Background(), cis.Restrictions, false); err != nil {
		t.Fatalf("the collection carrying the signed feature: %v", err)
	}
	if f.p.Version(cis.Restrictions) != 7 {
		t.Fatal("the bound restrictions version is not in use")
	}
}

// Without publisher keys every new version is held, and the status says
// why; nothing is ever used.
func TestNoPublisherKeysHoldsEverything(t *testing.T) {
	f := newProjection(t, func(c *cis.Config) { c.Publishers = nil })
	f.stub.publishAll()
	var ue *cis.UntrustedError
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.As(err, &ue) {
		t.Fatalf("%v", err)
	}
	if _, _, _, err := f.p.USpaceAirspace(); !errors.Is(err, cis.ErrNoProjection) {
		t.Fatal("an unverified designation is in use")
	}
	if line := f.p.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "ANSP_CIS_PUBLISHER_KEYS") {
		t.Fatalf("status %s", line)
	}
}

// A restriction is the ANSP's publication: the authority's key does not
// sign it.
func TestRestrictionsNeedTheANSPKey(t *testing.T) {
	f := newProjection(t, nil)
	body := fixture(t, cis.Restrictions, 0)
	f.stub.publish(cis.Restrictions, 7, body, "publisher")
	if err := f.p.Pull(context.Background(), cis.Restrictions, false); err != nil {
		t.Fatal(err)
	}
	f.stub.mu.Lock()
	h, _ := authorityRing.SignDetached(fixture(t, cis.Restrictions, 8), time.Now())
	f.stub.ds[cis.Restrictions] = &stubDataset{version: 8, etag: `"restrictions:8"`, body: fixture(t, cis.Restrictions, 8), sig: h}
	f.stub.mu.Unlock()
	var ue *cis.UntrustedError
	if err := f.p.Pull(context.Background(), cis.Restrictions, false); !errors.As(err, &ue) {
		t.Fatalf("an authority-signed restriction set was taken: %v", err)
	}
}

// An older version than the one held (a CISP replica behind) is not
// installed, counted; the same version is a confirmation.
func TestOlderVersionIgnored(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publish(cis.USpaceAirspace, 5, fixture(t, cis.USpaceAirspace, 5), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.USpaceAirspace) != 5 || f.p.Counters().Get(cis.CounterVersionReplays) != 1 {
		t.Fatal("rolled back")
	}
}

// cis_cache holding a higher version (another api instance) is never
// rolled back, and the pulled version is not installed.
func TestStoreHoldsNewer(t *testing.T) {
	f := newProjection(t, nil)
	f.store.rows[cis.USpaceAirspace] = cis.Stored{Dataset: cis.USpaceAirspace, Version: 9, Body: fixture(t, cis.USpaceAirspace, 9), FetchedAt: time.Now()}
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	if f.p.Version(cis.USpaceAirspace) != 0 || f.p.Counters().Get(cis.CounterStoreNewer) != 1 {
		t.Fatal("installed over a newer stored version")
	}
	if row, _ := f.store.row(cis.USpaceAirspace); row.Version != 9 {
		t.Fatal("rolled back")
	}
}

// A store failure fails the pull (nothing written to KV before the
// commit) and the status says the CISP side is down; the next pull
// with the store back installs.
func TestStoreFailureNothingProjected(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.store.fail = errors.New("database down")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err == nil {
		t.Fatal("installed without a commit")
	}
	if f.kv.value("uspace_airspace") != nil || f.p.Version(cis.USpaceAirspace) != 0 {
		t.Fatal("KV written before the commit")
	}
	if f.p.Counters().Get(cis.CounterStoreFailed) != 1 {
		t.Fatal("cis_store_failed")
	}
	f.store.fail = nil
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil || f.kv.value("uspace_airspace") == nil {
		t.Fatalf("after the store is back: %v", err)
	}
}

// KV unreachable: the version is in use and stored, the status says the
// projection is not written, and the next reconciliation writes it.
func TestKVFailureRetried(t *testing.T) {
	f := newProjection(t, func(c *cis.Config) { c.Policy = fixedPolicy(1) })
	f.stub.publishAll()
	f.kv.fail = errors.New("kv down")
	if err := f.p.Pull(context.Background(), cis.USpaceAirspace, false); err != nil {
		t.Fatal(err)
	}
	if line := f.p.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "KV cis_current not written") {
		t.Fatalf("status %s", line)
	}
	if f.p.Counters().Get(cis.CounterProjectionFailed) != 1 {
		t.Fatal("cis_projection_failed")
	}
	f.kv.mu.Lock()
	f.kv.fail = nil
	f.kv.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.p.Run(ctx)
	waitFor(t, 3*time.Second, "the reconciliation to write KV", func() bool { return f.kv.value("uspace_airspace") != nil })
}

// A dataset never published (404 no_version) is known empty, not a
// failure; the status says so.
func TestNoVersionYet(t *testing.T) {
	f := newProjection(t, nil)
	if err := f.p.Pull(context.Background(), cis.Restrictions, false); err != nil {
		t.Fatal(err)
	}
	r := f.p.Status(context.Background(), time.Now())
	if !strings.Contains(r.Line(), "restrictions: no version published yet") || r.State == cis.StateDown {
		t.Fatalf("status %s", r.Line())
	}
}

// The CISP serving its held snapshot (X-CIS-Stale) is counted and named.
func TestUpstreamStaleNamed(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.stub.stale = true
	f.pullAll(t)
	if f.p.Counters().Get(cis.CounterUpstreamStale) != 3 || !strings.Contains(f.p.Status(context.Background(), time.Now()).Line(), "X-CIS-Stale") {
		t.Fatal("upstream staleness hidden")
	}
}

// One test, the stub's log: the subscription is registered at start and
// the reconciliation pulls every dataset again within cis_reconcile_s
// without any notification (presence of both).
func TestSubscriptionAndReconciliationObserved(t *testing.T) {
	f := newProjection(t, func(c *cis.Config) {
		c.Policy = fixedPolicy(1)
		c.CallbackURL = "https://ansp.example.invalid/v1/cis/notifications"
	})
	f.stub.publishAll()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { f.p.Run(ctx) })
	waitFor(t, 5*time.Second, "two reads of every dataset and a subscription", func() bool {
		for _, d := range cis.Datasets {
			if len(f.stub.requests("GET", "/v1/"+string(d))) < 2 {
				return false
			}
		}
		return len(f.stub.requests("POST", "/v1/subscriptions")) == 1
	})
	cancel()
	wg.Wait()
	post := f.stub.requests("POST", "/v1/subscriptions")[0]
	if !strings.Contains(post.Body, `"callback_url":"https://ansp.example.invalid/v1/cis/notifications"`) ||
		!strings.Contains(post.Body, "uspace_airspace") || !strings.Contains(post.Body, "ussp_list") || !strings.Contains(post.Body, "restrictions") {
		t.Fatalf("subscription body %s", post.Body)
	}
	if f.p.SubscriptionID() != "sub-1" {
		t.Fatalf("subscription id %q", f.p.SubscriptionID())
	}
	reads := f.stub.requests("GET", "/v1/uspace_airspace")
	if reads[1].IfNoneMatch == "" {
		t.Fatal("the reconciliation read without If-None-Match")
	}
}

// A restart reuses the subscription (listed by its callback); the CISP
// forgetting it registers it again; a suspended one is re-activated.
func TestSubscriptionLifecycle(t *testing.T) {
	cb := "https://ansp.example.invalid/v1/cis/notifications"
	f := newProjection(t, func(c *cis.Config) { c.CallbackURL = cb })
	ctx := context.Background()
	if err := f.p.EnsureSubscription(ctx); err != nil || f.p.SubscriptionID() != "sub-1" {
		t.Fatalf("first: %v %q", err, f.p.SubscriptionID())
	}
	// Absence: a check of a known subscription registers nothing.
	if err := f.p.EnsureSubscription(ctx); err != nil || len(f.stub.requests("POST", "/v1/subscriptions")) != 1 {
		t.Fatal("registered twice")
	}
	// A restarted process finds it by its callback.
	again := cis.New(cis.Config{Client: f.stub.client(t), CallbackURL: cb})
	if err := again.EnsureSubscription(ctx); err != nil || again.SubscriptionID() != "sub-1" || len(f.stub.requests("POST", "/v1/subscriptions")) != 1 {
		t.Fatalf("restart: %v %q", err, again.SubscriptionID())
	}
	// Presence: unknown at the CISP, registered again.
	f.stub.forgetSubscriptions()
	if err := f.p.EnsureSubscription(ctx); err != nil || f.p.SubscriptionID() != "sub-2" || f.p.Counters().Get(cis.CounterResubscribed) != 1 {
		t.Fatalf("re-registration: %v %q", err, f.p.SubscriptionID())
	}
	f.stub.suspend("sub-2")
	if err := f.p.EnsureSubscription(ctx); err != nil || len(f.stub.requests("PATCH", "/v1/subscriptions/sub-2")) != 1 {
		t.Fatalf("suspended not re-activated: %v", err)
	}
	// The CISP down: the failure is counted and named.
	f.stub.setDown(true)
	if err := cis.New(cis.Config{Client: f.stub.client(t), CallbackURL: cb}).EnsureSubscription(ctx); err == nil {
		t.Fatal("subscribed to a dead CISP")
	}
}

// A warm start serves cis_cache with its stored age before any pull and
// projects it.
func TestWarmFromStore(t *testing.T) {
	f := newProjection(t, nil)
	f.stub.publishAll()
	f.pullAll(t)
	kv := newMemKV()
	old := time.Now().Add(-100 * time.Second)
	f.store.mu.Lock()
	r := f.store.rows[cis.USpaceAirspace]
	r.FetchedAt = old
	f.store.rows[cis.USpaceAirspace] = r
	f.store.mu.Unlock()
	p := cis.New(cis.Config{Store: f.store, KV: kv})
	p.Warm(context.Background())
	v, at, _, err := p.USpaceAirspace()
	if err != nil || v != "3" || !at.Equal(old) || kv.value("uspace_airspace") == nil {
		t.Fatalf("warm: %v %v %v", v, at, err)
	}
	// No CISP configured: Run returns after the warm-up and the status
	// says why nothing moves.
	p.Run(context.Background())
	if line := p.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "no CISP configured") {
		t.Fatalf("status %s", line)
	}
	if err := p.Pull(context.Background(), cis.USpaceAirspace, false); !errors.Is(err, cis.ErrNoCISP) {
		t.Fatal(err)
	}
	// A store that cannot be read is named.
	bad := newMemStore()
	bad.fail = errors.New("db down")
	q := cis.New(cis.Config{Store: bad})
	q.Warm(context.Background())
	if line := q.Status(context.Background(), time.Now()).Line(); !strings.Contains(line, "cis_cache not read") {
		t.Fatalf("status %s", line)
	}
}
