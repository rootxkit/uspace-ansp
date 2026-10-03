package cis_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// receiverFixture is a running projection on the stub with the receiver
// in front of it, verifying with core's CompactVerifier over the CISP's
// test key.
type receiverFixture struct {
	*fixtureProjection
	rc  *cis.Receiver
	jti atomic.Int64
}

func newReceiver(t *testing.T, mutate func(*cis.ReceiverConfig)) *receiverFixture {
	t.Helper()
	f := &receiverFixture{fixtureProjection: newProjection(t, func(c *cis.Config) {
		c.CallbackURL = "https://" + ourHost + cis.NotificationsPath
	})}
	f.stub.publishAll()
	f.pullAll(t)
	if err := f.p.EnsureSubscription(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
		Issuers:   map[string]coreauth.IssuerConfig{cispIssuer: {Keys: cispRing.JWKS()}},
		Audiences: []string{ourHost, labAlias},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := cis.ReceiverConfig{Verifier: v, Subscription: f.p.SubscriptionID, Store: f.store, Guard: f.stub.client(t), Trigger: f.p.Trigger,
		Counters: f.p.Counters()}
	if mutate != nil {
		mutate(&cfg)
	}
	f.rc = cis.NewReceiver(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go f.p.Run(ctx)
	// Let the start-up pulls of Run finish, so a test's measurement and
	// request counts see only what it caused.
	waitFor(t, 3*time.Second, "the start-up pulls", func() bool {
		for _, d := range cis.Datasets {
			if len(f.stub.requests("GET", "/v1/"+string(d))) < 2 {
				return false
			}
		}
		return true
	})
	time.Sleep(20 * time.Millisecond)
	return f
}

// change is a cis/change/v1 record.
func (f *receiverFixture) change(d cis.Dataset, v int64, reason, pullURL string) json.RawMessage {
	if pullURL == "" {
		pullURL = f.stub.srv.URL + "/v1/" + string(d) + "?since_version=" + strconv.FormatInt(v-1, 10)
	}
	b, _ := json.Marshal(map[string]any{
		"schema": "cis/change/v1", "msg_id": "42", "producer": "cisp/deliver-1", "dataset": d, "version": v,
		"etag": `"` + string(d) + ":" + strconv.FormatInt(v, 10) + `"`, "feature_ids": []string{}, "removed_ids": []string{},
		"reason": reason, "at": time.Now().UTC().Format(time.RFC3339Nano), "pull_url": pullURL,
	})
	return b
}

// sign is the CISP's delivery JWS for body.
func (f *receiverFixture) sign(t *testing.T, ring *coreauth.KeyRing, iss, aud, sub, jti string, body json.RawMessage) string {
	t.Helper()
	if jti == "" {
		jti = "d-" + strconv.FormatInt(f.jti.Add(1), 10)
	}
	tok, err := ring.SignCompact(coreauth.CompactClaims{Issuer: iss, Audience: aud, Subject: sub, JTI: jti}, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *receiverFixture) post(token, ctype string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, cis.NotificationsPath, strings.NewReader(token))
	req.Header.Set("Content-Type", ctype)
	w := httptest.NewRecorder()
	f.rc.ServeHTTP(w, req)
	return w
}

func (f *receiverFixture) valid(t *testing.T, d cis.Dataset, v int64, reason, pullURL string) string {
	return f.sign(t, cispRing, cispIssuer, ourHost, f.p.SubscriptionID(), "", f.change(d, v, reason, pullURL))
}

// A valid notification answers 202 and the pull it triggers installs
// the new version within 100 ms (measured).
func TestNotificationTriggersPull(t *testing.T) {
	f := newReceiver(t, nil)
	f.stub.publish(cis.USpaceAirspace, 4, fixture(t, cis.USpaceAirspace, 4), "publisher")
	installed := f.p.Installed(cis.USpaceAirspace)
	start := time.Now()
	w := f.post(f.valid(t, cis.USpaceAirspace, 4, "publication", ""), cis.ContentTypeJOSE)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	select {
	case <-installed:
	case <-time.After(2 * time.Second):
		t.Fatal("the notification did not reach the projection")
	}
	took := time.Since(start)
	if n := len(f.stub.requests("GET", "/v1/uspace_airspace/versions/4")); n != 1 {
		t.Fatalf("version 4 was read %d times", n)
	}
	t.Logf("notification to installed version: %v", took)
	if took > 100*time.Millisecond {
		t.Fatalf("the notification path took %v, the budget is 100 ms", took)
	}
	if f.p.Version(cis.USpaceAirspace) != 4 || f.p.Counters().Get(cis.CounterNotifyAccepted) != 1 {
		t.Fatal("not installed or not counted")
	}
	if f.p.Counters().Get(cis.CounterPullURLMismatch) != 0 {
		t.Fatal("a pull_url on the CISP's host was counted as a mismatch")
	}
}

// Refusals: a bad signature, an issuer not on the list, a wrong aud
// (the system id, another system's host) are 401 and pull nothing; the
// lab alias is accepted (the twin).
func TestNotificationRefusals(t *testing.T) {
	f := newReceiver(t, nil)
	body := func() json.RawMessage { return f.change(cis.USpaceAirspace, 3, "publication", "") }
	sub := f.p.SubscriptionID()
	for _, tc := range []struct {
		name  string
		token string
		code  int
	}{
		{"signed by another key", f.sign(t, otherRing, cispIssuer, ourHost, sub, "", body()), 401},
		{"tampered", tamper(f.sign(t, cispRing, cispIssuer, ourHost, sub, "", body())), 401},
		{"issuer not on the list", f.sign(t, cispRing, "https://rogue.example.invalid", ourHost, sub, "", body()), 401},
		{"aud the system id", f.sign(t, cispRing, cispIssuer, "ansp-01", sub, "", body()), 401},
		{"aud another system's host", f.sign(t, cispRing, cispIssuer, "ussp.example.invalid", sub, "", body()), 401},
		{"another subscription", f.sign(t, cispRing, cispIssuer, ourHost, "sub-99", "", body()), 401},
		{"not a JWS", "hello", 401},
		{"the lab alias", f.sign(t, cispRing, cispIssuer, labAlias, sub, "", body()), 202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.post(tc.token, cis.ContentTypeJOSE)
			if w.Code != tc.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if tc.code == 401 && !strings.Contains(w.Body.String(), "problems/signature") {
				t.Fatalf("problem %s", w.Body)
			}
		})
	}
	if got := f.p.Counters().Get(cis.CounterNotifyBadSignature); got != 6 {
		t.Fatalf("cis_notify_bad_signature %d", got)
	}
	if got := f.p.Counters().Get(cis.CounterNotifyWrongSub); got != 1 {
		t.Fatalf("cis_notify_wrong_subscription %d", got)
	}
}

// A replayed delivery id is acknowledged 204 without a pull (the
// contract: the CISP stops retrying), counted; the first was 202.
func TestNotificationReplay(t *testing.T) {
	f := newReceiver(t, nil)
	tok := f.sign(t, cispRing, cispIssuer, ourHost, f.p.SubscriptionID(), "dup-1", f.change(cis.USpaceAirspace, 3, "publication", ""))
	if w := f.post(tok, cis.ContentTypeJOSE); w.Code != http.StatusAccepted {
		t.Fatalf("first %d", w.Code)
	}
	if w := f.post(tok, cis.ContentTypeJOSE); w.Code != http.StatusNoContent {
		t.Fatalf("replay %d %s", w.Code, w.Body)
	}
	if f.p.Counters().Get(cis.CounterNotifyReplayed) != 1 || f.p.Counters().Get(cis.CounterNotifyAccepted) != 1 {
		t.Fatal("counters")
	}
}

// subscription_test, republished and a reason this build does not know
// answer 204 and send no request to the CISP; the twin: publication
// answers 202 and makes one read.
func TestNoopReasonsPullNothing(t *testing.T) {
	f := newReceiver(t, nil)
	before := len(f.stub.requests("GET", ""))
	for _, reason := range []string{"subscription_test", "republished", "zone_reshuffled"} {
		if w := f.post(f.valid(t, cis.USpaceAirspace, 3, reason, ""), cis.ContentTypeJOSE); w.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", reason, w.Code)
		}
	}
	// A dataset this system does not project is acknowledged too.
	if w := f.post(f.sign(t, cispRing, cispIssuer, ourHost, f.p.SubscriptionID(), "", f.change("zones", 9, "publication", "")), cis.ContentTypeJOSE); w.Code != http.StatusNoContent {
		t.Fatalf("zones: %d", w.Code)
	}
	time.Sleep(100 * time.Millisecond)
	if after := len(f.stub.requests("GET", "")); after != before {
		t.Fatalf("a no-op reason made %d requests", after-before)
	}
	if f.p.Counters().Get(cis.CounterNotifyNoop) != 4 || f.p.Counters().Get(cis.CounterNotifyUnknownReason) != 2 {
		t.Fatalf("noop %d unknown %d", f.p.Counters().Get(cis.CounterNotifyNoop), f.p.Counters().Get(cis.CounterNotifyUnknownReason))
	}
	if w := f.post(f.valid(t, cis.USpaceAirspace, 3, "publication", ""), cis.ContentTypeJOSE); w.Code != http.StatusAccepted {
		t.Fatalf("publication: %d", w.Code)
	}
	waitFor(t, 2*time.Second, "one read after a publication", func() bool { return len(f.stub.requests("GET", "")) == before+1 })
}

// A pull_url on a foreign host (or plain http) is never followed: the
// configured dataset URL is pulled and the mismatch counted.
func TestForeignPullURL(t *testing.T) {
	f := newReceiver(t, nil)
	f.stub.publish(cis.USSPList, 3, fixture(t, cis.USSPList, 3), "publisher")
	installed := f.p.Installed(cis.USSPList)
	w := f.post(f.valid(t, cis.USSPList, 3, "publication", "https://evil.example.invalid/v1/ussp_list"), cis.ContentTypeJOSE)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
	select {
	case <-installed:
	case <-time.After(2 * time.Second):
		t.Fatal("the configured URL was not pulled")
	}
	if f.p.Version(cis.USSPList) != 3 || f.p.Counters().Get(cis.CounterPullURLMismatch) != 1 {
		t.Fatal("not pulled from the configured URL or not counted")
	}
	plain := strings.Replace(f.stub.srv.URL, "https://", "http://", 1) + "/v1/ussp_list"
	if w := f.post(f.valid(t, cis.USSPList, 3, "publication", plain), cis.ContentTypeJOSE); w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
	if f.p.Counters().Get(cis.CounterPullURLMismatch) != 2 {
		t.Fatal("plain http followed")
	}
}

// The body bounds and the media type (E-10), and a record that is not
// cis/change/v1.
func TestNotificationShape(t *testing.T) {
	f := newReceiver(t, nil)
	if w := f.post(f.valid(t, cis.USpaceAirspace, 3, "publication", ""), "application/json"); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("media type %d", w.Code)
	}
	if w := f.post(strings.Repeat("a", cis.MaxNotificationBytes+1), cis.ContentTypeJOSE); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large %d", w.Code)
	}
	bad, _ := json.Marshal(map[string]any{"schema": "cis/change/v2", "dataset": "uspace_airspace", "version": 1, "reason": "publication"})
	if w := f.post(f.sign(t, cispRing, cispIssuer, ourHost, f.p.SubscriptionID(), "", bad), cis.ContentTypeJOSE); w.Code != http.StatusBadRequest {
		t.Fatalf("schema %d %s", w.Code, w.Body)
	}
	for _, m := range []map[string]any{
		{"schema": "cis/change/v1", "dataset": "", "version": 1, "reason": "publication"},
		{"schema": "cis/change/v1", "dataset": "uspace_airspace", "version": -1, "reason": "publication"},
		{"schema": "cis/change/v1", "dataset": "uspace_airspace", "version": 1, "reason": ""},
		{"schema": "cis/change/v1", "dataset": 7},
	} {
		b, _ := json.Marshal(m)
		if w := f.post(f.sign(t, cispRing, cispIssuer, ourHost, f.p.SubscriptionID(), "", b), cis.ContentTypeJOSE); w.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", m, w.Code)
		}
	}
	// The body limit enforced by the server's MaxBytesReader is 413 too.
	req := httptest.NewRequest(http.MethodPost, cis.NotificationsPath, strings.NewReader(strings.Repeat("a", 100)))
	req.Header.Set("Content-Type", cis.ContentTypeJOSE)
	w := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(w, req.Body, 10)
	f.rc.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("max bytes %d", w.Code)
	}
}

// Fail closed: no subscription registered yet, the delivery-id store
// down, or full, all answer 503 so the CISP retries; nothing is pulled.
func TestNotificationUnavailable(t *testing.T) {
	f := newReceiver(t, nil)
	tok := f.valid(t, cis.USpaceAirspace, 3, "publication", "")

	none := newReceiver(t, func(c *cis.ReceiverConfig) { c.Subscription = func() string { return "" } })
	if w := none.post(none.valid(t, cis.USpaceAirspace, 3, "publication", ""), cis.ContentTypeJOSE); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("no subscription %d", w.Code)
	}

	f.store.mu.Lock()
	f.store.fail = errors.New("db down")
	f.store.mu.Unlock()
	if w := f.post(tok, cis.ContentTypeJOSE); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("store down %d", w.Code)
	}
	f.store.mu.Lock()
	f.store.fail = nil
	for i := 0; i < cis.MaxLiveJTIs; i++ {
		f.store.jtis["x "+strconv.Itoa(i)] = time.Now().Add(time.Hour)
	}
	f.store.mu.Unlock()
	if w := f.post(tok, cis.ContentTypeJOSE); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("full %d", w.Code)
	}
	if f.p.Counters().Get(cis.CounterNotifyStoreFailed) != 1 || f.p.Counters().Get(cis.CounterNotifyJTIFull) != 1 {
		t.Fatal("counters")
	}
	// The twin: room again, the same delivery is accepted.
	f.store.mu.Lock()
	f.store.jtis = map[string]time.Time{}
	f.store.mu.Unlock()
	if w := f.post(tok, cis.ContentTypeJOSE); w.Code != http.StatusAccepted {
		t.Fatalf("after %d", w.Code)
	}
}

// Without a pull_url guard every pull_url is counted as unchecked, not
// as a mismatch (ansp audit N-7: the mismatch counter means a pull_url
// off the configured CISP); the configured URL is still pulled.
func TestNoGuardCountsEveryPullURL(t *testing.T) {
	f := newReceiver(t, func(c *cis.ReceiverConfig) { c.Guard = nil })
	if w := f.post(f.valid(t, cis.USpaceAirspace, 3, "publication", ""), cis.ContentTypeJOSE); w.Code != http.StatusAccepted {
		t.Fatal(w.Code)
	}
	if f.p.Counters().Get(cis.CounterPullURLUnchecked) != 1 || f.p.Counters().Get(cis.CounterPullURLMismatch) != 0 {
		t.Fatalf("counters %v", f.p.Counters().Snapshot())
	}
}

// The lazy verifier refuses every notification, counted, until its keys
// are fetched, and says so.
func TestLazyNotifyVerifier(t *testing.T) {
	addr := freePort(t)
	l := cis.NewLazyNotifyVerifier(coreauth.CompactConfig{
		Issuers: map[string]coreauth.IssuerConfig{cispIssuer: {JWKSURL: "https://" + addr + "/jwks"}}, Audiences: []string{ourHost},
		JWKSFetchTimeout: 200 * time.Millisecond,
	}, time.Millisecond, nil)
	if ok, why := l.Ready(); ok || why == "" {
		t.Fatal("ready before a fetch")
	}
	var te *coreauth.TokenError
	if _, _, err := l.Verify(context.Background(), "a.b.c"); !errors.As(err, &te) || te.Counter != cis.CounterNotifyKeysUnavailable {
		t.Fatalf("%v", err)
	}
	if err := l.Build(context.Background()); err == nil {
		t.Fatal("built without keys")
	}
	if ok, why := l.Ready(); ok || !strings.Contains(why, "not fetched") {
		t.Fatal(why)
	}
	if l.Counters() != nil {
		t.Fatal("counters before build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	l.Run(ctx) // returns when ctx ends

	// The twin: static keys build at once and verify.
	rings(t)
	ok := cis.NewLazyNotifyVerifier(coreauth.CompactConfig{
		Issuers: map[string]coreauth.IssuerConfig{cispIssuer: {Keys: cispRing.JWKS()}}, Audiences: []string{ourHost},
	}, 0, nil)
	ok.Run(context.Background())
	if r, _ := ok.Ready(); !r || ok.Counters() == nil {
		t.Fatal("not built")
	}
	tok, _ := cispRing.SignCompact(coreauth.CompactClaims{Issuer: cispIssuer, Audience: ourHost, Subject: "s", JTI: "j"}, json.RawMessage(`{}`), time.Now())
	if _, _, err := ok.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
}

// The lazy publisher verifier holds every version until its keys are
// fetched; the twin builds and verifies.
func TestLazyPublisherVerifier(t *testing.T) {
	addr := freePort(t)
	l := cis.NewLazyPublisherVerifier(coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{cis.PublisherAuthority: {JWKSURL: "https://" + addr + "/jwks"}}, JWKSFetchTimeout: 200 * time.Millisecond,
	}, 0)
	if _, err := l.Verify(context.Background(), cis.PublisherAuthority, "h", []byte("x")); err == nil {
		t.Fatal("verified without keys")
	}
	if l.Counters() != nil {
		t.Fatal("counters")
	}
	rings(t)
	ok := cis.NewLazyPublisherVerifier(coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{cis.PublisherAuthority: {Keys: authorityRing.JWKS()}},
	}, 0)
	ok.Run(context.Background())
	h, _ := authorityRing.SignDetached([]byte("payload"), time.Now())
	if _, err := ok.Verify(context.Background(), cis.PublisherAuthority, h, []byte("payload")); err != nil || ok.Counters() == nil {
		t.Fatal(err)
	}
}

// tamper flips one character of the signature part.
func tamper(tok string) string {
	i := strings.LastIndex(tok, ".") + 5
	c := byte('A')
	if tok[i] == 'A' {
		c = 'B'
	}
	return tok[:i] + string(c) + tok[i+1:]
}
