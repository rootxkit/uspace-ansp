package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// call runs one request through mw and returns the recorder and the
// principal the handler saw (nil when it did not run).
func call(t testing.TB, mw func(http.Handler) http.Handler, method, path string, hdr map[string]string) (*httptest.ResponseRecorder, *Principal) {
	t.Helper()
	var seen *Principal
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := PrincipalFrom(r.Context()); ok {
			seen = &p
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, seen
}

func problemOf(t testing.TB, rec *httptest.ResponseRecorder) ProblemBody {
	t.Helper()
	var p ProblemBody
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem: %s", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" || p.Status != rec.Code {
		t.Fatalf("problem headers %v body %+v", rec.Header(), p)
	}
	return p
}

func withBearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

// E-01: an accepted token next to each refusal of aud. The public host
// and the lab alias are accepted; "ansp" (ANSP_SYSTEM_ID) and another
// system's host are refused as rejected_audience, with core's counter.
func TestMachineAudiencePairs(t *testing.T) {
	w := newWorld(t)
	mw := w.guard.RequireScopes("ansp.traffic")
	for _, aud := range []string{ownHost, labAlias} {
		rec, p := call(t, mw, http.MethodGet, "/v1/x", withBearer(w.eco.token(t, "authority-01", aud, []string{"ansp.traffic"}, w.clock.Now())))
		if rec.Code != http.StatusOK || p == nil || p.Claims.Subject != "authority-01" || p.Claims.Audience != aud || p.Session {
			t.Fatalf("aud %s: %d %+v", aud, rec.Code, p)
		}
		cl, ok := ClaimsFrom(context.WithValue(context.Background(), principalKey{}, *p))
		if !ok || cl.Subject != "authority-01" {
			t.Fatal("ClaimsFrom")
		}
	}
	for _, aud := range []string{"ansp", "cisp.test"} {
		tok := w.eco.token(t, "authority-01", aud, []string{"ansp.traffic"}, w.clock.Now())
		rec, p := call(t, mw, http.MethodGet, "/v1/x", withBearer(tok))
		if pb := problemOf(t, rec); rec.Code != http.StatusUnauthorized || p != nil || pb.Slug() != coreauth.CounterRejectedAudience ||
			pb.Errors[0].Field != "aud" || strings.Contains(rec.Body.String(), tok) {
			t.Fatalf("aud %s: %d %s", aud, rec.Code, rec.Body.String())
		}
	}
	m := w.guard.Machine.(*MachineVerifier)
	if m.Counters().Get(coreauth.CounterAccepted) != 2 || m.Counters().Get(coreauth.CounterRejectedAudience) != 2 ||
		w.guard.Counters().Get(CounterMachineAccepted) != 2 || w.guard.Counters().Get(CounterTokenRefused) != 2 {
		t.Fatalf("counters %v %v", m.Counters().Snapshot(), w.guard.Counters().Snapshot())
	}
}

// Every listed scope is required; one missing is 403, all present 200.
func TestRequireScopesEveryScope(t *testing.T) {
	w := newWorld(t)
	mw := w.guard.RequireScopes("ansp.coordination", "ansp.requests")
	rec, _ := call(t, mw, http.MethodGet, "/v1/x", withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.coordination"}, w.clock.Now())))
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Slug() != SlugForbidden || pb.Errors[0].Reason != "missing ansp.requests" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec, p := call(t, mw, http.MethodGet, "/v1/x", withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.coordination", "ansp.requests"}, w.clock.Now())))
	if rec.Code != http.StatusOK || p == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestNoOrBadBearer(t *testing.T) {
	w := newWorld(t)
	mw := w.guard.RequireScopes("ansp.traffic")
	for name, hdr := range map[string]map[string]string{
		"none":   nil,
		"basic":  {"Authorization": "Basic dXNlcjpwYXNz"},
		"empty":  {"Authorization": "Bearer "},
		"nospce": {"Authorization": "Bearer"},
	} {
		rec, p := call(t, mw, http.MethodGet, "/v1/x", hdr)
		if pb := problemOf(t, rec); rec.Code != http.StatusUnauthorized || p != nil || pb.Slug() != SlugUnauthenticated ||
			rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Two Authorization headers: refused, not "the first one wins".
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("served") }))
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	tok := w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now())
	r.Header.Add("Authorization", "Bearer "+tok)
	r.Header.Add("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized || w.guard.Counters().Get(CounterNoCredential) != 5 {
		t.Fatalf("%d %v", rec.Code, w.guard.Counters().Snapshot())
	}
}

// A guard without a machine verifier refuses every ecosystem token
// (counted) and still admits sessions.
func TestNoMachineVerifier(t *testing.T) {
	w := newWorld(t)
	w.guard.Machine = nil
	rec, _ := call(t, w.guard.Require(Access{Scopes: []string{"ansp.traffic"}, AnyRole: true}), http.MethodGet, "/v1/x",
		withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now())))
	if rec.Code != http.StatusUnauthorized || w.guard.Counters().Get(CounterNoMachineVerifier) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	w.addUser(t, "viewer1", "a long password 1", RoleViewer)
	res, _ := w.signIn(t, "viewer1", "a long password 1")
	rec, p := call(t, w.guard.Require(Access{Scopes: []string{"ansp.traffic"}, AnyRole: true}), http.MethodGet, "/v1/x", withBearer(res.Token))
	if rec.Code != http.StatusOK || !p.Session {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// A machine token on a session-only route is 403, after it verified.
func TestMachineOnSessionRoute(t *testing.T) {
	w := newWorld(t)
	rec, _ := call(t, w.guard.RequireRole(RoleAdmin), http.MethodGet, "/v1/x", withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now())))
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Detail != "this operation requires a console session" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestAccessValidate(t *testing.T) {
	for _, bad := range []Access{
		{}, {Public: true, Scopes: []string{"a"}}, {Public: true, MTLS: true}, {Roles: []string{"pilot"}},
		{Scopes: []string{""}}, {MTLS: true, AnyRole: true}, {AnyRole: true, Roles: []string{RoleAdmin}},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v validated", bad)
		}
	}
	for _, good := range []Access{{Public: true}, {Scopes: []string{"a"}, MTLS: true}, {AnyRole: true}, {Roles: Roles}} {
		if err := good.Validate(); err != nil {
			t.Fatalf("%+v: %v", good, err)
		}
	}
	if s := (Access{Scopes: []string{"ansp.traffic"}, MTLS: true, AnyRole: true}).String(); s != "token:ansp.traffic+mtls or session" {
		t.Fatal(s)
	}
	if s := (Access{Roles: []string{RoleAdmin, RoleViewer}}).String(); s != "session:admin|viewer" {
		t.Fatal(s)
	}
	if (Access{Public: true}).String() != "public" {
		t.Fatal("public")
	}
	// An invalid access refuses everything with 500 (fail closed).
	w := newWorld(t)
	rec, _ := call(t, w.guard.Require(Access{}), http.MethodGet, "/v1/x", nil)
	if rec.Code != http.StatusInternalServerError || w.guard.Counters().Get(CounterMisconfigured) != 1 {
		t.Fatalf("%d", rec.Code)
	}
	rec, _ = call(t, w.guard.Require(Access{Public: true}), http.MethodGet, "/v1/x", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("public: %d", rec.Code)
	}
}

// E-01 for mTLS with ANSP_MTLS_MODE=required: the subject bound to sub
// is accepted; another subject, an absent header, two headers and an
// unmapped sub are refused 403 without naming either subject.
func TestMTLSRequiredPairs(t *testing.T) {
	w := newWorld(t)
	mw := w.guard.Require(Access{Scopes: []string{"ansp.coordination"}, MTLS: true})
	tok := w.eco.token(t, ussp, ownHost, []string{"ansp.coordination"}, w.clock.Now())
	hdr := withBearer(tok)
	hdr[HeaderClientCertSubject] = "CN=" + ussp
	rec, p := call(t, mw, http.MethodPost, "/v1/coordination/notices", hdr)
	if rec.Code != http.StatusOK || p.MTLSSubject != "CN="+ussp {
		t.Fatalf("matching subject: %d %s", rec.Code, rec.Body.String())
	}
	hdr[HeaderClientCertSubject] = "CN=someone-else"
	rec, _ = call(t, mw, http.MethodPost, "/v1/coordination/notices", hdr)
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Slug() != SlugMTLSMismatch || strings.Contains(rec.Body.String(), "someone-else") ||
		strings.Contains(rec.Body.String(), "CN="+ussp) {
		t.Fatalf("mismatch: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = call(t, mw, http.MethodPost, "/v1/coordination/notices", withBearer(tok))
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Slug() != SlugMTLSRequired {
		t.Fatalf("absent: %d %s", rec.Code, rec.Body.String())
	}
	other := withBearer(w.eco.token(t, "ussp-geo-02", ownHost, []string{"ansp.coordination"}, w.clock.Now()))
	other[HeaderClientCertSubject] = "CN=ussp-geo-02"
	rec, _ = call(t, mw, http.MethodPost, "/v1/coordination/notices", other)
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Errors[0].Reason != "no binding" {
		t.Fatalf("unmapped: %d %s", rec.Code, rec.Body.String())
	}
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("served") }))
	r := httptest.NewRequest(http.MethodPost, "/v1/coordination/notices", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Add(HeaderClientCertSubject, "CN="+ussp)
	r.Header.Add(HeaderClientCertSubject, "CN="+ussp)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("two headers: %d", rec.Code)
	}
	c := w.guard.MTLS.Counters()
	if c.Get(CounterMTLSAccepted) != 1 || c.Get(CounterMTLSMismatch) != 1 || c.Get(CounterMTLSAbsent) != 2 || c.Get(CounterMTLSUnbound) != 1 ||
		w.guard.Counters().Get(CounterMTLSRefused) != 4 {
		t.Fatalf("counters %v %v", c.Snapshot(), w.guard.Counters().Snapshot())
	}
	// A route that binds certificates with no binding configured fails
	// closed.
	w.guard.MTLS = nil
	rec, _ = call(t, mw, http.MethodPost, "/v1/coordination/notices", hdr)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("no MTLS: %d", rec.Code)
	}
}

// syncBuffer is a log sink a test can read while the server writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// With ANSP_MTLS_MODE=off a call without the header is accepted
// (counted as unchecked) while obs.Server logs the mode at error level
// every status period (E-01 pair of the test above, E-02: read the
// line).
func TestMTLSOffAcceptsAndIsLogged(t *testing.T) {
	w := newWorld(t)
	off, err := NewMTLS(config.MTLSOff, nil)
	must(t, err)
	w.guard.MTLS = off
	mux := http.NewServeMux()
	mux.Handle("GET /v1/manned-traffic/snapshot", w.guard.Require(Access{Scopes: []string{"ansp.traffic"}, MTLS: true})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	cfg := config.Config{Process: config.ProcessMannedFeed, Instance: "t", HTTPAddr: "127.0.0.1:0", MTLSMode: config.MTLSOff, LogLevel: "info"}
	logs := &syncBuffer{}
	srv := &obs.Server{Config: cfg, Logger: obs.LoggerTo(logs, cfg), Registry: obs.Metrics(), Mux: mux, StatusPeriod: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	for deadline := time.Now().Add(5 * time.Second); strings.Count(logs.String(), "mTLS is off") < 2; {
		if time.Now().After(deadline) {
			t.Fatalf("no error-level mTLS line:\n%s", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/snapshot", nil)
	r.Header.Set("Authorization", "Bearer "+w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	cancel()
	must(t, <-done)
	if rec.Code != http.StatusOK || off.Counters().Get(CounterMTLSOffSkipped) != 1 || off.Mode() != config.MTLSOff {
		t.Fatalf("%d %v", rec.Code, off.Counters().Snapshot())
	}
	if !strings.Contains(logs.String(), `"level":"ERROR","msg":"mTLS is off`) {
		t.Fatalf("not at error level:\n%s", logs.String())
	}
}

func TestNewMTLS(t *testing.T) {
	if _, err := NewMTLS(config.MTLSRequired, nil); err == nil {
		t.Fatal("required without bindings")
	}
	if _, err := NewMTLS("sometimes", nil); err == nil {
		t.Fatal("unknown mode")
	}
	m, err := NewMTLS(config.MTLSRequired, map[string]string{"a": "CN=a"})
	if err != nil || m.Mode() != config.MTLSRequired {
		t.Fatal(err)
	}
}

func TestParseMTLSBindings(t *testing.T) {
	b, err := ParseMTLSBindings([]byte(`[{"sub":"ussp-geo-01","subject":"CN=ussp-geo-01,O=Test"},{"sub":"authority-01","subject":" CN=a "}]`))
	if err != nil || b["ussp-geo-01"] != "CN=ussp-geo-01,O=Test" || b["authority-01"] != "CN=a" {
		t.Fatalf("%v %v", b, err)
	}
	for name, raw := range map[string]string{
		"duplicate": `[{"sub":"a","subject":"CN=a"},{"sub":"a","subject":"CN=b"}]`,
		"empty":     `[{"sub":"a","subject":""}]`,
		"object":    `{"a":"CN=a"}`,
		"unknown":   `[{"sub":"a","subject":"CN=a","trust":"tofu"}]`,
		"long":      `[{"sub":"a","subject":"` + strings.Repeat("x", MaxSubjectBytes+1) + `"}]`,
	} {
		if _, err := ParseMTLSBindings([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	many := make([]Binding, MaxBindings+1)
	for i := range many {
		many[i] = Binding{Sub: strings.Repeat("a", i%50+1) + string(rune('a'+i%26)) + strings.Repeat("b", i/50), Subject: "CN=x"}
	}
	raw, _ := json.Marshal(many)
	if _, err := ParseMTLSBindings(raw); err == nil {
		t.Fatal("more than MaxBindings accepted")
	}
	dir := t.TempDir()
	p := dir + "/bindings.json"
	must(t, writeFile(p, `[{"sub":"a","subject":"CN=a"}]`))
	if b, err := LoadMTLSBindings(p); err != nil || b["a"] != "CN=a" {
		t.Fatal(err)
	}
	if _, err := LoadMTLSBindings(dir + "/missing.json"); err == nil {
		t.Fatal("missing file")
	}
}

// E-02: the issuer's JWKS becomes unreachable after start: tokens are
// still verified from core's cache and readiness says jwks degraded,
// "stale (age N s)"; with the JWKS back it says ok again.
func TestJWKSOutageAfterStart(t *testing.T) {
	w := newWorld(t)
	m := w.guard.Machine.(*MachineVerifier)
	chk := m.Check()
	if s, reason := chk.Probe(context.Background()); s != obs.StateOK || reason != "" || chk.Name != obs.DepJWKS || !chk.Required {
		t.Fatalf("%s %s", s, reason)
	}
	w.eco.down.Store(true)
	w.clock.Add(42 * time.Second)
	rec, _ := call(t, w.guard.RequireScopes("ansp.traffic"), http.MethodGet, "/v1/x", withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now())))
	if rec.Code != http.StatusOK {
		t.Fatalf("cached keys: %d %s", rec.Code, rec.Body.String())
	}
	s, reason := chk.Probe(context.Background())
	if s != obs.StateDegraded || reason != "https://authority.test: stale (age 42 s: HTTP 502)" {
		t.Fatalf("%s %q", s, reason)
	}
	rep := (&obs.Health{Process: "api"}).Check(context.Background(), chk)
	if rep.Status != obs.StatusReady || rep.Summary[0] != "jwks: degraded (https://authority.test: stale (age 42 s: HTTP 502))" {
		t.Fatalf("%+v", rep)
	}
	w.eco.down.Store(false)
	if s, _ := chk.Probe(context.Background()); s != obs.StateOK {
		t.Fatalf("back: %s", s)
	}
}

func TestJWKSProbeAnswers(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"not a JWKS": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"x":1}`)) },
	}
	for want, h := range cases {
		srv := httptest.NewServer(h)
		m := &MachineVerifier{jwks: map[string]string{"https://i.test": srv.URL}, probe: srv.Client(), now: time.Now,
			fetched: map[string]time.Time{"https://i.test": time.Now()}, lastErr: map[string]string{}}
		_, reason := m.probeAll(context.Background())
		srv.Close()
		if !strings.Contains(reason, want) {
			t.Fatalf("%q", reason)
		}
	}
	m := &MachineVerifier{jwks: map[string]string{"https://i.test": "http://127.0.0.1:1/jwks"}, probe: http.DefaultClient, now: time.Now,
		fetched: map[string]time.Time{}, lastErr: map[string]string{}}
	if _, reason := m.probeAll(context.Background()); !strings.Contains(reason, "unreachable") {
		t.Fatal(reason)
	}
	if err := m.fetchJWKS(context.Background(), "::not a url"); err == nil {
		t.Fatal("bad URL")
	}
}

// Start-up fails while an issuer's JWKS cannot be fetched (core's
// semantics); NewMachineVerifier refuses a configuration without
// issuers or audiences.
func TestMachineVerifierStart(t *testing.T) {
	e := newEcosystem(t)
	e.down.Store(true)
	_, err := NewMachineVerifierWith(context.Background(), coreauth.Config{
		Issuers: map[string]coreauth.IssuerConfig{e.URL: {JWKSURL: e.JWKS}}, Audiences: audiences(), StrictSessionClaims: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "ANSP_TOKEN_ISSUERS") {
		t.Fatalf("got %v", err)
	}
	if _, err := NewMachineVerifier(context.Background(), config.Config{}); err == nil {
		t.Fatal("no issuers")
	}
	e.down.Store(false)
	m, err := NewMachineVerifier(context.Background(), config.Config{
		TokenIssuers: []config.Issuer{{Issuer: e.URL, JWKSURL: e.JWKS}}, Audiences: audiences(),
	})
	if err != nil || m.probe == nil {
		t.Fatal(err)
	}
	tok := e.token(t, ussp, ownHost, []string{"ansp.traffic"}, time.Now())
	if cl, err := m.Verify(context.Background(), tok); err != nil || cl.Subject != ussp {
		t.Fatal(err)
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	for _, tok := range []string{"", "a.b", "a.!!!.c", "a." + "eyJpc3MiOjF9" + ".c", strings.Repeat("a", coreauth.DefaultMaxTokenBytes+1)} {
		if unverifiedIssuer(tok) != "" {
			t.Fatalf("%q has an issuer", tok)
		}
	}
	if unverifiedIssuer("a.eyJpc3MiOiJodHRwczovL3gifQ.c") != "https://x" {
		t.Fatal("iss not read")
	}
}

func TestWriteErrorShapes(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/x?secret=1", nil)
	rec := httptest.NewRecorder()
	WriteError(rec, r, errors.Join(core.Fieldf("a", "b"), core.Fieldf("c", "d")))
	if p := problemOf(t, rec); rec.Code != http.StatusBadRequest || len(p.Errors) != 2 || p.Instance != "/v1/x" {
		t.Fatalf("%+v", p)
	}
	rec = httptest.NewRecorder()
	WriteError(rec, r, errors.New("pq: relation users does not exist"))
	if p := problemOf(t, rec); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "relation") || p.Errors == nil {
		t.Fatalf("%s", rec.Body.String())
	}
	fields := make([]FieldReason, MaxProblemErrors+5)
	rec = httptest.NewRecorder()
	WriteProblem(rec, r, http.StatusTooManyRequests, SlugRateLimited, "x", fields, 1500*time.Millisecond)
	if p := problemOf(t, rec); !p.Truncated || len(p.Errors) != MaxProblemErrors || rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("%+v %v", p, rec.Header())
	}
	if (&ProblemBody{Type: "x"}).Slug() != "" || (&Error{Slug: "s", Detail: "d"}).Error() != "s: d" {
		t.Fatal("slug")
	}
}
