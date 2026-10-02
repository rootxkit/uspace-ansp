package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

func TestParseAccess(t *testing.T) {
	for _, s := range []string{
		"public", "jws:cisp", "session", "session:admin", "session:watch_supervisor|admin",
		"token:ansp.traffic", "token:ansp.traffic+mtls", "token:a.b+c:d", "token:ansp.coordination or session",
		"token:ansp.traffic+mtls or session:viewer",
	} {
		a, err := ParseAccess(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if a.String() != s {
			t.Fatalf("%q renders as %q", s, a.String())
		}
	}
	for _, s := range []string{
		"", "nobody", "public or session", "jws:cisp or session", "jws:", "jws:Cisp", "session:", "session:pilot",
		"session:admin|admin", "token:", "token:+mtls", "token:mtls", "token:a+a", "token:A", "session or session",
		"token:a or token:b", "session:admin or", strings.Repeat("token:a", 50), "token:a+b+c+d+e+f+g+h+i",
	} {
		if a, err := ParseAccess(s); err == nil {
			t.Fatalf("%q parsed as %+v", s, a)
		}
	}
}

// Every x-auth of the contract parses and renders back as written, and
// the auth operations' x-auth equals AccessTable: a change to either
// alone fails (docs/PLAN.md section 15 gap 22).
func TestContractAccessRules(t *testing.T) {
	table := AccessTable()
	var authTagged []string
	for _, op := range gen.Operations {
		a, err := ParseAccess(op.Auth)
		if err != nil {
			t.Fatalf("%s: x-auth %q: %v", op.ID, op.Auth, err)
		}
		if a.String() != op.Auth {
			t.Fatalf("%s: x-auth %q renders as %q", op.ID, op.Auth, a.String())
		}
		if op.Tag != "auth" {
			continue
		}
		authTagged = append(authTagged, op.Pattern)
		want, ok := table[op.Pattern]
		if !ok || want.String() != op.Auth {
			t.Fatalf("%s: the contract says %q, AccessTable %q", op.Pattern, op.Auth, want.String())
		}
	}
	slices.Sort(authTagged)
	var keys []string
	for k := range table {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(authTagged, keys) {
		t.Fatalf("auth operations in the contract %v, in AccessTable %v", authTagged, keys)
	}
}

func ok200(w http.ResponseWriter, r *http.Request) {
	if _, err := io.ReadAll(r.Body); err != nil {
		apierr.WriteError(w, r, apierr.TooLarge(16))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Routes serves an operation only through its x-auth, only for its
// process, and fails closed on everything else (absence), and serves
// what is right (presence).
func TestRoutesFailClosed(t *testing.T) {
	w := newWorld(t)
	ops := []Operation{
		{ID: "pub", Pattern: "GET /pub", Process: "api", Auth: "public"},
		{ID: "sess", Pattern: "GET /sess", Process: "api", Auth: "session:admin"},
		{ID: "body", Pattern: "POST /body", Process: "api", Auth: "public"},
		{ID: "signed", Pattern: "POST /signed", Process: "api", Auth: "jws:cisp"},
		{ID: "bad", Pattern: "GET /bad", Process: "api", Auth: "session:pilot"},
		{ID: "feed", Pattern: "GET /feed", Process: "manned-feed", Auth: "session"},
		{ID: "health", Pattern: "GET /healthz", Process: ProcessEach, Auth: "public"},
		{ID: "never", Pattern: "GET /never", Process: "api", Auth: "public"},
		{ID: "pub", Pattern: "GET /dup", Process: "api", Auth: "public"},
	}
	mux := http.NewServeMux()
	rt := NewRoutes(mux, "api", w.guard, 16, ops)
	for _, p := range []string{"GET /pub", "GET /sess", "POST /body", "POST /signed", "GET /bad", "GET /feed", "GET /healthz", "GET /stray", "GET /pub"} {
		rt.HandleFunc(p, ok200)
	}
	err := rt.Err()
	for _, want := range []string{
		"GET /dup (pub) is in the operation list twice", "GET /bad (bad): x-auth", "GET /stray is no operation of the contract",
		"GET /pub is registered twice", "GET /never (never) is an operation of api and no handler was registered",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q in %v", want, err)
		}
	}
	serve := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}
	// Presence: the public route and the signed one are served, a body
	// within the bound is read.
	if serve(http.MethodGet, "/pub", "") != http.StatusOK || serve(http.MethodPost, "/signed", "x") != http.StatusOK ||
		serve(http.MethodPost, "/body", strings.Repeat("a", 16)) != http.StatusOK {
		t.Fatal("a served route was refused")
	}
	// Absence: a session route without a session, a route whose rule
	// does not parse, another process's route, the health route obs
	// serves, a stray pattern, and a body past the bound.
	for path, want := range map[string]int{"/sess": 401, "/bad": 404, "/feed": 404, "/healthz": 404, "/stray": 404} {
		if got := serve(http.MethodGet, path, ""); got != want {
			t.Fatalf("%s: %d, want %d", path, got, want)
		}
	}
	if got := serve(http.MethodPost, "/body", strings.Repeat("a", 17)); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body past the bound: %d", got)
	}
	if got := rt.Served(); len(got) != 4 || got["POST /signed"].JWS != "cisp" || got["GET /pub"].String() != "public" {
		t.Fatalf("served: %v", got)
	}
	if NewRoutes(mux, "api", nil, 0, nil).Err() == nil {
		t.Fatal("no guard and no bound were accepted")
	}
}

// A signed-body rule admits the request to its handler and nothing
// else: a JWS access is never combined with another rule.
func TestJWSAccess(t *testing.T) {
	if err := (Access{JWS: "cisp", Public: true}).Validate(); err == nil {
		t.Fatal("jws and public")
	}
	if err := (Access{JWS: "cisp", Scopes: []string{"a"}}).Validate(); err == nil {
		t.Fatal("jws and a scope")
	}
	if err := (Access{JWS: "cisp"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
