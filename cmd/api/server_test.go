package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/config"
)

// scopeVerifier accepts "scopes:<a>,<b>" as a machine token granting
// those scopes and refuses anything else.
type scopeVerifier struct{}

func (scopeVerifier) Verify(_ context.Context, token string) (coreauth.Claims, error) {
	list, ok := strings.CutPrefix(token, "scopes:")
	if !ok {
		return coreauth.Claims{}, &coreauth.TokenError{Counter: coreauth.CounterRejectedSignature, Claim: "signature", Reason: "test"}
	}
	return coreauth.Claims{Issuer: "https://authority.test", Subject: "ussp-01", Scopes: strings.Split(list, ",")}, nil
}

func testServer(t *testing.T, h *auth.Handlers) (*auth.Routes, http.Handler) {
	t.Helper()
	mtls, err := auth.NewMTLS(config.MTLSOff, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	rt, err := mountAPI(mux, &auth.Guard{Machine: scopeVerifier{}, MTLS: mtls}, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt, mux
}

type answer struct {
	code    int
	problem apierr.Problem
	header  http.Header
}

func call(t *testing.T, h http.Handler, method, path, token, ctype, body string) answer {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	a := answer{code: rec.Code, header: rec.Header()}
	if rec.Header().Get("Content-Type") == "application/problem+json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &a.problem); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return a
}

// Every operation of api is served behind its x-auth; the others are
// not served by api (presence and absence, WP-3).
func TestMountAPIServesTheContract(t *testing.T) {
	rt, _ := testServer(t, nil)
	served := rt.Served()
	for _, op := range gen.Operations {
		_, ok := served[op.Pattern]
		if want := op.Process == process; ok != want {
			t.Errorf("%s (%s, process %s): served %v", op.Pattern, op.ID, op.Process, ok)
		}
		if ok && served[op.Pattern].String() != op.Auth {
			t.Errorf("%s: served behind %q, the contract says %q", op.Pattern, served[op.Pattern].String(), op.Auth)
		}
	}
	if len(served) == 0 {
		t.Fatal("nothing served")
	}
}

func TestUnimplementedAndRefusals(t *testing.T) {
	_, h := testServer(t, nil)
	for _, tc := range []struct {
		name, method, path, token, ctype, body string
		code                                   int
		slug                                   string
	}{
		// Presence: a caller the rule admits reaches the (501) handler.
		{"token admitted", "GET", "/v1/coordination/notices/01K6P3Q8Y2D6W4Z1V7R5T9X3MB", "scopes:ansp.coordination", "", "", 501, apierr.SlugNotImplemented},
		// WP-5 serves the restrictions; without the database they say so.
		{"restrictions without a database", "GET", "/v1/restrictions", "scopes:ansp.coordination", "", "", 503, apierr.SlugUnavailable},
		{"restriction request without a database", "POST", "/v1/restriction-requests", "scopes:ansp.requests", "application/json", "{}", 503, apierr.SlugUnavailable},
		{"stream without a database", "GET", "/v1/restrictions/stream", "scopes:ansp.coordination", "", "", 403, apierr.SlugForbidden},
		{"signed body admitted to its handler", "POST", "/v1/cis/notifications", "", "application/jose", "aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl", 501, apierr.SlugNotImplemented},
		{"constraint details", "GET", "/uss/v1/constraints/2f8343be-6482-4d1b-a474-16847e01af1e", "scopes:utm.constraint_processing", "", "", 501, apierr.SlugNotImplemented},
		// Absence: no credential, a missing scope, a session-only route
		// for a machine, a route of another process.
		{"no credential", "GET", "/v1/restrictions", "", "", "", 401, apierr.SlugUnauthenticated},
		{"refused token", "GET", "/v1/restrictions", "forged", "", "", 401, coreauth.CounterRejectedSignature},
		{"missing scope", "GET", "/v1/restrictions", "scopes:ansp.traffic", "", "", 403, apierr.SlugForbidden},
		{"session only", "GET", "/v1/adapters", "scopes:ansp.coordination", "", "", 403, apierr.SlugForbidden},
		{"another process", "GET", "/v1/manned-traffic/snapshot", "scopes:ansp.traffic", "", "", 404, ""},
		// The generated binding and decoding answer the one error body.
		{"bad path parameter", "GET", "/uss/v1/constraints/not-a-uuid", "scopes:utm.constraint_processing", "", "", 400, apierr.SlugInvalidRequest},
		{"bad JSON body", "POST", "/v1/coordination/notices", "scopes:ansp.coordination", "application/json", "{", 400, apierr.SlugInvalidRequest},
		{"body past the bound", "POST", "/v1/coordination/notices", "scopes:ansp.coordination", "application/json", `{"a":"` + strings.Repeat("x", maxBodyBytes) + `"}`, 413, apierr.SlugBodyTooLarge},
		// Sign-in is not configured here: 503 that says so.
		{"sign-in not configured", "POST", "/v1/auth/login", "", "application/json", `{"username":"a","password":"b"}`, 503, apierr.SlugUnavailable},
		{"jwks not configured", "GET", "/.well-known/jwks.json", "", "", "", 503, apierr.SlugUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := call(t, h, tc.method, tc.path, tc.token, tc.ctype, tc.body)
			if a.code != tc.code || (tc.slug != "" && a.problem.Slug() != tc.slug) {
				t.Fatalf("%d %+v", a.code, a.problem)
			}
			if tc.code == 503 && a.header.Get("Retry-After") == "" {
				t.Fatal("503 without Retry-After")
			}
		})
	}
}

func TestRequestErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err   error
		code  int
		field string
	}{
		{&gen.InvalidParamFormatError{ParamName: "id", Err: errors.New("value 'x' sent")}, 400, "id"},
		{&gen.RequiredParamError{ParamName: "bbox"}, 400, "bbox"},
		{&gen.RequiredHeaderError{ParamName: "Idempotency-Key"}, 400, "Idempotency-Key"},
		{&gen.TooManyValuesForParamError{ParamName: "state", Count: 2}, 400, "state"},
		{&gen.UnmarshalingParamError{ParamName: "at", Err: errors.New("x")}, 400, "at"},
		{&gen.UnescapedCookieParamError{ParamName: "uspace_session", Err: errors.New("x")}, 400, "uspace_session"},
		{errors.New("can't decode JSON body: unexpected EOF"), 400, "body"},
		{&http.MaxBytesError{Limit: 10}, 413, "body"},
	} {
		rec := httptest.NewRecorder()
		requestError(rec, httptest.NewRequest(http.MethodGet, "/v1/x", nil), tc.err)
		var p apierr.Problem
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if rec.Code != tc.code || len(p.Errors) != 1 || p.Errors[0].Field != tc.field || strings.Contains(rec.Body.String(), "value 'x'") {
			t.Fatalf("%T: %d %s", tc.err, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	responseError(rec, httptest.NewRequest(http.MethodGet, "/v1/x", nil), errors.New("pq: secret detail"))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	responseError(rec, httptest.NewRequest(http.MethodGet, "/v1/x", nil), apierr.Conflict("taken"))
	if rec.Code != 409 {
		t.Fatal(rec.Code)
	}
}

// With sign-in configured the auth operations reach their handlers:
// the JWKS is served (presence of the WP-2 mount on the generated
// router).
func TestSignInMounted(t *testing.T) {
	keys := auth.NewPublicKeys()
	_, h := testServer(t, &auth.Handlers{Keys: keys})
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(body), `"keys"`) || rec.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("%d %s", rec.Code, body)
	}
}
