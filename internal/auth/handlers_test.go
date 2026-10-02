package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// authOps is the auth operations as the contract lists them (a test
// holds AccessTable and api/openapi.yaml equal).
func authOps() []Operation {
	var ops []Operation
	for pattern, a := range AccessTable() {
		ops = append(ops, Operation{ID: pattern, Pattern: pattern, Process: "api", Auth: a.String()})
	}
	return ops
}

// server is the auth operations mounted through Routes, behind RealIP,
// as cmd/api mounts them on the generated router.
func (w *world) server(t testing.TB) http.Handler {
	t.Helper()
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8"})
	must(t, err)
	rt := NewRoutes(http.NewServeMux(), "api", w.guard, 1<<20, authOps(), RealIP(proxies))
	h := &Handlers{Accounts: w.accounts, Keys: w.keys}
	for pattern, serve := range map[string]http.HandlerFunc{
		OpLogin: h.Login, OpMFA: h.VerifyMFA, OpLogout: h.Logout, OpMe: h.Me, OpUsers: h.Users,
		OpAddUser: h.AddUser, OpResetMFA: h.ResetMFA, OpDisable: h.Disable, OpJWKS: h.Keys.ServeHTTP,
	} {
		rt.Handle(pattern, serve)
	}
	must(t, rt.Err())
	return rt
}

func do(t testing.TB, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		must(t, err)
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-For", "192.0.2.77")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// The HTTP sign-in from login to logout, as the BFF drives it.
func TestHTTPSignInFlow(t *testing.T) {
	w := newWorld(t)
	h := w.server(t)
	w.addUser(t, "admin1", pw, RoleAdmin)

	rec := do(t, h, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": "admin1", "password": pw, "extra": "ignored"})
	var lr struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment *struct {
			Secret string `json:"secret"`
			URI    string `json:"otpauth_uri"`
		} `json:"enrolment"`
	}
	must(t, json.Unmarshal(rec.Body.Bytes(), &lr))
	if rec.Code != http.StatusOK || lr.MFAToken == "" || lr.Enrolment == nil || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	if ev := w.store.events(EventLoginPasswordAccepted); ev[0].Payload.(map[string]any)["remote_ip"] != "192.0.2.77" {
		t.Fatalf("the client address is not the forwarded one: %+v", ev[0].Payload)
	}
	rec = do(t, h, http.MethodPost, "/v1/auth/mfa", "", map[string]string{"mfa_token": lr.MFAToken, "code": w.code(t, lr.Enrolment.Secret)})
	var mr mfaResponse
	must(t, json.Unmarshal(rec.Body.Bytes(), &mr))
	if rec.Code != http.StatusOK || mr.TokenType != "Bearer" || mr.IdleTimeoutS != 1800 || mr.User.Role != RoleAdmin {
		t.Fatalf("mfa: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, http.MethodGet, "/v1/auth/me", mr.Token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"username":"admin1"`) {
		t.Fatalf("me: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/v1/users", mr.Token, map[string]string{"username": "viewer1", "password": pw, "role": RoleViewer})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created UserView
	must(t, json.Unmarshal(rec.Body.Bytes(), &created))
	rec = do(t, h, http.MethodPost, "/v1/users", mr.Token, map[string]string{"username": "v", "password": "x", "role": "pilot"})
	if p := problemOf(t, rec); rec.Code != http.StatusBadRequest || len(p.Errors) != 3 {
		t.Fatalf("invalid user: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/v1/users", mr.Token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"viewer1"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/v1/users/"+created.ID+"/reset-mfa", mr.Token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/v1/users/"+created.ID+"/disable", mr.Token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/v1/users/not-a-uuid/disable", mr.Token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/v1/users/x/reset-mfa", mr.Token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/.well-known/jwks.json", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kid"`) {
		t.Fatalf("jwks: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, http.MethodPost, "/v1/auth/logout", mr.Token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/v1/auth/me", mr.Token, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout: %d", rec.Code)
	}
}

// Fail closed: the user operations refuse no token and a viewer; the
// sign-in operations refuse bodies that are not their JSON object.
func TestHTTPRefusals(t *testing.T) {
	w := newWorld(t)
	h := w.server(t)
	w.addUser(t, "viewer1", pw, RoleViewer)
	res, _ := w.signIn(t, "viewer1", pw)
	for _, op := range [][2]string{
		{http.MethodGet, "/v1/users"}, {http.MethodPost, "/v1/users"}, {http.MethodPost, "/v1/users/x/reset-mfa"},
		{http.MethodPost, "/v1/users/x/disable"},
	} {
		if rec := do(t, h, op[0], op[1], "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%v without a token: %d", op, rec.Code)
		}
		if rec := do(t, h, op[0], op[1], res.Token, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%v as viewer: %d", op, rec.Code)
		}
	}
	for _, op := range [][2]string{{http.MethodPost, "/v1/auth/logout"}, {http.MethodGet, "/v1/auth/me"}} {
		if rec := do(t, h, op[0], op[1], "", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%v: %d", op, rec.Code)
		}
	}
	for name, body := range map[string]string{
		"not json": "username=a", "array": `[]`, "two values": `{"username":"a"} {}`,
		"too large": `{"username":"` + strings.Repeat("a", MaxBodyBytes) + `"}`,
	} {
		for _, path := range []string{"/v1/auth/login", "/v1/auth/mfa"} {
			rec := do(t, h, http.MethodPost, path, "", body)
			want, slug := http.StatusBadRequest, SlugInvalidRequest
			if name == "too large" {
				want, slug = http.StatusRequestEntityTooLarge, apierr.SlugBodyTooLarge
			}
			if p := problemOf(t, rec); rec.Code != want || p.Slug() != slug {
				t.Fatalf("%s %s: %d %s", name, path, rec.Code, rec.Body.String())
			}
		}
	}
	if rec := do(t, h, http.MethodPost, "/v1/users", res.Token, `{`); rec.Code != http.StatusForbidden {
		t.Fatalf("the guard runs before the body is read: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": "viewer1", "password": "wrong password!"})
	if p := problemOf(t, rec); rec.Code != http.StatusUnauthorized || p.Slug() != SlugInvalidCredentials {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/v1/auth/mfa", "", map[string]string{"mfa_token": "x", "code": "123456"})
	if p := problemOf(t, rec); rec.Code != http.StatusUnauthorized || p.Slug() != SlugMFARefused {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	w.store.fail["users"] = errDown
	if rec := do(t, h, http.MethodGet, "/v1/users", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatal(rec.Code)
	}
}

func TestHTTPStoreDown(t *testing.T) {
	w := newWorld(t)
	h := w.server(t)
	w.addUser(t, "admin1", pw, RoleAdmin)
	res, _ := w.signIn(t, "admin1", pw)
	w.store.fail["users"] = errDown
	if rec := do(t, h, http.MethodGet, "/v1/users", res.Token, nil); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	w.store.fail = map[string]error{"tx": errDown}
	for _, op := range [][2]string{{http.MethodGet, "/v1/auth/me"}, {http.MethodPost, "/v1/auth/logout"}, {http.MethodPost, "/v1/users/x/disable"},
		{http.MethodPost, "/v1/users/x/reset-mfa"}} {
		if rec := do(t, h, op[0], op[1], res.Token, nil); rec.Code != http.StatusInternalServerError {
			t.Fatalf("%v: %d", op, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/v1/users", res.Token, map[string]string{"username": "viewer2", "password": pw, "role": RoleViewer}); rec.Code != http.StatusInternalServerError {
		t.Fatal(rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/v1/auth/mfa", "", map[string]string{"mfa_token": "x", "code": "123456"}); rec.Code != http.StatusInternalServerError {
		t.Fatal(rec.Code)
	}
}

// M22: a WebSocket upgrade takes the session cookie on an allowed
// Origin, or a bearer; no ticket.
func TestRequireUpgrade(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "viewer1", pw, RoleViewer)
	res, _ := w.signIn(t, "viewer1", pw)
	a := Access{Scopes: []string{"ansp.traffic"}, AnyRole: true}
	mw := w.guard.RequireUpgrade(a)
	up := func(hdr map[string]string, cookie string) (*httptest.ResponseRecorder, *Principal) {
		var seen *Principal
		h := mw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			p, _ := PrincipalFrom(r.Context())
			seen = &p
			rw.WriteHeader(http.StatusSwitchingProtocols)
		}))
		r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/stream", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: CookieSession, Value: cookie})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec, seen
	}
	rec, p := up(map[string]string{"Origin": "https://ansp.test"}, res.Token)
	if rec.Code != http.StatusSwitchingProtocols || p == nil || !p.Session {
		t.Fatalf("cookie on an allowed origin: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = up(map[string]string{"Origin": "https://evil.test"}, res.Token)
	if rec.Code != http.StatusForbidden || w.guard.Counters().Get(CounterOriginRefused) != 1 {
		t.Fatalf("other origin: %d", rec.Code)
	}
	rec, _ = up(nil, res.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: %d", rec.Code)
	}
	rec, _ = up(map[string]string{"Origin": "https://ansp.test"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: %d", rec.Code)
	}
	machine := w.eco.token(t, ussp, ownHost, []string{"ansp.traffic"}, w.clock.Now())
	rec, _ = up(map[string]string{"Origin": "https://ansp.test"}, machine)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("machine token in the cookie: %d", rec.Code)
	}
	rec, p = up(withBearer(machine), "")
	if rec.Code != http.StatusSwitchingProtocols || p.Session || p.Claims.Subject != ussp {
		t.Fatalf("bearer: %d %s", rec.Code, rec.Body.String())
	}
	_, p = up(map[string]string{"Origin": "https://ansp.test"}, res.Token)
	must(t, w.accounts.Logout(t.Context(), *p))
	rec, _ = up(map[string]string{"Origin": "https://ansp.test"}, res.Token)
	if pb := problemOf(t, rec); rec.Code != http.StatusUnauthorized || pb.Slug() != SlugSessionRefused {
		t.Fatalf("after logout: %d", rec.Code)
	}
}

func TestCheckCSRF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if CheckCSRF(r) != nil {
		t.Fatal("GET")
	}
	r = httptest.NewRequest(http.MethodPost, "/", nil)
	if CheckCSRF(r) == nil {
		t.Fatal("no cookie")
	}
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "abc"})
	if CheckCSRF(r) == nil {
		t.Fatal("no header")
	}
	r.Header.Set(HeaderCSRF, "abd")
	if CheckCSRF(r) == nil {
		t.Fatal("mismatch")
	}
	r.Header.Set(HeaderCSRF, "abc")
	if CheckCSRF(r) != nil {
		t.Fatal("match refused")
	}
}
