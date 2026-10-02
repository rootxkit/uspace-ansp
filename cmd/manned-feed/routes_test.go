package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/feed"
	"github.com/rootxkit/uspace-ansp/internal/picture"
)

// scopeVerifier accepts "scopes:<a>,<b>" as a machine token of ussp-01
// granting those scopes and refuses anything else.
type scopeVerifier struct{}

func (scopeVerifier) Verify(_ context.Context, token string) (coreauth.Claims, error) {
	list, ok := strings.CutPrefix(token, "scopes:")
	if !ok {
		return coreauth.Claims{}, &coreauth.TokenError{Counter: coreauth.CounterRejectedSignature, Claim: "signature", Reason: "test"}
	}
	return coreauth.Claims{Issuer: "https://authority.test", Subject: "ussp-01", Scopes: strings.Split(list, ",")}, nil
}

type liveChecker struct{}

func (liveChecker) CheckSession(context.Context, string, string) (string, error) {
	return auth.RoleViewer, nil
}

const origin = "https://ansp.test"

// feedRoutes serves the feed's operations behind a real guard.
func feedRoutes(t *testing.T, mtlsMode string, bindings map[string]string, proxies []netip.Prefix) (*httptest.Server, string) {
	t.Helper()
	mtls, err := auth.NewMTLS(mtlsMode, bindings, proxies)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := auth.NewSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := coreauth.NewKeyRing(sk)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.NewSessionVerifier(context.Background(), auth.SessionVerifierConfig{
		Issuer: origin, Ring: ring, Audiences: []string{"ansp.test"}, Checker: liveChecker{}})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := ring.Issuer(origin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok, err := iss.IssueSession(coreauth.SessionClaims{Audience: "ansp.test", Subject: "user-1", Roles: []string{auth.RoleViewer},
		Realm: auth.RealmConsole, IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	g := &auth.Guard{Machine: scopeVerifier{}, Sessions: sessions, MTLS: mtls, Origins: []string{origin}, UpgradeReLogin: true}
	pic := picture.New(nil, nil, picture.NoCIS{}, nil, picture.DefaultLimits())
	svc := feed.New(feed.Config{StatusPeriod: time.Hour}, feed.Deps{Picture: pic, Sessions: sessions})
	mux := http.NewServeMux()
	rt, err := mountFeed(mux, g, svc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range gen.Operations {
		op := &gen.Operations[i]
		_, ok := rt.Served()[op.Pattern]
		if want := op.Process == process; ok != want {
			t.Fatalf("%s served %v, want %v", op.Pattern, ok, want)
		}
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, tok
}

func dial(t *testing.T, srv *httptest.Server, h http.Header) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/manned-traffic/stream", &websocket.DialOptions{HTTPHeader: h})
	if err == nil {
		defer c.CloseNow()
		return resp.StatusCode, nil
	}
	if resp != nil {
		return resp.StatusCode, err
	}
	return 0, err
}

func bearer(tok string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	return h
}

// TestTrafficScopeIsRequired: without ansp.traffic 403, with it 101.
func TestTrafficScopeIsRequired(t *testing.T) {
	srv, _ := feedRoutes(t, config.MTLSOff, nil, nil)
	if code, _ := dial(t, srv, bearer("scopes:cis.read")); code != http.StatusForbidden {
		t.Fatalf("without the scope: %d", code)
	}
	if code, err := dial(t, srv, bearer("scopes:ansp.traffic")); code != http.StatusSwitchingProtocols {
		t.Fatalf("with the scope: %d %v", code, err)
	}
	if code, _ := dial(t, srv, bearer("garbage")); code != http.StatusUnauthorized {
		t.Fatalf("a refused token: %d", code)
	}
	r, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/manned-traffic/snapshot", nil)
	r.Header.Set("Authorization", "Bearer scopes:ansp.traffic")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("snapshot %d", resp.StatusCode)
	}
}

// TestTheSessionCookieIsTakenOnlyFromTheAllowedOrigin (M22).
func TestTheSessionCookieIsTakenOnlyFromTheAllowedOrigin(t *testing.T) {
	srv, tok := feedRoutes(t, config.MTLSOff, nil, nil)
	h := http.Header{}
	h.Set("Cookie", auth.CookieSession+"="+tok)
	h.Set("Origin", "https://evil.test")
	if code, _ := dial(t, srv, h); code != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", code)
	}
	h.Set("Origin", origin)
	if code, err := dial(t, srv, h); code != http.StatusSwitchingProtocols {
		t.Fatalf("same origin: %d %v", code, err)
	}
}

// TestMTLSRequiredBindsTheSubjectFromTrustedProxiesOnly (M25): without
// the subject header refused, with it from the trusted proxy accepted,
// with it from any other peer refused (the header is not believed).
func TestMTLSRequiredBindsTheSubjectFromTrustedProxiesOnly(t *testing.T) {
	bindings := map[string]string{"ussp-01": "CN=ussp-01,O=GEO-TEST"}
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	srv, _ := feedRoutes(t, config.MTLSRequired, bindings, trusted)
	h := bearer("scopes:ansp.traffic")
	if code, _ := dial(t, srv, h); code != http.StatusForbidden {
		t.Fatalf("without the subject: %d", code)
	}
	h.Set(auth.HeaderClientCertSubject, "CN=ussp-01,O=GEO-TEST")
	if code, err := dial(t, srv, h); code != http.StatusSwitchingProtocols {
		t.Fatalf("with the subject from the proxy: %d %v", code, err)
	}
	h.Set(auth.HeaderClientCertSubject, "CN=someone-else")
	if code, _ := dial(t, srv, h); code != http.StatusForbidden {
		t.Fatalf("another subject: %d", code)
	}
	untrusted, _ := feedRoutes(t, config.MTLSRequired, bindings, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	h.Set(auth.HeaderClientCertSubject, "CN=ussp-01,O=GEO-TEST")
	if code, _ := dial(t, untrusted, h); code != http.StatusForbidden {
		t.Fatalf("the header from an untrusted peer was believed: %d", code)
	}
}
