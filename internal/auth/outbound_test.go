package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// tokenService is a stub of the authority's POST /oauth/token that
// records every request (presence is asserted, not assumed).
type tokenService struct {
	mu       sync.Mutex
	requests []map[string]string
	status   atomic.Int32 // 0 = 200
	ttlS     atomic.Int64
	n        atomic.Int64
	srv      *httptest.Server
}

func newTokenService(t testing.TB) *tokenService {
	t.Helper()
	s := &tokenService{}
	s.ttlS.Store(600)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		req := map[string]string{"content_type": r.Header.Get("Content-Type")}
		for k := range r.PostForm {
			req[k] = r.PostForm.Get(k)
		}
		s.mu.Lock()
		s.requests = append(s.requests, req)
		s.mu.Unlock()
		if st := s.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable","error_description":"down"}`))
			return
		}
		n := s.n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("tok-%s-%d", req["audience"], n),
			"token_type": "Bearer", "expires_in": s.ttlS.Load()})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *tokenService) last() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[len(s.requests)-1]
}

func (s *tokenService) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func newSource(t testing.TB, ts *tokenService, c *clock) *TokenSource {
	t.Helper()
	src, err := NewTokenSource(TokenSourceConfig{TokenURL: ts.srv.URL + "/oauth/token", ClientID: "ansp-01", ClientSecret: "test-secret",
		Now: c.Now, Backoff: time.Millisecond})
	must(t, err)
	return src
}

// The token request for the CISP carries audience = the CISP's host,
// for the DSS the DSS's host (M18), as client ansp-01 (M24), one token
// per (aud, scope set).
func TestTokenAudiencePerTarget(t *testing.T) {
	ts := newTokenService(t)
	c := newClock(t0())
	src := newSource(t, ts, c)
	ctx := context.Background()
	tok, err := src.Token(ctx, "https://cisp.test/v1", "cis.publish:restrictions")
	must(t, err)
	if r := ts.last(); r["audience"] != "cisp.test" || r["client_id"] != "ansp-01" || r["client_secret"] != "test-secret" ||
		r["grant_type"] != "client_credentials" || r["scope"] != "cis.publish:restrictions" ||
		r["content_type"] != "application/x-www-form-urlencoded" || tok != "tok-cisp.test-1" {
		t.Fatalf("%v %s", r, tok)
	}
	tok, err = src.Token(ctx, "https://dss.test:8443/dss/v1/", "utm.constraint_management")
	must(t, err)
	if r := ts.last(); r["audience"] != "dss.test:8443" || tok != "tok-dss.test:8443-2" {
		t.Fatalf("%v %s", r, tok)
	}
	again, err := src.Token(ctx, "https://cisp.test/other/path", "cis.publish:restrictions")
	if err != nil || again != "tok-cisp.test-1" || ts.count() != 2 {
		t.Fatalf("not cached: %s %d", again, ts.count())
	}
	if _, err := src.TokenFor(ctx, "cisp.test", []string{"cis.read", "cis.publish:restrictions", "cis.read"}); err != nil || ts.count() != 3 ||
		ts.last()["scope"] != "cis.publish:restrictions cis.read" {
		t.Fatalf("scope set: %v", ts.last())
	}
	if src.Counters().Get(CounterTokenFetchOK) != 3 || src.Len() != 3 {
		t.Fatalf("%v", src.Counters().Snapshot())
	}
}

func TestAudienceOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://CISP.test":                   "cisp.test",
		"https://cisp.test/":                  "cisp.test",
		"https://cisp.test/v1/restrictions?x": "cisp.test",
		"https://dss.test:8443/dss/v1":        "dss.test:8443",
		"http://ussp-geo-01:8080/":            "ussp-geo-01:8080",
		"https://user:pass@authority.test/a":  "authority.test",
	} {
		if got, err := AudienceOf(in); err != nil || got != want {
			t.Fatalf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "cisp.test", "ftp://cisp.test", "https://", "::"} {
		if _, err := AudienceOf(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// 06 T5: from half its lifetime on a token is refreshed in the
// background while the cached one is handed out; during an outage of
// the token service the cached token is used until its exp (counted),
// then calls fail with the service's error.
func TestTokenRefreshAndOutage(t *testing.T) {
	ts := newTokenService(t)
	c := newClock(t0())
	src := newSource(t, ts, c)
	ctx := context.Background()
	first, err := src.Token(ctx, "https://cisp.test", "cis.read")
	must(t, err)
	c.Add(299 * time.Second)
	if tok, _ := src.Token(ctx, "https://cisp.test", "cis.read"); tok != first || ts.count() != 1 {
		t.Fatal("refreshed before half the lifetime")
	}
	c.Add(2 * time.Second)
	if tok, _ := src.Token(ctx, "https://cisp.test", "cis.read"); tok != first {
		t.Fatal("the caller waited for the refresh")
	}
	waitFor(t, func() bool { return src.Counters().Get(CounterTokenFetchOK) == 2 })
	second, _ := src.Token(ctx, "https://cisp.test", "cis.read")
	if second == first {
		t.Fatal("the refresh was not used")
	}

	ts.status.Store(http.StatusServiceUnavailable)
	c.Add(301 * time.Second) // past half of the second token's life
	if tok, err := src.Token(ctx, "https://cisp.test", "cis.read"); err != nil || tok != second {
		t.Fatalf("cached during the outage: %v", err)
	}
	waitFor(t, func() bool { return src.Counters().Get(CounterTokenFetchFailed) == 1 })
	// Bounded retry: three attempts per fetch on a 503.
	if n := ts.count(); n != 2+DefaultTokenAttempts {
		t.Fatalf("%d requests", n)
	}
	if tok, err := src.Token(ctx, "https://cisp.test", "cis.read"); err != nil || tok != second || src.Counters().Get(CounterTokenCachedUsed) == 0 {
		t.Fatalf("cached token not used and counted: %v %v", err, src.Counters().Snapshot())
	}
	waitFor(t, func() bool { return src.Counters().Get(CounterTokenFetchFailed) >= 2 }) // the second call started another refresh
	c.Add(300 * time.Second)                                                            // past exp
	_, err = src.Token(ctx, "https://cisp.test", "cis.read")
	var tse *TokenServiceError
	if !errors.As(err, &tse) || tse.Status != http.StatusServiceUnavailable || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("after exp: %v", err)
	}
	ts.status.Store(0)
	if _, err := src.Token(ctx, "https://cisp.test", "cis.read"); err != nil {
		t.Fatalf("service back: %v", err)
	}
}

// A 4xx is not retried; a caller's cancelled context does not fail the
// fetch for the others.
func TestTokenRefusedAndCancelled(t *testing.T) {
	ts := newTokenService(t)
	ts.status.Store(http.StatusBadRequest)
	src := newSource(t, ts, newClock(t0()))
	_, err := src.Token(context.Background(), "https://cisp.test", "cis.read")
	var tse *TokenServiceError
	if !errors.As(err, &tse) || tse.Code != "temporarily_unavailable" || ts.count() != 1 {
		t.Fatalf("%v %d", err, ts.count())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Token(ctx, "https://cisp.test", "cis.read"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := src.TokenFor(context.Background(), "cisp.test", nil); err == nil {
		t.Fatal("no scope")
	}
	if _, err := src.Token(context.Background(), "cisp.test", "x"); err == nil {
		t.Fatal("not a URL")
	}
}

// E-10: the cache holds at most MaxEntries tokens; the least recently
// used is evicted (counted).
func TestTokenCacheBound(t *testing.T) {
	ts := newTokenService(t)
	src, err := NewTokenSource(TokenSourceConfig{TokenURL: ts.srv.URL, ClientID: "ansp-01", ClientSecret: "s", MaxEntries: 2})
	must(t, err)
	for i := range 3 {
		_, err := src.TokenFor(context.Background(), fmt.Sprintf("ussp-%d.test", i), []string{"utm.constraint_processing"})
		must(t, err)
	}
	if src.Len() != 2 || src.Counters().Get(CounterTokenEvicted) != 1 {
		t.Fatalf("%d %v", src.Len(), src.Counters().Snapshot())
	}
}

func TestNewTokenSource(t *testing.T) {
	if _, err := NewTokenSource(TokenSourceConfig{TokenURL: "ftp://x"}); err == nil {
		t.Fatal("bad URL")
	}
	if _, err := NewTokenSource(TokenSourceConfig{TokenURL: "https://authority.test/oauth/token", ClientID: "ansp-01"}); err == nil {
		t.Fatal("no secret")
	}
	c := TokenSourceFromConfig(config.Config{TokenURL: "https://authority.test/oauth/token", ClientID: "ansp-01", ClientSecret: "s"})
	if c.ClientID != "ansp-01" || c.ClientSecret != "s" {
		t.Fatal(c)
	}
	if _, err := NewTokenSource(c); err != nil {
		t.Fatal(err)
	}
}

func TestParseTokenResponse(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"not json":   {200, `x`},
		"no token":   {200, `{"token_type":"Bearer","expires_in":60}`},
		"mac":        {200, `{"access_token":"a","token_type":"mac","expires_in":60}`},
		"no expiry":  {200, `{"access_token":"a","token_type":"Bearer"}`},
		"long life":  {200, `{"access_token":"a","token_type":"Bearer","expires_in":3601}`},
		"float":      {200, `{"access_token":"a","token_type":"Bearer","expires_in":1.5}`},
		"refused":    {401, `{"error":"invalid_client"}`},
		"empty 500":  {500, ``},
		"huge token": {200, `{"access_token":"` + strings.Repeat("a", 9000) + `","token_type":"Bearer","expires_in":60}`},
	} {
		if tok, _, err := ParseTokenResponse(c.status, []byte(c.body)); err == nil || tok != "" {
			t.Fatalf("%s accepted", name)
		}
	}
	_, _, err := ParseTokenResponse(500, nil)
	if err.Error() != "token request refused (500 http_500): " {
		t.Fatal(err)
	}
	long := strings.Repeat("é", 300)
	_, _, err = ParseTokenResponse(400, []byte(`{"error":"x","error_description":"`+long+`"}`))
	var tse *TokenServiceError
	if !errors.As(err, &tse) || len(tse.Description) > 200 {
		t.Fatal("description not clipped")
	}
	tok, ttl, err := ParseTokenResponse(200, []byte(`{"access_token":"a","token_type":"bearer","expires_in":60}`))
	if err != nil || tok != "a" || ttl != time.Minute {
		t.Fatal(err)
	}
}

func TestTokenBodyBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 200)))
	}))
	defer srv.Close()
	src, err := NewTokenSource(TokenSourceConfig{TokenURL: srv.URL, ClientID: "a", ClientSecret: "b", MaxBodyBytes: 100})
	must(t, err)
	if _, err := src.Token(context.Background(), "https://cisp.test", "cis.read"); err == nil || !strings.Contains(err.Error(), "larger than 100") {
		t.Fatal(err)
	}
	srv.Close()
	src, err = NewTokenSource(TokenSourceConfig{TokenURL: srv.URL, ClientID: "a", ClientSecret: "b", Backoff: time.Millisecond})
	must(t, err)
	if _, err := src.Token(context.Background(), "https://cisp.test", "cis.read"); !errors.Is(err, errUnreachable) {
		t.Fatal(err)
	}
}
