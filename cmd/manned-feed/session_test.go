package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/feed"
	"github.com/rootxkit/uspace-ansp/internal/picture"
)

// kvEntry is one sessions_live update.
type kvEntry struct {
	key   string
	value []byte
	op    jetstream.KeyValueOp
}

func (e *kvEntry) Bucket() string                  { return bus.BucketSessionsLive }
func (e *kvEntry) Key() string                     { return e.key }
func (e *kvEntry) Value() []byte                   { return e.value }
func (e *kvEntry) Revision() uint64                { return 1 }
func (e *kvEntry) Created() time.Time              { return time.Time{} }
func (e *kvEntry) Delta() uint64                   { return 0 }
func (e *kvEntry) Operation() jetstream.KeyValueOp { return e.op }

// liveKV is sessions_live as api projects it: the initial values, the
// end-of-initial marker, then every put and delete the test makes.
type liveKV struct{ ch chan jetstream.KeyValueEntry }

func (k *liveKV) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	return k, nil
}
func (k *liveKV) Updates() <-chan jetstream.KeyValueEntry { return k.ch }
func (k *liveKV) Stop() error                             { return nil }

func (k *liveKV) put(t *testing.T, jti string, s auth.LiveSession) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	k.ch <- &kvEntry{key: jti, value: b, op: jetstream.KeyValuePut}
}

// sessionFeed is manned-feed's guard as wireGuard builds it from env
// (the public key file, no signing key), following liveKV, in front of
// the feed's routes.
type sessionFeed struct {
	srv *httptest.Server
	kv  *liveKV
	g   *auth.Guard
}

func feedEnv(extra ...string) []string {
	return append([]string{"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_PUBLIC_BASE_URL=" + origin,
		"ANSP_AUDIENCES=ansp.test", "ANSP_WS_ALLOWED_ORIGINS=" + origin}, extra...)
}

// sessionKey is api's session key: the ring that signs (api's) and the
// path of its public part as gen-secrets derives it (manned-feed's).
func sessionKey(t *testing.T) (*coreauth.KeyRing, string) {
	t.Helper()
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
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "session.pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return ring, path
}

func newSessionFeed(t *testing.T, environ []string) *sessionFeed {
	t.Helper()
	cfg, err := config.LoadFrom(environ, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b, err := bus.Connect(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	g, checker, err := wireGuard(ctx, cfg, b, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f := &sessionFeed{g: g, kv: &liveKV{ch: make(chan jetstream.KeyValueEntry, 16)}}
	if checker != nil {
		checker.Up = nil // the bus of this test is liveKV, which is up
		go checker.Follow(ctx, func(context.Context) (auth.WatchKV, error) { return f.kv, nil })
	}
	pic := picture.New(nil, nil, picture.NoCIS{}, nil, picture.DefaultLimits())
	deps := feed.Deps{Picture: pic}
	if g.Sessions != nil {
		deps.Sessions = g.Sessions
	}
	svc := feed.New(feed.Config{StatusPeriod: time.Hour}, deps)
	mux := http.NewServeMux()
	if _, err := mountFeed(mux, g, svc); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func cookieUpgrade(tok string) http.Header {
	h := http.Header{}
	h.Set("Cookie", auth.CookieSession+"="+tok)
	h.Set("Origin", origin)
	return h
}

func issue(t *testing.T, ring *coreauth.KeyRing, jti, realm string, iat, exp time.Time) string {
	t.Helper()
	iss, err := ring.Issuer(origin)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := iss.IssueSession(coreauth.SessionClaims{Audience: "ansp.test", Subject: "user-" + jti[:1], Roles: []string{auth.RoleViewer},
		Realm: realm, IssuedAt: iat, ExpiresAt: exp, JTI: jti})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestConsoleSessionStreamsWithThePublicKey (row 54): with
// ANSP_SESSION_PUBLIC_KEY_FILE, a live console session upgrades the
// picture's stream (101); an expired, a revoked, a wrong-realm and a
// tampered session are refused 401.
func TestConsoleSessionStreamsWithThePublicKey(t *testing.T) {
	ring, pub := sessionKey(t)
	f := newSessionFeed(t, feedEnv("ANSP_SESSION_PUBLIC_KEY_FILE="+pub))
	if f.g.Sessions == nil || f.g.Sessions.Issuer() != origin {
		t.Fatal("no session verifier from the public key")
	}
	now := time.Now().UTC().Truncate(time.Second)
	live := func(j byte) string {
		jti := strings.Repeat(string(j), 32)
		f.kv.put(t, jti, auth.LiveSession{UserID: "user-" + string(j), Role: auth.RoleViewer, ExpiresAt: now.Add(time.Hour)})
		return jti
	}
	valid := issue(t, ring, live('a'), auth.RealmConsole, now, now.Add(time.Hour))
	expired := issue(t, ring, live('b'), auth.RealmConsole, now.Add(-2*time.Hour), now.Add(-time.Hour))
	realm := issue(t, ring, live('c'), "portal", now, now.Add(time.Hour))
	revoked := issue(t, ring, live('d'), auth.RealmConsole, now, now.Add(time.Hour))
	parts := strings.Split(issue(t, ring, live('e'), auth.RealmConsole, now, now.Add(time.Hour)), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), auth.RoleViewer, auth.RoleAdmin, 1)))
	tampered := strings.Join(parts, ".")
	f.kv.ch <- nil // the initial values are in

	// Presence: the valid session streams, once the projection is read.
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, err := dial(t, f.srv, cookieUpgrade(valid))
		if code == http.StatusSwitchingProtocols {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a valid session: %d %v", code, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The revoked one streams until api deletes its key, then is refused.
	if code, err := dial(t, f.srv, cookieUpgrade(revoked)); code != http.StatusSwitchingProtocols {
		t.Fatalf("before revocation: %d %v", code, err)
	}
	f.kv.ch <- &kvEntry{key: strings.Repeat("d", 32), op: jetstream.KeyValueDelete}
	// Within the verifier's cache TTL (auth.DefaultSessionCacheTTL).
	deadline = time.Now().Add(auth.DefaultSessionCacheTTL + 5*time.Second)
	for {
		code, _ := dial(t, f.srv, cookieUpgrade(revoked))
		if code == http.StatusUnauthorized {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a revoked session: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for name, tok := range map[string]string{"expired": expired, "wrong realm": realm, "tampered": tampered} {
		if code, _ := dial(t, f.srv, cookieUpgrade(tok)); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d, want 401", name, code)
		}
	}
	if code, err := dial(t, f.srv, cookieUpgrade(valid)); code != http.StatusSwitchingProtocols {
		t.Fatalf("the valid session after the refusals: %d %v", code, err)
	}
}

// TestNoPublicKeyRefusesConsoleSessions: without
// ANSP_SESSION_PUBLIC_KEY_FILE manned-feed verifies no session (fail
// closed): the same valid session is refused 401, and machine tokens are
// still served.
func TestNoPublicKeyRefusesConsoleSessions(t *testing.T) {
	ring, _ := sessionKey(t)
	f := newSessionFeed(t, feedEnv())
	if f.g.Sessions != nil {
		t.Fatal("a session verifier without a key")
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok := issue(t, ring, strings.Repeat("a", 32), auth.RealmConsole, now, now.Add(time.Hour))
	if code, _ := dial(t, f.srv, cookieUpgrade(tok)); code != http.StatusUnauthorized {
		t.Fatalf("a console session without the key: %d, want 401", code)
	}
}

// TestTheSessionSigningKeyIsRefused: ANSP_SESSION_KEY_FILE refuses
// the start, naming the public key variable; a private key given as the
// public key is refused too.
func TestTheSessionSigningKeyIsRefused(t *testing.T) {
	_, pub := sessionKey(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(t.TempDir(), "session.pem")
	if err := os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"the signing key":         {feedEnv("ANSP_SESSION_KEY_FILE="+priv, "ANSP_SESSION_PUBLIC_KEY_FILE="+pub), "ANSP_SESSION_KEY_FILE"},
		"a private key as public": {feedEnv("ANSP_SESSION_PUBLIC_KEY_FILE=" + priv), "a private key"},
		"no issuer":               {[]string{"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_SESSION_PUBLIC_KEY_FILE=" + pub}, "ANSP_PUBLIC_BASE_URL"},
	} {
		cfg, err := config.LoadFrom(tc.env, os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		b, err := bus.Connect(context.Background(), cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := wireGuard(context.Background(), cfg, b, prometheus.NewRegistry()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
