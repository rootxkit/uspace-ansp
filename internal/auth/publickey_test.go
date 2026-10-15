package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
)

// liveMap is a SessionChecker over a map jti -> {sub, role}; revoke
// deletes the row, as api's logout and revocation delete the
// sessions_live key.
type liveMap struct {
	mu   sync.Mutex
	rows map[string][2]string
}

func (m *liveMap) CheckSession(_ context.Context, jti, sub string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[jti]
	if !ok || r[0] != sub {
		return "", fmt.Errorf("%w: no live session", ErrSessionRefused)
	}
	return r[1], nil
}

func (m *liveMap) revoke(jti string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, jti)
}

func publicPEM(t testing.TB, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	must(t, err)
	return pemOf(t, "PUBLIC KEY", der)
}

// sessionOf issues a session token with the signing ring of the test
// session key, as api's sign-in does.
func sessionOf(t testing.TB, ring *coreauth.KeyRing, c coreauth.SessionClaims) string {
	t.Helper()
	iss, err := ring.Issuer(ownIssuer)
	must(t, err)
	tok, err := iss.IssueSession(c)
	must(t, err)
	return tok
}

// TestPublicKeySessionVerifier is manned-feed's verifier (row 54): the
// public part of the session key alone verifies api's sessions, and a
// session that is expired, revoked, of another realm, tampered with or
// signed by another key is refused.
func TestPublicKeySessionVerifier(t *testing.T) {
	sess, _, other := testKeys(t)
	pub, err := ParsePublicKeyPEM(publicPEM(t, &sess.PublicKey))
	must(t, err)
	live := &liveMap{rows: map[string][2]string{}}
	v, err := NewSessionVerifier(context.Background(), SessionVerifierConfig{Issuer: ownIssuer, PublicKey: pub, Audiences: audiences(),
		Checker: live, CacheTTL: time.Nanosecond})
	must(t, err)
	ring := sessionRing(t)
	otherRing, err := coreauth.NewKeyRing(signingKey(t, other))
	must(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	claims := func(j byte, realm string, iat, exp time.Time) coreauth.SessionClaims {
		live.rows[jti(j)] = [2]string{"u-" + string(j), RoleViewer}
		return coreauth.SessionClaims{Audience: ownHost, Subject: "u-" + string(j), Roles: []string{RoleViewer}, Realm: realm,
			IssuedAt: iat, ExpiresAt: exp, JTI: jti(j)}
	}

	// Presence: a live console session is accepted, with its role.
	valid := sessionOf(t, ring, claims('a', RealmConsole, now, now.Add(time.Hour)))
	cl, err := v.Verify(context.Background(), valid)
	if err != nil || cl.Roles[0] != RoleViewer || cl.JTI != jti('a') || cl.Realm != RealmConsole {
		t.Fatalf("a valid session: %+v %v", cl, err)
	}

	// Revoked after it was accepted: the next check refuses it.
	live.revoke(jti('a'))
	time.Sleep(time.Millisecond) // past the cache TTL
	if _, err := v.Verify(context.Background(), valid); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("a revoked session: %v", err)
	}

	tampered := func(tok string) string {
		parts := strings.Split(tok, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		must(t, err)
		up := strings.Replace(string(payload), `"`+RoleViewer+`"`, `"`+RoleAdmin+`"`, 1)
		if up == string(payload) {
			t.Fatal("nothing to tamper with")
		}
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(up))
		return strings.Join(parts, ".")
	}
	for name, tc := range map[string]struct {
		token   string
		counter string
	}{
		"expired":     {sessionOf(t, ring, claims('b', RealmConsole, now.Add(-2*time.Hour), now.Add(-time.Hour))), coreauth.CounterRejectedExpired},
		"wrong realm": {sessionOf(t, ring, claims('c', "portal", now, now.Add(time.Hour))), CounterSessionShape},
		"tampered":    {tampered(sessionOf(t, ring, claims('d', RealmConsole, now, now.Add(time.Hour)))), coreauth.CounterRejectedSignature},
		"another key": {sessionOf(t, otherRing, claims('e', RealmConsole, now, now.Add(time.Hour))), coreauth.CounterRejectedKID},
	} {
		_, err := v.Verify(context.Background(), tc.token)
		var te *coreauth.TokenError
		if !errors.As(err, &te) || te.Counter != tc.counter {
			t.Fatalf("%s: %v, want a token refusal counted %s", name, err, tc.counter)
		}
	}
	if n := v.CoreCounters().Get(coreauth.CounterAccepted); n != 3 { // valid twice, wrong realm once
		t.Fatalf("core accepted %d", n)
	}
}

func TestPublicKeySessionVerifierConfig(t *testing.T) {
	sess, _, _ := testKeys(t)
	ring := sessionRing(t)
	for name, c := range map[string]SessionVerifierConfig{
		"neither": {Issuer: ownIssuer, Audiences: audiences(), Checker: &liveMap{}},
		"both":    {Issuer: ownIssuer, Ring: ring, PublicKey: &sess.PublicKey, Audiences: audiences(), Checker: &liveMap{}},
	} {
		if _, err := NewSessionVerifier(context.Background(), c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// The key set is served from memory only: any other request fails.
	_, client, err := publicKeyIssuer(&sess.PublicKey)
	must(t, err)
	for _, u := range []string{"https://ansp.test/.well-known/jwks.json", "http://127.0.0.1:1/"} {
		resp, err := client.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s answered %d", u, resp.StatusCode)
		}
	}
	resp, err := client.Get(publicKeyJWKSURL)
	must(t, err)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the key set: %d", resp.StatusCode)
	}
}

func TestPublicKeyFiles(t *testing.T) {
	sess, _, _ := testKeys(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, b, 0o600))
		return p
	}
	pkcs1 := pemOf(t, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&sess.PublicKey))
	for name, b := range map[string][]byte{"pkix.pem": publicPEM(t, &sess.PublicKey), "pkcs1.pem": pkcs1} {
		pub, err := LoadPublicKeyFile("ANSP_SESSION_PUBLIC_KEY_FILE", write(name, b))
		if err != nil || !pub.Equal(&sess.PublicKey) || Thumbprint(pub) != Thumbprint(&sess.PublicKey) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(sess)
	must(t, err)
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	must(t, err)
	shortDER, err := x509.MarshalPKIXPublicKey(&short.PublicKey)
	must(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	must(t, err)
	for name, tc := range map[string]struct {
		b    []byte
		want string
	}{
		"pkcs1 private": {pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(sess)), "a private key"},
		"pkcs8 private": {pemOf(t, "PRIVATE KEY", pkcs8), "a private key"},
		"short":         {pemOf(t, "PUBLIC KEY", shortDER), "1024 bits"},
		"ec":            {pemOf(t, "PUBLIC KEY", ecDER), "not an RSA key"},
		"two blocks":    {append(publicPEM(t, &sess.PublicKey), pkcs1...), "more than one PEM block"},
		"not pem":       {[]byte("not a key"), "no PEM block"},
		"certificate":   {pemOf(t, "CERTIFICATE", []byte{1}), "not a public key"},
		"bad pkix":      {pemOf(t, "PUBLIC KEY", []byte{1}), "not a SubjectPublicKeyInfo"},
		"bad pkcs1":     {pemOf(t, "RSA PUBLIC KEY", []byte{1}), "not a PKCS #1"},
	} {
		_, err := LoadPublicKeyFile("ANSP_SESSION_PUBLIC_KEY_FILE", write(strings.ReplaceAll(name, " ", "-"), tc.b))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "ANSP_SESSION_PUBLIC_KEY_FILE") {
			t.Fatalf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if _, err := LoadPublicKeyFile("ANSP_SESSION_PUBLIC_KEY_FILE", filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file was accepted")
	}
}
