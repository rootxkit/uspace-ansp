package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.0/8", " 192.0.2.10 ", "::ffff:198.51.100.1"})
	must(t, err)
	if _, err := ParseTrustedProxies([]string{"not-an-address"}); err == nil {
		t.Fatal("bad proxy")
	}
	for name, c := range map[string]struct {
		peer string
		xff  []string
		want string
	}{
		"untrusted peer, header ignored": {"203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		"trusted peer, rightmost hop":    {"10.0.0.2:1", []string{"6.6.6.6, 198.18.0.1"}, "198.18.0.1"},
		"chain of proxies":               {"10.0.0.2:1", []string{"198.18.0.1", "192.0.2.10, 10.1.1.1"}, "198.18.0.1"},
		"garbage stops at last trusted":  {"10.0.0.2:1", []string{"x, 10.1.1.1"}, "10.1.1.1"},
		"no header":                      {"10.0.0.2:1", nil, "10.0.0.2"},
		"no port":                        {"203.0.113.5", nil, "203.0.113.5"},
		"mapped proxy":                   {"[::ffff:198.51.100.1]:1", []string{"198.18.0.9"}, "198.18.0.9"},
	} {
		if got := ClientIP(c.peer, c.xff, proxies); got != c.want {
			t.Fatalf("%s: %s", name, got)
		}
	}
	long := strings.Repeat("10.9.9.9, ", MaxForwardedHops+5) + "198.18.0.3"
	if got := ClientIP("10.0.0.2:1", []string{"1.1.1.1, " + long}, proxies); got != "198.18.0.3" {
		t.Fatal(got)
	}
	allTrusted := strings.TrimSuffix(strings.Repeat("10.9.9.9, ", MaxForwardedHops+5), ", ")
	if got := ClientIP("10.0.0.2:1", []string{"1.1.1.1, " + allTrusted}, proxies); got != "10.9.9.9" {
		t.Fatalf("the hops beyond the bound are not read: %s", got)
	}
	if ClientIP("203.0.113.5:1", []string{"1.2.3.4"}, nil) != "203.0.113.5" {
		t.Fatal("no proxies")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "garbage"
	if RemoteIP(r) != "garbage" {
		t.Fatal(RemoteIP(r))
	}
}

// E-10: the limiter remembers at most its bound of keys (the least
// recently seen evicted, counted), and a spent bucket refills.
func TestRateLimiterBound(t *testing.T) {
	c := newClock(t0())
	l := NewRateLimiter(60, 3, nil, c.Now)
	for i := range 5 {
		if ok, _ := l.Allow(fmt.Sprintf("ip:%d", i)); !ok {
			t.Fatal("a fresh key refused")
		}
	}
	if l.Len() != 3 || l.counters.Get(CounterLimiterEvict) != 2 {
		t.Fatalf("%d %v", l.Len(), l.counters.Snapshot())
	}
	one := NewRateLimiter(1, 10, nil, c.Now)
	if ok, _ := one.Allow("k"); !ok {
		t.Fatal("first")
	}
	ok, wait := one.Allow("k")
	if ok || wait != time.Minute {
		t.Fatalf("%v %v", ok, wait)
	}
	c.Add(time.Minute)
	if ok, _ := one.Allow("k"); !ok {
		t.Fatal("past the window")
	}
	if NewRateLimiter(0, 0, nil, nil).max != 1 {
		t.Fatal("bounds")
	}
}

// E-10: the session cache holds at most its bound (evicted, counted),
// and an entry is reused only within its TTL.
func TestSessionCacheBound(t *testing.T) {
	c := newClock(t0())
	counters := &core.Counters{}
	sc := newSessionCache(2, time.Second, c.Now, counters)
	sc.put("a", "u", RoleViewer)
	sc.put("b", "u", RoleViewer)
	sc.put("b", "u", RoleViewer)
	sc.put("c", "u", RoleViewer)
	if sc.len() != 2 || counters.Get(CounterSessionCacheEvict) != 1 || sc.live("a", "u", RoleViewer) {
		t.Fatalf("%d", sc.len())
	}
	if !sc.live("c", "u", RoleViewer) || sc.live("c", "v", RoleViewer) {
		t.Fatal("subject not compared")
	}
	sc.put("c", "u", RoleViewer)
	c.Add(time.Second)
	if sc.live("c", "u", RoleViewer) {
		t.Fatal("past the TTL")
	}
	sc.forget("b")
	sc.forget("none")
	if sc.len() != 0 {
		t.Fatal(sc.len())
	}

	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	res, _ := w.signIn(t, "sup1", pw)
	for range 3 {
		_, err := w.sessions.Verify(context.Background(), res.Token)
		must(t, err)
	}
	if w.sessions.Counters().Get(CounterSessionCacheHit) != 2 || w.sessions.CacheLen() != 1 || w.sessions.CoreCounters().Get(coreauth.CounterAccepted) != 3 {
		t.Fatalf("%v", w.sessions.Counters().Snapshot())
	}
}

func TestNewSessionVerifierRefusals(t *testing.T) {
	ring := sessionRing(t)
	ok := SessionVerifierConfig{Issuer: ownIssuer, Ring: ring, Audiences: audiences(), Checker: (*Accounts)(nil)}
	for name, c := range map[string]SessionVerifierConfig{
		"issuer":   {Ring: ring, Audiences: audiences(), Checker: ok.Checker},
		"ring":     {Issuer: ownIssuer, Audiences: audiences(), Checker: ok.Checker},
		"audience": {Issuer: ownIssuer, Ring: ring, Checker: ok.Checker},
		"checker":  {Issuer: ownIssuer, Ring: ring, Audiences: audiences()},
	} {
		if _, err := NewSessionVerifier(context.Background(), c); err == nil {
			t.Fatalf("no %s accepted", name)
		}
	}
	v, err := NewSessionVerifier(context.Background(), ok)
	if err != nil || v.Issuer() != ownIssuer {
		t.Fatal(err)
	}
}

func pemOf(t testing.TB, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestKeyFiles(t *testing.T) {
	s, _, _ := testKeys(t)
	dir := t.TempDir()
	p8, err := x509.MarshalPKCS8PrivateKey(s)
	must(t, err)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		must(t, os.WriteFile(p, b, 0o600))
		return p
	}
	for name, b := range map[string][]byte{"pkcs1": pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(s)), "pkcs8": pemOf(t, "PRIVATE KEY", p8)} {
		sk, err := LoadKeyFile("ANSP_SESSION_KEY_FILE", write(name, b))
		if err != nil || sk.KID != Thumbprint(&s.PublicKey) || len(sk.KID) != 43 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	must(t, err)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	must(t, err)
	enc := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	for name, b := range map[string][]byte{
		"empty":     nil,
		"two":       append(pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(s)), pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(s))...),
		"encrypted": enc,
		"ec":        pemOf(t, "PRIVATE KEY", ecDER),
		"cert":      pemOf(t, "CERTIFICATE", []byte{1, 2}),
		"bad pkcs1": pemOf(t, "RSA PRIVATE KEY", []byte{1, 2}),
		"bad pkcs8": pemOf(t, "PRIVATE KEY", []byte{1, 2}),
		"short":     pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(small)),
		"huge":      []byte(strings.Repeat("x", MaxKeyFileBytes+1)),
	} {
		if _, err := LoadKeyFile("ANSP_SESSION_KEY_FILE", write(name, b)); err == nil {
			t.Fatalf("%s accepted", name)
		} else if strings.Contains(err.Error(), "PRIVATE KEY-----") {
			t.Fatalf("%s: the error quotes the file", name)
		}
	}
	if _, err := LoadKeyFile("ANSP_SESSION_KEY_FILE", filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file")
	}
	if _, err := NewSigningKey(nil); err == nil {
		t.Fatal("nil key")
	}
	bad := *s
	bad.D = big.NewInt(1)
	if _, err := NewSigningKey(&bad); err == nil {
		t.Fatal("a key that does not validate")
	}
}

func TestPublicKeys(t *testing.T) {
	_, eco, other := testKeys(t)
	pk := NewPublicKeys()
	sess := sessionRing(t)
	must(t, pk.Add("session", sess))
	if err := pk.Add("session", sess); err == nil {
		t.Fatal("name twice")
	}
	if err := pk.Add("again", sess); err == nil {
		t.Fatal("kid twice")
	}
	if err := pk.Add("", nil); err == nil {
		t.Fatal("nil ring")
	}
	delivery, err := coreauth.NewKeyRing(signingKey(t, eco), signingKey(t, other))
	must(t, err)
	must(t, pk.Add("delivery", delivery))
	rec := httptest.NewRecorder()
	pk.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			D   string `json:"d"`
		} `json:"keys"`
	}
	must(t, json.Unmarshal(rec.Body.Bytes(), &set))
	if rec.Code != http.StatusOK || len(set.Keys) != 3 || rec.Header().Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, k := range set.Keys {
		if k.Alg != "RS256" || k.Use != "sig" || k.D != "" || k.KID == "" {
			t.Fatalf("%+v", k)
		}
	}
	if set.Keys[0].KID != sess.ActiveKID() {
		t.Fatal("order")
	}
}

func TestSealer(t *testing.T) {
	key := make([]byte, SealKeyBytes)
	_, _ = rand.Read(key)
	dir := t.TempDir()
	hexPath, b64Path, badPath := filepath.Join(dir, "hex"), filepath.Join(dir, "b64"), filepath.Join(dir, "bad")
	must(t, os.WriteFile(hexPath, []byte(hex.EncodeToString(key)+"\n"), 0o600))
	must(t, os.WriteFile(b64Path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	must(t, os.WriteFile(badPath, []byte("too short"), 0o600))
	a, err := LoadSealer(hexPath)
	must(t, err)
	b, err := LoadSealer(b64Path)
	must(t, err)
	if a.KeyID() != b.KeyID() || len(a.KeyID()) != 16 {
		t.Fatal("key id")
	}
	if _, err := LoadSealer(badPath); err == nil {
		t.Fatal("short key")
	}
	if _, err := LoadSealer(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
	if _, err := NewSealer([]byte{1}); err == nil {
		t.Fatal("short")
	}
	sealed, err := a.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user_mfa:1"))
	must(t, err)
	if got, err := b.Open(a.KeyID(), sealed, []byte("user_mfa:1")); err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kid    string
		sealed []byte
		aad    string
	}{
		"other row":  {a.KeyID(), sealed, "user_mfa:2"},
		"other key":  {"0000000000000000", sealed, "user_mfa:1"},
		"truncated":  {a.KeyID(), sealed[:10], "user_mfa:1"},
		"tampered":   {a.KeyID(), append(append([]byte{}, sealed[:len(sealed)-1]...), sealed[len(sealed)-1]^1), "user_mfa:1"},
		"empty blob": {a.KeyID(), nil, "user_mfa:1"},
	} {
		if _, err := a.Open(c.kid, c.sealed, []byte(c.aad)); !errors.Is(err, ErrSealedKey) {
			t.Fatalf("%s opened", name)
		}
	}
}

func TestTOTP(t *testing.T) {
	secret, uri, err := NewTOTPSecret("sup1")
	must(t, err)
	if again, err := TOTPURI("sup1", secret); err != nil || again != uri {
		t.Fatalf("%s %s %v", uri, again, err)
	}
	if _, err := TOTPURI("sup1", "!!!"); err == nil {
		t.Fatal("bad secret")
	}
	now := t0()
	code, err := totpCode(secret, now)
	must(t, err)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || step != now.Unix()/30 {
		t.Fatal("right code")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("the same step twice")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(TOTPPeriod), 0); !ok {
		t.Fatal("one step of skew")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(3*TOTPPeriod), 0); ok {
		t.Fatal("three steps late")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", " 12345"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Fatalf("%q", bad)
		}
	}
}

func TestHasher(t *testing.T) {
	h := cheapHasher(t)
	enc, err := h.Hash(pw)
	must(t, err)
	if ok, err := h.Verify(pw, enc); !ok || err != nil {
		t.Fatal("right password")
	}
	if ok, _ := h.Verify("wrong", enc); ok {
		t.Fatal("wrong password")
	}
	if _, err := h.Hash(strings.Repeat("a", MaxSecretBytes+1)); err == nil {
		t.Fatal("long secret hashed")
	}
	long := pw + strings.Repeat("a", MaxSecretBytes)
	if ok, _ := h.Verify(long, enc); ok {
		t.Fatal("long secret matched")
	}
	for _, bad := range []string{
		"", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$dGFn", "$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHQ$dGFndGFndGFndGFndGFn",
		"$argon2id$v=19$m=64,t=1$c2FsdHNhbHQ$dGFn", "$argon2id$v=19$x=64,t=1,p=1$c2FsdHNhbHQ$dGFn",
		"$argon2id$v=19$m=a,t=1,p=1$c2FsdHNhbHQ$dGFn", "$argon2id$v=19$m=64,t=1,p=300$c2FsdHNhbHQ$dGFn",
		"$argon2id$v=19$m=64,t=0,p=1$c2FsdHNhbHQ$dGFndGFndGFndGFndGFn", "$argon2id$v=19$m=64,t=1,p=1$!!$dGFndGFndGFndGFndGFn",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$dGFn",
	} {
		if ok, err := h.Verify(pw, bad); ok || !errors.Is(err, ErrMalformedHash) {
			t.Fatalf("%q: %v %v", bad, ok, err)
		}
	}
	if _, err := NewHasherWithParams(HashParams{}); err == nil {
		t.Fatal("zero parameters")
	}
	def, err := NewHasher()
	must(t, err)
	if def.p.MemoryKiB != HashMemoryKiB || def.p.Time != HashTime {
		t.Fatal("defaults")
	}
}

// E-10: the SeenRecorder never blocks: a full queue drops (counted);
// a flush coalesces per client and counts what it wrote or failed to.
func TestSeenRecorder(t *testing.T) {
	s := NewSeenRecorder(3, time.Hour)
	for i := range 5 {
		s.Record(ClientSeen{ClientID: "ussp-geo-01", Issuer: "https://authority.test", Scopes: []string{fmt.Sprintf("s%d", i%2)}})
	}
	if s.Counters().Get(CounterSeenDropped) != 2 {
		t.Fatalf("%v", s.Counters().Snapshot())
	}
	store := newMemStore(newClock(t0()))
	s.Flush(context.Background(), store)
	if len(store.clientsSeen) != 1 || len(store.clientsSeen[0]) != 1 || len(store.clientsSeen[0][0].Scopes) != 2 {
		t.Fatalf("%+v", store.clientsSeen)
	}
	s.Record(ClientSeen{ClientID: "a", Scopes: make([]string, MaxScopesSeen+3)})
	store.fail["seen"] = errDown
	s.Flush(context.Background(), store)
	if s.Counters().Get(CounterSeenWriteFailed) != 1 || s.Counters().Get(CounterSeenWritten) != 1 {
		t.Fatalf("%v", s.Counters().Snapshot())
	}
	// Run flushes on its period and once more when stopped.
	delete(store.fail, "seen")
	r := NewSeenRecorder(0, time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, store); close(done) }()
	r.Record(ClientSeen{ClientID: "b", MTLSSubject: "CN=b"})
	waitFor(t, func() bool { return r.Counters().Get(CounterSeenWritten) == 1 })
	r.Record(ClientSeen{ClientID: "c"})
	cancel()
	<-done
	if r.Counters().Get(CounterSeenWritten) != 2 {
		t.Fatalf("%v", r.Counters().Snapshot())
	}
	// A batch is bounded and merges the subject of a later call.
	m := NewSeenRecorder(MaxSeenBatch+10, time.Hour)
	m.Record(ClientSeen{ClientID: "x"})
	m.Record(ClientSeen{ClientID: "x", MTLSSubject: "CN=x"})
	for i := range MaxSeenBatch + 5 {
		m.Record(ClientSeen{ClientID: fmt.Sprintf("c%d", i)})
	}
	first := m.drain()
	if len(first) != MaxSeenBatch || first[0].MTLSSubject != "CN=x" {
		t.Fatalf("%d %+v", len(first), first[0])
	}
}

// The guard records accepted machine calls, with the bound subject.
func TestGuardRecordsClientsSeen(t *testing.T) {
	w := newWorld(t)
	w.guard.Seen = NewSeenRecorder(10, time.Hour)
	hdr := withBearer(w.eco.token(t, ussp, ownHost, []string{"ansp.coordination"}, w.clock.Now()))
	hdr[HeaderClientCertSubject] = "CN=" + ussp
	rec, _ := call(t, w.guard.Require(Access{Scopes: []string{"ansp.coordination"}, MTLS: true}), http.MethodPost, "/v1/coordination/notices", hdr)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	got := w.guard.Seen.drain()
	if len(got) != 1 || got[0].ClientID != ussp || got[0].MTLSSubject != "CN="+ussp || got[0].Issuer != w.eco.URL {
		t.Fatalf("%+v", got)
	}
}

// BenchmarkArgon2id is the cost of one password hash with the
// production parameters; 06 section 3 asks for at least 100 ms on the
// CI runner, and the benchmark fails below it.
func BenchmarkArgon2id(b *testing.B) {
	h, err := NewHasher()
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := h.Hash(pw); err != nil {
			b.Fatal(err)
		}
	}
	if per := b.Elapsed() / time.Duration(b.N); per < 100*time.Millisecond {
		b.Fatalf("argon2id takes %s per hash, under the 100 ms floor", per)
	}
}

// BenchmarkVerifyToken is one machine token through core's verifier
// (cached JWKS).
func BenchmarkVerifyToken(b *testing.B) {
	e := newEcosystem(b)
	c := newClock(time.Now())
	m := newMachine(b, e, c)
	tok := e.token(b, ussp, ownHost, []string{"ansp.traffic"}, c.Now())
	ctx := context.Background()
	for b.Loop() {
		if _, err := m.Verify(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
}
