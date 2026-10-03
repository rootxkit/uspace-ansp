package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/audit"
)

// The keys of the tests: generated once per run, never written anywhere
// (06 section 4: no key material in the repository).
var (
	keysOnce sync.Once
	keySess  *rsa.PrivateKey
	keyEco   *rsa.PrivateKey
	keyOther *rsa.PrivateKey
)

func testKeys(t testing.TB) (sess, eco, other *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		for _, k := range []**rsa.PrivateKey{&keySess, &keyEco, &keyOther} {
			var err error
			if *k, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
				panic(err)
			}
		}
	})
	return keySess, keyEco, keyOther
}

const (
	ownHost   = "ansp.test"
	labAlias  = "ansp-api"
	ownIssuer = "https://ansp.test"
	ussp      = "ussp-geo-01"
)

func audiences() []string { return []string{ownHost, labAlias} }

// clock is a settable test clock.
type clock struct{ t atomic.Int64 }

func newClock(at time.Time) *clock {
	c := &clock{}
	c.t.Store(at.UnixNano())
	return c
}
func (c *clock) Now() time.Time      { return time.Unix(0, c.t.Load()).UTC() }
func (c *clock) Add(d time.Duration) { c.t.Add(int64(d)) }
func t0() time.Time                  { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func signingKey(t testing.TB, k *rsa.PrivateKey) coreauth.SigningKey {
	t.Helper()
	sk, err := NewSigningKey(k)
	must(t, err)
	return sk
}

func sessionRing(t testing.TB) *coreauth.KeyRing {
	t.Helper()
	s, _, _ := testKeys(t)
	r, err := coreauth.NewKeyRing(signingKey(t, s))
	must(t, err)
	return r
}

// ecosystem is a fake token service: an issuer whose JWKS an httptest
// server publishes until Down.
type ecosystem struct {
	URL    string
	JWKS   string
	issuer *coreauth.Issuer
	down   atomic.Bool
	hits   atomic.Int64
}

func newEcosystem(t testing.TB) *ecosystem {
	t.Helper()
	_, k, _ := testKeys(t)
	e := &ecosystem{URL: "https://authority.test"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.hits.Add(1)
		if e.down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(e.issuer.JWKS())
	}))
	t.Cleanup(srv.Close)
	e.JWKS = srv.URL + "/.well-known/jwks.json"
	var err error
	e.issuer, err = coreauth.NewIssuer(e.URL, k, signingKey(t, k).KID)
	must(t, err)
	return e
}

func (e *ecosystem) token(t testing.TB, sub, aud string, scopes []string, now time.Time) string {
	t.Helper()
	tok, err := e.issuer.Issue(sub, aud, scopes, 10*time.Minute, now)
	must(t, err)
	return tok
}

func newMachine(t testing.TB, e *ecosystem, c *clock) *MachineVerifier {
	t.Helper()
	m, err := NewMachineVerifierWith(context.Background(), coreauth.Config{
		Issuers:             map[string]coreauth.IssuerConfig{e.URL: {JWKSURL: e.JWKS}},
		Audiences:           audiences(),
		StrictSessionClaims: true,
		Now:                 c.Now,
	}, nil)
	must(t, err)
	return m
}

// memStore is Store in memory: one lock for the whole store, a
// transaction rolled back by restoring a copy of every table.
type memStore struct {
	mu    sync.Mutex
	clock *clock
	seq   int
	data  memData
	// fail, when set, fails the named operation.
	fail map[string]error
	// writes counts the operations that wrote.
	clientsSeen [][]ClientSeen
	// recorded is whether the open transaction audited already;
	// lockAfterAudit lists the lockout-row locks taken after an audit in
	// one transaction. The audit takes the month's advisory lock to the
	// end of the transaction, so a row lock after it, against a failed
	// sign-in that holds the row and waits for the month, deadlocks
	// (ansp audit S-6): every row lock comes before the first audit.
	recorded       bool
	lockAfterAudit []string
}

type memData struct {
	users      map[string]User
	mfa        map[string]MFA
	challenges map[string]Challenge
	lockouts   map[string]Lockout
	sessions   map[string]SessionRow
	events     []audit.Event
}

func (d memData) clone() memData {
	return memData{users: maps.Clone(d.users), mfa: maps.Clone(d.mfa), challenges: maps.Clone(d.challenges),
		lockouts: maps.Clone(d.lockouts), sessions: maps.Clone(d.sessions), events: slices.Clone(d.events)}
}

func newMemStore(c *clock) *memStore {
	return &memStore{clock: c, fail: map[string]error{}, data: memData{users: map[string]User{}, mfa: map[string]MFA{},
		challenges: map[string]Challenge{}, lockouts: map[string]Lockout{}, sessions: map[string]SessionRow{}}}
}

func (m *memStore) failing(op string) error { return m.fail[op] }

func (m *memStore) events(eventType string) []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for _, e := range m.data.events {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

func (m *memStore) InTx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failing("tx"); err != nil {
		return err
	}
	saved := m.data.clone()
	m.recorded = false
	if err := fn(ctx, memTx{m}); err != nil {
		m.data = saved
		return err
	}
	return nil
}

func (m *memStore) Session(_ context.Context, jti string) (SessionRow, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failing("session"); err != nil {
		return SessionRow{}, time.Time{}, err
	}
	s, ok := m.data.sessions[jti]
	if !ok {
		return SessionRow{}, m.clock.Now(), ErrNotFound
	}
	return s, m.clock.Now(), nil
}

func (m *memStore) TouchSession(_ context.Context, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failing("touch"); err != nil {
		return err
	}
	if s, ok := m.data.sessions[jti]; ok && s.RevokedAt == nil {
		s.LastSeenAt = m.clock.Now()
		m.data.sessions[jti] = s
	}
	return nil
}

func (m *memStore) Users(_ context.Context, limit int) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failing("users"); err != nil {
		return nil, err
	}
	out := slices.Collect(maps.Values(m.data.users))
	slices.SortFunc(out, func(a, b User) int {
		if a.Username < b.Username {
			return -1
		}
		return 1
	})
	return out[:min(limit, len(out))], nil
}

func (m *memStore) RecordClientsSeen(_ context.Context, seen []ClientSeen) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failing("seen"); err != nil {
		return err
	}
	m.clientsSeen = append(m.clientsSeen, slices.Clone(seen))
	return nil
}

type memTx struct{ m *memStore }

func (t memTx) d() *memData { return &t.m.data }

func (t memTx) Now(context.Context) (time.Time, error) {
	if err := t.m.failing("now"); err != nil {
		return time.Time{}, err
	}
	return t.m.clock.Now(), nil
}

func (t memTx) Record(_ context.Context, ev audit.Event) error {
	if err := t.m.failing("record"); err != nil {
		return err
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	if _, err := json.Marshal(ev.Payload); err != nil {
		return err
	}
	t.d().events = append(t.d().events, ev)
	t.m.recorded = true
	return nil
}

// rowLock notes a lockout-row lock taken after an audit.
func (t memTx) rowLock(name string) {
	if t.m.recorded {
		t.m.lockAfterAudit = append(t.m.lockAfterAudit, name)
	}
}

func (t memTx) UserByUsername(_ context.Context, username string) (User, error) {
	if err := t.m.failing("user"); err != nil {
		return User{}, err
	}
	for id := range t.d().users {
		if u := t.d().users[id]; u.Username == username {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (t memTx) UserByID(_ context.Context, id string) (User, error) {
	u, ok := t.d().users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (t memTx) UserForUpdate(ctx context.Context, id string) (User, error) {
	return t.UserByID(ctx, id)
}

func (t memTx) CountUsers(context.Context) (int64, error) { return int64(len(t.d().users)), nil }

func (t memTx) CountActiveAdmins(context.Context) (int64, error) {
	var n int64
	for id := range t.d().users {
		if u := t.d().users[id]; u.Role == RoleAdmin && u.Status == StatusActive {
			n++
		}
	}
	return n, nil
}

func (t memTx) InsertUser(ctx context.Context, u User, _ string, at time.Time) (User, error) {
	if err := t.m.failing("insert_user"); err != nil {
		return User{}, err
	}
	if _, err := t.UserByUsername(ctx, u.Username); err == nil {
		return User{}, ErrConflict
	}
	t.m.seq++
	u.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", t.m.seq)
	u.CreatedAt, u.UpdatedAt = at, at
	t.d().users[u.ID] = u
	return u, nil
}

func (t memTx) SetUserStatus(_ context.Context, id, status, _ string, at time.Time) (User, error) {
	u, ok := t.d().users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Status, u.UpdatedAt = status, at
	t.d().users[id] = u
	return u, nil
}

func (t memTx) TouchLogin(_ context.Context, id string, at time.Time) error {
	u := t.d().users[id]
	u.LastLoginAt = &at
	t.d().users[id] = u
	return nil
}

func (t memTx) Lockout(_ context.Context, username string, _ time.Time) (Lockout, error) {
	if err := t.m.failing("lockout"); err != nil {
		return Lockout{}, err
	}
	t.rowLock("Lockout")
	l, ok := t.d().lockouts[username]
	if !ok {
		l = Lockout{Username: username}
		t.d().lockouts[username] = l
	}
	return l, nil
}

func (t memTx) PeekLockout(_ context.Context, username string) (Lockout, error) {
	l, ok := t.d().lockouts[username]
	if !ok {
		return Lockout{}, ErrNotFound
	}
	return l, nil
}

func (t memTx) SetLockout(_ context.Context, l Lockout, _ time.Time) error {
	t.rowLock("SetLockout")
	t.d().lockouts[l.Username] = l
	return nil
}

func (t memTx) ClearLockout(_ context.Context, username string) error {
	t.rowLock("ClearLockout")
	delete(t.d().lockouts, username)
	return nil
}

func (t memTx) MFAForUpdate(_ context.Context, userID string) (MFA, error) {
	if err := t.m.failing("mfa"); err != nil {
		return MFA{}, err
	}
	m, ok := t.d().mfa[userID]
	if !ok {
		return MFA{}, ErrNotFound
	}
	return m, nil
}

func (t memTx) SaveMFA(_ context.Context, m MFA, _ time.Time) error {
	t.d().mfa[m.UserID] = m
	return nil
}

func (t memTx) DeleteMFA(_ context.Context, userID string) error {
	delete(t.d().mfa, userID)
	return nil
}

func (t memTx) InsertChallenge(_ context.Context, c Challenge) error {
	t.d().challenges[c.TokenHash] = c
	return nil
}

func (t memTx) ChallengeForUpdate(_ context.Context, hash string) (Challenge, error) {
	c, ok := t.d().challenges[hash]
	if !ok {
		return Challenge{}, ErrNotFound
	}
	return c, nil
}

func (t memTx) CountChallengeAttempt(_ context.Context, hash string) error {
	c := t.d().challenges[hash]
	c.Attempts++
	t.d().challenges[hash] = c
	return nil
}

func (t memTx) UseChallenge(_ context.Context, hash string, at time.Time) error {
	c := t.d().challenges[hash]
	c.UsedAt = &at
	t.d().challenges[hash] = c
	return nil
}

func (t memTx) InsertSession(_ context.Context, s SessionRow) error {
	if err := t.m.failing("insert_session"); err != nil {
		return err
	}
	t.d().sessions[s.JTI] = s
	return nil
}

func (t memTx) RevokeSession(_ context.Context, jti, reason string, at time.Time) (bool, error) {
	if err := t.m.failing("revoke"); err != nil {
		return false, err
	}
	s, ok := t.d().sessions[jti]
	if !ok || s.RevokedAt != nil {
		return false, nil
	}
	s.RevokedAt, s.RevokeReason = &at, reason
	t.d().sessions[jti] = s
	return true, nil
}

func (t memTx) RevokeUserSessions(ctx context.Context, userID, reason string, at time.Time) ([]string, error) {
	var out []string
	for jti := range t.d().sessions {
		if s := t.d().sessions[jti]; s.UserID == userID && s.RevokedAt == nil {
			if _, err := t.RevokeSession(ctx, jti, reason, at); err != nil {
				return nil, err
			}
			out = append(out, jti)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (t memTx) Sweep(_ context.Context, before, now time.Time) (sessions, challenges, lockouts int64, err error) {
	if err := t.m.failing("sweep"); err != nil {
		return 0, 0, 0, err
	}
	for k := range t.d().sessions {
		if t.d().sessions[k].ExpiresAt.Before(before) {
			delete(t.d().sessions, k)
			sessions++
		}
	}
	for k, c := range t.d().challenges {
		if c.ExpiresAt.Before(before) {
			delete(t.d().challenges, k)
			challenges++
		}
	}
	for k, l := range t.d().lockouts {
		if l.LockedUntil == nil || l.LockedUntil.Before(now) {
			delete(t.d().lockouts, k)
			lockouts++
		}
	}
	return sessions, challenges, lockouts, nil
}

var errDown = errors.New("connection refused")

// cheapHasher is argon2id with the cheapest parameters the bounds allow.
func cheapHasher(t testing.TB) *Hasher {
	t.Helper()
	h, err := NewHasherWithParams(HashParams{MemoryKiB: 64, Time: 1, Threads: 1})
	must(t, err)
	return h
}

// world is the accounts service, the session verifier and the guard of
// the tests, on a memory store and a test clock.
type world struct {
	clock    *clock
	store    *memStore
	accounts *Accounts
	sessions *SessionVerifier
	guard    *Guard
	keys     *PublicKeys
	eco      *ecosystem
}

func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{clock: newClock(t0())}
	w.store = newMemStore(w.clock)
	ring := sessionRing(t)
	sealer, err := NewSealer(make([]byte, SealKeyBytes))
	must(t, err)
	w.accounts, err = NewAccounts(AccountsDeps{
		Store: w.store, Hasher: cheapHasher(t), Sealer: sealer, Ring: ring, Issuer: ownIssuer,
		IPLimiter: NewRateLimiter(1000, 100, nil, w.clock.Now), UserLimiter: NewRateLimiter(1000, 100, nil, w.clock.Now),
	}, AccountsConfig{Audience: ownHost, LockoutAfter: 3, LockoutFor: 15 * time.Minute})
	must(t, err)
	w.sessions, err = NewSessionVerifier(context.Background(), SessionVerifierConfig{
		Issuer: ownIssuer, Ring: ring, Audiences: audiences(), Checker: w.accounts, Now: w.clock.Now,
	})
	must(t, err)
	w.accounts.SetSessionVerifier(w.sessions)
	w.eco = newEcosystem(t)
	// httptest.NewRequest's peer is 192.0.2.1: the fixture's Caddy.
	proxies, err := ParseTrustedProxies([]string{"192.0.2.1"})
	must(t, err)
	mtls, err := NewMTLS("required", map[string]string{ussp: "CN=" + ussp}, proxies)
	must(t, err)
	w.guard = &Guard{Machine: newMachine(t, w.eco, w.clock), Sessions: w.sessions, MTLS: mtls, Origins: []string{"https://ansp.test"}}
	w.keys = NewPublicKeys()
	must(t, w.keys.Add("session", ring))
	return w
}

// addUser creates an account directly.
func (w *world) addUser(t testing.TB, username, password, role string) User {
	t.Helper()
	v, err := w.accounts.CreateUser(context.Background(), Principal{}, username, password, role)
	must(t, err)
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	return w.store.data.users[v.ID]
}

// code is the TOTP code of secret at the clock's now.
func (w *world) code(t testing.TB, secret string) string {
	t.Helper()
	c, err := totpCode(secret, w.clock.Now())
	must(t, err)
	return c
}

// signIn logs in and passes the MFA step, enrolling on the way, and
// returns the session token and the TOTP secret.
func (w *world) signIn(t testing.TB, username, password string) (MFAResult, string) {
	t.Helper()
	ctx := context.Background()
	lr, err := w.accounts.Login(ctx, username, password, RequestInfo{RemoteIP: "192.0.2.1"})
	must(t, err)
	if lr.Enrolment == nil {
		t.Fatal("no enrolment for a new account")
	}
	res, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, lr.Enrolment.Secret), RequestInfo{RemoteIP: "192.0.2.1"})
	must(t, err)
	return res, lr.Enrolment.Secret
}

// totpCode is the RFC 6238 code of secret at at (pquerna/otp).
func totpCode(secret string, at time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

// waitFor polls cond for up to five seconds.
func waitFor(t testing.TB, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}
