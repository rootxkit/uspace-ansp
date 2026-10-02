//go:build integration

package store_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

const authPW = "correct horse battery"

// authWorld is the accounts service on a scratch relational database,
// working as ansp_app.
type authWorld struct {
	dsn      string
	db       *store.Relational
	repo     store.AuthRepo
	accounts *auth.Accounts
	sessions *auth.SessionVerifier
}

func newAuthWorld(t *testing.T) *authWorld {
	t.Helper()
	w := &authWorld{dsn: storetest.Scratch(t, store.TreeRelational, true)}
	w.db = storetest.Relational(t, w.dsn, store.RoleRelational)
	w.repo = store.AuthRepo{DB: w.db}
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
	sealKey := make([]byte, auth.SealKeyBytes)
	_, _ = rand.Read(sealKey)
	sealer, err := auth.NewSealer(sealKey)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := auth.NewHasherWithParams(auth.HashParams{MemoryKiB: 64, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	w.accounts, err = auth.NewAccounts(auth.AccountsDeps{
		Store: w.repo, Hasher: hasher, Sealer: sealer, Ring: ring, Issuer: "https://ansp.test",
		IPLimiter: auth.NewRateLimiter(1000, 100, nil, nil), UserLimiter: auth.NewRateLimiter(1000, 100, nil, nil),
	}, auth.AccountsConfig{Audience: "ansp.test", LockoutAfter: 3, LockoutFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	w.sessions, err = auth.NewSessionVerifier(context.Background(), auth.SessionVerifierConfig{
		Issuer: "https://ansp.test", Ring: ring, Audiences: []string{"ansp.test"}, Checker: w.accounts, CacheTTL: time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.accounts.SetSessionVerifier(w.sessions)
	return w
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func eventCount(t *testing.T, dsn, eventType string) int64 {
	t.Helper()
	return scalar[int64](t, dsn, `SELECT count(*) FROM events WHERE event_type = $1`, eventType)
}

// The sign-in against real PostgreSQL as ansp_app: account, enrolment,
// session row, the session token verified with the row checked, logout
// ending it; every step an events row in the hash chain.
func TestIntegrationAuthSignIn(t *testing.T) {
	ctx := ctxT(t)
	w := newAuthWorld(t)
	v, err := w.accounts.CreateUser(ctx, auth.Principal{}, "sup1", authPW, auth.RoleWatchSupervisor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.accounts.CreateUser(ctx, auth.Principal{}, "sup1", authPW, auth.RoleViewer); !isStatus(err, http.StatusConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	lr, err := w.accounts.Login(ctx, "sup1", authPW, auth.RequestInfo{RemoteIP: "192.0.2.1", UserAgent: "test"})
	if err != nil || lr.Enrolment == nil {
		t.Fatalf("login: %v", err)
	}
	res, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, code(t, lr.Enrolment.Secret, time.Now()), auth.RequestInfo{RemoteIP: "192.0.2.1"})
	if err != nil {
		t.Fatalf("mfa: %v", err)
	}
	cl, err := w.sessions.Verify(ctx, res.Token)
	if err != nil || cl.Subject != v.ID || cl.JTI != res.JTI || !slices.Equal(cl.Roles, []string{auth.RoleWatchSupervisor}) {
		t.Fatalf("session: %+v %v", cl, err)
	}
	if n := scalar[int64](t, w.dsn, `SELECT count(*) FROM user_sessions WHERE jti = $1 AND revoked_at IS NULL`, res.JTI); n != 1 {
		t.Fatal("no live session row")
	}
	if enrolled := scalar[bool](t, w.dsn, `SELECT enrolled_at IS NOT NULL FROM user_mfa WHERE user_id = $1`, v.ID); !enrolled {
		t.Fatal("enrolment not confirmed")
	}
	if err := w.accounts.Logout(ctx, auth.Principal{Session: true, Claims: cl}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sessions.Verify(ctx, res.Token); !errors.Is(err, auth.ErrSessionRefused) {
		t.Fatalf("after logout: %v", err)
	}
	for _, ev := range []string{auth.EventUserCreated, auth.EventLoginPasswordAccepted, auth.EventMFAEnrolled, auth.EventSessionStarted, auth.EventLogout} {
		if eventCount(t, w.dsn, ev) != 1 {
			t.Fatalf("%s: %d events", ev, eventCount(t, w.dsn, ev))
		}
	}
	err = w.db.Do(ctx, func(ctx context.Context, db relational.DBTX, _ *relational.Queries) error {
		ok, broken, err := audit.Verify(ctx, db, audit.MonthStart(time.Now().UTC()))
		if err == nil && !ok {
			t.Fatalf("hash chain broken at %v", broken)
		}
		return err
	})
	if err != nil {
		t.Fatalf("hash chain: %v", err)
	}
	me, err := w.accounts.Me(ctx, auth.Principal{Session: true, Claims: cl})
	if err != nil || me.LastLoginAt == nil {
		t.Fatalf("me: %+v %v", me, err)
	}
	users, err := w.accounts.Users(ctx)
	if err != nil || len(users) != 1 {
		t.Fatal(err)
	}
}

func isStatus(err error, status int) bool {
	var e *apierr.Problem
	return errors.As(err, &e) && e.Status == status
}

// The MFA row is locked FOR UPDATE: two sign-ins presenting the same
// code at once yield one session, the other is refused (E-01: the
// winner proves the code works; the loser that it is spent once).
func TestIntegrationAuthOneCodeOneSession(t *testing.T) {
	ctx := ctxT(t)
	w := newAuthWorld(t)
	if _, err := w.accounts.CreateUser(ctx, auth.Principal{}, "sup1", authPW, auth.RoleWatchSupervisor); err != nil {
		t.Fatal(err)
	}
	lr, err := w.accounts.Login(ctx, "sup1", authPW, auth.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	secret := lr.Enrolment.Secret
	// Confirm the enrolment with the code of an earlier step.
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, code(t, secret, time.Now().Add(-30*time.Second)), auth.RequestInfo{}); err != nil {
		t.Fatal(err)
	}
	var tokens []string
	for range 2 {
		lr, err := w.accounts.Login(ctx, "sup1", authPW, auth.RequestInfo{})
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, lr.MFAToken)
	}
	c := code(t, secret, time.Now())
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = w.accounts.VerifyMFA(ctx, tokens[i], c, auth.RequestInfo{})
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !isStatus(err, http.StatusUnauthorized) {
			t.Fatalf("unexpected: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d sessions from one code: %v", ok, errs)
	}
	if n := scalar[int64](t, w.dsn, `SELECT count(*) FROM events WHERE event_type = 'mfa_refused' AND payload->>'reason' = 'code_replayed'`); n != 1 {
		t.Fatalf("replay not audited: %d", n)
	}
}

// The lockout lives in the database: failures from two services (two
// replicas) add up, lock the username for both, and the lock is judged
// on the database clock.
func TestIntegrationAuthLockoutAcrossReplicas(t *testing.T) {
	ctx := ctxT(t)
	a := newAuthWorld(t)
	if _, err := a.accounts.CreateUser(ctx, auth.Principal{}, "sup1", authPW, auth.RoleWatchSupervisor); err != nil {
		t.Fatal(err)
	}
	b := *a
	other, err := auth.NewAccounts(auth.AccountsDeps{
		Store: a.repo, Hasher: mustHasher(t), Sealer: mustSealer(t), Ring: mustRing(t), Issuer: "https://ansp.test",
		IPLimiter: auth.NewRateLimiter(1000, 100, nil, nil), UserLimiter: auth.NewRateLimiter(1000, 100, nil, nil),
	}, auth.AccountsConfig{Audience: "ansp.test", LockoutAfter: 3, LockoutFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b.accounts = other
	_, _ = a.accounts.Login(ctx, "sup1", "wrong password!", auth.RequestInfo{})
	_, _ = b.accounts.Login(ctx, "sup1", "wrong password!", auth.RequestInfo{})
	_, _ = a.accounts.Login(ctx, "sup1", "wrong password!", auth.RequestInfo{})
	_, err = b.accounts.Login(ctx, "sup1", authPW, auth.RequestInfo{})
	if !isStatus(err, http.StatusTooManyRequests) {
		t.Fatalf("not locked on the other replica: %v", err)
	}
	if n := scalar[int64](t, a.dsn, `SELECT count(*) FROM login_lockouts WHERE username = 'sup1' AND locked_until > clock_timestamp()`); n != 1 {
		t.Fatal("no lock row")
	}
	// An unknown username locks the same way: the lock tells nothing
	// about whether the account exists.
	for range 3 {
		_, _ = a.accounts.Login(ctx, "nobody", authPW, auth.RequestInfo{})
	}
	if _, err := a.accounts.Login(ctx, "nobody", authPW, auth.RequestInfo{}); !isStatus(err, http.StatusTooManyRequests) {
		t.Fatalf("unknown username: %v", err)
	}
	if eventCount(t, a.dsn, auth.EventLoginLocked) != 2 {
		t.Fatal("locks not audited")
	}
}

// Admin changes and the sweep against the real tables.
func TestIntegrationAuthAdminAndSweep(t *testing.T) {
	ctx := ctxT(t)
	w := newAuthWorld(t)
	created, err := w.accounts.Bootstrap(ctx, "root", authPW)
	if err != nil || !created {
		t.Fatalf("bootstrap: %v", err)
	}
	if again, err := w.accounts.Bootstrap(ctx, "root2", authPW); err != nil || again {
		t.Fatal("bootstrapped twice")
	}
	v, err := w.accounts.CreateUser(ctx, auth.Principal{}, "view1", authPW, auth.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	lr, err := w.accounts.Login(ctx, "view1", authPW, auth.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, code(t, lr.Enrolment.Secret, time.Now()), auth.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.accounts.ResetMFA(ctx, auth.Principal{}, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sessions.Verify(ctx, res.Token); !errors.Is(err, auth.ErrSessionRefused) {
		t.Fatalf("session after reset: %v", err)
	}
	if n := scalar[int64](t, w.dsn, `SELECT count(*) FROM user_mfa WHERE user_id = $1`, v.ID); n != 0 {
		t.Fatal("MFA row left")
	}
	d, err := w.accounts.Disable(ctx, auth.Principal{}, v.ID)
	if err != nil || d.Status != auth.StatusDisabled {
		t.Fatal(err)
	}
	var rootID string
	for _, u := range mustUsers(t, w) {
		if u.Username == "root" {
			rootID = u.ID
		}
	}
	if _, err := w.accounts.Disable(ctx, auth.Principal{}, rootID); !isStatus(err, http.StatusConflict) {
		t.Fatalf("last admin: %v", err)
	}
	if _, err := w.accounts.Disable(ctx, auth.Principal{}, "not-a-uuid"); !isStatus(err, http.StatusNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	// Age the rows past their lifetimes (as the owner) and sweep.
	if err := exec(t, w.dsn, `UPDATE user_sessions SET issued_at = issued_at - interval '3 days', expires_at = expires_at - interval '3 days'`); err != nil {
		t.Fatal(err)
	}
	if err := exec(t, w.dsn, `UPDATE login_challenges SET created_at = created_at - interval '3 days', expires_at = expires_at - interval '3 days'`); err != nil {
		t.Fatal(err)
	}
	s, c, _, err := w.accounts.Sweep(ctx)
	if err != nil || s != 1 || c != 1 {
		t.Fatalf("sweep %d %d %v", s, c, err)
	}
}

func mustUsers(t *testing.T, w *authWorld) []auth.UserView {
	t.Helper()
	us, err := w.accounts.Users(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	return us
}

// oauth_clients_seen: first and last seen, the scopes merged and
// capped, the subject kept when a later call has none.
func TestIntegrationClientsSeen(t *testing.T) {
	ctx := ctxT(t)
	w := newAuthWorld(t)
	if err := w.repo.RecordClientsSeen(ctx, []auth.ClientSeen{
		{ClientID: "ussp-geo-01", Issuer: "https://authority.test", MTLSSubject: "CN=ussp-geo-01", Scopes: []string{"ansp.traffic"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.repo.RecordClientsSeen(ctx, []auth.ClientSeen{
		{ClientID: "ussp-geo-01", Issuer: "https://authority.test", Scopes: []string{"ansp.coordination", "ansp.traffic"}},
		{ClientID: "authority-01", Issuer: "https://authority.test"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := scalar[[]string](t, w.dsn, `SELECT scopes_seen FROM oauth_clients_seen WHERE client_id = 'ussp-geo-01'`); !slices.Equal(got, []string{"ansp.coordination", "ansp.traffic"}) {
		t.Fatal(got)
	}
	if got := scalar[string](t, w.dsn, `SELECT mtls_subject FROM oauth_clients_seen WHERE client_id = 'ussp-geo-01'`); got != "CN=ussp-geo-01" {
		t.Fatal(got)
	}
	if !scalar[bool](t, w.dsn, `SELECT first_seen_at <= last_seen_at FROM oauth_clients_seen WHERE client_id = 'ussp-geo-01'`) {
		t.Fatal("first after last")
	}
	many := make([]string, 70)
	for i := range many {
		many[i] = "s" + string(rune('A'+i%26)) + string(rune('a'+i/26))
	}
	if err := w.repo.RecordClientsSeen(ctx, []auth.ClientSeen{{ClientID: "lab-01", Issuer: "https://lab.test", Scopes: many}}); err != nil {
		t.Fatal(err)
	}
	if n := scalar[int32](t, w.dsn, `SELECT cardinality(scopes_seen) FROM oauth_clients_seen WHERE client_id = 'lab-01'`); n != 64 {
		t.Fatalf("scopes not capped: %d", n)
	}
	// The recorder writes through the repository.
	rec := auth.NewSeenRecorder(4, time.Hour)
	rec.Record(auth.ClientSeen{ClientID: "cisp-01", Issuer: "https://authority.test", Scopes: []string{"ansp.requests"}})
	rec.Flush(ctx, w.repo)
	if rec.Counters().Get(auth.CounterSeenWritten) != 1 || scalar[int64](t, w.dsn, `SELECT count(*) FROM oauth_clients_seen`) != 4 {
		t.Fatal("recorder did not write")
	}
}

// ansp_app cannot delete accounts or rewrite the clients log; it may
// delete what the sweep and an MFA reset delete.
func TestIntegrationAuthGrants(t *testing.T) {
	w := newAuthWorld(t)
	for _, sql := range []string{"DELETE FROM users", "DELETE FROM oauth_clients_seen"} {
		err := w.db.Tx(ctxT(t), func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for _, sql := range []string{"DELETE FROM user_sessions", "DELETE FROM login_challenges", "DELETE FROM login_lockouts", "DELETE FROM user_mfa"} {
		err := w.db.Tx(ctxT(t), func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
}

func mustHasher(t *testing.T) *auth.Hasher {
	t.Helper()
	h, err := auth.NewHasherWithParams(auth.HashParams{MemoryKiB: 64, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustSealer(t *testing.T) *auth.Sealer {
	t.Helper()
	s, err := auth.NewSealer(make([]byte, auth.SealKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustRing(t *testing.T) *coreauth.KeyRing {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := auth.NewSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := coreauth.NewKeyRing(sk)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
