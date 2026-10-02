package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

const pw = "correct horse battery"

func asError(t testing.TB, err error) *apierr.Problem {
	t.Helper()
	var e *apierr.Problem
	if !errors.As(err, &e) {
		t.Fatalf("not an *apierr.Problem: %v", err)
	}
	return e
}

func reasons(evs []string, w *world, eventType string) []string {
	for _, e := range w.store.events(eventType) {
		if p, ok := e.Payload.(map[string]any); ok {
			if r, ok := p["reason"].(string); ok {
				evs = append(evs, r)
			}
		}
	}
	return evs
}

// The whole sign-in of a new account: the password step returns the
// mfa_pending token and the enrolment (an account without MFA can only
// enrol); the first right code confirms it and returns a session token
// in the one session shape (M20), which the guard accepts for the
// account's role and refuses for another (roles[], never scope).
func TestSignInEnrolsThenSession(t *testing.T) {
	w := newWorld(t)
	u := w.addUser(t, "Viewer1", pw, RoleViewer)
	if u.Username != "viewer1" {
		t.Fatalf("username %q", u.Username)
	}
	res, secret := w.signIn(t, " VIEWER1 ", pw)
	cl, err := w.sessions.Verify(context.Background(), res.Token)
	must(t, err)
	if cl.Issuer != ownIssuer || cl.Audience != ownHost || cl.Subject != u.ID || !slices.Equal(cl.Scopes, []string{"session"}) ||
		!slices.Equal(cl.Roles, []string{RoleViewer}) || cl.Realm != RealmConsole || cl.JTI != res.JTI ||
		!cl.ExpiresAt.Equal(t0().Add(MaxSessionTTL)) || res.IdleTimeout != SessionIdleTimeout {
		t.Fatalf("claims %+v", cl)
	}
	rec, p := call(t, w.guard.RequireRole(RoleViewer, RoleAdmin), http.MethodGet, "/v1/x", withBearer(res.Token))
	if rec.Code != http.StatusOK || !p.Session || p.Role != RoleViewer {
		t.Fatalf("allowed role: %d %s", rec.Code, rec.Body.String())
	}
	rec, _ = call(t, w.guard.RequireRole(RoleWatchSupervisor), http.MethodGet, "/v1/x", withBearer(res.Token))
	if pb := problemOf(t, rec); rec.Code != http.StatusForbidden || pb.Errors[0].Field != "roles" {
		t.Fatalf("forbidden role: %d %s", rec.Code, rec.Body.String())
	}
	for _, ev := range []string{EventLoginPasswordAccepted, EventMFAEnrolled, EventSessionStarted} {
		if len(w.store.events(ev)) != 1 {
			t.Fatalf("%s events: %d", ev, len(w.store.events(ev)))
		}
	}
	// Enrolled: the next login shows no secret.
	w.clock.Add(TOTPPeriod)
	lr, err := w.accounts.Login(context.Background(), "viewer1", pw, RequestInfo{RemoteIP: "192.0.2.1"})
	must(t, err)
	if lr.Enrolment != nil {
		t.Fatal("enrolment shown again")
	}
	if _, err := w.accounts.VerifyMFA(context.Background(), lr.MFAToken, w.code(t, secret), RequestInfo{}); err != nil {
		t.Fatal(err)
	}
	if w.accounts.Counters().Get(CounterSessionsStarted) != 2 || w.accounts.Counters().Get(CounterLoginAccepted) != 2 {
		t.Fatalf("%v", w.accounts.Counters().Snapshot())
	}
}

// A pending enrolment shows the same secret again until confirmed.
func TestPendingEnrolmentShownAgain(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	a, err := w.accounts.Login(context.Background(), "sup1", pw, RequestInfo{})
	must(t, err)
	b, err := w.accounts.Login(context.Background(), "sup1", pw, RequestInfo{})
	must(t, err)
	if a.Enrolment == nil || b.Enrolment == nil || a.Enrolment.Secret != b.Enrolment.Secret || !strings.HasPrefix(b.Enrolment.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("%+v %+v", a.Enrolment, b.Enrolment)
	}
}

// E-01: a right code is accepted, a wrong code and the same code twice
// are refused; each refusal counts against the challenge and the
// username, and the next time step's code is accepted.
func TestMFARightWrongReplayed(t *testing.T) {
	w := newWorld(t)
	u := w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	_, secret := w.signIn(t, "sup1", pw)
	ctx := context.Background()

	lr, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	wrong := "000000"
	if w.code(t, secret) == wrong {
		wrong = "111111"
	}
	_, err = w.accounts.VerifyMFA(ctx, lr.MFAToken, wrong, RequestInfo{})
	if e := asError(t, err); e.Status != http.StatusUnauthorized || e.Slug() != SlugMFARefused {
		t.Fatalf("%+v", e)
	}
	_, err = w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, secret), RequestInfo{})
	if e := asError(t, err); e.Slug() != SlugMFARefused {
		t.Fatalf("replayed code accepted: %v", err)
	}
	got := reasons(nil, w, EventMFARefused)
	if !slices.Equal(got, []string{"wrong_code", "code_replayed"}) {
		t.Fatalf("reasons %v", got)
	}
	w.store.mu.Lock()
	if c := w.store.data.challenges[hashToken(lr.MFAToken)]; c.Attempts != 2 || c.UsedAt != nil {
		t.Fatalf("challenge %+v", c)
	}
	if l := w.store.data.lockouts["sup1"]; l.Failures != 2 {
		t.Fatalf("lockout %+v", l)
	}
	w.store.mu.Unlock()
	w.clock.Add(TOTPPeriod)
	res, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, secret), RequestInfo{})
	if err != nil || res.User.ID != u.ID {
		t.Fatalf("next step: %v", err)
	}
	// The challenge is spent, and success cleared the lockout.
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, secret), RequestInfo{}); asError(t, err).Slug() != SlugMFARefused {
		t.Fatal("used challenge accepted")
	}
	w.store.mu.Lock()
	_, stillLocked := w.store.data.lockouts["sup1"]
	w.store.mu.Unlock()
	if stillLocked {
		t.Fatal("lockout not cleared by a success")
	}
	if !slices.Contains(reasons(nil, w, EventMFARefused), "challenge_used") {
		t.Fatal("challenge_used not audited")
	}
}

func TestMFAChallengeRefusals(t *testing.T) {
	w := newWorld(t)
	w.accounts.cfg.LockoutAfter = 100 // the challenge's own bound first
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	ctx := context.Background()
	if _, err := w.accounts.VerifyMFA(ctx, "", "123456", RequestInfo{}); asError(t, err).Slug() != SlugMFARefused {
		t.Fatal("empty token")
	}
	if _, err := w.accounts.VerifyMFA(ctx, "unknown", "123456", RequestInfo{}); asError(t, err).Slug() != SlugMFARefused {
		t.Fatal("unknown token")
	}
	lr, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	// Exhausted: ChallengeAttempts wrong codes, then even the right one.
	for range DefaultChallengeAttempts {
		_, _ = w.accounts.VerifyMFA(ctx, lr.MFAToken, "abcdef", RequestInfo{})
	}
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, lr.Enrolment.Secret), RequestInfo{}); err == nil {
		t.Fatal("exhausted challenge accepted")
	}
	// Expired.
	w.store.mu.Lock()
	w.store.data.lockouts = map[string]Lockout{}
	w.store.mu.Unlock()
	lr, err = w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	w.clock.Add(DefaultChallengeTTL)
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, lr.Enrolment.Secret), RequestInfo{}); err == nil {
		t.Fatal("expired challenge accepted")
	}
	got := reasons(nil, w, EventMFARefused)
	for _, want := range []string{"malformed", "challenge_unknown", "challenge_exhausted", "challenge_expired"} {
		if !slices.Contains(got, want) {
			t.Fatalf("%s not audited: %v", want, got)
		}
	}
}

// A reset between the password and the code, and a disable, refuse
// the code; a secret sealed under another key is 503, never accepted.
func TestMFAStateChanges(t *testing.T) {
	w := newWorld(t)
	u := w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	admin := w.addUser(t, "admin1", pw, RoleAdmin)
	adminP := Principal{Session: true, Role: RoleAdmin, Claims: coreauth.Claims{Subject: admin.ID}}
	ctx := context.Background()
	lr, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	_, err = w.accounts.ResetMFA(ctx, adminP, u.ID)
	must(t, err)
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, lr.Enrolment.Secret), RequestInfo{}); err == nil {
		t.Fatal("code accepted after a reset")
	}
	lr, err = w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	w.store.mu.Lock()
	m := w.store.data.mfa[u.ID]
	m.KeyID = "0000000000000000"
	w.store.data.mfa[u.ID] = m
	w.store.mu.Unlock()
	_, err = w.accounts.VerifyMFA(ctx, lr.MFAToken, "123456", RequestInfo{})
	if e := asError(t, err); e.Status != http.StatusServiceUnavailable {
		t.Fatalf("%+v", e)
	}
	if _, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{}); asError(t, err).Status != http.StatusServiceUnavailable {
		t.Fatal("pending secret under another key")
	}
	_, err = w.accounts.Disable(ctx, adminP, u.ID)
	must(t, err)
	if _, err := w.accounts.VerifyMFA(ctx, lr.MFAToken, "123456", RequestInfo{}); err == nil {
		t.Fatal("disabled account")
	}
	if !slices.Contains(reasons(nil, w, EventMFARefused), "user_disabled") || !slices.Contains(reasons(nil, w, EventMFARefused), "mfa_reset") {
		t.Fatal(reasons(nil, w, EventMFARefused))
	}
}

// S-15 and E-10: wrong passwords lock the username in the database after
// LockoutAfter failures, for a known and an unknown username alike, and
// a locked username is refused 429 with Retry-After even with the right
// password; past LockoutFor it signs in again.
func TestLoginLockout(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	ctx := context.Background()
	for _, user := range []string{"sup1", "nobody"} {
		for i := range 3 {
			_, err := w.accounts.Login(ctx, user, "wrong password!", RequestInfo{})
			if e := asError(t, err); e.Status != http.StatusUnauthorized || e.Slug() != SlugInvalidCredentials {
				t.Fatalf("%s failure %d: %+v", user, i, e)
			}
		}
		_, err := w.accounts.Login(ctx, user, pw, RequestInfo{})
		if e := asError(t, err); e.Status != http.StatusTooManyRequests || e.Slug() != SlugAccountLocked || e.RetryAfter != 15*time.Minute {
			t.Fatalf("%s locked: %+v", user, e)
		}
	}
	if len(w.store.events(EventLoginLocked)) != 2 || w.accounts.Counters().Get(CounterLoginLocked) != 4 {
		t.Fatalf("locks %d %v", len(w.store.events(EventLoginLocked)), w.accounts.Counters().Snapshot())
	}
	w.clock.Add(15 * time.Minute)
	if _, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{}); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	// A failure after the lock is over starts a new count.
	_, _ = w.accounts.Login(ctx, "sup1", "wrong password!", RequestInfo{})
	w.store.mu.Lock()
	l := w.store.data.lockouts["sup1"]
	w.store.mu.Unlock()
	if l.Failures != 1 || l.LockedUntil != nil {
		t.Fatalf("%+v", l)
	}
}

// Wrong codes lock the username too, and a locked username's code is
// refused with 429.
func TestMFAFailuresLock(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	ctx := context.Background()
	lr, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	must(t, err)
	for range 3 {
		_, _ = w.accounts.VerifyMFA(ctx, lr.MFAToken, "abcdef", RequestInfo{})
	}
	_, err = w.accounts.VerifyMFA(ctx, lr.MFAToken, w.code(t, lr.Enrolment.Secret), RequestInfo{})
	if e := asError(t, err); e.Status != http.StatusTooManyRequests || e.Slug() != SlugAccountLocked {
		t.Fatalf("%+v", e)
	}
}

// S-15 and E-10: the per-address and per-username limiters answer 429
// with Retry-After, and admit again once the window has passed.
func TestLoginRateLimits(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	w.accounts.ipLimiter = NewRateLimiter(2, 100, nil, w.clock.Now)
	ctx := context.Background()
	ri := RequestInfo{RemoteIP: "198.51.100.7"}
	for range 2 {
		if _, err := w.accounts.Login(ctx, "sup1", pw, ri); err != nil {
			t.Fatal(err)
		}
	}
	_, err := w.accounts.Login(ctx, "sup1", pw, ri)
	if e := asError(t, err); e.Status != http.StatusTooManyRequests || e.Slug() != SlugRateLimited || e.RetryAfter != 30*time.Second {
		t.Fatalf("%+v", e)
	}
	if _, err := w.accounts.VerifyMFA(ctx, "x", "123456", ri); asError(t, err).Slug() != SlugRateLimited {
		t.Fatal("MFA step not limited by address")
	}
	if _, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{RemoteIP: "198.51.100.8"}); err != nil {
		t.Fatalf("another address: %v", err)
	}
	w.clock.Add(time.Minute)
	if _, err := w.accounts.Login(ctx, "sup1", pw, ri); err != nil {
		t.Fatalf("past the window: %v", err)
	}
	w.accounts.userLimiter = NewRateLimiter(1, 100, nil, w.clock.Now)
	_, _ = w.accounts.Login(ctx, "sup1", pw, RequestInfo{RemoteIP: "203.0.113.1"})
	if _, err := w.accounts.Login(ctx, "SUP1", pw, RequestInfo{RemoteIP: "203.0.113.2"}); asError(t, err).Slug() != SlugRateLimited {
		t.Fatal("per-username limit")
	}
	got := reasons(nil, w, EventLoginRefused)
	if !slices.Contains(got, "rate_limited_address") || !slices.Contains(got, "rate_limited_username") {
		t.Fatal(got)
	}
}

// Invalid input is the same answer as a wrong password, after the same
// work, and touches no lockout.
func TestLoginInvalidInput(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for _, in := range [][2]string{{"x", pw}, {"sup1", strings.Repeat("p", MaxSecretBytes+1)}, {"", ""}} {
		_, err := w.accounts.Login(ctx, in[0], in[1], RequestInfo{})
		if e := asError(t, err); e.Slug() != SlugInvalidCredentials {
			t.Fatalf("%v: %+v", in, e)
		}
	}
	w.store.mu.Lock()
	n := len(w.store.data.lockouts)
	w.store.mu.Unlock()
	if n != 0 || !slices.Equal(reasons(nil, w, EventLoginRefused), []string{"invalid_input", "invalid_input", "invalid_input"}) {
		t.Fatalf("%d %v", n, reasons(nil, w, EventLoginRefused))
	}
}

func TestDisabledUserCannotSignIn(t *testing.T) {
	w := newWorld(t)
	u := w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	w.addUser(t, "admin1", pw, RoleAdmin)
	_, err := w.accounts.Disable(context.Background(), Principal{}, u.ID)
	must(t, err)
	if _, err := w.accounts.Login(context.Background(), "sup1", pw, RequestInfo{}); asError(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal("disabled account signed in")
	}
	if !slices.Contains(reasons(nil, w, EventLoginRefused), "user_disabled") {
		t.Fatal("not audited")
	}
}

// E-01: a session is accepted before logout and refused after it, at
// once in this process; another process's verifier, holding the session
// in its cache, refuses it once the cache entry is older than its TTL.
func TestLogoutRevokes(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	res, _ := w.signIn(t, "sup1", pw)
	other, err := NewSessionVerifier(context.Background(), SessionVerifierConfig{Issuer: ownIssuer, Ring: sessionRing(t),
		Audiences: audiences(), Checker: w.accounts, Now: w.clock.Now})
	must(t, err)
	mw := w.guard.Require(Access{AnyRole: true})
	rec, p := call(t, mw, http.MethodGet, "/v1/auth/me", withBearer(res.Token))
	if rec.Code != http.StatusOK || p.Claims.JTI != res.JTI {
		t.Fatalf("before logout: %d", rec.Code)
	}
	if _, err := other.Verify(context.Background(), res.Token); err != nil {
		t.Fatal(err)
	}
	must(t, w.accounts.Logout(context.Background(), *p))
	rec, _ = call(t, mw, http.MethodGet, "/v1/auth/me", withBearer(res.Token))
	if pb := problemOf(t, rec); rec.Code != http.StatusUnauthorized || pb.Slug() != SlugSessionRefused {
		t.Fatalf("after logout: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := other.Verify(context.Background(), res.Token); err != nil {
		t.Fatalf("within the other cache's TTL: %v", err)
	}
	w.clock.Add(DefaultSessionCacheTTL)
	if _, err := other.Verify(context.Background(), res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("past the TTL: %v", err)
	}
	if len(w.store.events(EventLogout)) != 1 || w.guard.Counters().Get(CounterSessionRefused) != 1 {
		t.Fatal("logout not audited or not counted")
	}
	if err := w.accounts.Logout(context.Background(), Principal{}); asError(t, err).Status != http.StatusForbidden {
		t.Fatal("a machine principal logged out")
	}
}

// The old session shape (scope = the role) and every other deviation
// from M20 are refused, though signed by this system's key.
func TestSessionShapeRefused(t *testing.T) {
	w := newWorld(t)
	u := w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	ring := sessionRing(t)
	iss, err := ring.Issuer(ownIssuer)
	must(t, err)
	now := w.clock.Now()
	old, err := iss.Issue(u.ID, ownHost, []string{RoleWatchSupervisor}, time.Hour, now)
	must(t, err)
	session := func(realm string, roles ...string) string {
		tok, err := iss.IssueSession(coreauth.SessionClaims{Audience: ownHost, Subject: u.ID, Roles: roles, Realm: realm,
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), JTI: "0123456789abcdef0123456789abcdef"})
		must(t, err)
		return tok
	}
	for name, c := range map[string]struct{ tok, claim string }{
		"old shape":   {old, "scope"},
		"portal":      {session("portal", RoleViewer), "realm"},
		"two roles":   {session(RealmConsole, RoleViewer, RoleAdmin), "roles"},
		"pilot":       {session(RealmConsole, "remote_pilot"), "roles"},
		"no such jti": {session(RealmConsole, RoleWatchSupervisor), ""},
	} {
		rec, _ := call(t, w.guard.Require(Access{AnyRole: true}), http.MethodGet, "/v1/x", withBearer(c.tok))
		pb := problemOf(t, rec)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		if c.claim != "" && (pb.Slug() != CounterSessionShape || pb.Errors[0].Field != c.claim) {
			t.Fatalf("%s: %s", name, rec.Body.String())
		}
		if c.claim == "" && pb.Slug() != SlugSessionRefused {
			t.Fatalf("%s: %s", name, rec.Body.String())
		}
	}
	if w.sessions.Counters().Get(CounterSessionShape) != 4 || w.sessions.Counters().Get(CounterSessionNotLive) != 1 {
		t.Fatalf("%v", w.sessions.Counters().Snapshot())
	}
}

// A session row of another account, or with another role, refuses the
// token; an unreadable store is 503, not 401.
func TestSessionRowMismatch(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	res, _ := w.signIn(t, "sup1", pw)
	w.store.mu.Lock()
	row := w.store.data.sessions[res.JTI]
	w.store.data.sessions[res.JTI] = SessionRow{JTI: row.JTI, UserID: "someone-else", Role: row.Role, IssuedAt: row.IssuedAt,
		ExpiresAt: row.ExpiresAt, LastSeenAt: row.LastSeenAt}
	w.store.mu.Unlock()
	if _, err := w.sessions.Verify(context.Background(), res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("other account: %v", err)
	}
	row.Role = RoleAdmin
	w.store.mu.Lock()
	w.store.data.sessions[res.JTI] = row
	w.store.mu.Unlock()
	if _, err := w.sessions.Verify(context.Background(), res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("other role: %v", err)
	}
	w.store.fail["session"] = errDown
	rec, _ := call(t, w.guard.Require(Access{AnyRole: true}), http.MethodGet, "/v1/x", withBearer(res.Token))
	if pb := problemOf(t, rec); rec.Code != http.StatusServiceUnavailable || pb.Slug() != SlugUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if w.sessions.Counters().Get(CounterSessionCheckError) != 1 || w.guard.Counters().Get(CounterSessionUnchecked) != 1 {
		t.Fatal("not counted")
	}
}

// Idle 30 minutes ends a session for good (audited); use within the
// window keeps it alive; 12 h ends it whatever the use.
func TestSessionIdleAndExpiry(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	res, _ := w.signIn(t, "sup1", pw)
	ctx := context.Background()
	for range 3 {
		w.clock.Add(20 * time.Minute)
		if _, err := w.sessions.Verify(ctx, res.Token); err != nil {
			t.Fatalf("in use: %v", err)
		}
	}
	w.clock.Add(31 * time.Minute)
	if _, err := w.sessions.Verify(ctx, res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("idle: %v", err)
	}
	w.store.mu.Lock()
	row := w.store.data.sessions[res.JTI]
	w.store.mu.Unlock()
	if row.RevokeReason != "idle" || len(w.store.events(EventSessionIdleEnded)) != 1 {
		t.Fatalf("%+v", row)
	}
	if _, err := w.sessions.Verify(ctx, res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("an idle session came back")
	}

	res, _ = w.signInAgain(t, "sup1")
	for range 36 { // 12 h in 20-minute steps
		w.clock.Add(20 * time.Minute)
		_, err := w.sessions.Verify(ctx, res.Token)
		if err != nil {
			var te *coreauth.TokenError
			if !errors.As(err, &te) && !errors.Is(err, ErrSessionRefused) {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("a session outlived 12 h")
}

// signInAgain signs an enrolled account in at the next time step.
func (w *world) signInAgain(t testing.TB, username string) (MFAResult, string) {
	t.Helper()
	w.clock.Add(TOTPPeriod)
	w.store.mu.Lock()
	var secret string
	for id := range w.store.data.users {
		if u := w.store.data.users[id]; u.Username == username {
			m := w.store.data.mfa[u.ID]
			b, err := w.accounts.sealer.Open(m.KeyID, m.SecretEnc, mfaAAD(u.ID))
			must(t, err)
			secret = string(b)
		}
	}
	w.store.mu.Unlock()
	lr, err := w.accounts.Login(context.Background(), username, pw, RequestInfo{})
	must(t, err)
	res, err := w.accounts.VerifyMFA(context.Background(), lr.MFAToken, w.code(t, secret), RequestInfo{})
	must(t, err)
	return res, secret
}

// The row is checked on the database clock it comes with, and a store
// that cannot touch the row refuses to answer.
func TestCheckSessionTouch(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	res, _ := w.signIn(t, "sup1", pw)
	w.clock.Add(2 * time.Minute)
	w.store.fail["touch"] = errDown
	if _, err := w.accounts.CheckSession(context.Background(), res.JTI, res.User.ID); !errors.Is(err, errDown) {
		t.Fatalf("%v", err)
	}
	delete(w.store.fail, "touch")
	if role, err := w.accounts.CheckSession(context.Background(), res.JTI, res.User.ID); err != nil || role != RoleWatchSupervisor {
		t.Fatal(err)
	}
}

func TestAdminOperations(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	admin := w.addUser(t, "admin1", pw, RoleAdmin)
	adminP := Principal{Session: true, Role: RoleAdmin, Claims: coreauth.Claims{Subject: admin.ID}}

	_, err := w.accounts.CreateUser(ctx, adminP, "x", "short", "pilot")
	if fields := apierr.FromError(err).Errors; len(fields) != 3 {
		t.Fatalf("validation: %v", fields)
	}
	if _, err := w.accounts.CreateUser(ctx, adminP, "ok-user", "\xff\xfe invalid utf8 ..", RoleViewer); len(apierr.FromError(err).Errors) != 1 {
		t.Fatal("invalid UTF-8 password")
	}
	if _, err := w.accounts.CreateUser(ctx, adminP, "ok-user", strings.Repeat("p", MaxSecretBytes+1), RoleViewer); len(apierr.FromError(err).Errors) != 1 {
		t.Fatal("long password")
	}
	v, err := w.accounts.CreateUser(ctx, adminP, "sup1", pw, RoleWatchSupervisor)
	must(t, err)
	if _, err := w.accounts.CreateUser(ctx, adminP, "SUP1", pw, RoleViewer); asError(t, err).Status != http.StatusConflict {
		t.Fatal("duplicate username")
	}
	users, err := w.accounts.Users(ctx)
	if err != nil || len(users) != 2 || users[0].Username != "admin1" {
		t.Fatalf("%v %v", users, err)
	}

	res, _ := w.signIn(t, "sup1", pw)
	reset, err := w.accounts.ResetMFA(ctx, adminP, v.ID)
	if err != nil || reset.ID != v.ID {
		t.Fatal(err)
	}
	if _, err := w.sessions.Verify(ctx, res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("session after reset: %v", err)
	}
	lr, err := w.accounts.Login(ctx, "sup1", pw, RequestInfo{})
	if err != nil || lr.Enrolment == nil {
		t.Fatal("no new enrolment after a reset")
	}

	if _, err := w.accounts.Disable(ctx, adminP, admin.ID); asError(t, err).Status != http.StatusConflict {
		t.Fatal("the last admin was disabled")
	}
	if _, err := w.accounts.Disable(ctx, adminP, "00000000-0000-4000-8000-999999999999"); asError(t, err).Status != http.StatusNotFound {
		t.Fatal("unknown account")
	}
	d, err := w.accounts.Disable(ctx, adminP, v.ID)
	if err != nil || d.Status != StatusDisabled {
		t.Fatal(err)
	}
	for _, ev := range []string{EventUserCreated, EventMFAReset, EventUserDisabled} {
		if len(w.store.events(ev)) == 0 {
			t.Fatalf("%s not audited", ev)
		}
	}
	w.store.fail["users"] = errDown
	if _, err := w.accounts.Users(ctx); !errors.Is(err, errDown) {
		t.Fatal(err)
	}
	me, err := w.accounts.Me(ctx, adminP)
	if err != nil || me.Username != "admin1" {
		t.Fatal(err)
	}
	if _, err := w.accounts.Me(ctx, Principal{Session: true, Claims: coreauth.Claims{Subject: "gone"}}); asError(t, err).Status != http.StatusNotFound {
		t.Fatal("me of a deleted account")
	}
	if _, err := w.accounts.Me(ctx, Principal{}); asError(t, err).Status != http.StatusForbidden {
		t.Fatal("me of a machine")
	}
}

func TestBootstrap(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.accounts.Bootstrap(ctx, "root", "short"); err == nil {
		t.Fatal("short password")
	}
	created, err := w.accounts.Bootstrap(ctx, "root", pw)
	if err != nil || !created {
		t.Fatal(err)
	}
	created, err = w.accounts.Bootstrap(ctx, "root2", pw)
	if err != nil || created {
		t.Fatal("bootstrapped with an account present")
	}
	if len(w.store.events(EventUserBootstrapped)) != 1 {
		t.Fatal("not audited")
	}
}

// E-10: the sweep deletes expired sessions and challenges and stale
// lockouts.
func TestSweep(t *testing.T) {
	w := newWorld(t)
	w.addUser(t, "sup1", pw, RoleWatchSupervisor)
	w.signIn(t, "sup1", pw)
	_, _ = w.accounts.Login(context.Background(), "sup1", "wrong password!", RequestInfo{})
	w.clock.Add(MaxSessionTTL + SweepRetention + time.Minute)
	s, c, l, err := w.accounts.Sweep(context.Background())
	if err != nil || s != 1 || c != 1 || l != 1 || w.accounts.Counters().Get(CounterSessionsSwept) != 1 {
		t.Fatalf("%d %d %d %v", s, c, l, err)
	}
	w.store.fail["sweep"] = errDown
	errs := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go w.accounts.RunSweep(ctx, time.Millisecond, func(err error) {
		select {
		case errs <- err:
		default:
		}
	})
	if err := <-errs; !errors.Is(err, errDown) {
		t.Fatal(err)
	}
	cancel()
}

// Refusals whose audit row cannot be written are counted, and the
// answer stands.
func TestRefusalNotSaved(t *testing.T) {
	w := newWorld(t)
	w.store.fail["record"] = errDown
	if _, err := w.accounts.Login(context.Background(), "x", "y", RequestInfo{}); asError(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal(err)
	}
	if _, err := w.accounts.Login(context.Background(), "nobody", pw, RequestInfo{}); asError(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal(err)
	}
	if w.accounts.Counters().Get(CounterRefusalNotSaved) != 2 {
		t.Fatalf("%v", w.accounts.Counters().Snapshot())
	}
	w.store.fail = map[string]error{"tx": errDown}
	if _, err := w.accounts.Login(context.Background(), "nobody", pw, RequestInfo{}); !errors.Is(err, errDown) {
		t.Fatalf("store down: %v", err)
	}
}

func TestNewAccountsRefusals(t *testing.T) {
	w := newWorld(t)
	sealer, _ := NewSealer(make([]byte, SealKeyBytes))
	lim := NewRateLimiter(1, 1, nil, nil)
	full := AccountsDeps{Store: w.store, Hasher: cheapHasher(t), Sealer: sealer, Ring: sessionRing(t), Issuer: ownIssuer, IPLimiter: lim, UserLimiter: lim}
	ok := AccountsConfig{Audience: ownHost, LockoutAfter: 1, LockoutFor: time.Minute}
	for name, c := range map[string]struct {
		d AccountsDeps
		c AccountsConfig
	}{
		"no store":    {AccountsDeps{}, ok},
		"no sealer":   {func() AccountsDeps { d := full; d.Sealer = nil; return d }(), ok},
		"no ring":     {func() AccountsDeps { d := full; d.Ring = nil; return d }(), ok},
		"no issuer":   {func() AccountsDeps { d := full; d.Issuer = ""; return d }(), ok},
		"no audience": {full, AccountsConfig{LockoutAfter: 1, LockoutFor: time.Minute}},
		"no lockout":  {full, AccountsConfig{Audience: ownHost}},
	} {
		if _, err := NewAccounts(c.d, c.c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	a, err := NewAccounts(full, AccountsConfig{Audience: ownHost, LockoutAfter: 1, LockoutFor: time.Minute, SessionTTL: 24 * time.Hour})
	if err != nil || a.Config().SessionTTL != MaxSessionTTL {
		t.Fatal("a TTL over 12 h is clipped")
	}
}
