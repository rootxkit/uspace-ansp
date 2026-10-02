package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/config"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// Defaults and bounds of the accounts service.
const (
	// DefaultChallengeTTL is how long the mfa_pending token of a login
	// lives; DefaultChallengeAttempts how many codes it may carry.
	DefaultChallengeTTL      = 5 * time.Minute
	DefaultChallengeAttempts = 5
	// MinPasswordChars is the shortest password an admin may set.
	MinPasswordChars = 12
	// MaxUsersListed bounds GET /v1/users.
	MaxUsersListed = 1000
	// touchEvery bounds the writes of last_seen_at to one a minute per
	// session.
	touchEvery = time.Minute
	// SweepRetention keeps an expired session or challenge, and an
	// untouched lockout, this long before the sweep deletes it.
	SweepRetention = 24 * time.Hour
)

// Audit event types of accounts and sessions (internal/audit).
const (
	EventLoginRefused          = "login_refused"
	EventLoginLocked           = "login_locked"
	EventLoginPasswordAccepted = "login_password_accepted"
	EventMFARefused            = "mfa_refused"
	EventMFAEnrolled           = "mfa_enrolled"
	EventSessionStarted        = "session_started"
	EventLogout                = "logout"
	EventSessionIdleEnded      = "session_idle_ended"
	EventUserCreated           = "user_created"
	EventUserBootstrapped      = "user_bootstrapped"
	EventUserDisabled          = "user_disabled"
	EventMFAReset              = "mfa_reset"
)

// Audit purposes.
const (
	purposeSignIn = "console sign-in (06 section 3)"
	purposeAdmin  = "console account administration (01 section 4)"
)

// Counters of the accounts service.
const (
	CounterLoginAccepted   = "login_password_accepted"
	CounterLoginRefused    = "login_refused"
	CounterLoginLocked     = "login_locked"
	CounterMFARefused      = "mfa_refused"
	CounterSessionsStarted = "sessions_started"
	CounterSessionsIdle    = "sessions_idle_ended"
	CounterSessionsSwept   = "sessions_swept"
	CounterRefusalNotSaved = "auth_refusal_event_failed"
)

// AccountsConfig are the sign-in and session settings.
type AccountsConfig struct {
	// Audience is this system's own host (ANSP_AUDIENCES[0]): the aud of
	// every session (M20).
	Audience string
	// LockoutAfter consecutive failures of a username (password or
	// code) lock it for LockoutFor, in the database.
	LockoutAfter int
	LockoutFor   time.Duration
	// SessionTTL is exp - iat (at most MaxSessionTTL); IdleTimeout ends
	// a session unused for that long.
	SessionTTL  time.Duration
	IdleTimeout time.Duration
	// ChallengeTTL and ChallengeAttempts bound the mfa_pending token.
	ChallengeTTL      time.Duration
	ChallengeAttempts int
}

// AccountsConfigFrom is the configuration of cfg.
func AccountsConfigFrom(cfg config.Config) AccountsConfig {
	c := AccountsConfig{
		LockoutAfter: cfg.LoginLockoutAfter, LockoutFor: time.Duration(cfg.LoginLockoutS) * time.Second,
	}
	if len(cfg.Audiences) > 0 {
		c.Audience = cfg.Audiences[0]
	}
	return c
}

func (c *AccountsConfig) defaults() error {
	if c.Audience == "" {
		return core.Fieldf("ANSP_AUDIENCES", "required: its first host is the aud of every session")
	}
	if c.LockoutAfter <= 0 || c.LockoutFor <= 0 {
		return core.Fieldf("ANSP_LOGIN_LOCKOUT_AFTER", "the lockout needs a positive count and duration")
	}
	if c.SessionTTL <= 0 || c.SessionTTL > MaxSessionTTL {
		c.SessionTTL = MaxSessionTTL
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = SessionIdleTimeout
	}
	if c.ChallengeTTL <= 0 {
		c.ChallengeTTL = DefaultChallengeTTL
	}
	if c.ChallengeAttempts <= 0 {
		c.ChallengeAttempts = DefaultChallengeAttempts
	}
	return nil
}

// Accounts is console accounts, the two-step sign-in with mandatory
// TOTP, sessions and their administration. It implements
// SessionChecker.
type Accounts struct {
	store       Store
	hasher      *Hasher
	sealer      *Sealer
	issuer      *coreauth.Issuer
	kid         string
	ipLimiter   *RateLimiter
	userLimiter *RateLimiter
	cfg         AccountsConfig
	counters    core.Counters
	// sessions, when set, forgets a session this process ended.
	sessions *SessionVerifier
}

// AccountsDeps are what Accounts works with.
type AccountsDeps struct {
	Store  Store
	Hasher *Hasher
	Sealer *Sealer
	// Ring is the session key ring; Issuer the iss of sessions.
	Ring   *coreauth.KeyRing
	Issuer string
	// IPLimiter and UserLimiter bound sign-in attempts per address and
	// per username (S-15).
	IPLimiter   *RateLimiter
	UserLimiter *RateLimiter
}

// NewAccounts checks the dependencies and the configuration.
func NewAccounts(d AccountsDeps, c AccountsConfig) (*Accounts, error) {
	switch {
	case d.Store == nil || d.Hasher == nil || d.IPLimiter == nil || d.UserLimiter == nil:
		return nil, errors.New("accounts: a store, a hasher and both limiters are required")
	case d.Sealer == nil:
		return nil, core.Fieldf("ANSP_SECRETS_KEY_FILE", "required: TOTP secrets are sealed under it")
	case d.Ring == nil:
		return nil, core.Fieldf("ANSP_SESSION_KEY_FILE", "required: sessions are signed with it")
	}
	if err := c.defaults(); err != nil {
		return nil, err
	}
	iss, err := d.Ring.Issuer(d.Issuer)
	if err != nil {
		return nil, core.Fieldf("ANSP_PUBLIC_BASE_URL", "cannot issue sessions: %v", err)
	}
	return &Accounts{store: d.Store, hasher: d.Hasher, sealer: d.Sealer, issuer: iss, kid: d.Ring.ActiveKID(),
		ipLimiter: d.IPLimiter, userLimiter: d.UserLimiter, cfg: c}, nil
}

// SetSessionVerifier lets logout and revocation drop the session from
// v's cache at once.
func (s *Accounts) SetSessionVerifier(v *SessionVerifier) { s.sessions = v }

// Counters are the service's counters.
func (s *Accounts) Counters() *core.Counters { return &s.counters }

// Config is the effective configuration.
func (s *Accounts) Config() AccountsConfig { return s.cfg }

// RequestInfo is what a request says about its client.
type RequestInfo struct {
	RemoteIP  string
	UserAgent string
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{2,63}$`)

// NormalizeUsername is the stored form of a username: trimmed and
// lower-case.
func NormalizeUsername(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// invalidUsername labels, in the audit log only, a sign-in whose
// username no account can have.
const invalidUsername = "(invalid)"

// clip bounds a value from a request before it is stored.
func clip(v string, n int) string {
	v = strings.ToValidUTF8(v, "?")
	for len(v) > n {
		v = v[:n]
		for len(v) > 0 && !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

func invalidCredentials() error {
	return refusal(http.StatusUnauthorized, SlugInvalidCredentials, "the username or the password is wrong")
}

func rateLimited(wait time.Duration) error {
	e := refusal(http.StatusTooManyRequests, SlugRateLimited, "too many sign-in attempts; wait and try again")
	e.RetryAfter = wait
	return e
}

func accountLocked(wait time.Duration) error {
	e := refusal(http.StatusTooManyRequests, SlugAccountLocked, "too many failed sign-ins: this username is locked for a while")
	e.RetryAfter = max(wait, time.Second)
	return e
}

func mfaRefused(detail string) error { return refusal(http.StatusUnauthorized, SlugMFARefused, detail) }

func (s *Accounts) limited(ri RequestInfo, username string) (bool, time.Duration, string) {
	if ok, wait := s.ipLimiter.Allow("ip:" + ri.RemoteIP); !ok {
		return true, wait, "rate_limited_address"
	}
	if username != "" {
		if ok, wait := s.userLimiter.Allow("u:" + clip(username, 64)); !ok {
			return true, wait, "rate_limited_username"
		}
	}
	return false, 0, ""
}

func userEvent(userID, username, eventType string, payload map[string]any) audit.Event {
	actorType, actorID, entityType, entityID := audit.ActorUser, userID, "user", userID
	if userID == "" {
		actorType, actorID, entityType, entityID = audit.ActorSystem, "anonymous", "login", "login:"+username
	}
	payload["username"] = username
	return audit.Event{ActorType: actorType, ActorID: actorID, Purpose: purposeSignIn, EntityType: entityType,
		EntityID: entityID, EventType: eventType, Payload: payload}
}

// recordOwnTx records ev in a transaction of its own; a failure is
// counted (the refusal stands).
func (s *Accounts) recordOwnTx(ctx context.Context, ev audit.Event) {
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error { return tx.Record(ctx, ev) })
	if err != nil {
		s.counters.Inc(CounterRefusalNotSaved)
	}
}

func (s *Accounts) loginRefused(ctx context.Context, username string, ri RequestInfo, reason string) {
	s.counters.Inc(CounterLoginRefused)
	s.recordOwnTx(ctx, userEvent("", username, EventLoginRefused, map[string]any{"reason": reason, "remote_ip": ri.RemoteIP}))
}

func locked(l Lockout, now time.Time) (time.Duration, bool) {
	if l.LockedUntil != nil && now.Before(*l.LockedUntil) {
		return l.LockedUntil.Sub(now), true
	}
	return 0, false
}

// Enrolment is a pending TOTP enrolment, shown until the first code
// confirms it.
type Enrolment struct {
	Secret     string
	OTPAuthURI string
}

// LoginResult is the first step's answer: the mfa_pending token.
type LoginResult struct {
	MFAToken  string
	ExpiresAt time.Time
	// Enrolment is set while the account has no confirmed TOTP: such an
	// account can only enrol (the next step confirms it and signs in).
	Enrolment *Enrolment
}

// Login checks a password and opens an MFA challenge. An unknown user, a
// disabled user and a wrong password get one answer after one argon2id
// verification each, and each is a failure of the username in
// login_lockouts; a locked username is refused (429, Retry-After)
// before any verification. Attempts are limited per address and per
// username (S-15). Every attempt is an audit event.
func (s *Accounts) Login(ctx context.Context, username, password string, ri RequestInfo) (LoginResult, error) {
	norm := NormalizeUsername(username)
	if lim, wait, reason := s.limited(ri, norm); lim {
		s.loginRefused(ctx, auditName(norm), ri, reason)
		return LoginResult{}, rateLimited(wait)
	}
	if !usernamePattern.MatchString(norm) || len(password) > MaxSecretBytes {
		s.hasher.VerifyDummy(password)
		s.loginRefused(ctx, invalidUsername, ri, "invalid_input")
		return LoginResult{}, invalidCredentials()
	}
	var now time.Time
	var lock Lockout
	var u User
	found := false
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		if now, err = tx.Now(ctx); err != nil {
			return err
		}
		if lock, err = tx.PeekLockout(ctx, norm); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		u, err = tx.UserByUsername(ctx, norm)
		switch {
		case err == nil:
			found = true
		case !errors.Is(err, ErrNotFound):
			return err
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("read account: %w", err)
	}
	if wait, ok := locked(lock, now); ok {
		s.counters.Inc(CounterLoginLocked)
		s.loginRefused(ctx, norm, ri, "locked")
		return LoginResult{}, accountLocked(wait)
	}
	if !found {
		s.hasher.VerifyDummy(password)
		return LoginResult{}, s.failure(ctx, norm, "", ri, "unknown_user")
	}
	if ok, _ := s.hasher.Verify(password, u.PasswordHash); !ok {
		return LoginResult{}, s.failure(ctx, norm, u.ID, ri, "wrong_password")
	}
	if u.Status != StatusActive {
		return LoginResult{}, s.failure(ctx, norm, u.ID, ri, "user_disabled")
	}
	var out LoginResult
	err = s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		m, err := tx.MFAForUpdate(ctx, u.ID)
		switch {
		case errors.Is(err, ErrNotFound):
			secret, uri, err := NewTOTPSecret(u.Username)
			if err != nil {
				return err
			}
			sealed, err := s.sealer.Seal([]byte(secret), mfaAAD(u.ID))
			if err != nil {
				return err
			}
			if err := tx.SaveMFA(ctx, MFA{UserID: u.ID, KeyID: s.sealer.KeyID(), SecretEnc: sealed}, now); err != nil {
				return err
			}
			out.Enrolment = &Enrolment{Secret: secret, OTPAuthURI: uri}
		case err != nil:
			return err
		case m.EnrolledAt == nil:
			secret, err := s.sealer.Open(m.KeyID, m.SecretEnc, mfaAAD(u.ID))
			if err != nil {
				return mfaUnavailable()
			}
			uri, err := TOTPURI(u.Username, string(secret))
			if err != nil {
				return mfaUnavailable()
			}
			out.Enrolment = &Enrolment{Secret: string(secret), OTPAuthURI: uri}
		}
		token, hash, err := newChallengeToken()
		if err != nil {
			return err
		}
		out.MFAToken, out.ExpiresAt = token, now.Add(s.cfg.ChallengeTTL)
		if err := tx.InsertChallenge(ctx, Challenge{TokenHash: hash, UserID: u.ID, CreatedAt: now, ExpiresAt: out.ExpiresAt,
			RemoteIP: clip(ri.RemoteIP, 64)}); err != nil {
			return err
		}
		return tx.Record(ctx, userEvent(u.ID, u.Username, EventLoginPasswordAccepted, map[string]any{
			"enrolment_pending": out.Enrolment != nil, "remote_ip": ri.RemoteIP}))
	})
	if err != nil {
		return LoginResult{}, wrapUnlessRefusal("open challenge", err)
	}
	s.counters.Inc(CounterLoginAccepted)
	return out, nil
}

func mfaUnavailable() error {
	return refusal(http.StatusServiceUnavailable, SlugUnavailable, "the second factor cannot be checked: the TOTP secret does not open under ANSP_SECRETS_KEY_FILE")
}

func wrapUnlessRefusal(what string, err error) error {
	var e *apierr.Problem
	if errors.As(err, &e) {
		return e
	}
	return fmt.Errorf("%s: %w", what, err)
}

// auditName is the username as the audit log names it.
func auditName(norm string) string {
	if usernamePattern.MatchString(norm) {
		return norm
	}
	return invalidUsername
}

func mfaAAD(userID string) []byte { return []byte("user_mfa:" + userID) }

// newChallengeToken is 256 random bits, base64url, and its SHA-256 hex:
// only the hash is stored.
func newChallengeToken() (token, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b[:])
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// failure counts one failed sign-in of username in its own transaction,
// locks it at LockoutAfter, audits both, and returns the one answer
// every failure gets.
func (s *Accounts) failure(ctx context.Context, username, userID string, ri RequestInfo, reason string) error {
	s.counters.Inc(CounterLoginRefused)
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		failures, err := s.countFailure(ctx, tx, username, now)
		if err != nil {
			return err
		}
		return tx.Record(ctx, userEvent(userID, username, EventLoginRefused, map[string]any{
			"reason": reason, "failures": failures, "remote_ip": ri.RemoteIP}))
	})
	if err != nil {
		s.counters.Inc(CounterRefusalNotSaved)
	}
	return invalidCredentials()
}

// countFailure adds one failure to username's lockout row (locked to
// the end of the transaction) and locks it at LockoutAfter; a lock is a
// login_locked event. A lock that is over starts a new count.
func (s *Accounts) countFailure(ctx context.Context, tx Tx, username string, now time.Time) (int, error) {
	l, err := tx.Lockout(ctx, username, now)
	if err != nil {
		return 0, err
	}
	if l.LockedUntil != nil && !now.Before(*l.LockedUntil) {
		l.Failures, l.LockedUntil = 0, nil
	}
	l.Failures++
	lockNow := l.Failures >= s.cfg.LockoutAfter && l.LockedUntil == nil
	if lockNow {
		until := now.Add(s.cfg.LockoutFor)
		l.LockedUntil = &until
	}
	if err := tx.SetLockout(ctx, l, now); err != nil {
		return 0, err
	}
	if !lockNow {
		return l.Failures, nil
	}
	s.counters.Inc(CounterLoginLocked)
	return l.Failures, tx.Record(ctx, audit.Event{ActorType: audit.ActorSystem, ActorID: "login-lockout", Purpose: purposeSignIn,
		EntityType: "login", EntityID: "login:" + username, EventType: EventLoginLocked,
		Payload: map[string]any{"username": username, "failures": l.Failures, "locked_until": l.LockedUntil}})
}

// UserView is an account as the API shows it (no hash, no secret).
type UserView struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func viewOf(u User) UserView {
	return UserView{ID: u.ID, Username: u.Username, Role: u.Role, Status: u.Status, CreatedAt: u.CreatedAt.UTC(), LastLoginAt: utcPtr(u.LastLoginAt)}
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// MFAResult is the second step's answer: a session.
type MFAResult struct {
	Token       string
	JTI         string
	ExpiresAt   time.Time
	IdleTimeout time.Duration
	User        UserView
}

// VerifyMFA exchanges the mfa_pending token and a TOTP code for a
// session. The challenge, the account and its MFA row are locked FOR
// UPDATE in that order, so a code is spent once even by two sign-ins at
// once (the TOTP step must be after the last one accepted: the same
// code twice is refused). A wrong code counts against the challenge and
// against the username's lockout. The first right code confirms a
// pending enrolment. Refusals are mfa_refused events committed with the
// counts; the session is a session_started event in the transaction
// that creates it.
func (s *Accounts) VerifyMFA(ctx context.Context, mfaToken, code string, ri RequestInfo) (MFAResult, error) {
	if lim, wait, reason := s.limited(ri, ""); lim {
		s.counters.Inc(CounterMFARefused)
		s.recordOwnTx(ctx, userEvent("", invalidUsername, EventMFARefused, map[string]any{"reason": reason, "remote_ip": ri.RemoteIP}))
		return MFAResult{}, rateLimited(wait)
	}
	if mfaToken == "" || len(mfaToken) > 128 || len(code) > 16 {
		s.counters.Inc(CounterMFARefused)
		s.recordOwnTx(ctx, userEvent("", invalidUsername, EventMFARefused, map[string]any{"reason": "malformed", "remote_ip": ri.RemoteIP}))
		return MFAResult{}, mfaRefused("send the mfa_token of the login with a six-digit code")
	}
	var out MFAResult
	var refused error
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		refuse := func(userID, username, reason string, answer error) error {
			s.counters.Inc(CounterMFARefused)
			refused = answer
			return tx.Record(ctx, userEvent(userID, username, EventMFARefused, map[string]any{"reason": reason, "remote_ip": ri.RemoteIP}))
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		hash := hashToken(mfaToken)
		ch, err := tx.ChallengeForUpdate(ctx, hash)
		if errors.Is(err, ErrNotFound) {
			return refuse("", invalidUsername, "challenge_unknown", mfaRefused("the mfa_token is not valid; sign in again"))
		}
		if err != nil {
			return err
		}
		u, err := tx.UserForUpdate(ctx, ch.UserID)
		if err != nil {
			return err
		}
		switch {
		case ch.UsedAt != nil:
			return refuse(u.ID, u.Username, "challenge_used", mfaRefused("the mfa_token was used; sign in again"))
		case !now.Before(ch.ExpiresAt):
			return refuse(u.ID, u.Username, "challenge_expired", mfaRefused("the mfa_token expired; sign in again"))
		case ch.Attempts >= s.cfg.ChallengeAttempts:
			return refuse(u.ID, u.Username, "challenge_exhausted", mfaRefused("too many wrong codes; sign in again"))
		case u.Status != StatusActive:
			return refuse(u.ID, u.Username, "user_disabled", mfaRefused("the mfa_token is not valid; sign in again"))
		}
		lock, err := tx.PeekLockout(ctx, u.Username)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if wait, ok := locked(lock, now); ok {
			return refuse(u.ID, u.Username, "locked", accountLocked(wait))
		}
		m, err := tx.MFAForUpdate(ctx, u.ID)
		if errors.Is(err, ErrNotFound) {
			return refuse(u.ID, u.Username, "mfa_reset", mfaRefused("the mfa_token is not valid; sign in again"))
		}
		if err != nil {
			return err
		}
		secret, err := s.sealer.Open(m.KeyID, m.SecretEnc, mfaAAD(u.ID))
		if err != nil {
			return mfaUnavailable()
		}
		step, ok := VerifyTOTP(string(secret), code, now, m.LastStep)
		if !ok {
			reason := "wrong_code"
			if _, replay := VerifyTOTP(string(secret), code, now, -1); replay {
				reason = "code_replayed"
			}
			if err := tx.CountChallengeAttempt(ctx, hash); err != nil {
				return err
			}
			if _, err := s.countFailure(ctx, tx, u.Username, now); err != nil {
				return err
			}
			return refuse(u.ID, u.Username, reason, mfaRefused("the code is wrong or was already used"))
		}
		m.LastStep = step
		if m.EnrolledAt == nil {
			m.EnrolledAt = &now
			if err := tx.Record(ctx, userEvent(u.ID, u.Username, EventMFAEnrolled, map[string]any{})); err != nil {
				return err
			}
		}
		if err := tx.SaveMFA(ctx, m, now); err != nil {
			return err
		}
		if err := tx.UseChallenge(ctx, hash, now); err != nil {
			return err
		}
		if err := tx.ClearLockout(ctx, u.Username); err != nil {
			return err
		}
		if err := tx.TouchLogin(ctx, u.ID, now); err != nil {
			return err
		}
		u.LastLoginAt = &now
		out, err = s.startSession(ctx, tx, u, ri, now)
		return err
	})
	if err != nil {
		return MFAResult{}, wrapUnlessRefusal("verify MFA", err)
	}
	if refused != nil {
		return MFAResult{}, refused
	}
	s.counters.Inc(CounterSessionsStarted)
	return out, nil
}

// startSession inserts the session row and signs its token through
// core's Issuer.IssueSession: aud this system's host, sub the account,
// scope "session", roles [role], realm console, jti the session id,
// iat and exp from the database clock.
func (s *Accounts) startSession(ctx context.Context, tx Tx, u User, ri RequestInfo, now time.Time) (MFAResult, error) {
	jti, err := randomHex(16)
	if err != nil {
		return MFAResult{}, err
	}
	issued := now.Truncate(time.Second)
	row := SessionRow{JTI: jti, UserID: u.ID, Role: u.Role, IssuedAt: issued, ExpiresAt: issued.Add(s.cfg.SessionTTL),
		LastSeenAt: issued, RemoteIP: clip(ri.RemoteIP, 64), UserAgent: clip(ri.UserAgent, 256)}
	if err := tx.InsertSession(ctx, row); err != nil {
		return MFAResult{}, err
	}
	token, err := s.issuer.IssueSession(coreauth.SessionClaims{
		Audience: s.cfg.Audience, Subject: u.ID, Roles: []string{u.Role}, Realm: RealmConsole,
		IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, JTI: jti,
	})
	if err != nil {
		return MFAResult{}, err
	}
	err = tx.Record(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: u.ID, Purpose: purposeSignIn, EntityType: "session",
		EntityID: jti, EventType: EventSessionStarted,
		Payload: map[string]any{"role": u.Role, "exp": row.ExpiresAt.UTC(), "kid": s.kid, "remote_ip": ri.RemoteIP}})
	return MFAResult{Token: token, JTI: jti, ExpiresAt: row.ExpiresAt.UTC(), IdleTimeout: s.cfg.IdleTimeout, User: viewOf(u)}, err
}

// CheckSession implements SessionChecker on the database clock: the
// session row exists for that account, is not revoked, has not expired
// and was used within IdleTimeout; an idle session is ended so that it
// stays ended. last_seen_at moves at most once a minute.
func (s *Accounts) CheckSession(ctx context.Context, jti, sub string) (string, error) {
	row, now, err := s.store.Session(ctx, jti)
	if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("%w: unknown session", ErrSessionRefused)
	}
	if err != nil {
		return "", err
	}
	switch {
	case row.UserID != sub:
		return "", fmt.Errorf("%w: the session is not this account's", ErrSessionRefused)
	case row.RevokedAt != nil:
		return "", fmt.Errorf("%w: the session was ended (%s)", ErrSessionRefused, row.RevokeReason)
	case !now.Before(row.ExpiresAt):
		return "", fmt.Errorf("%w: the session expired", ErrSessionRefused)
	case now.Sub(row.LastSeenAt) > s.cfg.IdleTimeout:
		s.counters.Inc(CounterSessionsIdle)
		err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
			at, err := tx.Now(ctx)
			if err != nil {
				return err
			}
			ended, err := tx.RevokeSession(ctx, jti, "idle", at)
			if err != nil || !ended {
				return err
			}
			return tx.Record(ctx, audit.Event{ActorType: audit.ActorSystem, ActorID: "session-idle", Purpose: purposeSignIn,
				EntityType: "session", EntityID: jti, EventType: EventSessionIdleEnded,
				Payload: map[string]any{"user_id": sub, "idle_s": int64(s.cfg.IdleTimeout / time.Second)}})
		})
		if err != nil {
			s.counters.Inc(CounterRefusalNotSaved)
		}
		return "", fmt.Errorf("%w: the session was idle longer than %s", ErrSessionRefused, s.cfg.IdleTimeout)
	}
	if now.Sub(row.LastSeenAt) >= touchEvery {
		if err := s.store.TouchSession(ctx, jti); err != nil {
			return "", err
		}
	}
	return row.Role, nil
}

func (s *Accounts) forget(jtis ...string) {
	if s.sessions == nil {
		return
	}
	for _, j := range jtis {
		s.sessions.Forget(j)
	}
}

// Logout ends the caller's session.
func (s *Accounts) Logout(ctx context.Context, p Principal) error {
	if !p.Session {
		return refusal(http.StatusForbidden, SlugForbidden, "only a console session can be ended")
	}
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.RevokeSession(ctx, p.Claims.JTI, "logout", now); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{ActorType: audit.ActorUser, ActorID: p.Claims.Subject, Purpose: purposeSignIn,
			EntityType: "session", EntityID: p.Claims.JTI, EventType: EventLogout, Payload: map[string]any{}})
	})
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	s.forget(p.Claims.JTI)
	return nil
}

// Me is the account behind a session.
type Me struct {
	UserView
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

// Me returns the caller's account.
func (s *Accounts) Me(ctx context.Context, p Principal) (Me, error) {
	if !p.Session {
		return Me{}, refusal(http.StatusForbidden, SlugForbidden, "a console session is required")
	}
	var u User
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		var err error
		u, err = tx.UserByID(ctx, p.Claims.Subject)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return Me{}, refusal(http.StatusNotFound, SlugNotFound, "the account no longer exists")
	}
	if err != nil {
		return Me{}, fmt.Errorf("read account: %w", err)
	}
	return Me{UserView: viewOf(u), SessionExpiresAt: p.Claims.ExpiresAt.UTC()}, nil
}

func actorOf(p Principal) (audit.ActorType, string) {
	if p.Session {
		return audit.ActorUser, p.Claims.Subject
	}
	return audit.ActorSystem, "bootstrap"
}

// validateNewUser checks a new account's fields, naming each at fault.
func validateNewUser(username, password, role string) (string, error) {
	norm := NormalizeUsername(username)
	var errs []error
	if !usernamePattern.MatchString(norm) {
		errs = append(errs, core.Fieldf("username", "3 to 64 of a-z 0-9 . _ @ -, starting with a letter or digit"))
	}
	switch n := utf8.RuneCountInString(password); {
	case !utf8.ValidString(password):
		errs = append(errs, core.Fieldf("password", "not valid UTF-8"))
	case n < MinPasswordChars:
		errs = append(errs, core.Fieldf("password", "at least %d characters", MinPasswordChars))
	case len(password) > MaxSecretBytes:
		errs = append(errs, core.Fieldf("password", "at most %d bytes", MaxSecretBytes))
	}
	if !slices.Contains(Roles, role) {
		errs = append(errs, core.Fieldf("role", "one of %s", strings.Join(Roles, ", ")))
	}
	return norm, errors.Join(errs...)
}

// CreateUser creates an account (admin). Its TOTP is enrolled at its
// first sign-in; until then it can only enrol.
func (s *Accounts) CreateUser(ctx context.Context, actor Principal, username, password, role string) (UserView, error) {
	norm, err := validateNewUser(username, password, role)
	if err != nil {
		return UserView{}, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return UserView{}, err
	}
	at, aid := actorOf(actor)
	var out User
	err = s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		out, err = tx.InsertUser(ctx, User{Username: norm, PasswordHash: hash, Role: role, Status: StatusActive}, aid, now)
		if errors.Is(err, ErrConflict) {
			return refusal(http.StatusConflict, SlugConflict, "the username is taken", apierr.FieldProblem{Field: "username", Reason: "taken"})
		}
		if err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{ActorType: at, ActorID: aid, Purpose: purposeAdmin, EntityType: "user", EntityID: out.ID,
			EventType: EventUserCreated, Payload: map[string]any{"username": norm, "role": role}})
	})
	if err != nil {
		return UserView{}, wrapUnlessRefusal("create user", err)
	}
	return viewOf(out), nil
}

// Users lists the accounts (admin), at most MaxUsersListed.
func (s *Accounts) Users(ctx context.Context) ([]UserView, error) {
	us, err := s.store.Users(ctx, MaxUsersListed)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	out := make([]UserView, 0, len(us))
	for i := range us {
		out = append(out, viewOf(us[i]))
	}
	return out, nil
}

func notFoundUser() error { return refusal(http.StatusNotFound, SlugNotFound, "no such account") }

// ResetMFA deletes an account's TOTP and ends its sessions (admin): its
// next sign-in enrols again.
func (s *Accounts) ResetMFA(ctx context.Context, actor Principal, id string) (UserView, error) {
	return s.change(ctx, actor, id, EventMFAReset, "mfa_reset", func(ctx context.Context, tx Tx, u User, _ time.Time) (User, error) {
		return u, tx.DeleteMFA(ctx, u.ID)
	})
}

// Disable disables an account and ends its sessions (admin); the last
// active admin cannot be disabled.
func (s *Accounts) Disable(ctx context.Context, actor Principal, id string) (UserView, error) {
	return s.change(ctx, actor, id, EventUserDisabled, "user_disabled", func(ctx context.Context, tx Tx, u User, now time.Time) (User, error) {
		if u.Status == StatusActive && u.Role == RoleAdmin {
			n, err := tx.CountActiveAdmins(ctx)
			if err != nil {
				return User{}, err
			}
			if n <= 1 {
				return User{}, refusal(http.StatusConflict, SlugConflict, "the last active admin cannot be disabled")
			}
		}
		_, aid := actorOf(actor)
		return tx.SetUserStatus(ctx, u.ID, StatusDisabled, aid, now)
	})
}

// change applies fn to a locked account, ends its sessions and records
// eventType, in one transaction.
func (s *Accounts) change(ctx context.Context, actor Principal, id, eventType, reason string,
	fn func(ctx context.Context, tx Tx, u User, now time.Time) (User, error),
) (UserView, error) {
	at, aid := actorOf(actor)
	var out User
	var ended []string
	err := s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		u, err := tx.UserForUpdate(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return notFoundUser()
		}
		if err != nil {
			return err
		}
		if out, err = fn(ctx, tx, u, now); err != nil {
			return err
		}
		if ended, err = tx.RevokeUserSessions(ctx, u.ID, reason, now); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{ActorType: at, ActorID: aid, Purpose: purposeAdmin, EntityType: "user", EntityID: u.ID,
			EventType: eventType, Payload: map[string]any{"username": u.Username, "sessions_ended": len(ended)}})
	})
	if err != nil {
		return UserView{}, wrapUnlessRefusal(eventType, err)
	}
	s.forget(ended...)
	return viewOf(out), nil
}

// Bootstrap creates the first admin when there is no account at all
// (ANSP_BOOTSTRAP_ADMIN_*); with any account it does nothing. It reports
// whether it created one.
func (s *Accounts) Bootstrap(ctx context.Context, username, password string) (bool, error) {
	norm, err := validateNewUser(username, password, RoleAdmin)
	if err != nil {
		return false, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return false, err
	}
	created := false
	err = s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		n, err := tx.CountUsers(ctx)
		if err != nil || n > 0 {
			return err
		}
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		u, err := tx.InsertUser(ctx, User{Username: norm, PasswordHash: hash, Role: RoleAdmin, Status: StatusActive}, "bootstrap", now)
		if errors.Is(err, ErrConflict) {
			return nil // another replica bootstrapped it first
		}
		if err != nil {
			return err
		}
		created = true
		return tx.Record(ctx, audit.Event{ActorType: audit.ActorSystem, ActorID: "bootstrap", Purpose: purposeAdmin, EntityType: "user",
			EntityID: u.ID, EventType: EventUserBootstrapped, Payload: map[string]any{"username": norm, "role": RoleAdmin}})
	})
	return created, err
}

// Sweep deletes sessions and challenges expired more than
// SweepRetention ago and lockouts untouched for as long that hold no
// lock, on the database clock: the tables stay bounded (E-10).
func (s *Accounts) Sweep(ctx context.Context) (sessions, challenges, lockouts int64, err error) {
	err = s.store.InTx(ctx, func(ctx context.Context, tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		sessions, challenges, lockouts, err = tx.Sweep(ctx, now.Add(-SweepRetention), now)
		return err
	})
	if err == nil && sessions > 0 {
		s.counters.Add(CounterSessionsSwept, uint64(sessions))
	}
	return sessions, challenges, lockouts, err
}

// RunSweep sweeps every interval until ctx ends, passing a failure to
// onError (the process logs it).
func (s *Accounts) RunSweep(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, _, _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil && onError != nil {
				onError(err)
			}
		}
	}
}
