package auth

import (
	"container/list"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// The console roles (01 section 4).
const (
	RoleWatchSupervisor = "watch_supervisor"
	RoleViewer          = "viewer"
	RoleAdmin           = "admin"
)

// Roles are every console role.
var Roles = []string{RoleWatchSupervisor, RoleViewer, RoleAdmin}

// RealmConsole is the realm of every session of this system (M20).
const RealmConsole = "console"

// The session contract (M20, M21, M22).
const (
	CookieSession = "uspace_session"
	CookieCSRF    = "uspace_csrf"
	HeaderCSRF    = "X-CSRF-Token"
	// CloseReLogin is the WebSocket close code that means "sign in
	// again": the session ended or was refused mid-stream.
	CloseReLogin = 4401
)

// Session bounds (M20, 06 section 3).
const (
	// MaxSessionTTL bounds exp - iat of a session token.
	MaxSessionTTL = 12 * time.Hour
	// SessionIdleTimeout ends a session not used for this long.
	SessionIdleTimeout = 30 * time.Minute
)

// Defaults of the revocation cache.
const (
	DefaultSessionCacheTTL  = 5 * time.Second
	DefaultSessionCacheSize = 4096
)

// Counters of the session verifier.
const (
	CounterSessionShape      = "session_shape_refused"
	CounterSessionNotLive    = "session_not_live"
	CounterSessionCheckError = "session_check_failed"
	CounterSessionCacheHit   = "session_cache_hit"
	CounterSessionCacheEvict = "session_cache_evicted"
)

// ErrSessionRefused wraps the reason a session token's session is not
// live (unknown, revoked, expired, idle).
var ErrSessionRefused = errors.New("session refused")

// SessionChecker is the stateful half of a session token: the session
// row exists for that account and is live; it returns the row's role.
// An error wrapping ErrSessionRefused refuses the token; any other is
// the store being unavailable.
type SessionChecker interface {
	CheckSession(ctx context.Context, jti, sub string) (role string, err error)
}

// SessionVerifierConfig configures a SessionVerifier.
type SessionVerifierConfig struct {
	// Issuer is this system's issuer URL (the iss of every session).
	Issuer string
	// Ring holds the session key: its JWKS is the static key set the
	// core verifier checks with (no network).
	Ring *coreauth.KeyRing
	// Audiences are ANSP_AUDIENCES; a session's aud is the first.
	Audiences []string
	// Checker checks the session row; required.
	Checker SessionChecker
	// CacheTTL is how long a live answer is reused before the row is
	// read again (default DefaultSessionCacheTTL); CacheSize bounds the
	// cache (default DefaultSessionCacheSize).
	CacheTTL  time.Duration
	CacheSize int
	// Now is the clock of core's exp check and of the cache.
	Now func() time.Time
}

// SessionVerifier verifies console session tokens: core's Verifier with
// this system as the one issuer (keys from the session ring, no network)
// and the same audiences and StrictSessionClaims as machine tokens, then
// the session shape of M20 (scope exactly "session", realm console, one
// known role), then the session row through a short bounded cache, so
// logout and revocation take effect within CacheTTL everywhere and at
// once in the process that ended the session (Forget).
type SessionVerifier struct {
	issuer   string
	v        *coreauth.Verifier
	checker  SessionChecker
	cache    *sessionCache
	counters core.Counters
}

// NewSessionVerifier builds a SessionVerifier.
func NewSessionVerifier(ctx context.Context, c SessionVerifierConfig) (*SessionVerifier, error) {
	switch {
	case c.Issuer == "":
		return nil, core.Fieldf("ANSP_PUBLIC_BASE_URL", "required: it is the issuer of console sessions")
	case c.Ring == nil:
		return nil, core.Fieldf("ANSP_SESSION_KEY_FILE", "required to verify console sessions")
	case len(c.Audiences) == 0:
		return nil, core.Fieldf("ANSP_AUDIENCES", "required to verify console sessions")
	case c.Checker == nil:
		return nil, errors.New("a session checker is required")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultSessionCacheTTL
	}
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultSessionCacheSize
	}
	v, err := coreauth.NewVerifier(ctx, coreauth.Config{
		Issuers:             map[string]coreauth.IssuerConfig{c.Issuer: {Keys: c.Ring.JWKS()}},
		Audiences:           slices.Clone(c.Audiences),
		StrictSessionClaims: true,
		Now:                 c.Now,
	})
	if err != nil {
		return nil, err
	}
	s := &SessionVerifier{issuer: c.Issuer, v: v, checker: c.Checker}
	s.cache = newSessionCache(c.CacheSize, c.CacheTTL, c.Now, &s.counters)
	return s, nil
}

// Issuer is the iss of every session.
func (s *SessionVerifier) Issuer() string { return s.issuer }

// Counters are this verifier's own counters; CoreCounters core's.
func (s *SessionVerifier) Counters() *core.Counters { return &s.counters }

// CoreCounters are the core verifier's counters.
func (s *SessionVerifier) CoreCounters() *core.Counters { return s.v.Counters() }

// Forget drops jti from the cache (logout, revocation in this process).
func (s *SessionVerifier) Forget(jti string) { s.cache.forget(jti) }

// CacheLen is the number of cached sessions.
func (s *SessionVerifier) CacheLen() int { return s.cache.len() }

func shapeError(claim, reason string) error {
	return &coreauth.TokenError{Counter: CounterSessionShape, Claim: claim, Reason: reason}
}

// Verify verifies a session token and checks its session. A refusal is
// a *coreauth.TokenError (the token), an error wrapping
// ErrSessionRefused (the session), or another error (the store).
func (s *SessionVerifier) Verify(ctx context.Context, token string) (coreauth.Claims, error) {
	cl, err := s.v.Verify(ctx, token)
	if err != nil {
		return coreauth.Claims{}, err
	}
	switch {
	case len(cl.Scopes) != 1 || cl.Scopes[0] != coreauth.SessionScope:
		// The old shape (scope = the role) and any machine scope.
		s.counters.Inc(CounterSessionShape)
		return coreauth.Claims{}, shapeError("scope", `a session token carries scope "session" alone`)
	case cl.Realm != RealmConsole:
		s.counters.Inc(CounterSessionShape)
		return coreauth.Claims{}, shapeError("realm", `the realm is not "console"`)
	case len(cl.Roles) != 1 || !slices.Contains(Roles, cl.Roles[0]):
		s.counters.Inc(CounterSessionShape)
		return coreauth.Claims{}, shapeError("roles", "a session carries exactly one console role")
	}
	if s.cache.live(cl.JTI, cl.Subject, cl.Roles[0]) {
		s.counters.Inc(CounterSessionCacheHit)
		return cl, nil
	}
	role, err := s.checker.CheckSession(ctx, cl.JTI, cl.Subject)
	switch {
	case errors.Is(err, ErrSessionRefused):
		s.counters.Inc(CounterSessionNotLive)
		return coreauth.Claims{}, err
	case err != nil:
		s.counters.Inc(CounterSessionCheckError)
		return coreauth.Claims{}, fmt.Errorf("the session could not be checked: %w", err)
	case role != cl.Roles[0]:
		s.counters.Inc(CounterSessionNotLive)
		return coreauth.Claims{}, fmt.Errorf("%w: the session's role is not the token's", ErrSessionRefused)
	}
	s.cache.put(cl.JTI, cl.Subject, role)
	return cl, nil
}

// sessionCache remembers live sessions for a short time, bounded in
// entries (E-10): the least recently used is evicted, counted.
type sessionCache struct {
	ttl      time.Duration
	max      int
	now      func() time.Time
	counters *core.Counters

	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List
}

type cachedSession struct {
	jti, sub, role string
	until          time.Time
}

func newSessionCache(size int, ttl time.Duration, now func() time.Time, counters *core.Counters) *sessionCache {
	return &sessionCache{ttl: ttl, max: size, now: now, counters: counters, items: map[string]*list.Element{}, order: list.New()}
}

func (c *sessionCache) live(jti, sub, role string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[jti]
	if !ok {
		return false
	}
	e := el.Value.(*cachedSession)
	if !c.now().Before(e.until) || e.sub != sub || e.role != role {
		c.order.Remove(el)
		delete(c.items, jti)
		return false
	}
	c.order.MoveToFront(el)
	return true
}

func (c *sessionCache) put(jti, sub, role string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[jti]; ok {
		c.order.Remove(el)
		delete(c.items, jti)
	}
	for len(c.items) >= c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*cachedSession).jti)
		c.counters.Inc(CounterSessionCacheEvict)
	}
	c.items[jti] = c.order.PushFront(&cachedSession{jti: jti, sub: sub, role: role, until: c.now().Add(c.ttl)})
}

func (c *sessionCache) forget(jti string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[jti]; ok {
		c.order.Remove(el)
		delete(c.items, jti)
	}
}

func (c *sessionCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// CheckCSRF is the double-submit check of M21, the reference the BFF
// implements before it forwards a state-changing request: on any method
// but GET, HEAD and OPTIONS the X-CSRF-Token header must equal the
// uspace_csrf cookie (constant time), both present. The api itself
// never reads the session from a cookie on a REST call (the BFF
// forwards it as a bearer, which a cross-site page cannot set), so it
// does not need this check; the WebSocket upgrade is a GET.
func CheckCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	c, err := r.Cookie(CookieCSRF)
	if err != nil || c.Value == "" {
		return errors.New("no " + CookieCSRF + " cookie")
	}
	h := r.Header.Get(HeaderCSRF)
	if h == "" || subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) != 1 {
		return errors.New("the " + HeaderCSRF + " header does not match the " + CookieCSRF + " cookie")
	}
	return nil
}
