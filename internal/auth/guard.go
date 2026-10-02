package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// Counters of the Guard (counter names, not credentials).
//
//nolint:gosec // counter names
const (
	CounterNoCredential      = "auth_no_credential"
	CounterTokenRefused      = "auth_token_refused"
	CounterScopeRefused      = "auth_scope_refused"
	CounterRoleRefused       = "auth_role_refused"
	CounterSessionRefused    = "auth_session_refused"
	CounterSessionUnchecked  = "auth_session_unchecked"
	CounterMTLSRefused       = "auth_mtls_refused"
	CounterOriginRefused     = "auth_origin_refused"
	CounterMachineAccepted   = "auth_machine_accepted"
	CounterSessionAccepted   = "auth_session_accepted"
	CounterNoMachineVerifier = "auth_no_machine_verifier"
	CounterMisconfigured     = "auth_route_misconfigured"
)

// Access is what one operation requires of its caller (the x-auth of
// its OpenAPI entry): Public, or a machine token granting every one of
// Scopes, and/or a session whose role is one of Roles (AnyRole: any
// console role). MTLS binds the client certificate of a machine caller
// (the /v1/manned-traffic/* and /v1/coordination/* groups). An Access
// that is neither public nor restricted grants nothing: Validate
// refuses it, and Routes does not serve its route.
type Access struct {
	Public  bool
	Scopes  []string
	Roles   []string
	AnyRole bool
	MTLS    bool
}

// Validate refuses an Access that grants nothing or contradicts itself.
func (a Access) Validate() error {
	restricted := len(a.Scopes) > 0 || len(a.Roles) > 0 || a.AnyRole
	switch {
	case a.Public && (restricted || a.MTLS):
		return errors.New("public and restricted at once")
	case !a.Public && !restricted:
		return errors.New("neither public nor restricted to a scope or a role")
	case a.MTLS && len(a.Scopes) == 0:
		return errors.New("mTLS binds machine callers, and no scope admits one")
	case slices.Contains(a.Scopes, ""):
		return errors.New("an empty scope")
	case a.AnyRole && len(a.Roles) > 0:
		return errors.New("any role and a list of roles at once")
	}
	for _, r := range a.Roles {
		if !slices.Contains(Roles, r) {
			return fmt.Errorf("%q is not a console role", r)
		}
	}
	return nil
}

func (a Access) admitsMachines() bool { return len(a.Scopes) > 0 }
func (a Access) admitsSessions() bool { return a.AnyRole || len(a.Roles) > 0 }

// String renders a for logs and errors.
func (a Access) String() string {
	if a.Public {
		return "public"
	}
	var parts []string
	if len(a.Scopes) > 0 {
		s := "token:" + strings.Join(a.Scopes, "+")
		if a.MTLS {
			s += "+mtls"
		}
		parts = append(parts, s)
	}
	if a.AnyRole {
		parts = append(parts, "session")
	}
	if len(a.Roles) > 0 {
		parts = append(parts, "session:"+strings.Join(a.Roles, "|"))
	}
	return strings.Join(parts, " or ")
}

// TokenVerifier verifies an ecosystem token (MachineVerifier).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.Claims, error)
}

// Principal is the authenticated caller of a request.
type Principal struct {
	Claims coreauth.Claims
	// Session is true for a console session, whose Role is its one role.
	Session bool
	Role    string
	// MTLSSubject is the bound certificate subject of a machine caller
	// on an mTLS route with ANSP_MTLS_MODE=required.
	MTLSSubject string
}

type principalKey struct{}

// WithPrincipal puts p on ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom is the request's authenticated caller.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// ClaimsFrom is the verified claims of the request's token.
func ClaimsFrom(ctx context.Context) (coreauth.Claims, bool) {
	p, ok := PrincipalFrom(ctx)
	return p.Claims, ok
}

// Guard authenticates requests: a bearer token from the Authorization
// header, judged by the SessionVerifier when its iss is this system's
// and by the machine verifier otherwise (the unverified iss only chooses
// which verifier refuses or accepts it). Refusals are RFC 9457 problems
// that never echo the token: 401 for a token core refuses (the problem
// type is core's counter, rejected_audience, rejected_expired, ...) or a
// session that is not live, 403 for a missing scope or role or a
// refused certificate binding, 503 when the session store cannot be
// read. Every refusal and acceptance is counted.
type Guard struct {
	Machine  TokenVerifier
	Sessions *SessionVerifier
	MTLS     *MTLS
	// Seen records accepted machine calls (oauth_clients_seen); may be
	// nil.
	Seen *SeenRecorder
	// Origins are ANSP_WS_ALLOWED_ORIGINS, for cookie upgrades.
	Origins []string

	counters core.Counters
}

// Counters are the guard's counters.
func (g *Guard) Counters() *core.Counters { return &g.counters }

// RequireScopes admits a machine token granting every one of scopes
// (brief WP-2): Require(Access{Scopes: scopes}).
func (g *Guard) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return g.Require(Access{Scopes: scopes})
}

// RequireRole admits a session whose roles[] holds one of roles, never
// reading scope.
func (g *Guard) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return g.Require(Access{Roles: roles})
}

// Require is the middleware that enforces a. An invalid Access refuses
// every request with 500 (fail closed).
func (g *Guard) Require(a Access) func(http.Handler) http.Handler {
	invalid := a.Validate()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if invalid != nil {
				g.counters.Inc(CounterMisconfigured)
				WriteProblem(w, r, http.StatusInternalServerError, SlugInternal, "this route has no valid access rule", nil, 0)
				return
			}
			if a.Public {
				next.ServeHTTP(w, r)
				return
			}
			token, err := bearer(r)
			if err != nil {
				g.counters.Inc(CounterNoCredential)
				w.Header().Set("WWW-Authenticate", `Bearer`)
				WriteProblem(w, r, http.StatusUnauthorized, SlugUnauthenticated, err.Error(),
					[]FieldReason{{Field: "Authorization", Reason: err.Error()}}, 0)
				return
			}
			p, aerr := g.authenticate(r, token, a)
			if aerr != nil {
				if aerr.Status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				}
				WriteError(w, r, aerr)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// bearer is the token of the one Authorization header.
func bearer(r *http.Request) (string, error) {
	vals := r.Header.Values("Authorization")
	switch {
	case len(vals) == 0:
		return "", errors.New("no bearer token")
	case len(vals) > 1:
		return "", errors.New("more than one Authorization header")
	}
	scheme, token, ok := strings.Cut(vals[0], " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", errors.New("the Authorization header is not a bearer token")
	}
	return token, nil
}

// authenticate judges token against a.
func (g *Guard) authenticate(r *http.Request, token string, a Access) (Principal, *Error) {
	if g.Sessions != nil && unverifiedIssuer(token) == g.Sessions.Issuer() {
		return g.session(r.Context(), token, a)
	}
	return g.machine(r, token, a)
}

func tokenRefusal(err error) *Error {
	var te *coreauth.TokenError
	if errors.As(err, &te) {
		return refusal(http.StatusUnauthorized, te.Counter, "the token is refused", FieldReason{Field: te.Claim, Reason: te.Reason})
	}
	return refusal(http.StatusUnauthorized, SlugUnauthenticated, "the token is refused")
}

func (g *Guard) machine(r *http.Request, token string, a Access) (Principal, *Error) {
	if g.Machine == nil {
		g.counters.Inc(CounterNoMachineVerifier)
		return Principal{}, refusal(http.StatusUnauthorized, coreauth.CounterRejectedIssuer, "this process accepts no ecosystem token",
			FieldReason{Field: "iss", Reason: "no ecosystem issuer is configured"})
	}
	cl, err := g.Machine.Verify(r.Context(), token)
	if err != nil {
		g.counters.Inc(CounterTokenRefused)
		return Principal{}, tokenRefusal(err)
	}
	if !a.admitsMachines() {
		g.counters.Inc(CounterScopeRefused)
		return Principal{}, refusal(http.StatusForbidden, SlugForbidden, "this operation requires a console session")
	}
	for _, s := range a.Scopes {
		if !cl.HasScope(s) {
			g.counters.Inc(CounterScopeRefused)
			return Principal{}, refusal(http.StatusForbidden, SlugForbidden, "the token does not grant a scope this operation requires",
				FieldReason{Field: "scope", Reason: "missing " + s})
		}
	}
	p := Principal{Claims: cl}
	if a.MTLS {
		if g.MTLS == nil {
			g.counters.Inc(CounterMisconfigured)
			return Principal{}, refusal(http.StatusInternalServerError, SlugInternal, "this route binds client certificates and none is configured")
		}
		subject, err := g.MTLS.Check(r, cl.Subject)
		if err != nil {
			g.counters.Inc(CounterMTLSRefused)
			var e *Error
			errors.As(err, &e)
			return Principal{}, e
		}
		p.MTLSSubject = subject
	}
	g.counters.Inc(CounterMachineAccepted)
	if g.Seen != nil {
		g.Seen.Record(ClientSeen{ClientID: cl.Subject, Issuer: cl.Issuer, MTLSSubject: p.MTLSSubject, Scopes: cl.Scopes})
	}
	return p, nil
}

func (g *Guard) session(ctx context.Context, token string, a Access) (Principal, *Error) {
	cl, err := g.Sessions.Verify(ctx, token)
	var te *coreauth.TokenError
	switch {
	case errors.As(err, &te):
		g.counters.Inc(CounterTokenRefused)
		return Principal{}, tokenRefusal(err)
	case errors.Is(err, ErrSessionRefused):
		g.counters.Inc(CounterSessionRefused)
		return Principal{}, refusal(http.StatusUnauthorized, SlugSessionRefused, "the session has ended; sign in again")
	case err != nil:
		g.counters.Inc(CounterSessionUnchecked)
		e := refusal(http.StatusServiceUnavailable, SlugUnavailable, "the session cannot be checked now")
		e.RetryAfter = DefaultSessionCacheTTL
		return Principal{}, e
	}
	role := cl.Roles[0]
	if !a.admitsSessions() || (!a.AnyRole && !slices.Contains(a.Roles, role)) {
		g.counters.Inc(CounterRoleRefused)
		return Principal{}, refusal(http.StatusForbidden, SlugForbidden, "the session's role may not perform this operation",
			FieldReason{Field: "roles", Reason: "requires " + a.String()})
	}
	g.counters.Inc(CounterSessionAccepted)
	return Principal{Claims: cl, Session: true, Role: role}, nil
}

// RequireUpgrade is the WebSocket rule of M22 for a: a request with an
// Authorization header is judged as any other (a machine client, or the
// BFF); one without it must carry the uspace_session cookie on a request
// whose Origin is on ANSP_WS_ALLOWED_ORIGINS, and the cookie must hold a
// live session admitted by a. There is no ticket. A refusal is an HTTP
// problem before the upgrade; a session that ends mid-stream is the
// stream's to close with CloseReLogin.
func (g *Guard) RequireUpgrade(a Access) func(http.Handler) http.Handler {
	byBearer := g.Require(a)
	return func(next http.Handler) http.Handler {
		bearerNext := byBearer(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Values("Authorization")) > 0 || a.Public || a.Validate() != nil {
				bearerNext.ServeHTTP(w, r)
				return
			}
			p, err := g.fromCookie(r, a)
			if err != nil {
				WriteError(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

func (g *Guard) fromCookie(r *http.Request, a Access) (Principal, *Error) {
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(g.Origins, origin) {
		g.counters.Inc(CounterOriginRefused)
		return Principal{}, refusal(http.StatusForbidden, SlugForbidden, "the Origin of this upgrade is not allowed",
			FieldReason{Field: "Origin", Reason: "not on the allow-list"})
	}
	c, err := r.Cookie(CookieSession)
	if err != nil || c.Value == "" {
		g.counters.Inc(CounterNoCredential)
		return Principal{}, refusal(http.StatusUnauthorized, SlugUnauthenticated, "no "+CookieSession+" cookie and no bearer token")
	}
	if g.Sessions == nil || unverifiedIssuer(c.Value) != g.Sessions.Issuer() {
		g.counters.Inc(CounterTokenRefused)
		return Principal{}, refusal(http.StatusUnauthorized, SlugUnauthenticated, "the "+CookieSession+" cookie does not hold a session of this system")
	}
	return g.session(r.Context(), c.Value, a)
}
