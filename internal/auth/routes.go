package auth

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// ProcessEach is the x-process of the health endpoints every process
// serves through obs.Server (/healthz, /readyz, /metrics).
const ProcessEach = "each"

// Bounds of the x-auth grammar.
const (
	maxAccessLen = 256
	maxScopes    = 8
)

// ParseAccess reads an x-auth value of api/openapi.yaml:
//
//	public
//	jws:<signer group>
//	session                      any console role
//	session:<role>[|<role>...]   a console session with one of the roles
//	token:<scope>[+<scope>...][+mtls]
//
// with alternatives joined by " or " (at most one token and one session
// alternative). Anything else is refused, and so is an Access that
// Validate refuses: an operation whose rule does not parse is not
// served (Routes).
func ParseAccess(s string) (Access, error) {
	var a Access
	if s == "" || len(s) > maxAccessLen {
		return a, errors.New("an x-auth is required, at most 256 bytes")
	}
	alts := strings.Split(s, " or ")
	var sawToken, sawSession bool
	for _, alt := range alts {
		kind, arg, hasArg := strings.Cut(alt, ":")
		switch {
		case alt == "public" || kind == "jws":
			if len(alts) != 1 {
				return Access{}, fmt.Errorf("%q cannot be an alternative", kind)
			}
			if alt == "public" {
				a.Public = true
			} else {
				a.JWS = arg
			}
		case kind == "session" && !sawSession:
			sawSession = true
			if !hasArg {
				a.AnyRole = true
				continue
			}
			for _, role := range strings.Split(arg, "|") {
				if role == "" || slices.Contains(a.Roles, role) {
					return Access{}, fmt.Errorf("session: empty or repeated role in %q", arg)
				}
				a.Roles = append(a.Roles, role)
			}
		case kind == "token" && hasArg && !sawToken:
			sawToken = true
			parts := strings.Split(arg, "+")
			if parts[len(parts)-1] == "mtls" {
				a.MTLS, parts = true, parts[:len(parts)-1]
			}
			if len(parts) == 0 || len(parts) > maxScopes {
				return Access{}, fmt.Errorf("token: between 1 and %d scopes", maxScopes)
			}
			for _, scope := range parts {
				if !scopeLike(scope) || slices.Contains(a.Scopes, scope) {
					return Access{}, fmt.Errorf("token: %q is not a scope, or is repeated", scope)
				}
				a.Scopes = append(a.Scopes, scope)
			}
		default:
			return Access{}, fmt.Errorf("%q is not an access rule", alt)
		}
	}
	if err := a.Validate(); err != nil {
		return Access{}, err
	}
	return a, nil
}

func slugLike(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		lower := c >= 'a' && c <= 'z'
		tail := i > 0 && (c >= '0' && c <= '9' || c == '_' || c == '-')
		if !lower && !tail {
			return false
		}
	}
	return true
}

// scopeChars are the characters of a scope (ansp.traffic,
// cis.publish:restrictions, utm.constraint_processing).
const scopeChars = "abcdefghijklmnopqrstuvwxyz0123456789_.:-"

func scopeLike(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(scopeChars, c) {
			return false
		}
	}
	return true
}

// Operation is one operation of the contract as the router needs it
// (cmd/api builds the list from api/gen.Operations).
type Operation struct {
	ID        string
	Pattern   string
	Process   string
	Auth      string
	WebSocket bool
}

// Routes is the router of one process. The router generated from
// api/openapi.yaml registers every operation of the contract on it (it
// is the generated code's ServeMux), and Routes serves a pattern only
// through the operation's x-auth, enforced by the guard before any
// parameter is bound or any body read, with the body bounded at
// maxBody bytes. Operations of another process, and the health
// endpoints obs serves, are left out. Every route fails closed: a
// pattern that is no operation of the contract is not served and is an
// error, an x-auth that does not parse is not served and is an error,
// and an operation of this process that was never registered is an
// error. The process refuses to start on Err.
type Routes struct {
	mux         *http.ServeMux
	process     string
	guard       *Guard
	maxBody     int64
	middlewares []func(http.Handler) http.Handler
	ops         map[string]Operation
	served      map[string]Access
	seen        map[string]bool
	errs        []error
}

// NewRoutes is the router of process over mux for ops, enforced by
// guard, each body bounded at maxBody bytes, every route wrapped in
// middlewares (outermost first). A duplicate pattern or ID in ops is an
// error.
func NewRoutes(mux *http.ServeMux, process string, guard *Guard, maxBody int64, ops []Operation, middlewares ...func(http.Handler) http.Handler) *Routes {
	rt := &Routes{mux: mux, process: process, guard: guard, maxBody: maxBody, middlewares: middlewares,
		ops: map[string]Operation{}, served: map[string]Access{}, seen: map[string]bool{}}
	ids := map[string]bool{}
	for _, op := range ops {
		if _, dup := rt.ops[op.Pattern]; dup || ids[op.ID] {
			rt.errs = append(rt.errs, fmt.Errorf("%s (%s) is in the operation list twice", op.Pattern, op.ID))
			continue
		}
		ids[op.ID] = true
		rt.ops[op.Pattern] = op
	}
	if maxBody <= 0 {
		rt.errs = append(rt.errs, errors.New("a body bound above zero is required"))
	}
	if guard == nil {
		rt.errs = append(rt.errs, errors.New("a guard is required"))
	}
	return rt
}

// HandleFunc registers h under pattern (the generated router's call).
func (rt *Routes) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	rt.Handle(pattern, http.HandlerFunc(h))
}

// Handle registers h under pattern behind its operation's access rule,
// or records why it cannot.
func (rt *Routes) Handle(pattern string, h http.Handler) {
	op, ok := rt.ops[pattern]
	if !ok {
		rt.errs = append(rt.errs, fmt.Errorf("%s is no operation of the contract; it is not served", pattern))
		return
	}
	if rt.seen[pattern] {
		rt.errs = append(rt.errs, fmt.Errorf("%s is registered twice", pattern))
		return
	}
	rt.seen[pattern] = true
	if op.Process != rt.process {
		return
	}
	a, err := ParseAccess(op.Auth)
	if err != nil {
		rt.errs = append(rt.errs, fmt.Errorf("%s (%s): x-auth %q: %w; it is not served", pattern, op.ID, op.Auth, err))
		return
	}
	if rt.guard == nil || rt.maxBody <= 0 {
		return
	}
	limit := rt.maxBody
	next := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		h.ServeHTTP(w, r)
	}))
	if op.WebSocket {
		next = rt.guard.RequireUpgrade(a)(next)
	} else {
		next = rt.guard.Require(a)(next)
	}
	for i := len(rt.middlewares) - 1; i >= 0; i-- {
		next = rt.middlewares[i](next)
	}
	rt.served[pattern] = a
	rt.mux.Handle(pattern, next)
}

// ServeHTTP serves the underlying mux.
func (rt *Routes) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.mux.ServeHTTP(w, r) }

// Served is the access rule of every pattern served, by pattern.
func (rt *Routes) Served() map[string]Access {
	out := make(map[string]Access, len(rt.served))
	for p, a := range rt.served {
		out[p] = a
	}
	return out
}

// Err is every problem found, including the operations of this process
// that were never registered.
func (rt *Routes) Err() error {
	errs := slices.Clone(rt.errs)
	var missing []string
	for p, op := range rt.ops {
		if op.Process == rt.process && !rt.seen[p] {
			missing = append(missing, p)
		}
	}
	slices.Sort(missing)
	for _, p := range missing {
		errs = append(errs, fmt.Errorf("%s (%s) is an operation of %s and no handler was registered", p, rt.ops[p].ID, rt.process))
	}
	return errors.Join(errs...)
}
