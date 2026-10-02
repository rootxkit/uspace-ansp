package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
)

// maxBodyBytes bounds every request body of the API (06 T9: 1 MiB); an
// operation may bound its own body lower (auth.MaxBodyBytes).
const maxBodyBytes = 1 << 20

// signInUnavailableRetry is the Retry-After of the auth operations while
// console sign-in is not configured.
const signInUnavailableRetry = 60 * time.Second

// operations is the contract's operation list as the router needs it.
func operations() []auth.Operation {
	out := make([]auth.Operation, 0, len(gen.Operations))
	for i := range gen.Operations {
		op := &gen.Operations[i]
		out = append(out, auth.Operation{ID: op.ID, Pattern: op.Pattern, Process: op.Process, Auth: op.Auth, WebSocket: op.WebSocket})
	}
	return out
}

// apiServer is the generated server interface of api: every operation
// answers 501 not_implemented through the strict server's
// gen.Unimplemented until its work package serves it, except the
// console sign-in, user and key operations of WP-2, which are mounted
// here (docs/PLAN.md section 15 gap 22). Auth is nil while console
// sign-in is not configured; those operations then answer 503.
type apiServer struct {
	gen.ServerInterface
	auth *auth.Handlers
}

func newAPIServer(h *auth.Handlers) apiServer {
	strict := gen.NewStrictHandlerWithOptions(gen.Unimplemented{}, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestError,
		ResponseErrorHandlerFunc: responseError,
	})
	return apiServer{ServerInterface: strict, auth: h}
}

// mountAPI registers every operation of api on mux through the
// generated router, each behind its x-auth (auth.Routes), and returns
// the routes or why they cannot be served.
func mountAPI(mux *http.ServeMux, guard *auth.Guard, h *auth.Handlers, middlewares ...func(http.Handler) http.Handler) (*auth.Routes, error) {
	rt := auth.NewRoutes(mux, process, guard, maxBodyBytes, operations(), middlewares...)
	gen.HandlerWithOptions(newAPIServer(h), gen.StdHTTPServerOptions{BaseRouter: rt, ErrorHandlerFunc: requestError})
	err := rt.Err()
	return rt, err
}

func (s apiServer) signIn(w http.ResponseWriter, r *http.Request, serve func(*auth.Handlers, http.ResponseWriter, *http.Request)) {
	if s.auth == nil {
		apierr.WriteError(w, r, apierr.Unavailable(signInUnavailableRetry, "console sign-in is not configured on this instance (ANSP_SESSION_KEY_FILE)"))
		return
	}
	serve(s.auth, w, r)
}

// Login serves POST /v1/auth/login (WP-2).
func (s apiServer) Login(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).Login)
}

// VerifyMfa serves POST /v1/auth/mfa (WP-2).
func (s apiServer) VerifyMfa(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).VerifyMFA)
}

// Logout serves POST /v1/auth/logout (WP-2).
func (s apiServer) Logout(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).Logout)
}

// GetMe serves GET /v1/auth/me (WP-2).
func (s apiServer) GetMe(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).Me)
}

// ListUsers serves GET /v1/users (WP-2).
func (s apiServer) ListUsers(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).Users)
}

// CreateUser serves POST /v1/users (WP-2).
func (s apiServer) CreateUser(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, (*auth.Handlers).AddUser)
}

// ResetUserMfa serves POST /v1/users/{id}/reset-mfa (WP-2); the handler
// reads the bound id from the request's path.
func (s apiServer) ResetUserMfa(w http.ResponseWriter, r *http.Request, _ gen.UserID) {
	s.signIn(w, r, (*auth.Handlers).ResetMFA)
}

// DisableUser serves POST /v1/users/{id}/disable (WP-2).
func (s apiServer) DisableUser(w http.ResponseWriter, r *http.Request, _ gen.UserID) {
	s.signIn(w, r, (*auth.Handlers).Disable)
}

// GetJwks serves GET /.well-known/jwks.json (WP-2).
func (s apiServer) GetJwks(w http.ResponseWriter, r *http.Request) {
	s.signIn(w, r, func(h *auth.Handlers, w http.ResponseWriter, r *http.Request) { h.Keys.ServeHTTP(w, r) })
}

// requestError answers a request the generated code could not bind or
// decode: 413 past the body bound, 400 naming the parameter or the body
// otherwise. The reason is this system's text, never the value sent.
func requestError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		mbe      *http.MaxBytesError
		format   *gen.InvalidParamFormatError
		required *gen.RequiredParamError
		header   *gen.RequiredHeaderError
		many     *gen.TooManyValuesForParamError
		unmarsh  *gen.UnmarshalingParamError
		cookie   *gen.UnescapedCookieParamError
	)
	var p *apierr.Problem
	switch {
	case errors.As(err, &mbe):
		p = apierr.TooLarge(mbe.Limit)
	case errors.As(err, &format):
		p = invalidField(format.ParamName, "is not in the format the operation takes")
	case errors.As(err, &required):
		p = invalidField(required.ParamName, "is required")
	case errors.As(err, &header):
		p = invalidField(header.ParamName, "is required")
	case errors.As(err, &many):
		p = invalidField(many.ParamName, "is given more than once")
	case errors.As(err, &unmarsh):
		p = invalidField(unmarsh.ParamName, "is not in the format the operation takes")
	case errors.As(err, &cookie):
		p = invalidField(cookie.ParamName, "is not a valid cookie value")
	default:
		p = invalidField("body", "is not the JSON document this operation takes")
	}
	apierr.WriteError(w, r, p)
}

func invalidField(field, reason string) *apierr.Problem {
	return apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, "the request is not valid",
		apierr.FieldProblem{Field: field, Reason: reason})
}

// responseError answers an operation that returned an error: 501 for
// gen.Unimplemented, the problem itself for an *apierr.Problem, 500
// without its text otherwise.
func responseError(w http.ResponseWriter, r *http.Request, err error) {
	var ni *gen.NotImplementedError
	if errors.As(err, &ni) {
		apierr.WriteError(w, r, apierr.NotImplemented(ni.Operation))
		return
	}
	apierr.WriteError(w, r, err)
}
