package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// MaxBodyBytes bounds the body of every request of these handlers.
const MaxBodyBytes = 16 << 10

// The operations this package serves (docs/PLAN.md section 6), each
// with its access entry. WP-3's api/openapi.yaml carries them under the
// auth tag with the same x-auth; the generated router replaces these
// patterns and keeps the table.
const (
	OpLogin    = "POST /v1/auth/login"
	OpMFA      = "POST /v1/auth/mfa"
	OpLogout   = "POST /v1/auth/logout"
	OpMe       = "GET /v1/auth/me"
	OpUsers    = "GET /v1/users"
	OpAddUser  = "POST /v1/users"
	OpResetMFA = "POST /v1/users/{id}/reset-mfa"
	OpDisable  = "POST /v1/users/{id}/disable"
	OpJWKS     = "GET /.well-known/jwks.json"
)

// AccessTable is the access entry of every operation above. Sign-in and
// the JWKS are public; everything else needs a console session.
func AccessTable() map[string]Access {
	return map[string]Access{
		OpLogin:    {Public: true},
		OpMFA:      {Public: true},
		OpLogout:   {AnyRole: true},
		OpMe:       {AnyRole: true},
		OpUsers:    {Roles: []string{RoleAdmin}},
		OpAddUser:  {Roles: []string{RoleAdmin}},
		OpResetMFA: {Roles: []string{RoleAdmin}},
		OpDisable:  {Roles: []string{RoleAdmin}},
		OpJWKS:     {Public: true},
	}
}

// Routes registers operations on a ServeMux only through their entry in
// an access table, so every route fails closed: a pattern without an
// entry is not served and is an error, an invalid entry is an error,
// and an entry no pattern used is an error (a renamed path must not
// leave its protection behind). The process refuses to start on Err.
type Routes struct {
	mux   *http.ServeMux
	table map[string]Access
	guard *Guard
	used  map[string]bool
	errs  []error
}

// NewRoutes wraps mux with table enforced by guard.
func NewRoutes(mux *http.ServeMux, table map[string]Access, guard *Guard) *Routes {
	return &Routes{mux: mux, table: table, guard: guard, used: map[string]bool{}}
}

// Handle registers h under pattern behind its access entry, or records
// why it cannot.
func (rt *Routes) Handle(pattern string, h http.Handler) {
	a, ok := rt.table[pattern]
	if !ok {
		rt.errs = append(rt.errs, fmt.Errorf("%s has no access entry; the route is not served", pattern))
		return
	}
	rt.used[pattern] = true
	if err := a.Validate(); err != nil {
		rt.errs = append(rt.errs, fmt.Errorf("%s: access %w", pattern, err))
		return
	}
	rt.mux.Handle(pattern, rt.guard.Require(a)(h))
}

// Err is every problem found, including entries no pattern used.
func (rt *Routes) Err() error {
	errs := slices.Clone(rt.errs)
	var unused []string
	for p := range rt.table {
		if !rt.used[p] {
			unused = append(unused, p)
		}
	}
	slices.Sort(unused)
	for _, p := range unused {
		errs = append(errs, fmt.Errorf("access entry %s matches no route", p))
	}
	return errors.Join(errs...)
}

// Handlers serves the auth and user operations over Accounts.
type Handlers struct {
	Accounts *Accounts
	Keys     *PublicKeys
}

// Mount registers every operation of AccessTable on rt.
func (h *Handlers) Mount(rt *Routes) {
	rt.Handle(OpLogin, http.HandlerFunc(h.login))
	rt.Handle(OpMFA, http.HandlerFunc(h.mfa))
	rt.Handle(OpLogout, http.HandlerFunc(h.logout))
	rt.Handle(OpMe, http.HandlerFunc(h.me))
	rt.Handle(OpUsers, http.HandlerFunc(h.users))
	rt.Handle(OpAddUser, http.HandlerFunc(h.addUser))
	rt.Handle(OpResetMFA, http.HandlerFunc(h.resetMFA))
	rt.Handle(OpDisable, http.HandlerFunc(h.disable))
	rt.Handle(OpJWKS, h.Keys)
}

func requestInfo(r *http.Request) RequestInfo {
	return RequestInfo{RemoteIP: RemoteIP(r), UserAgent: r.UserAgent()}
}

// decode reads a bounded JSON object into v; unknown members are
// ignored (02 section 1).
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return refusal(http.StatusRequestEntityTooLarge, SlugInvalidRequest, fmt.Sprintf("the body is larger than %d bytes", MaxBodyBytes))
		}
		return refusal(http.StatusBadRequest, SlugInvalidRequest, "the body is not the JSON object this operation takes",
			FieldReason{Field: "body", Reason: "not a JSON object of the expected members"})
	}
	if dec.More() {
		return refusal(http.StatusBadRequest, SlugInvalidRequest, "the body holds more than one JSON value",
			FieldReason{Field: "body", Reason: "trailing data"})
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type enrolmentBody struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

type loginResponse struct {
	MFAToken  string         `json:"mfa_token"`
	ExpiresAt time.Time      `json:"expires_at"`
	Enrolment *enrolmentBody `json:"enrolment,omitempty"`
}

func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		WriteError(w, r, err)
		return
	}
	res, err := h.Accounts.Login(r.Context(), in.Username, in.Password, requestInfo(r))
	if err != nil {
		WriteError(w, r, err)
		return
	}
	out := loginResponse{MFAToken: res.MFAToken, ExpiresAt: res.ExpiresAt.UTC()}
	if res.Enrolment != nil {
		out.Enrolment = &enrolmentBody{Secret: res.Enrolment.Secret, OTPAuthURI: res.Enrolment.OTPAuthURI}
	}
	writeJSON(w, http.StatusOK, out)
}

type mfaResponse struct {
	Token        string    `json:"token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	IdleTimeoutS int64     `json:"idle_timeout_s"`
	User         UserView  `json:"user"`
}

func (h *Handlers) mfa(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &in); err != nil {
		WriteError(w, r, err)
		return
	}
	res, err := h.Accounts.VerifyMFA(r.Context(), in.MFAToken, in.Code, requestInfo(r))
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, mfaResponse{Token: res.Token, TokenType: "Bearer", ExpiresAt: res.ExpiresAt,
		IdleTimeoutS: int64(res.IdleTimeout / time.Second), User: res.User})
}

func principal(r *http.Request) Principal {
	p, _ := PrincipalFrom(r.Context())
	return p
}

func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.Accounts.Logout(r.Context(), principal(r)); err != nil {
		WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) me(w http.ResponseWriter, r *http.Request) {
	me, err := h.Accounts.Me(r.Context(), principal(r))
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

func (h *Handlers) users(w http.ResponseWriter, r *http.Request) {
	us, err := h.Accounts.Users(r.Context())
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us})
}

func (h *Handlers) addUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(w, r, &in); err != nil {
		WriteError(w, r, err)
		return
	}
	u, err := h.Accounts.CreateUser(r.Context(), principal(r), in.Username, in.Password, in.Role)
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (h *Handlers) resetMFA(w http.ResponseWriter, r *http.Request) {
	u, err := h.Accounts.ResetMFA(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handlers) disable(w http.ResponseWriter, r *http.Request) {
	u, err := h.Accounts.Disable(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}
