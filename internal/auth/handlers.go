package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// MaxBodyBytes bounds the body of every request of these handlers.
const MaxBodyBytes = 16 << 10

// The operations this package serves (docs/PLAN.md section 6), each
// with its access entry. api/openapi.yaml carries them under the auth
// tag with the same x-auth, and the generated router (Routes) enforces
// the x-auth; a test holds this table and the contract equal, so that a
// change to either alone fails.
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

// Handlers serves the auth and user operations over Accounts; cmd/api
// mounts each method on the generated router under its operation.
type Handlers struct {
	Accounts *Accounts
	Keys     *PublicKeys
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
			return apierr.TooLarge(MaxBodyBytes)
		}
		return refusal(http.StatusBadRequest, SlugInvalidRequest, "the body is not the JSON object this operation takes",
			apierr.FieldProblem{Field: "body", Reason: "not a JSON object of the expected members"})
	}
	if dec.More() {
		return refusal(http.StatusBadRequest, SlugInvalidRequest, "the body holds more than one JSON value",
			apierr.FieldProblem{Field: "body", Reason: "trailing data"})
	}
	return nil
}

// The bounds of the sign-in bodies, as api/openapi.yaml LoginRequest
// and MfaRequest declare them (lengths in characters).
const (
	maxUsernameChars = 64
	maxPasswordChars = 1024
	maxMFATokenChars = 256
)

var mfaCodePattern = regexp.MustCompile(`^[0-9]{6}$`)

// schemaField is the refusal of one member the contract's schema
// refuses: missing or empty (every member here is required with
// minLength 1), or longer than maxChars.
func schemaField(field, v string, maxChars int) *apierr.FieldProblem {
	switch {
	case v == "":
		return &apierr.FieldProblem{Field: field, Reason: "required"}
	case utf8.RuneCountInString(v) > maxChars:
		return &apierr.FieldProblem{Field: field, Reason: "longer than the contract's maximum"}
	}
	return nil
}

// invalidBody is 400 invalid_request naming every field at fault, or
// nil when there is none. The sign-in operations judge their body
// against the contract's schema before any credential, limiter or
// audit (uspace-lab conformance finding C5): a body the schema refuses
// is not a sign-in attempt.
func invalidBody(fields ...*apierr.FieldProblem) error {
	var out []apierr.FieldProblem
	for _, f := range fields {
		if f != nil {
			out = append(out, *f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return refusal(http.StatusBadRequest, SlugInvalidRequest, "the request is not valid", out...)
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

// Login serves POST /v1/auth/login.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	if err := invalidBody(schemaField("username", in.Username, maxUsernameChars),
		schemaField("password", in.Password, maxPasswordChars)); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	res, err := h.Accounts.Login(r.Context(), in.Username, in.Password, requestInfo(r))
	if err != nil {
		apierr.WriteError(w, r, err)
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

// VerifyMFA serves POST /v1/auth/mfa.
func (h *Handlers) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := decode(w, r, &in); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	code := schemaField("code", in.Code, 6)
	if code == nil && !mfaCodePattern.MatchString(in.Code) {
		code = &apierr.FieldProblem{Field: "code", Reason: "not six digits"}
	}
	if err := invalidBody(schemaField("mfa_token", in.MFAToken, maxMFATokenChars), code); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	res, err := h.Accounts.VerifyMFA(r.Context(), in.MFAToken, in.Code, requestInfo(r))
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, mfaResponse{Token: res.Token, TokenType: "Bearer", ExpiresAt: res.ExpiresAt,
		IdleTimeoutS: int64(res.IdleTimeout / time.Second), User: res.User})
}

func principal(r *http.Request) Principal {
	p, _ := PrincipalFrom(r.Context())
	return p
}

// Logout serves POST /v1/auth/logout.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.Accounts.Logout(r.Context(), principal(r)); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Me serves GET /v1/auth/me.
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	me, err := h.Accounts.Me(r.Context(), principal(r))
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

// Users serves GET /v1/users.
func (h *Handlers) Users(w http.ResponseWriter, r *http.Request) {
	us, err := h.Accounts.Users(r.Context())
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us})
}

// AddUser serves POST /v1/users.
func (h *Handlers) AddUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(w, r, &in); err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	u, err := h.Accounts.CreateUser(r.Context(), principal(r), in.Username, in.Password, in.Role)
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

// ResetMFA serves POST /v1/users/{id}/reset-mfa.
func (h *Handlers) ResetMFA(w http.ResponseWriter, r *http.Request) {
	u, err := h.Accounts.ResetMFA(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// Disable serves POST /v1/users/{id}/disable.
func (h *Handlers) Disable(w http.ResponseWriter, r *http.Request) {
	u, err := h.Accounts.Disable(r.Context(), principal(r), r.PathValue("id"))
	if err != nil {
		apierr.WriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}
