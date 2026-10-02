package auth

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// ProblemTypeBase is the prefix of every problem type (M28).
const ProblemTypeBase = "https://schemas.uspace.ge/problems/"

// Problem slugs of this package beside core's token counters, which are
// the slug of a refused token (rejected_audience, rejected_expired, ...).
const (
	SlugUnauthenticated    = "unauthenticated"
	SlugForbidden          = "forbidden"
	SlugMTLSRequired       = "mtls_required"
	SlugMTLSMismatch       = "mtls_mismatch"
	SlugRateLimited        = "rate_limited"
	SlugInvalidCredentials = "invalid_credentials" //nolint:gosec // a problem slug, not a credential
	SlugMFARefused         = "mfa_refused"
	SlugAccountLocked      = "account_locked"
	SlugSessionRefused     = "session_refused"
	SlugInvalidRequest     = "invalid_request"
	SlugNotFound           = "not_found"
	SlugConflict           = "conflict"
	SlugUnavailable        = "unavailable"
	SlugInternal           = "internal"
)

// MaxProblemErrors caps the errors of a problem; beyond it truncated is
// set (M28).
const MaxProblemErrors = 100

// FieldReason is one entry of a problem's errors.
type FieldReason struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// ProblemBody is the ecosystem's one error body (RFC 9457, M28).
type ProblemBody struct {
	Type      string        `json:"type"`
	Title     string        `json:"title"`
	Status    int           `json:"status"`
	Detail    string        `json:"detail,omitempty"`
	Instance  string        `json:"instance,omitempty"`
	Errors    []FieldReason `json:"errors"`
	Truncated bool          `json:"truncated,omitempty"`
}

// Slug is the last path segment of Type.
func (p *ProblemBody) Slug() string {
	if len(p.Type) > len(ProblemTypeBase) {
		return p.Type[len(ProblemTypeBase):]
	}
	return ""
}

// Error is a refusal this package answers as a problem: status, slug,
// detail, the fields at fault and, for a 429 or 503, how long to wait.
// It never carries a credential.
type Error struct {
	Status     int
	Slug       string
	Detail     string
	Fields     []FieldReason
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Slug + ": " + e.Detail }

func refusal(status int, slug, detail string, fields ...FieldReason) *Error {
	return &Error{Status: status, Slug: slug, Detail: detail, Fields: fields}
}

// fieldsOf turns a joined *core.FieldError tree into problem fields.
func fieldsOf(err error) []FieldReason {
	var out []FieldReason
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, e := range joined.Unwrap() {
			out = append(out, fieldsOf(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		out = append(out, FieldReason{Field: fe.Field, Reason: fe.Reason})
	}
	return out
}

// WriteProblem writes a problem with status, slug and detail; r names
// the instance (the path, never the query, which may carry a value the
// caller did not mean to log).
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, slug, detail string, fields []FieldReason, retryAfter time.Duration) {
	body := ProblemBody{
		Type: ProblemTypeBase + slug, Title: http.StatusText(status), Status: status, Detail: detail, Errors: []FieldReason{},
	}
	if r != nil && r.URL != nil {
		body.Instance = r.URL.Path
	}
	if len(fields) > MaxProblemErrors {
		fields, body.Truncated = fields[:MaxProblemErrors], true
	}
	body.Errors = append(body.Errors, fields...)
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retryAfter.Seconds())))))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError answers err: an *Error as itself, a field error tree as 400
// invalid_request, anything else as 500 without its text (which may name
// a table or a value).
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	if errors.As(err, &e) {
		WriteProblem(w, r, e.Status, e.Slug, e.Detail, e.Fields, e.RetryAfter)
		return
	}
	if fields := fieldsOf(err); len(fields) > 0 {
		WriteProblem(w, r, http.StatusBadRequest, SlugInvalidRequest, "the request is not valid", fields, 0)
		return
	}
	WriteProblem(w, r, http.StatusInternalServerError, SlugInternal, "the request could not be completed", nil, 0)
}
