package apierr

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
)

// TypeBase is the prefix of every problem type (M28).
const TypeBase = "https://schemas.uspace.ge/problems/"

// Bounds of a written problem (E-10).
const (
	// MaxErrors caps errors; beyond it the rest is dropped and Truncated
	// is set (M28).
	MaxErrors = 100
	// MaxDetailBytes bounds detail.
	MaxDetailBytes = 1024
	// MaxFieldBytes bounds one field path.
	MaxFieldBytes = 256
	// MaxReasonBytes bounds one reason.
	MaxReasonBytes = 512
)

// The generic slugs. A package adds its own refusal names (the auth
// package's invalid_credentials, core's rejected_audience, ...).
const (
	SlugInvalidRequest       = "invalid_request"
	SlugUnauthenticated      = "unauthenticated"
	SlugForbidden            = "forbidden"
	SlugNotFound             = "not_found"
	SlugConflict             = "conflict"
	SlugBodyTooLarge         = "body_too_large"
	SlugUnsupportedMediaType = "unsupported_media_type"
	SlugUpgradeRequired      = "upgrade_required"
	SlugRateLimited          = "rate_limited"
	SlugInternal             = "internal"
	SlugNotImplemented       = "not_implemented"
	SlugUnavailable          = "unavailable"
)

// slugPattern is the slug grammar of problem/v1 ([a-z_]+).
var slugPattern = regexp.MustCompile(`^[a-z][a-z_]*$`)

// FieldProblem is one entry of a problem's errors: the JSON path (as
// core.FieldError and ed269.Problems write it) or the parameter or
// header name at fault, and why.
type FieldProblem struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Problem is the ecosystem's one error body (RFC 9457, M28). It is an
// error, so a package can return it and the handler write it as is.
type Problem struct { //nolint:errname // the brief and the ecosystem name the body Problem
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	Instance  string         `json:"instance,omitempty"`
	Errors    []FieldProblem `json:"errors"`
	Truncated bool           `json:"truncated,omitempty"`
	// RetryAfter is sent as the Retry-After header; never in the body.
	RetryAfter time.Duration `json:"-"`
}

// Error is "slug: detail".
func (p *Problem) Error() string { return p.Slug() + ": " + p.Detail }

// Slug is the last path segment of Type.
func (p *Problem) Slug() string {
	if len(p.Type) > len(TypeBase) && p.Type[:len(TypeBase)] == TypeBase {
		return p.Type[len(TypeBase):]
	}
	return ""
}

// At sets the instance to the request's path (never the query, which
// may carry a value the caller did not mean to log) and returns p.
func (p *Problem) At(r *http.Request) *Problem {
	if r != nil && r.URL != nil {
		p.Instance = cut(r.URL.Path, MaxFieldBytes)
	}
	return p
}

// New is a problem with status, slug, detail and field problems, bounded
// as the package says. A slug outside the problem/v1 grammar is a bug
// in the caller and is written as internal (fail closed, never a type
// the schema refuses).
func New(status int, slug, detail string, errs ...FieldProblem) *Problem {
	if !slugPattern.MatchString(slug) {
		slug, status = SlugInternal, http.StatusInternalServerError
	}
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	p := &Problem{Type: TypeBase + slug, Title: http.StatusText(status), Status: status, Detail: cut(detail, MaxDetailBytes), Errors: []FieldProblem{}}
	p.add(errs)
	return p
}

func (p *Problem) add(errs []FieldProblem) {
	for _, e := range errs {
		if len(p.Errors) == MaxErrors {
			p.Truncated = true
			return
		}
		p.Errors = append(p.Errors, FieldProblem{Field: cut(e.Field, MaxFieldBytes), Reason: cut(e.Reason, MaxReasonBytes)})
	}
}

// Invalid is 400 invalid_request listing errs (nil entries skipped),
// capped at MaxErrors with truncated set.
func Invalid(errs ...*core.FieldError) *Problem {
	fields := make([]FieldProblem, 0, min(len(errs), MaxErrors+1))
	for _, e := range errs {
		if e == nil {
			continue
		}
		fields = append(fields, FieldProblem{Field: e.Field, Reason: e.Reason})
		if len(fields) > MaxErrors {
			break
		}
	}
	return New(http.StatusBadRequest, SlugInvalidRequest, "the request is not valid", fields...)
}

// NotFound is 404 not_found.
func NotFound(detail string) *Problem { return New(http.StatusNotFound, SlugNotFound, detail) }

// Conflict is 409 conflict.
func Conflict(detail string) *Problem { return New(http.StatusConflict, SlugConflict, detail) }

// Unauthenticated is 401 unauthenticated.
func Unauthenticated(detail string) *Problem {
	return New(http.StatusUnauthorized, SlugUnauthenticated, detail)
}

// Forbidden is 403 forbidden for a caller whose token lacks scope; an
// empty scope is a refusal that names none.
func Forbidden(scope string) *Problem {
	if scope == "" {
		return New(http.StatusForbidden, SlugForbidden, "the caller may not perform this operation")
	}
	return New(http.StatusForbidden, SlugForbidden, "the token does not grant a scope this operation requires",
		FieldProblem{Field: "scope", Reason: "missing " + scope})
}

// TooLarge is 413 body_too_large for a body over limit bytes.
func TooLarge(limit int64) *Problem {
	return New(http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "the body is larger than "+strconv.FormatInt(limit, 10)+" bytes",
		FieldProblem{Field: "body", Reason: "larger than " + strconv.FormatInt(limit, 10) + " bytes"})
}

// UnsupportedMediaType is 415 for a body that is not want.
func UnsupportedMediaType(want string) *Problem {
	return New(http.StatusUnsupportedMediaType, SlugUnsupportedMediaType, "the body must be "+want,
		FieldProblem{Field: "Content-Type", Reason: "must be " + want})
}

// UpgradeRequired is 426 for a plain GET on a WebSocket endpoint.
func UpgradeRequired() *Problem {
	return New(http.StatusUpgradeRequired, SlugUpgradeRequired, "this endpoint is a WebSocket upgrade",
		FieldProblem{Field: "Upgrade", Reason: "must be websocket"})
}

// RateLimited is 429 rate_limited; Retry-After says when to come back.
func RateLimited(retryAfter time.Duration) *Problem {
	p := New(http.StatusTooManyRequests, SlugRateLimited, "too many requests; retry later")
	p.RetryAfter = retryAfter
	return p
}

// Unavailable is 503 unavailable: a dependency cannot answer now;
// Retry-After says when to come back.
func Unavailable(retryAfter time.Duration, detail string) *Problem {
	p := New(http.StatusServiceUnavailable, SlugUnavailable, detail)
	p.RetryAfter = retryAfter
	return p
}

// Internal is 500 internal, with no detail of the cause.
func Internal() *Problem {
	return New(http.StatusInternalServerError, SlugInternal, "the request could not be completed")
}

// NotImplemented is 501 not_implemented: the operation is in the
// contract and a later work package serves it.
func NotImplemented(operation string) *Problem {
	return New(http.StatusNotImplemented, SlugNotImplemented, operation+" is in the contract and not served yet")
}

// Statuses are the HTTP statuses the constructors above produce; every
// error status api/openapi.yaml declares is one of them (a test holds
// the two together).
func Statuses() []int {
	return []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType,
		http.StatusUpgradeRequired, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusNotImplemented, http.StatusServiceUnavailable,
	}
}

// FromError is err as a problem: a *Problem as itself, a *core.FieldError
// or a joined tree of them as Invalid, anything else as Internal (its
// text is not written).
func FromError(err error) *Problem {
	if err == nil {
		return Internal()
	}
	var p *Problem
	if errors.As(err, &p) && p != nil {
		return p
	}
	if fields := fieldErrors(err, nil); len(fields) > 0 {
		return Invalid(fields...)
	}
	return Internal()
}

// maxWalk bounds the errors fieldErrors visits in one tree.
const maxWalk = 100_000

// fieldErrors flattens a tree of *core.FieldError (joined with
// errors.Join, wrapped with %w), stopping past MaxErrors (Invalid then
// sets truncated). The walk is iterative and bounded: the depth and
// size of a tree are not trusted.
func fieldErrors(err error, out []*core.FieldError) []*core.FieldError {
	stack := []error{err}
	for steps := 0; len(stack) > 0 && len(out) <= MaxErrors && steps < maxWalk; steps++ {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if fe, ok := e.(*core.FieldError); ok { //nolint:errorlint // this walk unwraps each level itself
			if fe != nil {
				out = append(out, fe)
			}
			continue
		}
		switch u := e.(type) { //nolint:errorlint // this walk unwraps each level itself
		case interface{ Unwrap() []error }:
			kids := u.Unwrap()
			for i := len(kids) - 1; i >= 0; i-- {
				if kids[i] != nil {
					stack = append(stack, kids[i])
				}
			}
		case interface{ Unwrap() error }:
			if kid := u.Unwrap(); kid != nil {
				stack = append(stack, kid)
			}
		}
	}
	return out
}

// Write writes p with status (p.Status is set to it; a nil p is written
// as internal). A 429 or 503 always carries Retry-After, at least one
// second.
func Write(w http.ResponseWriter, status int, p *Problem) {
	if p == nil {
		p = Internal()
		status = p.Status
	}
	if status < 400 || status > 599 {
		status = http.StatusInternalServerError
	}
	p.Status, p.Title = status, http.StatusText(status)
	if p.Errors == nil {
		p.Errors = []FieldProblem{}
	}
	if p.RetryAfter > 0 || status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		secs := max(1, int(math.Ceil(p.RetryAfter.Seconds())))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteError answers err (FromError) with r's path as the instance.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	p := FromError(err)
	if p.Instance == "" {
		_ = p.At(r)
	}
	Write(w, p.Status, p)
}

// cut bounds s to limit bytes at a UTF-8 boundary, and replaces invalid
// UTF-8 so that the body always encodes as written.
func cut(s string, limit int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if len(s) <= limit {
		return s
	}
	i := limit
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
