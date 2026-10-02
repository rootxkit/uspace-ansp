package apierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rootxkit/uspace-core/core"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Errors == nil {
		t.Fatal("errors is absent; problem/v1 requires it")
	}
	return p
}

// E-10: 101 field errors come back as 100 plus truncated (presence),
// 100 as 100 without truncated (absence).
func TestInvalidCapsAtMaxErrors(t *testing.T) {
	for n, truncated := range map[int]bool{MaxErrors + 1: true, MaxErrors: false, 1: false} {
		errs := make([]*core.FieldError, n)
		for i := range errs {
			errs[i] = core.Fieldf(fmt.Sprintf("features[%d].properties.type", i), "is not a zone type")
		}
		p := Invalid(errs...)
		if len(p.Errors) != min(n, MaxErrors) || p.Truncated != truncated || p.Status != http.StatusBadRequest || p.Slug() != SlugInvalidRequest {
			t.Fatalf("%d errors: %d kept, truncated %v", n, len(p.Errors), p.Truncated)
		}
		rec := httptest.NewRecorder()
		Write(rec, p.Status, p)
		got := decode(t, rec)
		if len(got.Errors) != min(n, MaxErrors) || got.Truncated != truncated || strings.Contains(rec.Body.String(), `"truncated":false`) {
			t.Fatalf("%d errors written: %s", n, rec.Body.String())
		}
	}
	// A joined tree past the cap, nested deeper than any stack would
	// like, is flattened and capped too.
	var err error
	for i := range 1000 {
		err = errors.Join(err, core.Fieldf(strconv.Itoa(i), "bad"))
	}
	if p := FromError(err); len(p.Errors) != MaxErrors || !p.Truncated {
		t.Fatalf("joined: %d %v", len(p.Errors), p.Truncated)
	}
	if p := Invalid(nil, core.Fieldf("a", "b")); len(p.Errors) != 1 {
		t.Fatal("a nil field error was kept")
	}
}

// Every constructor's status is in Statuses, every status of Statuses
// has a constructor, and each sets the problem/v1 type.
func TestConstructors(t *testing.T) {
	made := map[int]*Problem{}
	for _, p := range []*Problem{
		Invalid(core.Fieldf("a", "b")), Unauthenticated("no token"), Forbidden("ansp.traffic"), Forbidden(""),
		NotFound("no such restriction"), Conflict("already active"), TooLarge(1 << 20), UnsupportedMediaType("application/jose"),
		UpgradeRequired(), RateLimited(time.Second), Internal(), NotImplemented("listAdapters"), Unavailable(time.Second, "nats"),
	} {
		if !strings.HasPrefix(p.Type, TypeBase) || p.Slug() == "" || p.Title != http.StatusText(p.Status) {
			t.Fatalf("%+v", p)
		}
		made[p.Status] = p
	}
	for _, s := range Statuses() {
		if made[s] == nil {
			t.Fatalf("status %d has no constructor", s)
		}
	}
	if len(made) != len(Statuses()) {
		t.Fatalf("constructors make %d statuses, Statuses lists %d", len(made), len(Statuses()))
	}
	if p := Forbidden("ansp.traffic"); p.Errors[0] != (FieldProblem{Field: "scope", Reason: "missing ansp.traffic"}) {
		t.Fatalf("%+v", p.Errors)
	}
}

// Every error status api/openapi.yaml declares has a constructor here.
func TestEveryContractStatusHasAConstructor(t *testing.T) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			for code, resp := range op.Responses.Map() {
				status, err := strconv.Atoi(code)
				if err != nil || status < 400 {
					continue
				}
				if resp.Value == nil || resp.Value.Content.Get("application/problem+json") == nil {
					continue // the readiness report of /readyz
				}
				seen++
				if !slices.Contains(Statuses(), status) {
					t.Errorf("%s %s declares %d, which no apierr constructor makes", method, path, status)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no error response read from the contract")
	}
}

// A 429 or 503 always carries Retry-After, at least one second; other
// statuses carry none unless asked.
func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		p    *Problem
		want string
	}{
		{RateLimited(1500 * time.Millisecond), "2"},
		{Unavailable(0, "kv"), "1"},
		{New(http.StatusTooManyRequests, SlugRateLimited, "x"), "1"},
		{NotFound("x"), ""},
	} {
		rec := httptest.NewRecorder()
		Write(rec, tc.p.Status, tc.p)
		if got := rec.Header().Get("Retry-After"); got != tc.want || rec.Code != tc.p.Status {
			t.Fatalf("%d: Retry-After %q, want %q", tc.p.Status, got, tc.want)
		}
		if strings.Contains(rec.Body.String(), "RetryAfter") || strings.Contains(rec.Body.String(), "retry") && tc.want == "" {
			t.Fatalf("retry leaked into the body: %s", rec.Body.String())
		}
	}
}

// An error that is not a refusal is 500 without its text; the instance
// is the path without the query; a field error tree is 400.
func TestWriteError(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/x?token=secret-value", nil)
	r.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	WriteError(rec, r, errors.New("pq: relation users does not exist"))
	p := decode(t, rec)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "relation") || p.Instance != "/v1/x" ||
		strings.Contains(rec.Body.String(), "secret") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	WriteError(rec, r, fmt.Errorf("wrapped: %w", errors.Join(core.Fieldf("a", "b"), core.Fieldf("c", "d"))))
	if p := decode(t, rec); rec.Code != http.StatusBadRequest || len(p.Errors) != 2 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	WriteError(rec, r, fmt.Errorf("wrapped: %w", Conflict("taken")))
	if p := decode(t, rec); rec.Code != http.StatusConflict || p.Detail != "taken" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	WriteError(rec, r, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	Write(rec, http.StatusOK, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a nil problem: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	Write(rec, http.StatusOK, NotFound("x"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a success status is not a problem: %d", rec.Code)
	}
}

// A slug outside the problem/v1 grammar is written as internal; every
// written member is bounded and valid UTF-8 (E-10).
func TestBounds(t *testing.T) {
	if p := New(http.StatusConflict, "Bad-Slug", "x"); p.Slug() != SlugInternal || p.Status != http.StatusInternalServerError {
		t.Fatalf("%+v", p)
	}
	if p := New(200, SlugConflict, "x"); p.Status != http.StatusInternalServerError {
		t.Fatalf("%+v", p)
	}
	long := strings.Repeat("é", MaxDetailBytes)
	p := New(http.StatusBadRequest, SlugInvalidRequest, long+"\xff", FieldProblem{Field: long, Reason: long})
	if len(p.Detail) > MaxDetailBytes || len(p.Errors[0].Field) > MaxFieldBytes || len(p.Errors[0].Reason) > MaxReasonBytes {
		t.Fatalf("unbounded: %d %d %d", len(p.Detail), len(p.Errors[0].Field), len(p.Errors[0].Reason))
	}
	rec := httptest.NewRecorder()
	Write(rec, p.Status, p)
	if !json.Valid(rec.Body.Bytes()) || strings.Contains(rec.Body.String(), "���") {
		t.Fatalf("not valid JSON or broken UTF-8: %q", rec.Body.String()[:40])
	}
	if p := New(http.StatusBadRequest, SlugInvalidRequest, "ok\xff"); p.Detail != "ok�" {
		t.Fatalf("%q", p.Detail)
	}
	if (&Problem{Type: "https://example.test/x"}).Slug() != "" || NotFound("d").Error() != "not_found: d" {
		t.Fatal("slug")
	}
	r := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("a", 2*MaxFieldBytes), nil)
	if p := NotFound("x").At(r); len(p.Instance) > MaxFieldBytes {
		t.Fatal("instance unbounded")
	}
	if p := NotFound("x").At(nil); p.Instance != "" {
		t.Fatal("nil request")
	}
}

func BenchmarkInvalid(b *testing.B) {
	errs := make([]*core.FieldError, 150)
	for i := range errs {
		errs[i] = core.Fieldf("f", "r")
	}
	for b.Loop() {
		_ = Invalid(errs...)
	}
}
