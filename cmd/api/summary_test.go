package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// supervisorReq is a GET of a watch supervisor's session (the guard's
// principal, as the router sets it).
func supervisorReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	return r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Session: true, Role: auth.RoleWatchSupervisor,
		Claims: coreauth.Claims{Subject: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z"}}))
}

// pendingRepo holds requests awaiting a decision and their counts, and
// records the limit it was asked for.
type pendingRepo struct {
	restriction.Repo
	list   []restriction.Request
	more   bool
	counts restriction.RequestCounts
	err    error
	limit  int
}

func (p *pendingRepo) PendingRequests(_ context.Context, limit int) ([]restriction.Request, bool, error) {
	p.limit = limit
	return p.list, p.more, p.err
}

func (p *pendingRepo) PendingRequestCounts(_ context.Context, limit int) (restriction.RequestCounts, error) {
	p.limit = limit
	return p.counts, p.err
}

// Every summary and the request list refuse no credential 401 and a
// machine token 403 at the router, before the handler (session-only
// rules; the integration test runs each role).
func TestSummariesRefuseWithoutTheirSession(t *testing.T) {
	_, h := testServer(t, nil)
	for _, path := range []string{"/v1/restriction-requests", "/v1/restriction-requests/summary"} {
		if a := call(t, h, http.MethodGet, path, "", "", ""); a.code != http.StatusUnauthorized || a.problem.Slug() != apierr.SlugUnauthenticated {
			t.Errorf("%s without a credential: %d %+v", path, a.code, a.problem)
		}
		if a := call(t, h, http.MethodGet, path, "scopes:ansp.requests", "", ""); a.code != http.StatusForbidden || a.problem.Slug() != apierr.SlugForbidden {
			t.Errorf("%s with a machine token: %d %+v", path, a.code, a.problem)
		}
	}
}

// GET /v1/restriction-requests: the requests awaiting a decision in the
// contract's shape, the default and the given limit passed on, a limit
// outside the contract's bounds 400, a store failure 500 without its
// text, no database 503.
func TestListRestrictionRequests(t *testing.T) {
	at := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	repo := &pendingRepo{list: []restriction.Request{
		{ID: "01K6P1R2S3T4V5W6X7Y8Z9A0BC", Requester: "authority-01", Source: restriction.SourceAuthority, ReceivedAt: at, State: restriction.RequestReceived},
		{ID: "01K6P1R2S3T4V5W6X7Y8Z9A0BD", Requester: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z", Source: restriction.SourceConsole, ReceivedAt: at.Add(time.Minute), State: restriction.RequestReceived},
	}, more: true}
	s := apiServer{rs: &restrictionAPI{svc: &restriction.Service{Repo: repo}}}
	rec := httptest.NewRecorder()
	s.ListRestrictionRequests(rec, supervisorReq("/v1/restriction-requests"), gen.ListRestrictionRequestsParams{})
	if rec.Code != http.StatusOK || repo.limit != restriction.DefaultPendingRequestsListed {
		t.Fatalf("%d limit %d %s", rec.Code, repo.limit, rec.Body)
	}
	validateResponse(t, http.MethodGet, "/v1/restriction-requests", rec.Code, rec.Body.Bytes())
	var got struct {
		Requests  []map[string]any `json:"requests"`
		Truncated bool             `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Requests) != 2 || !got.Truncated ||
		got.Requests[0]["received_at"] != "2026-10-02T11:00:00.000Z" || got.Requests[1]["source"] != "console" {
		t.Fatalf("%s %v", rec.Body, err)
	}
	if strings.Contains(rec.Body.String(), "payload") {
		t.Fatalf("the list carries a payload: %s", rec.Body)
	}
	five := 5
	rec = httptest.NewRecorder()
	s.ListRestrictionRequests(rec, supervisorReq("/v1/restriction-requests?limit=5"), gen.ListRestrictionRequestsParams{Limit: &five})
	if rec.Code != http.StatusOK || repo.limit != 5 {
		t.Fatalf("limit 5: %d %d", rec.Code, repo.limit)
	}
	for _, bad := range []int{0, restriction.MaxPendingRequestsListed + 1} {
		rec = httptest.NewRecorder()
		s.ListRestrictionRequests(rec, supervisorReq("/v1/restriction-requests"), gen.ListRestrictionRequestsParams{Limit: &bad})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"field":"limit"`) {
			t.Fatalf("limit %d: %d %s", bad, rec.Code, rec.Body)
		}
	}
	repo.err = errors.New("pq: secret detail")
	rec = httptest.NewRecorder()
	s.ListRestrictionRequests(rec, supervisorReq("/v1/restriction-requests"), gen.ListRestrictionRequestsParams{})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("store down: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	apiServer{}.ListRestrictionRequests(rec, supervisorReq("/v1/restriction-requests"), gen.ListRestrictionRequestsParams{})
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("no database: %d", rec.Code)
	}
}

// GET /v1/restriction-requests/summary: the count, the oldest one's
// time and truncated in the contract's shape, read with
// MaxPendingRequestsCounted; none waiting is 0 with a null oldest; a
// store failure 500, no database 503.
func TestRestrictionRequestSummary(t *testing.T) {
	at := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	repo := &pendingRepo{counts: restriction.RequestCounts{CountedAt: at.Add(time.Hour), Received: 2, OldestReceivedAt: &at, Truncated: true}}
	s := apiServer{rs: &restrictionAPI{svc: &restriction.Service{Repo: repo}}}
	rec := httptest.NewRecorder()
	s.GetRestrictionRequestSummary(rec, supervisorReq("/v1/restriction-requests/summary"))
	want := `{"counted_at":"2026-10-02T12:00:00.000Z","received":2,"oldest_received_at":"2026-10-02T11:00:00.000Z","truncated":true}`
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != want || repo.limit != restriction.MaxPendingRequestsCounted {
		t.Fatalf("%d limit %d %s", rec.Code, repo.limit, rec.Body)
	}
	validateResponse(t, http.MethodGet, "/v1/restriction-requests/summary", rec.Code, rec.Body.Bytes())
	repo.counts = restriction.RequestCounts{CountedAt: at}
	rec = httptest.NewRecorder()
	s.GetRestrictionRequestSummary(rec, supervisorReq("/v1/restriction-requests/summary"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"received":0,"oldest_received_at":null`) {
		t.Fatalf("none: %d %s", rec.Code, rec.Body)
	}
	validateResponse(t, http.MethodGet, "/v1/restriction-requests/summary", rec.Code, rec.Body.Bytes())
	repo.err = errors.New("pq: secret detail")
	rec = httptest.NewRecorder()
	s.GetRestrictionRequestSummary(rec, supervisorReq("/v1/restriction-requests/summary"))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("store down: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	apiServer{}.GetRestrictionRequestSummary(rec, supervisorReq("/v1/restriction-requests/summary"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no database: %d", rec.Code)
	}
}
