package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/feed"
)

// feedReply is manned-feed's reply as it writes it (json of
// feed.Service.Summary).
const feedReply = `{"counted_at":"2026-10-16T10:00:00.000Z","total":2,"by_state":{"live":2,"stale":0,"source_disabled":0},` +
	`"relevant":1,"max_aircraft":5000,"relevance":"relevance: CIS version 42, 3 volumes, age 12 s","degraded":[],"policy_version":"1"}`

func summaryReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/summary", nil)
	return r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Session: true, Role: auth.RoleViewer,
		Claims: coreauth.Claims{Subject: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z"}}))
}

// GET /v1/manned-traffic/summary on api: a console session is answered
// manned-feed's count in the contract's shape, asked on the bus within
// the bound (E-01: the count first); every way the count is not known
// is 503 naming why with Retry-After, counted, never a 401 (which the
// console would read as its session refused); a reply that is not the
// summary is never served; a caller that is not a session is 401.
func TestMannedSummaryOnAPI(t *testing.T) {
	asked := 0
	a := &mannedSummaryAPI{ask: func(ctx context.Context) ([]byte, error) {
		asked++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the request is not bounded")
		}
		return []byte(feedReply), nil
	}}
	rec := httptest.NewRecorder()
	apiServer{ms: a}.GetMannedTrafficSummary(rec, summaryReq())
	if rec.Code != http.StatusOK || asked != 1 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d asked %d %s", rec.Code, asked, rec.Body)
	}
	validateResponse(t, http.MethodGet, "/v1/manned-traffic/summary", http.StatusOK, rec.Body.Bytes())
	var s feed.MannedSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil || s.Total != 2 || s.Relevant != 1 {
		t.Fatalf("%+v %v", s, err)
	}

	for _, tc := range []struct {
		name   string
		err    error
		reply  string
		detail string
		count  string
	}{
		{"no bus", bus.ErrNoBus, "", "ANSP_NATS_URL", counterMannedSummaryUnanswered},
		{"no manned-feed", nats.ErrNoResponders, "", "no responder", counterMannedSummaryUnanswered},
		{"no answer in time", context.DeadlineExceeded, "", "did not answer within", counterMannedSummaryUnanswered},
		{"the bus failed", errors.New("nats: connection closed"), "", "could not carry", counterMannedSummaryUnanswered},
		{"not the summary", nil, `{"icao24":"4ca7b5"}`, "not the picture's count", counterMannedSummaryRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &mannedSummaryAPI{ask: func(context.Context) ([]byte, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return []byte(tc.reply), nil
			}}
			rec := httptest.NewRecorder()
			apiServer{ms: a}.GetMannedTrafficSummary(rec, summaryReq())
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" ||
				!strings.Contains(rec.Body.String(), tc.detail) || !strings.Contains(rec.Body.String(), apierr.SlugUnavailable) {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "4ca7b5") || strings.Contains(rec.Body.String(), "connection closed") {
				t.Fatalf("the problem echoes the reply or the bus: %s", rec.Body)
			}
			if a.counters.Get(tc.count) != 1 {
				t.Fatalf("%s not counted", tc.count)
			}
			validateResponse(t, http.MethodGet, "/v1/manned-traffic/summary", http.StatusServiceUnavailable, rec.Body.Bytes())
		})
	}

	// A machine principal reaching the handler (the router refuses it
	// first) is not a console session.
	r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/summary", nil)
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Claims: coreauth.Claims{Subject: "ussp-01"}}))
	rec = httptest.NewRecorder()
	apiServer{ms: a}.GetMannedTrafficSummary(rec, r)
	if rec.Code != http.StatusUnauthorized || asked != 1 {
		t.Fatalf("machine: %d asked %d", rec.Code, asked)
	}
	// Not wired: 503 that says so.
	rec = httptest.NewRecorder()
	apiServer{}.GetMannedTrafficSummary(rec, summaryReq())
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("unwired: %d", rec.Code)
	}
}

// The route is api's (x-process api) and session-only: no credential
// 401 and a machine token 403 at the router, before the bus is asked.
func TestMannedSummaryRouteIsAPIs(t *testing.T) {
	_, h := testServer(t, nil)
	if a := call(t, h, http.MethodGet, "/v1/manned-traffic/summary", "", "", ""); a.code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d %+v", a.code, a.problem)
	}
	if a := call(t, h, http.MethodGet, "/v1/manned-traffic/summary", "scopes:ansp.traffic", "", ""); a.code != http.StatusForbidden {
		t.Fatalf("machine token: %d %+v", a.code, a.problem)
	}
}
