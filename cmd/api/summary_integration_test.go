//go:build integration

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// summaryCase is one summary operation and who may read it: the
// authorised role gets 200 with the contract's body, every other role
// 403 and no session 401 (fail closed, least privilege).
type summaryCase struct {
	path    string
	allowed string
}

// tokens are the stack's sessions by role.
func (s *coordStack) tokens() map[string]string {
	return map[string]string{"admin": s.admin, "watch_supervisor": s.watch, "viewer": s.viewer}
}

// checkSummaryAccess reads c.path as every role and without a session,
// and returns the authorised role's body, validated against the
// contract.
func (s *coordStack) checkSummaryAccess(t *testing.T, c summaryCase) []byte {
	t.Helper()
	var body []byte
	for role, tok := range s.tokens() {
		code, raw := s.c.do(http.MethodGet, c.path, tok, nil, nil)
		if role == c.allowed {
			if code != http.StatusOK {
				t.Fatalf("%s as %s: %d %s", c.path, role, code, raw)
			}
			validateResponse(t, http.MethodGet, c.path, code, raw)
			body = raw
			continue
		}
		if code != http.StatusForbidden {
			t.Fatalf("%s as %s: %d %s, want 403", c.path, role, code, raw)
		}
	}
	if code, raw := s.c.do(http.MethodGet, c.path, "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("%s without a session: %d %s", c.path, code, raw)
	}
	return body
}

// GET /v1/users/summary against the database: the admin reads the
// accounts counted (root, watch1, view1; then view1 disabled), the
// supervisor and the viewer are refused 403, no session 401.
func TestIntegrationUserSummary(t *testing.T) {
	s := newCoordStack(t, false)
	type summary struct {
		CountedAt string           `json:"counted_at"`
		Total     int64            `json:"total"`
		ByStatus  map[string]int64 `json:"by_status"`
		ByRole    map[string]int64 `json:"by_role"`
		Truncated bool             `json:"truncated"`
	}
	read := func() summary {
		t.Helper()
		var got summary
		if err := json.Unmarshal(s.checkSummaryAccess(t, summaryCase{path: "/v1/users/summary", allowed: "admin"}), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := read()
	if got.Total != 3 || got.ByStatus["active"] != 3 || got.ByStatus["disabled"] != 0 || got.ByRole["admin"] != 1 ||
		got.ByRole["watch_supervisor"] != 1 || got.ByRole["viewer"] != 1 || got.Truncated || got.CountedAt == "" {
		t.Fatalf("%+v", got)
	}
	var users struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}
	code, raw := s.c.do(http.MethodGet, "/v1/users", s.admin, nil, nil)
	if code != http.StatusOK || json.Unmarshal(raw, &users) != nil {
		t.Fatalf("%d %s", code, raw)
	}
	for _, u := range users.Users {
		if u.Username == "view1" {
			if code, raw := s.c.do(http.MethodPost, "/v1/users/"+u.ID+"/disable", s.admin, nil, nil); code != http.StatusOK {
				t.Fatalf("disable: %d %s", code, raw)
			}
		}
	}
	// view1 is disabled, so its session is gone: only the admin and the
	// supervisor are asked again.
	code, raw = s.c.do(http.MethodGet, "/v1/users/summary", s.admin, nil, nil)
	if err := json.Unmarshal(raw, &got); code != http.StatusOK || err != nil || got.Total != 3 || got.ByStatus["active"] != 2 || got.ByStatus["disabled"] != 1 {
		t.Fatalf("after the disable: %d %s", code, raw)
	}
	if code, raw := s.c.do(http.MethodGet, "/v1/users/summary", s.watch, nil, nil); code != http.StatusForbidden {
		t.Fatalf("supervisor: %d %s", code, raw)
	}
}

// The requests awaiting a decision against the database: a request
// sent is listed and counted for the supervisor (the viewer and the
// admin refused 403, no session 401), and leaves both once declined.
func TestIntegrationRestrictionRequestSummary(t *testing.T) {
	s := newCoordStack(t, false)
	type summary struct {
		Received         int64   `json:"received"`
		OldestReceivedAt *string `json:"oldest_received_at"`
		Truncated        bool    `json:"truncated"`
	}
	type list struct {
		Requests []struct {
			ID         string `json:"id"`
			Source     string `json:"source"`
			ReceivedAt string `json:"received_at"`
		} `json:"requests"`
		Truncated bool `json:"truncated"`
	}
	var sum summary
	if err := json.Unmarshal(s.checkSummaryAccess(t, summaryCase{path: "/v1/restriction-requests/summary", allowed: "watch_supervisor"}), &sum); err != nil ||
		sum.Received != 0 || sum.OldestReceivedAt != nil {
		t.Fatalf("none: %+v %v", sum, err)
	}
	body := map[string]any{"client_ref": "summary-1", "uspace_airspace_id": "GEOTU01",
		"geometry": map[string]any{"type": "Point", "coordinates": []float64{44.8, 41.71}}, "radius_m": 500,
		"lower_m": 0, "lower_ref": "WGS84", "upper_m": 120, "upper_ref": "WGS84",
		"starts_at": "2026-10-02T13:00:00.000Z", "ends_at": "2026-10-02T15:00:00.000Z", "reason_text": "Synthetic request (test)"}
	code, raw := s.c.do(http.MethodPost, "/v1/restriction-requests", s.viewer, nil, body)
	var q struct {
		ID         string `json:"id"`
		ReceivedAt string `json:"received_at"`
	}
	if code != http.StatusCreated || json.Unmarshal(raw, &q) != nil {
		t.Fatalf("request: %d %s", code, raw)
	}
	if err := json.Unmarshal(s.checkSummaryAccess(t, summaryCase{path: "/v1/restriction-requests/summary", allowed: "watch_supervisor"}), &sum); err != nil ||
		sum.Received != 1 || sum.OldestReceivedAt == nil || *sum.OldestReceivedAt != q.ReceivedAt || sum.Truncated {
		t.Fatalf("one: %+v %v", sum, err)
	}
	var l list
	if err := json.Unmarshal(s.checkSummaryAccess(t, summaryCase{path: "/v1/restriction-requests", allowed: "watch_supervisor"}), &l); err != nil ||
		len(l.Requests) != 1 || l.Requests[0].ID != q.ID || l.Requests[0].Source != "console" || l.Truncated {
		t.Fatalf("list: %+v %v", l, err)
	}
	if code, raw := s.c.do(http.MethodGet, "/v1/restriction-requests?limit=0", s.watch, nil, nil); code != http.StatusBadRequest {
		t.Fatalf("limit 0: %d %s", code, raw)
	}
	if code, raw := s.c.do(http.MethodPost, "/v1/restriction-requests/"+q.ID+"/decline", s.watch, nil, map[string]string{"reason": "test"}); code != http.StatusOK {
		t.Fatalf("decline: %d %s", code, raw)
	}
	code, raw = s.c.do(http.MethodGet, "/v1/restriction-requests/summary", s.watch, nil, nil)
	if err := json.Unmarshal(raw, &sum); code != http.StatusOK || err != nil || sum.Received != 0 || sum.OldestReceivedAt != nil {
		t.Fatalf("after the decline: %d %s", code, raw)
	}
	code, raw = s.c.do(http.MethodGet, "/v1/restriction-requests", s.watch, nil, nil)
	if err := json.Unmarshal(raw, &l); code != http.StatusOK || err != nil || len(l.Requests) != 0 {
		t.Fatalf("list after the decline: %d %s", code, raw)
	}
}

// The occurrence reports by delivery state against the database and the
// outbox: one delivered to the authority stub (sent), one held while it
// answers 503 (queued); the supervisor reads both counted (the viewer
// and the admin refused 403, no session 401); the store's bound past
// one report says truncated; no report_ref or narrative in the answer.
func TestIntegrationOccurrenceSummary(t *testing.T) {
	s := newCoordStack(t, false)
	type summary struct {
		Total     int64            `json:"total"`
		ByState   map[string]int64 `json:"by_state"`
		Truncated bool             `json:"truncated"`
	}
	read := func() (summary, string) {
		t.Helper()
		raw := s.checkSummaryAccess(t, summaryCase{path: "/v1/occurrences/summary", allowed: "watch_supervisor"})
		var got summary
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		return got, string(raw)
	}
	if got, _ := read(); got.Total != 0 || got.ByState["queued"] != 0 || got.Truncated {
		t.Fatalf("none: %+v", got)
	}
	aware := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	body := map[string]any{"channel": "mandatory", "occurred_at": restriction.Stamp(aware.Add(-5 * time.Minute)),
		"became_aware_at": restriction.Stamp(aware), "category": "airprox", "narrative": "Synthetic airprox (summary test)."}
	state := func(ref, want string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for s.count(`SELECT count(*) FROM deliveries d JOIN occurrence_reports o ON o.delivery_id = d.id WHERE o.report_ref = $1 AND d.state = $2`, ref, want) != 1 {
			if time.Now().After(deadline) {
				t.Fatalf("report %s not %s", ref, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	code, raw := s.c.do(http.MethodPost, "/v1/occurrences", s.watch, nil, body)
	var q1 coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(raw, &q1) != nil {
		t.Fatalf("%d %s", code, raw)
	}
	state(q1.ReportRef, "sent")
	s.authority.answer.Store(func(peerRequest) int { return http.StatusServiceUnavailable })
	body["became_aware_at"] = restriction.Stamp(aware.Add(time.Minute))
	code, raw = s.c.do(http.MethodPost, "/v1/occurrences", s.watch, nil, body)
	var q2 coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(raw, &q2) != nil {
		t.Fatalf("%d %s", code, raw)
	}
	s.authority.await(t, "/v1/occurrences", 2, 20*time.Second)
	state(q2.ReportRef, "queued")
	got, text := read()
	if got.Total != 2 || got.ByState["sent"] != 1 || got.ByState["queued"] != 1 || got.ByState["failed"] != 0 || got.Truncated {
		t.Fatalf("two: %s", text)
	}
	for _, leak := range []string{q1.ReportRef, q2.ReportRef, "Synthetic airprox"} {
		if strings.Contains(text, leak) {
			t.Fatalf("the summary names a report (%s): %s", leak, text)
		}
	}
	// Past the store's bound: the newest one counted, truncated said.
	c, err := store.CoordRepo{DB: s.db}.OccurrenceCounts(s.ctx, 1)
	if err != nil || c.Total != 1 || c.Queued != 1 || !c.Truncated {
		t.Fatalf("past the bound: %+v %v", c, err)
	}
	if c, err = (store.CoordRepo{DB: s.db}).OccurrenceCounts(s.ctx, 2); err != nil || c.Total != 2 || c.Truncated {
		t.Fatalf("at the bound: %+v %v", c, err)
	}
}

// GET /v1/manned-traffic/summary against real NATS: with no manned-feed
// on the bus every role's session is answered 503 naming why, and the
// session is not refused (GET /v1/auth/me 200 after it); with a
// responder answering as manned-feed does, every role reads the count
// in the contract's shape; no session 401, before the bus is asked.
func TestIntegrationMannedSummaryThroughAPI(t *testing.T) {
	s := newCoordStack(t, false)
	for role, tok := range s.tokens() {
		code, raw := s.c.do(http.MethodGet, "/v1/manned-traffic/summary", tok, nil, nil)
		if code != http.StatusServiceUnavailable || !strings.Contains(string(raw), "no responder") {
			t.Fatalf("%s without manned-feed: %d %s", role, code, raw)
		}
		if code, raw := s.c.do(http.MethodGet, "/v1/auth/me", tok, nil, nil); code != http.StatusOK {
			t.Fatalf("%s's session after the 503: %d %s", role, code, raw)
		}
	}
	asked := make(chan struct{}, 16)
	sub, err := s.b.Conn().QueueSubscribe(s.summarySubject, bus.QueueMannedSummary, func(m *nats.Msg) {
		asked <- struct{}{}
		_ = m.Respond([]byte(`{"counted_at":"2026-10-16T10:00:00.000Z","total":1,"by_state":{"live":1,"stale":0,"source_disabled":0},` +
			`"relevant":1,"max_aircraft":5000,"relevance":"relevance: synthetic","degraded":[],"policy_version":"1"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	for role, tok := range s.tokens() {
		code, raw := s.c.do(http.MethodGet, "/v1/manned-traffic/summary", tok, nil, nil)
		if code != http.StatusOK || !strings.Contains(string(raw), `"total":1`) {
			t.Fatalf("%s: %d %s", role, code, raw)
		}
		validateResponse(t, http.MethodGet, "/v1/manned-traffic/summary", code, raw)
	}
	before := len(asked)
	if code, raw := s.c.do(http.MethodGet, "/v1/manned-traffic/summary", "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("without a session: %d %s", code, raw)
	}
	if len(asked) != before {
		t.Fatal("the bus was asked for a caller without a session")
	}
}
