//go:build integration

package main

import (
	"encoding/json"
	"net/http"
	"testing"
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
