package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// Each refusal of the service is written as the one problem body with
// its slug, status, errors[] and Retry-After; an unknown error is 500
// without its text.
func TestRefusalMapping(t *testing.T) {
	for _, tc := range []struct {
		err   error
		code  int
		slug  string
		field string
	}{
		{&restriction.Refusal{Status: 400, Slug: restriction.SlugInvalid, Detail: "no", Fields: []*core.FieldError{core.Fieldf("lower_ref", "%s", restriction.ReasonAGL)}}, 400, restriction.SlugInvalid, "lower_ref"},
		{&restriction.Refusal{Status: 503, Slug: restriction.SlugCISStale, Detail: "stale", RetryAfter: 10 * time.Second}, 503, restriction.SlugCISStale, ""},
		{&restriction.Refusal{Status: 409, Slug: restriction.SlugIllegalTransition, Detail: "x"}, 409, restriction.SlugIllegalTransition, ""},
		{restriction.ErrNotFound, 404, apierr.SlugNotFound, ""},
		{restriction.ErrConflict, 409, apierr.SlugConflict, ""},
		{context.DeadlineExceeded, 503, apierr.SlugUnavailable, ""},
		{errors.New("secret text"), 500, apierr.SlugInternal, ""},
	} {
		rec := httptest.NewRecorder()
		refusal(rec, httptest.NewRequest(http.MethodGet, "/v1/restrictions", nil), tc.err)
		var p apierr.Problem
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if rec.Code != tc.code || p.Slug() != tc.slug || strings.Contains(rec.Body.String(), "secret text") {
			t.Fatalf("%v: %d %s", tc.err, rec.Code, rec.Body)
		}
		if tc.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != tc.field) {
			t.Fatalf("%v: %+v", tc.err, p.Errors)
		}
		if tc.code == 503 && rec.Header().Get("Retry-After") == "" {
			t.Fatal("503 without Retry-After")
		}
	}
}

func TestReadBody(t *testing.T) {
	read := func(ctype, body string, required bool) (int, []byte) {
		r := httptest.NewRequest(http.MethodPost, "/v1/restrictions", strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		if body == "" {
			r.ContentLength = 0
		}
		rec := httptest.NewRecorder()
		b, ok := readBody(rec, r, required)
		if ok {
			return 0, b
		}
		return rec.Code, nil
	}
	if code, b := read("application/json; charset=utf-8", `{"a":1}`, true); code != 0 || string(b) != `{"a":1}` {
		t.Fatal(code, string(b))
	}
	if code, b := read("", "", false); code != 0 || b != nil {
		t.Fatal("an absent optional body", code)
	}
	for name, tc := range map[string]struct {
		ctype, body string
		code        int
	}{
		"text body":      {"text/plain", `{}`, 415},
		"no type":        {"", `{}`, 415},
		"empty required": {"application/json", " ", 400},
		"absent":         {"application/json", "", 400},
		"past the bound": {"application/json", `{"a":"` + strings.Repeat("x", MaxRestrictionBodyBytes) + `"}`, 413},
	} {
		if code, _ := read(tc.ctype, tc.body, true); code != tc.code {
			t.Fatalf("%s: %d", name, code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
	r.Header.Set("Content-Type", "application/json")
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 10)
	rec := httptest.NewRecorder()
	if _, ok := readBody(rec, r, true); ok || rec.Code != 413 {
		t.Fatalf("route bound: %d", rec.Code)
	}
}

func TestParseBBox(t *testing.T) {
	if b, err := parseBBox("44.6,41.6,45,41.9"); err != nil || b != [4]float64{44.6, 41.6, 45, 41.9} {
		t.Fatal(b, err)
	}
	if _, err := parseBBox("170,41,-170,42"); err != nil {
		t.Fatal("across the antimeridian", err)
	}
	for _, bad := range []string{"1,2,3", "a,b,c,d", "181,0,1,1", "0,0,1,95", "0,2,1,1", "NaN,0,1,1"} {
		if _, err := parseBBox(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// A version's constraint is written only once the DSS holds it (WP-9
// adds the reference); the derived details stay in the store.
func TestVersionConstraintOnTheWire(t *testing.T) {
	v := restriction.Version{RestrictionID: "01K6P0A1B2C3D4E5F6G7H8J9KM", Version: 2, State: restriction.StateActive, Feature: json.RawMessage(`{}`),
		Constraint: json.RawMessage(`{"details":{"volumes":[]},"derivation":{}}`), ChangedBy: "system", ChangedAt: time.Unix(0, 0)}
	if got := toVersionJSON(v); string(got.Constraint) != "null" {
		t.Fatalf("%s", got.Constraint)
	}
	v.Constraint = json.RawMessage(`{"reference":{"id":"x"},"details":{"volumes":[]},"derivation":{}}`)
	if got := toVersionJSON(v); !strings.Contains(string(got.Constraint), `"reference"`) || strings.Contains(string(got.Constraint), "derivation") {
		t.Fatalf("%s", got.Constraint)
	}
}

func testStream() *restrictionStream {
	svc := &restriction.Service{Airspaces: restriction.NoProjection{}}
	return newRestrictionStream(svc, func(context.Context) (policy.Policy, error) {
		return policy.Policy{Version: 3, Thresholds: policy.Defaults()}, nil
	}, nil, producer)
}

// The relay: each (restriction, version) once whichever path brought
// it; a full client loses frames, counted, never blocks the others; the
// connection limit refuses with 503.
func TestStreamHub(t *testing.T) {
	st := testStream()
	a, _ := st.add()
	b, _ := st.add()
	st.Offer("r1.1", []byte("m1"))
	st.Offer("r1.1", []byte("m1 again"))
	st.OfferBus([]byte(`{"body":{"restriction_id":"r1","ansp_version":2}}`))
	st.OfferBus([]byte(`{"body":{"restriction_id":"r1","ansp_version":2}}`))
	st.OfferBus([]byte(`not json`))
	if len(a.send) != 2 || len(b.send) != 2 || st.Counters().Get(CounterStreamDuplicates) != 2 || st.Counters().Get(CounterStreamClientFrame) != 1 {
		t.Fatalf("%d %d %v", len(a.send), len(b.send), st.Counters().Snapshot())
	}
	for i := range StreamSendBuffer {
		st.Offer(fmt.Sprintf("x.%d", i), []byte("x"))
	}
	if a.dropped.Load() != 2 || st.Counters().Get(CounterStreamDropped) != 4 {
		t.Fatalf("dropped %d %v", a.dropped.Load(), st.Counters().Snapshot())
	}
	st.remove(a)
	st.remove(b)
	for range MaxStreamClients {
		if _, ok := st.add(); !ok {
			t.Fatal("refused under the limit")
		}
	}
	if _, ok := st.add(); ok {
		t.Fatal("past the limit")
	}
	rec := httptest.NewRecorder()
	st.serve(rec, httptest.NewRequest(http.MethodGet, "/v1/restrictions/stream", nil))
	if rec.Code != 503 || st.Counters().Get(CounterStreamRefusedFull) != 1 {
		t.Fatalf("%d", rec.Code)
	}
	// The dedupe memory is bounded.
	for i := range streamDedupe + 10 {
		st.Offer(fmt.Sprintf("y.%d", i), nil)
	}
	if len(st.seen) != streamDedupe || len(st.order) != streamDedupe {
		t.Fatalf("%d %d", len(st.seen), len(st.order))
	}
}

// The status frame says what is degraded (no projection here) and the
// policy's thresholds; the snapshot without a store says it could not be
// read (the presence of the degraded path, E-02).
func TestStreamFrames(t *testing.T) {
	st := testStream()
	c := &streamClient{send: make(chan []byte, 1)}
	c.dropped.Store(5)
	var env struct {
		Schema string     `json:"schema"`
		Body   statusBody `json:"body"`
	}
	_ = json.Unmarshal(st.status(context.Background(), "conn-1", c), &env)
	if env.Schema != schemaStatus || env.Body.PolicyVersion != "3" || env.Body.DroppedFrames != 5 || env.Body.StaleAfterS != 15 ||
		!contains(env.Body.Degraded, "cis_projection_unavailable") || env.Body.CISVersion != nil {
		t.Fatalf("%+v", env)
	}
	st.policy = func(context.Context) (policy.Policy, error) { return policy.Policy{}, errors.New("db down") }
	st.snapshotFailed.Store(true)
	st.snapshotTruncated.Store(true)
	_ = json.Unmarshal(st.status(context.Background(), "conn-1", c), &env)
	for _, d := range []string{"policy_unreadable", "restriction_snapshot_unavailable", "restriction_snapshot_truncated"} {
		if !contains(env.Body.Degraded, d) {
			t.Fatalf("no %s in %v", d, env.Body.Degraded)
		}
	}
	if env.Body.PolicyVersion != "unknown" {
		t.Fatal(env.Body.PolicyVersion)
	}
	if got := unique([]string{"a", "", "a", "b"}); len(got) != 2 {
		t.Fatal(got)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestSessionTokenAndUpgrade(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc")
	if sessionToken(r) != "abc" {
		t.Fatal("bearer")
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: auth.CookieSession, Value: "cookie"})
	if sessionToken(r) != "cookie" {
		t.Fatal("cookie")
	}
	if sessionToken(httptest.NewRequest(http.MethodGet, "/", nil)) != "" {
		t.Fatal("none")
	}
	if isTokenError(nil) || isTokenError(errors.New("x")) {
		t.Fatal("isTokenError")
	}
	s := apiServer{rs: &restrictionAPI{stream: testStream()}}
	rec := httptest.NewRecorder()
	s.StreamRestrictions(rec, httptest.NewRequest(http.MethodGet, "/v1/restrictions/stream", nil))
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain GET: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	apiServer{}.StreamRestrictions(rec, httptest.NewRequest(http.MethodGet, "/v1/restrictions/stream", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no database: %d", rec.Code)
	}
}

// Without the database the restrictions are not served and the log
// says so; a geoid file that cannot be loaded refuses the start; the
// publisher refuses without a bus.
func TestWireRestrictions(t *testing.T) {
	out := &syncBuffer{}
	logger := obs.LoggerTo(out, config.Config{Process: process, LogLevel: "info"})
	w, err := wireRestrictions(config.Config{}, nil, nil, nil, nil, obs.Metrics(), logger)
	if err != nil || w.api != nil || !strings.Contains(out.String(), "restrictions are not served") {
		t.Fatalf("%+v %v %s", w, err, out.String())
	}
	b, err := bus.ConnectWith(context.Background(), bus.Settings{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := (jsPublisher{b: b}).Publish(context.Background(), "restr.v1.planned.x", "x.1", nil); err == nil {
		t.Fatal("published without a bus")
	}
	bad := filepath.Join(t.TempDir(), "geoid.pgm")
	_ = os.WriteFile(bad, []byte("not a grid"), 0o600)
	if _, err := wireRestrictions(config.Config{GeoidFile: bad}, nil, nil, nil, nil, obs.Metrics(), logger); err != nil {
		t.Fatalf("no database comes first: %v", err)
	}
}

// actorOf: a session is a user with its role; a machine a client with
// its client id; none is no actor.
func TestActorOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := actorOf(r); ok {
		t.Fatal("no principal")
	}
	p := auth.Principal{Session: true, Role: auth.RoleViewer}
	p.Claims.Subject = "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z"
	a, ok := actorOf(r.WithContext(auth.WithPrincipal(r.Context(), p)))
	if !ok || a.Type != "user" || a.Role != auth.RoleViewer || a.ID != p.Claims.Subject {
		t.Fatalf("%+v", a)
	}
	m := auth.Principal{}
	m.Claims.Subject = "authority-01"
	a, ok = actorOf(r.WithContext(auth.WithPrincipal(r.Context(), m)))
	if !ok || a.Type != "client" || a.ID != "authority-01" {
		t.Fatalf("%+v", a)
	}
}

// A console request belongs to the account, not the role: two
// supervisors are two requesters (ansp audit S-8); a system's request
// belongs to its client id.
func TestRequesterIsTheAccount(t *testing.T) {
	a := restriction.Actor{Type: string(audit.ActorUser), ID: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z", Role: auth.RoleWatchSupervisor}
	b := restriction.Actor{Type: string(audit.ActorUser), ID: "01K6NZ8Q2W3E4R5T6Y7V8W9X1A", Role: auth.RoleWatchSupervisor}
	srcA, reqA := requesterOf(a)
	srcB, reqB := requesterOf(b)
	if srcA != restriction.SourceConsole || srcB != restriction.SourceConsole || reqA != a.ID || reqB != b.ID {
		t.Fatalf("%s %s, %s %s", srcA, reqA, srcB, reqB)
	}
	src, req := requesterOf(restriction.Actor{Type: string(audit.ActorClient), ID: "authority-01", Role: "authority-01"})
	if src != restriction.SourceAuthority || req != "authority-01" {
		t.Fatalf("%s %s", src, req)
	}
}

// What the handlers write for a restriction and a version holds to the
// contract (api/openapi.yaml), for a polygon and a circle, planned with
// nothing set and ended with everything set.
func TestRestrictionWireMatchesTheContract(t *testing.T) {
	feature := json.RawMessage(`{"type":"Feature","id":"DAR7K2Q","geometry":{"type":"Polygon","coordinates":[[[44.78,41.7],[44.82,41.7],[44.82,41.73],[44.78,41.7]]]},"properties":{"identifier":"DAR7K2Q","country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR"]}}`)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	role, sys := "watch_supervisor", restriction.RoleSystem
	c := core.LatLon{LatDeg: 41.71, LonDeg: 44.8}
	v1 := "42"
	planned := restriction.Restriction{ID: "01K6P0A1B2C3D4E5F6G7H8J9KM", AnspRef: "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM", Identifier: "DAR7K2Q",
		UspaceAirspaceID: "GEOTU01", ZoneType: core.ZoneProhibited,
		Shape:  restriction.Shape{Ring: []core.LatLon{{LatDeg: 41.7, LonDeg: 44.78}, {LatDeg: 41.7, LonDeg: 44.82}, {LatDeg: 41.73, LonDeg: 44.82}, {LatDeg: 41.7, LonDeg: 44.78}}},
		LowerM: 0, LowerRef: core.RefAMSL, UpperM: 120.5, UpperRef: core.RefAMSL, StartsAt: at, EndsAt: at.Add(time.Hour), ReasonText: "x",
		State: restriction.StatePlanned, AnspVersion: 1, CreatedBy: role, CreatedAt: at, DSSConstraintID: "2f8343be-6482-4d1b-a474-16847e01af1e",
		Feature: feature, CISVersion: &v1}
	ended := planned
	ended.Shape = restriction.Shape{Center: &c, RadiusM: 1500}
	ended.State, ended.AnspVersion, ended.ActivatedBy, ended.EndedBy, ended.ActivatedAt, ended.EndedAtActual = restriction.StateEnded, 3, &role, &sys, &at, &at
	ended.SupersedesID, ended.RequestID = &planned.ID, &planned.ID
	rs := &restrictionAPI{svc: &restriction.Service{Airspaces: restriction.NoProjection{}}}
	for _, x := range []restriction.Restriction{planned, ended} {
		raw, _ := json.Marshal(rs.restrictionJSON(context.Background(), x))
		validateResponse(t, http.MethodGet, "/v1/restrictions/{id}", http.StatusOK, raw)
	}
	raw, _ := json.Marshal(versionListJSON{Versions: []versionJSON{toVersionJSON(restriction.Version{RestrictionID: planned.ID, Version: 2,
		State: restriction.StateActive, Feature: feature, ChangedBy: sys, ChangedAt: at, ChangeReason: "scheduled activation at starts_at"})}})
	validateResponse(t, http.MethodGet, "/v1/restrictions/{id}/versions", http.StatusOK, raw)
	raw, _ = json.Marshal(toRequestJSON(restriction.Request{ID: planned.ID, Requester: "authority-01", Source: restriction.SourceAuthority,
		Payload:    json.RawMessage(`{"client_ref":"GCAA-1","geometry":{"type":"Point","coordinates":[44.8,41.7]},"radius_m":500,"lower_m":0,"lower_ref":"AMSL","upper_m":120,"upper_ref":"AMSL","starts_at":"2026-10-02T12:00:00.000Z","ends_at":"2026-10-02T13:00:00.000Z","reason_text":"x"}`),
		ReceivedAt: at, State: restriction.RequestReceived}))
	validateResponse(t, http.MethodGet, "/v1/restriction-requests/{id}", http.StatusOK, raw)
}

// emptyRestrictions is a store that holds no restriction (only the
// snapshot's reads are served).
type emptyRestrictions struct{ restriction.Repo }

func (emptyRestrictions) CurrentVersions(context.Context, restriction.State, int) ([]restriction.Version, bool, error) {
	return nil, false, nil
}

// emptyNotices is an inbox store that holds no notice.
type emptyNotices struct{ coord.Repo }

func (emptyNotices) Notices(context.Context, coord.Filter) ([]coord.Notice, error) { return nil, nil }

// A client that sends console/subscribe/v1 in a burst gets at most one
// snapshot per StreamResubscribeEvery (each one is a database read of
// every active and planned restriction, or every open notice); the
// burst is counted and answered by one deferred snapshot, never dropped
// in silence (ansp audit S-4). Twin: that snapshot is sent.
func TestStreamResubscribeThrottled(t *testing.T) {
	rs := testStream()
	rs.svc.Repo = emptyRestrictions{}
	cs := newCoordStream(&coord.Service{Repo: emptyNotices{}}, func(context.Context) (policy.Policy, error) {
		return policy.Policy{Version: 3, Thresholds: policy.Defaults()}, nil
	}, nil, producer)
	t.Run("restrictions", func(t *testing.T) {
		resubscribeBurst(t, rs.serve, func() uint64 { return rs.Counters().Get(CounterStreamResubscribeThrottled) })
	})
	t.Run("coordination", func(t *testing.T) {
		resubscribeBurst(t, cs.serve, func() uint64 { return cs.Counters().Get(CounterCoordStreamResubscribeThrottled) })
	})
}

func resubscribeBurst(t *testing.T, serve http.HandlerFunc, throttled func() uint64) {
	t.Helper()
	srv := httptest.NewServer(serve)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()
	snapshots := make(chan time.Time, 64)
	go func() {
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var f struct {
				Schema string `json:"schema"`
			}
			if json.Unmarshal(data, &f) == nil && f.Schema == schemaSnapshot {
				snapshots <- time.Now()
			}
		}
	}()
	select {
	case <-snapshots: // the snapshot on connect
	case <-ctx.Done():
		t.Fatal("no snapshot on connect")
	}
	start := time.Now()
	for range 20 {
		if err := ws.Write(ctx, websocket.MessageText, []byte(`{"schema":"console/subscribe/v1","body":{}}`)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	var got []time.Duration
	deadline := time.After(StreamResubscribeEvery + 700*time.Millisecond)
	for done := false; !done; {
		select {
		case at := <-snapshots:
			got = append(got, at.Sub(start))
		case <-deadline:
			done = true
		}
	}
	if len(got) != 1 || got[0] < StreamResubscribeEvery-300*time.Millisecond {
		t.Fatalf("snapshots after a burst of 20 subscribes: %v", got)
	}
	if throttled() == 0 {
		t.Fatal("the throttled subscribes are not counted")
	}
}
