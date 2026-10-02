//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// fixtureAirspaces is the CIS projection the lab publishes for a demo
// (M9): one USPACE feature, 44.6..45.0 E, 41.6..41.9 N, to 1500 m WGS84.
// WP-7 replaces it with the real projection.
type fixtureAirspaces struct{}

func (fixtureAirspaces) Current(context.Context) (restriction.Snapshot, error) {
	upper, lower := 1500.0, 0.0
	f := ed318.Feature{Type: "Feature",
		Geometry: ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{{
			{LatDeg: 41.6, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 44.6},
		}}, Layer: &ed318.Layer{Upper: &upper, UpperReference: core.RefWGS84, Lower: &lower, LowerReference: core.RefWGS84}},
		Properties: ed318.UASZone{Identifier: "GEOTU01", Country: "GEO", Type: core.ZoneUSpace},
	}
	return restriction.Snapshot{Version: "42", FetchedAt: time.Now().Add(-5 * time.Second), Airspaces: []ed318.Feature{f}}, nil
}

type apiClient struct {
	t    *testing.T
	base string
}

func (c apiClient) do(method, path, token string, header map[string]string, body any) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, ok := body.([]byte)
		if !ok {
			raw, _ = json.Marshal(body)
		}
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// signIn signs username in with password, enrolling TOTP at the first
// sign-in, and returns the session token.
func (c apiClient) signIn(username, password string) string {
	c.t.Helper()
	code, raw := c.do(http.MethodPost, "/v1/auth/login", "", nil, map[string]string{"username": username, "password": password})
	var lr struct {
		MFAToken  string `json:"mfa_token"`
		Enrolment struct {
			Secret string `json:"secret"`
		} `json:"enrolment"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &lr) != nil || lr.Enrolment.Secret == "" {
		c.t.Fatalf("login %s: %d %s", username, code, raw)
	}
	otpCode, err := totp.GenerateCodeCustom(lr.Enrolment.Secret, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		c.t.Fatal(err)
	}
	code, raw = c.do(http.MethodPost, "/v1/auth/mfa", "", nil, map[string]string{"mfa_token": lr.MFAToken, "code": otpCode})
	var mr struct {
		Token string `json:"token"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &mr) != nil || mr.Token == "" {
		c.t.Fatalf("mfa %s: %d %s", username, code, raw)
	}
	return mr.Token
}

type restrictionWire struct {
	ID          string          `json:"id"`
	AnspRef     string          `json:"ansp_ref"`
	Identifier  string          `json:"identifier"`
	State       string          `json:"state"`
	AnspVersion int64           `json:"ansp_version"`
	EndsAt      string          `json:"ends_at"`
	ActivatedBy string          `json:"activated_by"`
	Feature     json.RawMessage `json:"feature"`
	CISVersion  *string         `json:"cis_version"`
}

// The done-when of WP-5 through the HTTP API, against real PostgreSQL +
// PostGIS and NATS JetStream: a restriction planned, activated, extended
// and ended leaves four versions, four events and four restr.v1 messages;
// the console stream delivers a state change within 100 ms; the
// Idempotency-Key replays and conflicts; a viewer is refused the writes
// and reads.
func TestIntegrationRestrictionLifecycleOverHTTP(t *testing.T) {
	natsURL := os.Getenv("ANSP_NATS_URL")
	if natsURL == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rel := storetest.Scratch(t, store.TreeRelational, true)
	sk, sec, pwFile := authFiles(t)
	env := []string{"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_RELATIONAL_DSN=" + rel, "ANSP_NATS_URL=" + natsURL,
		"ANSP_SESSION_KEY_FILE=" + sk, "ANSP_SECRETS_KEY_FILE=" + sec, "ANSP_PUBLIC_BASE_URL=https://ansp.test",
		"ANSP_AUDIENCES=ansp.test,ansp-api", "ANSP_BOOTSTRAP_ADMIN_USERNAME=root", "ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE=" + pwFile,
		"ANSP_AUTHORITY_NAME=Test ANSP"}
	if creds := os.Getenv("ANSP_NATS_CREDS"); creds != "" {
		env = append(env, "ANSP_NATS_CREDS="+creds)
	}
	cfg, err := config.LoadFrom(env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger := obs.LoggerTo(logs, cfg)
	b, err := bus.Connect(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := openRelational(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg := obs.Metrics()
	aw, err := wireAuth(ctx, cfg, db, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := wireRestrictions(cfg, db, b, aw.guard.Sessions, fixtureAirspaces{}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	for _, fn := range rw.run {
		go fn(runCtx)
	}
	mux := http.NewServeMux()
	if _, err := mountAPI(mux, aw.guard, aw.handlers, rw.api, nil, nil, aw.realIP); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := apiClient{t: t, base: srv.URL}

	admin := c.signIn("root", "a long admin password")
	for _, u := range []struct{ name, role string }{{"watch1", "watch_supervisor"}, {"view1", "viewer"}} {
		if code, raw := c.do(http.MethodPost, "/v1/users", admin, nil, map[string]string{"username": u.name, "password": "a long password for " + u.name, "role": u.role}); code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", u.name, code, raw)
		}
	}
	watch := c.signIn("watch1", "a long password for watch1")
	viewer := c.signIn("view1", "a long password for view1")

	// The console stream: a status and a snapshot on connect.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/restrictions/stream"
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + watch}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	type wsFrame struct {
		data []byte
		at   time.Time // when the client read it
	}
	frames := make(chan wsFrame, 64)
	go func() {
		for {
			_, data, err := ws.Read(runCtx)
			if err != nil {
				close(frames)
				return
			}
			frames <- wsFrame{data, time.Now()}
		}
	}()
	next := func(schema string) (json.RawMessage, time.Time) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case f, ok := <-frames:
				if !ok {
					t.Fatal("stream closed")
				}
				var env struct {
					Schema string          `json:"schema"`
					Body   json.RawMessage `json:"body"`
				}
				_ = json.Unmarshal(f.data, &env)
				if env.Schema == schema {
					return env.Body, f.at
				}
			case <-deadline:
				t.Fatalf("no %s frame", schema)
			}
		}
	}
	status, _ := next("console/status/v1")
	if !strings.Contains(string(status), `"policy_version":"1"`) || !strings.Contains(string(status), `"cis_version":"42"`) || !strings.Contains(string(status), `"nats":"connected"`) {
		t.Fatalf("status %s", status)
	}
	if snap, _ := next("console/snapshot/v1"); !strings.Contains(string(snap), `"restrictions":[]`) {
		t.Fatalf("snapshot %s", snap)
	}

	start := time.Now().UTC().Truncate(time.Millisecond)
	body := map[string]any{
		"uspace_airspace_id": "GEOTU01", "zone_type": "PROHIBITED",
		"geometry": map[string]any{"type": "Polygon", "coordinates": [][][2]float64{{{44.78, 41.70}, {44.82, 41.70}, {44.82, 41.73}, {44.78, 41.73}, {44.78, 41.70}}}},
		"lower_m":  0, "lower_ref": "WGS84", "upper_m": 120, "upper_ref": "WGS84",
		"starts_at": restriction.Stamp(start), "ends_at": restriction.Stamp(start.Add(2 * time.Hour)),
		"reason_text": "Search and rescue (synthetic)",
	}
	raw, _ := json.Marshal(body)
	key := map[string]string{"Idempotency-Key": "console-wp5-1"}
	if code, out := c.do(http.MethodPost, "/v1/restrictions", viewer, key, raw); code != http.StatusForbidden {
		t.Fatalf("viewer plan: %d %s", code, out)
	}
	code, out := c.do(http.MethodPost, "/v1/restrictions", watch, key, raw)
	var r restrictionWire
	if code != http.StatusCreated || json.Unmarshal(out, &r) != nil || r.State != "planned" || r.AnspVersion != 1 || !restriction.ValidIdentifier(r.Identifier) || *r.CISVersion != "42" {
		t.Fatalf("plan: %d %s", code, out)
	}
	validateResponse(t, http.MethodPost, "/v1/restrictions", code, out)
	if _, at := next("restriction/state/v1"); at.IsZero() {
		t.Fatal("no planned frame")
	}
	// The same key and body: 200, the same restriction; another body: 409.
	if code, out := c.do(http.MethodPost, "/v1/restrictions", watch, key, raw); code != http.StatusOK || !strings.Contains(string(out), r.ID) {
		t.Fatalf("replay: %d %s", code, out)
	}
	other := bytes.Replace(raw, []byte(`"upper_m":120`), []byte(`"upper_m":110`), 1)
	if code, out := c.do(http.MethodPost, "/v1/restrictions", watch, key, other); code != http.StatusConflict || !strings.Contains(string(out), "idempotency_conflict") {
		t.Fatalf("conflict: %d %s", code, out)
	}
	// A refusal reads back as errors[] with the field and the type slug.
	agl := bytes.Replace(raw, []byte(`"lower_ref":"WGS84"`), []byte(`"lower_ref":"AGL"`), 1)
	if code, out := c.do(http.MethodPost, "/v1/restrictions", watch, map[string]string{"Idempotency-Key": "console-wp5-2"}, agl); code != http.StatusBadRequest ||
		!strings.Contains(string(out), `"type":"https://schemas.uspace.ge/problems/restriction_invalid"`) ||
		!strings.Contains(string(out), `{"field":"lower_ref","reason":"AGL is not supported for a dynamic restriction in this release"}`) {
		t.Fatalf("AGL: %d %s", code, out)
	}

	code, out = c.do(http.MethodPost, "/v1/restrictions/"+r.ID+"/activate", watch, nil, map[string]string{"reason": "rescue helicopter on scene"})
	answered := time.Now()
	if code != http.StatusOK || !strings.Contains(string(out), `"state":"active"`) {
		t.Fatalf("activate: %d %s", code, out)
	}
	frame, at := next("restriction/state/v1")
	if !strings.Contains(string(frame), `"state":"active"`) {
		t.Fatalf("frame %s", frame)
	}
	// Within 100 ms of the commit (the answer); the frame may well be
	// read before the answer is.
	if lag := at.Sub(answered); lag > 100*time.Millisecond {
		t.Fatalf("the stream delivered the activation %v after the answer", lag)
	}
	t.Logf("activate: frame read %v after the answer", at.Sub(answered))
	if code, out := c.do(http.MethodPost, "/v1/restrictions/"+r.ID+"/activate", watch, nil, map[string]string{"reason": "again"}); code != http.StatusConflict ||
		!strings.Contains(string(out), "illegal_transition") || !strings.Contains(string(out), "activate is not allowed from active") {
		t.Fatalf("illegal: %d %s", code, out)
	}
	newEnd := restriction.Stamp(start.Add(3 * time.Hour))
	if code, out := c.do(http.MethodPost, "/v1/restrictions/"+r.ID+"/extend", watch, nil, map[string]string{"ends_at": newEnd, "reason": "operation continues"}); code != http.StatusOK || !strings.Contains(string(out), `"ends_at":"`+newEnd+`"`) {
		t.Fatalf("extend: %d %s", code, out)
	}
	if code, out := c.do(http.MethodPost, "/v1/restrictions/"+r.ID+"/end", viewer, nil, map[string]string{"reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer end: %d %s", code, out)
	}
	code, out = c.do(http.MethodPost, "/v1/restrictions/"+r.ID+"/end", watch, nil, map[string]string{"reason": "rescue completed"})
	if code != http.StatusOK || !strings.Contains(string(out), `"state":"ended"`) || !strings.Contains(string(out), `"ansp_version":4`) {
		t.Fatalf("end: %d %s", code, out)
	}
	validateResponse(t, http.MethodPost, "/v1/restrictions/{id}/end", code, out)

	// Four versions (read as the viewer: reads are any role's).
	code, out = c.do(http.MethodGet, "/v1/restrictions/"+r.ID+"/versions", viewer, nil, nil)
	var vl struct {
		Versions []struct {
			Version int64  `json:"version"`
			State   string `json:"state"`
		} `json:"versions"`
	}
	if code != http.StatusOK || json.Unmarshal(out, &vl) != nil || len(vl.Versions) != 4 {
		t.Fatalf("versions: %d %s", code, out)
	}
	validateResponse(t, http.MethodGet, "/v1/restrictions/{id}/versions", code, out)
	var states []string
	for _, v := range vl.Versions {
		states = append(states, v.State)
	}
	if !slices.Equal(states, []string{"planned", "active", "active", "ended"}) {
		t.Fatalf("states %v", states)
	}
	// Four events.
	var page audit.Page
	if err := db.Do(ctx, func(ctx context.Context, q relational.DBTX, _ *relational.Queries) error {
		page, err = audit.Query(ctx, q, audit.Filter{EntityType: "restriction", EntityID: r.ID})
		return err
	}); err != nil || len(page.Events) != 4 {
		t.Fatalf("events: %d %v", len(page.Events), err)
	}
	// Four restr.v1 messages on the RESTR stream.
	cons, err := b.JetStream().OrderedConsumer(ctx, bus.StreamRestriction, jetstream.OrderedConsumerConfig{FilterSubjects: []string{bus.SubjectRestrictionPrefix + "*." + r.ID}})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := cons.FetchNoWait(10)
	if err != nil {
		t.Fatal(err)
	}
	var subjects []string
	for m := range batch.Messages() {
		subjects = append(subjects, strings.TrimSuffix(m.Subject(), "."+r.ID))
	}
	if !slices.Equal(subjects, []string{"restr.v1.planned", "restr.v1.active", "restr.v1.active", "restr.v1.ended"}) {
		t.Fatalf("restr.v1: %v", subjects)
	}
	t.Logf("WP-5 done-when: %d versions %v, %d events, %d restr.v1 messages %v", len(vl.Versions), states, len(page.Events), len(subjects), subjects)

	code, out = c.do(http.MethodGet, "/v1/restrictions?state=ended&bbox=44.7,41.6,44.9,41.8", viewer, nil, nil)
	if code != http.StatusOK || !strings.Contains(string(out), r.ID) {
		t.Fatalf("list: %d %s", code, out)
	}
	validateResponse(t, http.MethodGet, "/v1/restrictions", code, out)
	if code, out := c.do(http.MethodGet, "/v1/restrictions/01K6P0A1B2C3D4E5F6G7H8J9KM", viewer, nil, nil); code != http.StatusNotFound {
		t.Fatalf("unknown: %d %s", code, out)
	}
	if code, out := c.do(http.MethodGet, "/v1/restrictions/"+r.ID+"/versions/3", viewer, nil, nil); code != http.StatusOK || !strings.Contains(string(out), `"version":3`) {
		t.Fatalf("version 3: %d %s", code, out)
	}

	// A request from the console, accepted by the supervisor.
	delete(body, "zone_type")
	body["client_ref"] = "console-req-1"
	reqBody, _ := json.Marshal(body)
	code, out = c.do(http.MethodPost, "/v1/restriction-requests", viewer, nil, reqBody)
	var q struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if code != http.StatusCreated || json.Unmarshal(out, &q) != nil || q.State != "received" {
		t.Fatalf("request: %d %s", code, out)
	}
	validateResponse(t, http.MethodPost, "/v1/restriction-requests", code, out)
	if code, out := c.do(http.MethodPost, "/v1/restriction-requests/"+q.ID+"/accept", viewer, nil, map[string]string{"reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer accept: %d %s", code, out)
	}
	code, out = c.do(http.MethodPost, "/v1/restriction-requests/"+q.ID+"/accept", watch, nil, map[string]string{"reason": "for the event", "zone_type": "REQ_AUTHORIZATION"})
	if code != http.StatusOK || !strings.Contains(string(out), `"state":"accepted"`) || !strings.Contains(string(out), `"restriction_id"`) {
		t.Fatalf("accept: %d %s", code, out)
	}
	validateResponse(t, http.MethodPost, "/v1/restriction-requests/{id}/accept", code, out)
	if code, out := c.do(http.MethodPost, "/v1/restriction-requests/"+q.ID+"/decline", watch, nil, map[string]string{"reason": "late"}); code != http.StatusConflict {
		t.Fatalf("decline after accept: %d %s", code, out)
	}
}
