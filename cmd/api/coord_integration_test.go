//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nats-io/nats.go"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// subVerifier accepts "sub=<sub>;scopes=<a>,<b>" as a machine token of
// that client granting those scopes (the USSP stub's tokens).
type subVerifier struct{}

func (subVerifier) Verify(_ context.Context, token string) (coreauth.Claims, error) {
	sub, scopes, ok := strings.Cut(strings.TrimPrefix(token, "sub="), ";scopes=")
	if !ok || !strings.HasPrefix(token, "sub=") {
		return coreauth.Claims{}, &coreauth.TokenError{Counter: coreauth.CounterRejectedSignature, Claim: "signature", Reason: "test"}
	}
	return coreauth.Claims{Issuer: "https://authority.test", Subject: sub, Scopes: strings.Split(scopes, ",")}, nil
}

func usspToken(sub string) string { return "sub=" + sub + ";scopes=ansp.coordination" }

// coordStack is api with the inbox and the occurrence outbox against
// real PostgreSQL + PostGIS and NATS, a USSP stub as sender (machine
// tokens), the authority stub as the occurrence receiver, and a clock
// the test moves (the database clock plus an offset).
type coordStack struct {
	t         *testing.T
	ctx       context.Context
	c         apiClient
	api       *httptest.Server
	db        *store.Relational
	b         *bus.Bus
	co        *coordWiring
	authority *peer
	watch     string
	viewer    string
	logs      *syncBuffer
	coordMsgs chan *nats.Msg
	// offset moves the inbox's clock; listed and projected are the CIS
	// USSP list the sender is judged by.
	offset    atomic.Int64
	mu        sync.Mutex
	listed    []string
	projected bool
}

func (s *coordStack) setList(projected bool, ids ...string) {
	s.mu.Lock()
	s.listed, s.projected = ids, projected
	s.mu.Unlock()
}

func newCoordStack(t *testing.T, runTicker bool) *coordStack {
	t.Helper()
	natsURL := os.Getenv("ANSP_NATS_URL")
	if natsURL == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	rel := storetest.Scratch(t, store.TreeRelational, true)
	sk, sec, pwFile := authFiles(t)
	dir := t.TempDir()
	deliveryKey, _, _ := pemFiles(t, dir, "delivery")
	secretFile := filepath.Join(dir, "client.secret")
	_ = os.WriteFile(secretFile, []byte("synthetic-client-secret\n"), 0o600)
	s := &coordStack{t: t, ctx: ctx, logs: &syncBuffer{}, coordMsgs: make(chan *nats.Msg, 256), listed: []string{"ussp-01"}, projected: true}
	s.authority = newPeer(t, false)
	s.authority.answer.Store(func(peerRequest) int { return http.StatusAccepted })
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%s-%s","token_type":"Bearer","expires_in":300}`, r.Form.Get("audience"), r.Form.Get("scope"))
	}))
	t.Cleanup(tokenSrv.Close)
	env := []string{"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_RELATIONAL_DSN=" + rel, "ANSP_NATS_URL=" + natsURL,
		"ANSP_SESSION_KEY_FILE=" + sk, "ANSP_SECRETS_KEY_FILE=" + sec, "ANSP_PUBLIC_BASE_URL=https://ansp.test",
		"ANSP_AUDIENCES=ansp.test,ansp-api", "ANSP_BOOTSTRAP_ADMIN_USERNAME=root", "ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE=" + pwFile,
		"ANSP_AUTHORITY_NAME=Test ANSP", "ANSP_TOKEN_URL=" + tokenSrv.URL + "/oauth/token", "ANSP_CLIENT_SECRET_FILE=" + secretFile,
		"ANSP_DELIVERY_KEY_FILE=" + deliveryKey, "ANSP_AUTHORITY_URL=" + s.authority.srv.URL}
	if creds := os.Getenv("ANSP_NATS_CREDS"); creds != "" {
		env = append(env, "ANSP_NATS_CREDS="+creds)
	}
	cfg, err := config.LoadFrom(env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logger := obs.LoggerTo(s.logs, cfg)
	b, err := bus.Connect(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	_ = b.JetStream().DeleteConsumer(ctx, bus.StreamDeliver, workerConsumer)
	_ = b.JetStream().DeleteStream(ctx, bus.StreamDeliver)
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	s.b = b
	db, err := openRelational(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	s.db = db
	reg := obs.Metrics()
	aw, err := wireAuth(ctx, cfg, db, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	aw.guard.Machine = subVerifier{}
	rw, err := wireRestrictions(cfg, db, b, aw.guard.Sessions, fixtureAirspaces{}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	dw, err := wireDeliver(cfg, db, b, aw.keys, deliverOptions{roots: x509.NewCertPool()}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	attachDeliver(rw, dw)
	repo := store.CoordRepo{DB: db}
	pol := coord.DefaultPolicy()
	pol.TickEvery, pol.OccurrenceAlarmEvery = 100*time.Millisecond, 100*time.Millisecond
	clock := func(ctx context.Context) (time.Time, error) {
		now, err := repo.Now(ctx)
		return now.Add(time.Duration(s.offset.Load())), err
	}
	list := func() ([]string, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.listed, s.projected
	}
	co, err := wireCoord(cfg, db, b, aw.guard.Sessions, list, dw, coordOptions{clock: clock, policy: &pol}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	s.co = co
	sub, err := b.Conn().Subscribe(bus.SubjectCoordPrefix+">", func(m *nats.Msg) {
		select {
		case s.coordMsgs <- m:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	runCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	t.Cleanup(func() { stop(); wg.Wait() })
	fns := append(append([]func(context.Context){}, rw.run...), dw.run...)
	if runTicker {
		fns = append(fns, co.run...)
	} else {
		// The relay of coord.v1 to the console stream, without the
		// escalation ticker and the occurrence monitor (the test runs
		// those itself on its clock).
		fns = append(fns, co.relay)
	}
	for _, fn := range fns {
		wg.Add(1)
		go func() { defer wg.Done(); fn(runCtx) }()
	}
	mux := http.NewServeMux()
	if _, err := mountParts(mux, aw.guard, apiParts{auth: aw.handlers, rs: rw.api, co: co.api}, aw.realIP); err != nil {
		t.Fatal(err)
	}
	s.api = httptest.NewServer(mux)
	t.Cleanup(s.api.Close)
	s.c = apiClient{t: t, base: s.api.URL}
	admin := s.c.signIn("root", "a long admin password")
	for _, u := range []struct{ name, role string }{{"watch1", "watch_supervisor"}, {"view1", "viewer"}} {
		if code, raw := s.c.do(http.MethodPost, "/v1/users", admin, nil, map[string]string{"username": u.name, "password": "a long password for " + u.name, "role": u.role}); code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", u.name, code, raw)
		}
	}
	s.watch = s.c.signIn("watch1", "a long password for watch1")
	s.viewer = s.c.signIn("view1", "a long password for view1")
	return s
}

// notice is an Annex V notice of kind over [lon0, lon1] x [lat0, lat1]
// for the next hour.
func notice(kind, ref string, lon0, lat0, lon1, lat1 float64) map[string]any {
	now := time.Now().UTC().Truncate(time.Millisecond)
	ts := func(d time.Duration) string { return restriction.Stamp(now.Add(d)) }
	ft := func(d time.Duration) map[string]any { return map[string]any{"value": ts(d), "format": "RFC3339"} }
	alt := func(v float64) map[string]any { return map[string]any{"value": v, "reference": "W84", "units": "M"} }
	state := map[string]string{"intent_notice": "Accepted", "nonconformance": "Nonconforming", "contingent": "Contingent", "ended": "Activated"}[kind]
	n := map[string]any{
		"schema": "coordination/annex_v/v1", "notice_ref": ref, "kind": kind, "ussp_id": "ussp-01", "sent_at": ts(0),
		"intents": []any{map[string]any{
			"intent_ref": "6d1c2b4e-9a0f-4e3b-8c7d-2a1b0c9d8e7f", "authorisation_number": "GEO-UAS-2026-000183", "state": state,
			"time_start": ts(0), "time_end": ts(time.Hour),
			"volumes": []any{map[string]any{
				"volume": map[string]any{"outline_polygon": map[string]any{"vertices": []any{
					map[string]any{"lat": lat0, "lng": lon0}, map[string]any{"lat": lat0, "lng": lon1},
					map[string]any{"lat": lat1, "lng": lon1}, map[string]any{"lat": lat1, "lng": lon0},
				}}, "altitude_lower": alt(0), "altitude_upper": alt(150)},
				"time_start": ft(0), "time_end": ft(time.Hour),
			}},
		}},
	}
	if kind == "nonconformance" {
		n["nonconformance"] = map[string]any{"intent_ref": "6d1c2b4e-9a0f-4e3b-8c7d-2a1b0c9d8e7f", "authorisation_number": "GEO-UAS-2026-000183",
			"detected_at": ts(0), "reason": "threshold_exceeded", "distance_outside_m": 85}
	}
	return n
}

func (s *coordStack) submit(sub string, body any) (int, coord.Receipt, apierr.Problem) {
	s.t.Helper()
	code, raw := s.c.do(http.MethodPost, "/v1/coordination/notices", usspToken(sub), nil, body)
	var rec coord.Receipt
	var p apierr.Problem
	if code < 300 {
		strict(s.t, raw, &rec)
	} else {
		_ = json.Unmarshal(raw, &p)
	}
	return code, rec, p
}

func (s *coordStack) notice(token, ackID string) (int, coord.NoticeBody) {
	s.t.Helper()
	code, raw := s.c.do(http.MethodGet, "/v1/coordination/notices/"+ackID, token, nil, nil)
	var n coord.NoticeBody
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &n); err != nil {
			s.t.Fatal(err)
		}
	}
	return code, n
}

func (s *coordStack) count(query string, args ...any) int {
	s.t.Helper()
	var n int
	err := s.db.Do(s.ctx, func(ctx context.Context, db relational.DBTX, _ *relational.Queries) error {
		return db.QueryRow(ctx, query, args...).Scan(&n)
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return n
}

// awaitCoord waits for the coord.v1 message of a change (its message id).
func (s *coordStack) awaitCoord(msgID string) []byte {
	s.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m := <-s.coordMsgs:
			if m.Header.Get(nats.MsgIdHdr) == msgID {
				return m.Data
			}
		case <-deadline:
			s.t.Fatalf("no coord.v1 message %s", msgID)
		}
	}
}

// console is a console stream client.
type console struct {
	t      *testing.T
	frames chan []byte
}

func (s *coordStack) console(token string) *console {
	s.t.Helper()
	ws, _, err := websocket.Dial(s.ctx, "ws"+strings.TrimPrefix(s.api.URL, "http")+"/v1/coordination/stream",
		&websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = ws.CloseNow() })
	c := &console{t: s.t, frames: make(chan []byte, 256)}
	go func() {
		for {
			_, data, err := ws.Read(s.ctx)
			if err != nil {
				close(c.frames)
				return
			}
			c.frames <- data
		}
	}()
	return c
}

type frame struct {
	Schema string          `json:"schema"`
	Body   json.RawMessage `json:"body"`
}

// next is the next frame of schema whose body satisfies pred.
func (c *console) next(schema string, pred func(json.RawMessage) bool) json.RawMessage {
	c.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case raw, ok := <-c.frames:
			if !ok {
				c.t.Fatal("stream closed")
			}
			var f frame
			if json.Unmarshal(raw, &f) == nil && f.Schema == schema && (pred == nil || pred(f.Body)) {
				return f.Body
			}
		case <-deadline:
			c.t.Fatalf("no %s frame", schema)
		}
	}
}

func noticeWith(ackID, state string) func(json.RawMessage) bool {
	return func(raw json.RawMessage) bool {
		var b coord.NoticeBody
		return json.Unmarshal(raw, &b) == nil && b.AckID == ackID && b.State == state
	}
}

// The done-when of WP-10's intake through HTTP against real PostgreSQL
// + PostGIS and NATS: a valid notice is answered 202 with its ack_id
// after a row, an audit event and a coord.v1 message; the restriction
// its volumes cross is recorded (twin: none for one elsewhere); the
// sender reads received, a supervisor acknowledges, the sender reads
// acknowledged by the role; the console stream delivered both; replay,
// reuse, the examples, an unknown member, the kind enum and the bounds.
func TestIntegrationCoordinationNotices(t *testing.T) {
	s := newCoordStack(t, true)
	cons := s.console(s.watch)
	cons.next("console/status/v1", nil)
	cons.next("console/snapshot/v1", nil)

	// A planned restriction over the notice's area (WGS84 limits).
	start := time.Now().UTC().Truncate(time.Millisecond)
	code, out := s.c.do(http.MethodPost, "/v1/restrictions", s.watch, map[string]string{"Idempotency-Key": "coord-1"}, map[string]any{
		"uspace_airspace_id": "GEOTU01", "zone_type": "PROHIBITED",
		"geometry": map[string]any{"type": "Polygon", "coordinates": [][][2]float64{{{44.78, 41.70}, {44.82, 41.70}, {44.82, 41.73}, {44.78, 41.73}, {44.78, 41.70}}}},
		"lower_m":  0, "lower_ref": "WGS84", "upper_m": 120, "upper_ref": "WGS84",
		"starts_at": restriction.Stamp(start), "ends_at": restriction.Stamp(start.Add(2 * time.Hour)), "reason_text": "Search and rescue (synthetic)",
	})
	var r restrictionWire
	if code != http.StatusCreated || json.Unmarshal(out, &r) != nil {
		t.Fatalf("plan: %d %s", code, out)
	}

	code, rec, p := s.submit("ussp-01", notice("nonconformance", "nc-1", 44.79, 41.71, 44.81, 41.72))
	if code != http.StatusAccepted || rec.State != "received" || rec.AckID == "" || rec.ReceivedAt == "" {
		t.Fatalf("%d %+v %+v", code, rec, p)
	}
	if n := s.count(`SELECT count(*) FROM coordination_notices WHERE id = $1`, rec.AckID); n != 1 {
		t.Fatal("no row")
	}
	if n := s.count(`SELECT count(*) FROM events WHERE entity_id = $1 AND event_type = 'coordination_notice_received'`, rec.AckID); n != 1 {
		t.Fatal("no event")
	}
	var bus frame
	if err := json.Unmarshal(s.awaitCoord(rec.AckID+".1"), &bus); err != nil || bus.Schema != coord.SchemaNotice {
		t.Fatalf("%v %s", err, bus.Schema)
	}
	_, n := s.notice(s.watch, rec.AckID)
	if len(n.RestrictionIDs) != 1 || n.RestrictionIDs[0] != r.ID || n.SenderUnverified || !n.AcknowledgementRequired {
		t.Fatalf("%+v", n)
	}
	cons.next(coord.SchemaNotice, noticeWith(rec.AckID, "received"))

	// The twin: a notice elsewhere touches no restriction.
	code, far, _ := s.submit("ussp-01", notice("intent_notice", "in-far", 44.62, 41.62, 44.64, 41.64))
	if code != http.StatusAccepted {
		t.Fatal(code)
	}
	if _, n := s.notice(s.watch, far.AckID); len(n.RestrictionIDs) != 0 || n.AcknowledgementRequired {
		t.Fatalf("%+v", n)
	}

	// The sender polls: received, without the payload; another USSP
	// cannot read it.
	code, n = s.notice(usspToken("ussp-01"), rec.AckID)
	if code != http.StatusOK || n.State != "received" || n.Payload != nil || n.AcknowledgedBy != nil {
		t.Fatalf("%d %+v", code, n)
	}
	if code, _ := s.notice(usspToken("ussp-02"), rec.AckID); code != http.StatusNotFound {
		t.Fatal(code)
	}

	// A viewer cannot acknowledge; a supervisor does, once.
	if code, _ := s.c.do(http.MethodPost, "/v1/coordination/inbox/"+rec.AckID+"/acknowledge", s.viewer, nil, map[string]string{}); code != http.StatusForbidden {
		t.Fatal(code)
	}
	code, out = s.c.do(http.MethodPost, "/v1/coordination/inbox/"+rec.AckID+"/acknowledge", s.watch, nil, map[string]string{"note": "Aware (synthetic)"})
	if code != http.StatusOK || !strings.Contains(string(out), `"state":"acknowledged"`) {
		t.Fatalf("%d %s", code, out)
	}
	if code, _ := s.c.do(http.MethodPost, "/v1/coordination/inbox/"+rec.AckID+"/acknowledge", s.watch, nil, map[string]string{}); code != http.StatusConflict {
		t.Fatal(code)
	}
	code, n = s.notice(usspToken("ussp-01"), rec.AckID)
	if code != http.StatusOK || n.State != "acknowledged" || n.AcknowledgedBy == nil || *n.AcknowledgedBy != "watch_supervisor" || n.AcknowledgedAt == nil || n.AcknowledgementNote != nil {
		t.Fatalf("%+v", n)
	}
	cons.next(coord.SchemaNotice, noticeWith(rec.AckID, "acknowledged"))
	if n := s.count(`SELECT count(*) FROM events WHERE entity_id = $1 AND event_type = 'coordination_notice_acknowledged'`, rec.AckID); n != 1 {
		t.Fatal("no acknowledgement event")
	}

	// The inbox, audited.
	code, out = s.c.do(http.MethodGet, "/v1/coordination/inbox?state=acknowledged", s.viewer, nil, nil)
	if code != http.StatusOK || !strings.Contains(string(out), rec.AckID) || strings.Contains(string(out), far.AckID) {
		t.Fatalf("%d %s", code, out)
	}
	if n := s.count(`SELECT count(*) FROM events WHERE event_type = 'coordination_inbox_viewed'`); n != 1 {
		t.Fatal("the view is not audited")
	}

	// A replay answers the same ack_id, 200, one row; a reused ref 409.
	body := notice("contingent", "ct-1", 44.79, 41.71, 44.81, 41.72)
	code, first, _ := s.submit("ussp-01", body)
	if code != http.StatusAccepted {
		t.Fatal(code)
	}
	code, again, _ := s.submit("ussp-01", body)
	if code != http.StatusOK || again != first {
		t.Fatalf("%d %+v %+v", code, again, first)
	}
	if n := s.count(`SELECT count(*) FROM coordination_notices WHERE notice_ref = 'ct-1'`); n != 1 {
		t.Fatalf("%d rows", n)
	}
	body["remarks"] = "another notice"
	if code, _, p := s.submit("ussp-01", body); code != http.StatusConflict || p.Slug() != coord.SlugRefReused {
		t.Fatalf("%d %+v", code, p)
	}

	// Every example of the schema is accepted; an unknown member too; a
	// kind outside the enum is refused naming kind.
	dir := filepath.Join("..", "..", "schemas", "examples", "coordination", "annex_v", "v1")
	entries, _ := os.ReadDir(dir)
	accepted := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if code, _, p := s.submit("ussp-01", raw); code != http.StatusAccepted {
			t.Errorf("%s: %d %+v", e.Name(), code, p)
		}
		accepted++
	}
	if accepted < 4 {
		t.Fatalf("%d examples", accepted)
	}
	extra := notice("ended", "end-1", 44.79, 41.71, 44.81, 41.72)
	extra["a_member_from_v1_1"] = map[string]any{"x": true}
	if code, _, _ := s.submit("ussp-01", extra); code != http.StatusAccepted {
		t.Fatal(code)
	}
	bad := notice("ended", "bad-kind", 44.79, 41.71, 44.81, 41.72)
	bad["kind"] = "chatter"
	if code, _, p := s.submit("ussp-01", bad); code != http.StatusBadRequest || len(p.Errors) == 0 || p.Errors[0].Field != "kind" {
		t.Fatalf("%d %+v", code, p)
	}

	// E-10: a 1 MiB + 1 body and 1000 intents are refused by bound.
	big := bytes.Repeat([]byte(" "), coord.MaxNoticeBytes+1)
	copy(big, `{"x":1}`)
	if code, _ := s.c.do(http.MethodPost, "/v1/coordination/notices", usspToken("ussp-01"), nil, big); code != http.StatusRequestEntityTooLarge {
		t.Fatal(code)
	}
	many := notice("intent_notice", "many", 44.79, 41.71, 44.81, 41.72)
	in := many["intents"].([]any)[0]
	list := make([]any, 1000)
	for i := range list {
		list[i] = in
	}
	many["intents"] = list
	if code, _, p := s.submit("ussp-01", many); code != http.StatusBadRequest || p.Errors[0].Field != "intents" {
		t.Fatalf("%d %+v", code, p)
	}
	if n := s.count(`SELECT count(*) FROM coordination_notices WHERE notice_ref IN ('bad-kind', 'many')`); n != 0 {
		t.Fatal("a refused notice was stored")
	}
}

// An unknown sender is refused 403 with its audit row; with no USSP list
// projected a notice is accepted and flagged sender_unverified (the
// degraded case, E-02) and counted; the twin: listed, not flagged.
func TestIntegrationCoordinationSender(t *testing.T) {
	s := newCoordStack(t, true)
	code, _, p := s.submit("ussp-99", notice("nonconformance", "nc-x", 44.79, 41.71, 44.81, 41.72))
	if code != http.StatusForbidden || p.Slug() != coord.SlugSenderUnknown {
		t.Fatalf("%d %+v", code, p)
	}
	if n := s.count(`SELECT count(*) FROM events WHERE event_type = 'coordination_notice_refused' AND actor_id = 'ussp-99' AND entity_id = 'nc-x'`); n != 1 {
		t.Fatal("no audit row")
	}
	if n := s.count(`SELECT count(*) FROM coordination_notices`); n != 0 {
		t.Fatal("stored")
	}
	s.setList(false)
	code, rec, _ := s.submit("ussp-99", notice("nonconformance", "nc-y", 44.79, 41.71, 44.81, 41.72))
	if code != http.StatusAccepted {
		t.Fatal(code)
	}
	if _, n := s.notice(s.watch, rec.AckID); !n.SenderUnverified {
		t.Fatal("not flagged")
	}
	if s.co.api.svc.Counters().Get(coord.CounterSenderUnverified) != 1 {
		t.Fatal("not counted")
	}
	s.setList(true, "ussp-01")
	code, rec, _ = s.submit("ussp-01", notice("nonconformance", "nc-z", 44.79, 41.71, 44.81, 41.72))
	if code != http.StatusAccepted {
		t.Fatal(code)
	}
	if _, n := s.notice(s.watch, rec.AckID); n.SenderUnverified {
		t.Fatal("a listed sender flagged")
	}
}

// Escalation on the test's clock: at 60 s a nonconformance notice no
// person acknowledged is escalated (escalated_at, a frame), again at 90
// s by another instance on the same database (the state is on the row:
// a restart or a replica carries it on), and no more once acknowledged;
// an intent_notice never escalates.
func TestIntegrationCoordinationEscalation(t *testing.T) {
	s := newCoordStack(t, false)
	cons := s.console(s.watch)
	code, nc, _ := s.submit("ussp-01", notice("nonconformance", "nc-esc", 44.79, 41.71, 44.81, 41.72))
	code2, info, _ := s.submit("ussp-01", notice("intent_notice", "in-esc", 44.79, 41.71, 44.81, 41.72))
	if code != http.StatusAccepted || code2 != http.StatusAccepted {
		t.Fatal(code, code2)
	}
	svc := s.co.api.svc
	tick := func(svc *coord.Service, d time.Duration) coord.TickReport {
		t.Helper()
		s.offset.Store(int64(d))
		rep, err := svc.Tick(s.ctx)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if rep := tick(svc, 58*time.Second); len(rep.Escalated) != 0 {
		t.Fatal("escalated early")
	}
	rep := tick(svc, 61*time.Second)
	if len(rep.Escalated) != 1 || rep.Escalated[0].AckID != nc.AckID {
		t.Fatalf("%+v", rep)
	}
	cons.next(coord.SchemaNotice, noticeWith(nc.AckID, "escalated"))
	if _, n := s.notice(usspToken("ussp-01"), nc.AckID); n.State != "escalated" || n.EscalatedAt == nil || n.Escalations != 1 {
		t.Fatalf("%+v", n)
	}
	if rep := tick(svc, 80*time.Second); len(rep.Escalated) != 0 {
		t.Fatal("repeated within 30 s")
	}
	// Another instance (a new process with another producer and its own
	// service) carries the escalation on from the row.
	other := &coord.Service{Repo: store.CoordRepo{DB: s.db}, Producer: "ansp-2/api-2", Policy: coord.DefaultPolicy(),
		Clock: svc.Clock, Escalation: svc.Escalation, Bus: jsPublisher{b: s.b}}
	rep = tick(other, 92*time.Second)
	if len(rep.Escalated) != 1 || rep.Escalated[0].Escalations != 2 {
		t.Fatalf("%+v", rep)
	}
	esc := s.awaitCoord(nc.AckID + ".3")
	if !strings.Contains(string(esc), `"producer":"ansp-2/api-2"`) || !strings.Contains(string(esc), `"escalations":2`) {
		t.Fatalf("%s", esc)
	}
	if code, _ := s.c.do(http.MethodPost, "/v1/coordination/inbox/"+nc.AckID+"/acknowledge", s.watch, nil, nil); code != http.StatusOK {
		t.Fatal(code)
	}
	if rep := tick(svc, 10*time.Minute); len(rep.Escalated) != 0 {
		t.Fatal("escalated after the acknowledgement")
	}
	if _, n := s.notice(s.watch, info.AckID); n.State != "received" || n.EscalatedAt != nil {
		t.Fatalf("an intent_notice escalated: %+v", n)
	}
	if svc.Counters().Get(coord.CounterEscalated) != 1 || other.Counters().Get(coord.CounterEscalated) != 1 {
		t.Fatal("not counted")
	}
}

// An occurrence report reaches the authority stub with the reporter
// reference in clear and no name, while the row holds it sealed (the
// twin: the stored bytes are not the plaintext), and never in a log;
// with the authority down it stays queued and, at 60 h after
// became_aware_at on the test's clock, alarms until it is delivered.
func TestIntegrationOccurrences(t *testing.T) {
	s := newCoordStack(t, false)
	aware := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	body := map[string]any{
		"channel": "mandatory", "occurred_at": restriction.Stamp(aware.Add(-5 * time.Minute)), "became_aware_at": restriction.Stamp(aware),
		"category": "airprox", "manned": []any{map[string]any{"icao24": "4ca7b5", "callsign": "TST123"}},
		"narrative": "Synthetic airprox (test).", "reporter_person_ref": "staff-0042",
	}
	code, out := s.c.do(http.MethodPost, "/v1/occurrences", s.watch, nil, body)
	var q coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(out, &q) != nil || q.State != "queued" || q.DeadlineAt != restriction.Stamp(aware.Add(72*time.Hour)) {
		t.Fatalf("%d %s", code, out)
	}
	req := s.authority.await(t, "/v1/occurrences", 1, 20*time.Second)
	var msg coord.OccurrenceMessage
	if err := json.Unmarshal(req.Body, &msg); err != nil || msg.Reporter.PersonRef != "staff-0042" || msg.ReportRef != q.ReportRef ||
		msg.Schema != coord.SchemaOccurrence || strings.Contains(string(req.Body), "watch1") {
		t.Fatalf("%v %s", err, req.Body)
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer tok-"+s.authority.host()+"-occurrences.write") {
		t.Fatal(req.Header.Get("Authorization"))
	}
	var sealed []byte
	if err := s.db.Do(s.ctx, func(ctx context.Context, db relational.DBTX, _ *relational.Queries) error {
		return db.QueryRow(ctx, `SELECT reporter_person_ref_sealed FROM occurrence_reports WHERE id = $1`, q.ID).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte("staff-0042")) {
		t.Fatal("the reference is stored in clear")
	}
	awaitState := func(id, state string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for s.count(`SELECT count(*) FROM deliveries d JOIN occurrence_reports o ON o.delivery_id = d.id WHERE o.id = $1 AND d.state = $2`, id, state) != 1 {
			if time.Now().After(deadline) {
				t.Fatalf("report %s not %s", id, state)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	awaitState(q.ID, "sent")
	if n := s.count(`SELECT count(*) FROM deliveries WHERE body IS NOT NULL AND kind = 'occurrence'`); n != 0 {
		t.Fatal("a delivery keeps the body with the reference")
	}

	// The authority is down: queued, and alarmed at 60 h, not at 59 h.
	s.authority.answer.Store(func(peerRequest) int { return http.StatusServiceUnavailable })
	body["narrative"] = "Second synthetic report."
	code, out = s.c.do(http.MethodPost, "/v1/occurrences", s.watch, nil, body)
	var q2 coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(out, &q2) != nil {
		t.Fatalf("%d %s", code, out)
	}
	s.authority.await(t, "/v1/occurrences", 2, 20*time.Second)
	awaitState(q2.ID, "queued")
	occ := s.co.api.occ
	s.offset.Store(int64(58 * time.Hour))
	if rep, err := occ.Monitor(s.ctx); err != nil || len(rep.Raised) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	s.offset.Store(int64(59*time.Hour + time.Minute))
	rep, err := occ.Monitor(s.ctx)
	if err != nil || len(rep.Raised) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	code, out = s.c.do(http.MethodGet, "/v1/delivery-alarms", s.watch, nil, nil)
	if code != http.StatusOK || !strings.Contains(string(out), `"kind":"occurrence_undelivered"`) {
		t.Fatalf("%d %s", code, out)
	}
	// A click does not close it: it stays open until the delivery.
	code, _ = s.c.do(http.MethodPost, "/v1/delivery-alarms/"+rep.Raised[0].ID+"/acknowledge", s.watch, nil, map[string]string{"reason": "calling the authority"})
	if code != http.StatusOK || s.count(`SELECT count(*) FROM delivery_alarms WHERE id = $1 AND cleared_at IS NULL`, rep.Raised[0].ID) != 1 {
		t.Fatal("acknowledged closed the alarm")
	}
	s.authority.answer.Store(func(peerRequest) int { return http.StatusAccepted })
	awaitState(q2.ID, "sent")
	if rep, err := occ.Monitor(s.ctx); err != nil || len(rep.Cleared) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if strings.Contains(s.logs.String(), "staff-0042") {
		t.Fatal("the reporter reference is in a log line")
	}
}

// The console's Idempotency-Key on an occurrence report, against the
// database: a repeat with the key and body answers 200 with the first
// receipt and queues nothing more (one row, one delivery, one request to
// the authority); another body under the key is 409 with nothing stored;
// another key queues a new report (E-01 pair).
func TestIntegrationOccurrenceIdempotencyKey(t *testing.T) {
	s := newCoordStack(t, false)
	aware := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	body := map[string]any{
		"channel": "mandatory", "occurred_at": restriction.Stamp(aware.Add(-5 * time.Minute)), "became_aware_at": restriction.Stamp(aware),
		"category": "airprox", "narrative": "Synthetic airprox (idempotency test).",
	}
	key := map[string]string{"Idempotency-Key": "console-occ-1"}
	code, out := s.c.do(http.MethodPost, "/v1/occurrences", s.watch, key, body)
	var q coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(out, &q) != nil {
		t.Fatalf("%d %s", code, out)
	}
	code, out = s.c.do(http.MethodPost, "/v1/occurrences", s.watch, key, body)
	var again coord.Queued
	if code != http.StatusOK || json.Unmarshal(out, &again) != nil || again != q {
		t.Fatalf("repeat: %d %s, want 200 %+v", code, out, q)
	}
	if n := s.count(`SELECT count(*) FROM occurrence_reports WHERE idempotency_key = $1`, "console-occ-1"); n != 1 {
		t.Fatalf("%d reports for one key", n)
	}
	s.authority.await(t, "/v1/occurrences", 1, 20*time.Second)

	other := map[string]any{}
	for k, v := range body {
		other[k] = v
	}
	other["narrative"] = "Another synthetic airprox."
	code, out = s.c.do(http.MethodPost, "/v1/occurrences", s.watch, key, other)
	if code != http.StatusConflict || !strings.Contains(string(out), "idempotency_conflict") || !strings.Contains(string(out), q.ReportRef) {
		t.Fatalf("another body: %d %s", code, out)
	}
	code, out = s.c.do(http.MethodPost, "/v1/occurrences", s.watch, map[string]string{"Idempotency-Key": "console-occ-2"}, other)
	var q2 coord.Queued
	if code != http.StatusAccepted || json.Unmarshal(out, &q2) != nil || q2.ID == q.ID {
		t.Fatalf("another key: %d %s", code, out)
	}
	if n := s.count(`SELECT count(*) FROM occurrence_reports`); n != 2 {
		t.Fatalf("%d reports, want 2", n)
	}
	if n := s.count(`SELECT count(*) FROM deliveries WHERE kind = 'occurrence'`); n != 2 {
		t.Fatalf("%d occurrence deliveries, want 2", n)
	}
}
