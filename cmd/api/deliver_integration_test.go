//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/dss/dsstest"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// peerRequest is one request a stub peer received.
type peerRequest struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
	At                  time.Time
	// ClientSubject is the subject of the client certificate presented.
	ClientSubject string
}

// peer is an in-test CISP, USSP or authority recording every request.
type peer struct {
	mu     sync.Mutex
	reqs   []peerRequest
	answer atomic.Value // func(peerRequest) int
	srv    *httptest.Server
}

func (p *peer) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec := peerRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body, At: time.Now()}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		rec.ClientSubject = r.TLS.PeerCertificates[0].Subject.String()
	}
	p.mu.Lock()
	p.reqs = append(p.reqs, rec)
	p.mu.Unlock()
	code := http.StatusNoContent
	if f, ok := p.answer.Load().(func(peerRequest) int); ok {
		code = f(rec)
	}
	w.WriteHeader(code)
	if code != http.StatusNoContent {
		_, _ = io.WriteString(w, `{"replay":false}`)
	}
}

func (p *peer) requests(path string) []peerRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []peerRequest
	for _, r := range p.reqs {
		if path == "" || r.Path == path || strings.HasPrefix(r.Path, path+"/") {
			out = append(out, r)
		}
	}
	return out
}

func (p *peer) host() string {
	u, _ := url.Parse(p.srv.URL)
	return u.Host
}

// await waits for the n-th request on path.
func (p *peer) await(t *testing.T, path string, n int, within time.Duration) peerRequest {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if rs := p.requests(path); len(rs) >= n {
			return rs[n-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d requests on %s within %v, want %d", p.srv.URL, len(p.requests(path)), path, within, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newPeer(t *testing.T, tlsClients bool) *peer {
	t.Helper()
	p := &peer{}
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(p.handler))
	if tlsClients {
		// The CISP behind its proxy: a client certificate is required
		// (CISP_MTLS_MODE=required); the subject is what the proxy
		// forwards in X-Client-Cert-Subject.
		p.srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
		p.srv.StartTLS()
	} else {
		p.srv.Start()
	}
	t.Cleanup(p.srv.Close)
	return p
}

// pemFiles writes an RSA key (and a client certificate for it) made at
// test time.
func pemFiles(t *testing.T, dir, name string) (keyFile, certFile, subject string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := clientTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, certFile = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".crt")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, certFile, tmpl.Subject.String()
}

// deliverStack is api with its outbox against real PostgreSQL + PostGIS
// and NATS, an in-test CISP (TLS, client certificate required), a token
// service, two USSPs and the authority.
type deliverStack struct {
	t         *testing.T
	ctx       context.Context
	c         apiClient
	api       *httptest.Server
	db        *store.Relational
	b         *bus.Bus
	cisp      *peer
	ussps     []*peer
	authority *peer
	subject   string
	watch     string
	dw        *deliverWiring
	restr     chan map[string]any
	logs      *syncBuffer
	// dss is the in-test DSS (ovn semantics, WP-9) naming subs, the two
	// in-test subscribers.
	dss  *dsstest.DSS
	subs []*dsstest.USS
}

func newDeliverStack(t *testing.T) *deliverStack {
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
	clientKey, clientCert, subject := pemFiles(t, dir, "client")
	secretFile := filepath.Join(dir, "client.secret")
	_ = os.WriteFile(secretFile, []byte("synthetic-client-secret\n"), 0o600)

	s := &deliverStack{t: t, ctx: ctx, subject: subject, restr: make(chan map[string]any, 256), logs: &syncBuffer{}}
	s.cisp = newPeer(t, true)
	s.cisp.answer.Store(func(r peerRequest) int {
		switch {
		case r.Path == deliver.PathHeartbeat:
			return http.StatusNoContent
		case r.Method == http.MethodPost:
			return http.StatusCreated
		}
		return http.StatusOK
	})
	s.ussps = []*peer{newPeer(t, false), newPeer(t, false)}
	s.authority = newPeer(t, false)
	s.subs = []*dsstest.USS{dsstest.NewUSS(), dsstest.NewUSS()}
	s.dss = dsstest.New(dsstest.Subscriber{BaseURL: s.subs[0].URL(), Subscriptions: []string{"78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"}},
		dsstest.Subscriber{BaseURL: s.subs[1].URL(), Subscriptions: []string{"88ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"}})
	t.Cleanup(s.dss.Close)
	t.Cleanup(s.subs[0].Close)
	t.Cleanup(s.subs[1].Close)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%s-%s","token_type":"Bearer","expires_in":300}`, r.Form.Get("audience"), r.Form.Get("scope"))
	}))
	t.Cleanup(tokenSrv.Close)

	env := []string{"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off", "ANSP_RELATIONAL_DSN=" + rel, "ANSP_NATS_URL=" + natsURL,
		"ANSP_SESSION_KEY_FILE=" + sk, "ANSP_SECRETS_KEY_FILE=" + sec, "ANSP_PUBLIC_BASE_URL=https://ansp.test",
		"ANSP_AUDIENCES=ansp.test,ansp-api", "ANSP_BOOTSTRAP_ADMIN_USERNAME=root", "ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE=" + pwFile,
		"ANSP_AUTHORITY_NAME=Test ANSP", "ANSP_CISP_URL=" + s.cisp.srv.URL, "ANSP_TOKEN_URL=" + tokenSrv.URL + "/oauth/token",
		"ANSP_CLIENT_SECRET_FILE=" + secretFile, "ANSP_DELIVERY_KEY_FILE=" + deliveryKey,
		"ANSP_CISP_CLIENT_CERT_FILE=" + clientCert, "ANSP_CISP_CLIENT_KEY_FILE=" + clientKey,
		"ANSP_AUTHORITY_URL=" + s.authority.srv.URL, "ANSP_DSS_URL=" + s.dss.URL()}
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
	// A scratch work queue per test: the durable consumer is shared by
	// every api of one bus, so a test must not leave jobs for the next.
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
	rw, err := wireRestrictions(cfg, db, b, aw.guard.Sessions, fixtureAirspaces{}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.cisp.srv.Certificate())
	targets := func(context.Context) []deliver.Target {
		return []deliver.Target{{Name: "ussp-a", BaseURL: s.ussps[0].srv.URL}, {Name: "ussp-b", BaseURL: s.ussps[1].srv.URL},
			{Name: "authority", BaseURL: cfg.AuthorityURL}}
	}
	dw, err := wireDeliver(cfg, db, b, aw.keys, deliverOptions{targets: targets, roots: roots}, reg, logger)
	if err != nil {
		t.Fatal(err)
	}
	s.dw = dw
	attachDeliver(rw, dw)
	sub, err := b.Conn().Subscribe(bus.SubjectRestrictionPrefix+">", func(m *nats.Msg) {
		var env struct {
			Body map[string]any `json:"body"`
		}
		if json.Unmarshal(m.Data, &env) == nil {
			select {
			case s.restr <- env.Body:
			default:
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	runCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	t.Cleanup(func() { stop(); wg.Wait() })
	for _, fn := range append(rw.run, dw.run...) {
		wg.Add(1)
		go func() { defer wg.Done(); fn(runCtx) }()
	}
	mux := http.NewServeMux()
	if _, err := mountAPI(mux, aw.guard, aw.handlers, rw.api, nil, nil, aw.realIP); err != nil {
		t.Fatal(err)
	}
	s.api = httptest.NewServer(mux)
	t.Cleanup(s.api.Close)
	s.c = apiClient{t: t, base: s.api.URL}
	admin := s.c.signIn("root", "a long admin password")
	if code, raw := s.c.do(http.MethodPost, "/v1/users", admin, nil, map[string]string{"username": "watch1", "password": "a long password for watch1", "role": "watch_supervisor"}); code != http.StatusCreated {
		t.Fatalf("create watch1: %d %s", code, raw)
	}
	s.watch = s.c.signIn("watch1", "a long password for watch1")
	return s
}

func (s *deliverStack) jwksURL() string { return s.api.URL + "/.well-known/jwks.json" }

// plan plans a restriction starting now (WGS84 limits: no geoid).
func (s *deliverStack) plan(key string) restrictionWire {
	s.t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond)
	body := map[string]any{
		"uspace_airspace_id": "GEOTU01", "zone_type": "PROHIBITED",
		"geometry": map[string]any{"type": "Polygon", "coordinates": [][][2]float64{{{44.78, 41.70}, {44.82, 41.70}, {44.82, 41.73}, {44.78, 41.73}, {44.78, 41.70}}}},
		"lower_m":  0, "lower_ref": "WGS84", "upper_m": 120, "upper_ref": "WGS84",
		"starts_at": restriction.Stamp(start), "ends_at": restriction.Stamp(start.Add(2 * time.Hour)),
		"reason_text": "Search and rescue (synthetic)",
	}
	code, out := s.c.do(http.MethodPost, "/v1/restrictions", s.watch, map[string]string{"Idempotency-Key": key}, body)
	var r restrictionWire
	if code != http.StatusCreated || json.Unmarshal(out, &r) != nil {
		s.t.Fatalf("plan: %d %s", code, out)
	}
	return r
}

func (s *deliverStack) op(id, op string, body any) restrictionWire {
	s.t.Helper()
	code, out := s.c.do(http.MethodPost, "/v1/restrictions/"+id+"/"+op, s.watch, nil, body)
	var r restrictionWire
	if code != http.StatusOK || json.Unmarshal(out, &r) != nil {
		s.t.Fatalf("%s: %d %s", op, code, out)
	}
	return r
}

// changedAt is the database's changed_at of a version.
func (s *deliverStack) changedAt(id string, v int64) time.Time {
	s.t.Helper()
	code, out := s.c.do(http.MethodGet, fmt.Sprintf("/v1/restrictions/%s/versions/%d", id, v), s.watch, nil, nil)
	var ver struct {
		ChangedAt time.Time `json:"changed_at"`
	}
	if code != http.StatusOK || json.Unmarshal(out, &ver) != nil {
		s.t.Fatalf("version: %d %s", code, out)
	}
	return ver.ChangedAt
}

// verifyPublication checks a CISP request as the CISP does: the client
// certificate, the bearer for the CISP's host with the publish scope,
// the detached JWS over the exact body with the served JWKS (core's
// DetachedVerifier: b64 false, crit, kid, iat fresh), and the closed
// generated body.
func (s *deliverStack) verifyPublication(r peerRequest, into any) {
	s.t.Helper()
	if r.ClientSubject != s.subject {
		s.t.Fatalf("client certificate subject %q, want %q", r.ClientSubject, s.subject)
	}
	if want := "Bearer tok-" + s.cisp.host() + "-" + deliver.ScopePublish; r.Header.Get("Authorization") != want {
		s.t.Fatalf("bearer %q", r.Header.Get("Authorization"))
	}
	v, err := coreauth.NewDetachedVerifier(s.ctx, coreauth.DetachedConfig{Publishers: map[string]coreauth.IssuerConfig{"ansp-01": {JWKSURL: s.jwksURL()}}})
	if err != nil {
		s.t.Fatal(err)
	}
	sig, err := v.Verify(s.ctx, "ansp-01", r.Header.Get(deliver.HeaderSignature), r.Body)
	if err != nil {
		s.t.Fatalf("the CISP refuses the signature: %v", err)
	}
	if time.Since(sig.IssuedAt) > time.Minute {
		s.t.Fatalf("iat %v", sig.IssuedAt)
	}
	h, err := coreauth.ParseDetachedHeader(r.Header.Get(deliver.HeaderSignature))
	if err != nil || h.KID == "" {
		s.t.Fatalf("header %+v %v", h, err)
	}
	strict(s.t, r.Body, into)
}

// awaitBody waits for a restr.v1 body that pred accepts.
func (s *deliverStack) awaitBody(within time.Duration, pred func(map[string]any) bool) map[string]any {
	s.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case b := <-s.restr:
			if pred(b) {
				return b
			}
		case <-deadline:
			s.t.Fatal("no such restr.v1 message")
		}
	}
}

func (s *deliverStack) deliveries(query string, args ...any) int {
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

// The publication path end to end: plan, activate, extend and end each
// reach the CISP once, signed, over mTLS, with the pair (ansp_ref,
// ansp_version) in the body; the commit-to-wire latency of the
// activation is measured; published_version and restr.v1 say
// published; a replayed message sends nothing; a cancelled planned
// restriction sends the CISP its cancel and nothing to the DSS; the
// heartbeat carries the active ansp_ref; a row whose publish was lost is
// published by the outbox scan and delivered.
func TestIntegrationDeliverToTheCISP(t *testing.T) {
	s := newDeliverStack(t)
	hb := s.cisp.await(t, deliver.PathHeartbeat, 1, 10*time.Second)
	if hb.ClientSubject != s.subject || !strings.Contains(string(hb.Body), `"active_refs":[]`) {
		t.Fatalf("first heartbeat %s from %q", hb.Body, hb.ClientSubject)
	}

	r := s.plan("wp8-1")
	req := s.cisp.await(t, "/v1/restrictions", 1, 5*time.Second)
	var create cispclient.RestrictionCreate
	s.verifyPublication(req, &create)
	if req.Method != http.MethodPost || create.AnspRef != r.AnspRef || create.AnspVersion != 1 || create.State != cispclient.RestrictionCreateStatePlanned {
		t.Fatalf("create %s %s", req.Method, req.Body)
	}

	r = s.op(r.ID, "activate", map[string]string{"reason": "rescue helicopter on scene"})
	req = s.cisp.await(t, "/v1/restrictions", 2, 5*time.Second)
	var patch cispclient.RestrictionPatch
	s.verifyPublication(req, &patch)
	if req.Method != http.MethodPatch || req.Query != "by=ansp_ref" || patch.Op != cispclient.RestrictionPatchOpActivate || patch.AnspVersion != 2 {
		t.Fatalf("activate %s %s %s", req.Method, req.Query, req.Body)
	}
	if req.Path != "/v1/restrictions/"+r.AnspRef {
		t.Fatalf("path %s", req.Path)
	}
	lag := req.At.Sub(s.changedAt(r.ID, 2))
	t.Logf("commit-to-wire latency of the activation (version changed_at, database clock, to the CISP's receipt): %v (budget 200 ms)", lag)
	if lag > 2*time.Second {
		t.Fatalf("the activation reached the CISP %v after its commit", lag)
	}
	s.awaitBody(5*time.Second, func(b map[string]any) bool { return b["published"] == true && b["ansp_version"] == 2.0 })

	end := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	s.op(r.ID, "extend", map[string]string{"reason": "search area widened", "ends_at": restriction.Stamp(end)})
	req = s.cisp.await(t, "/v1/restrictions", 3, 5*time.Second)
	patch = cispclient.RestrictionPatch{}
	s.verifyPublication(req, &patch)
	if patch.Op != cispclient.RestrictionPatchOpExtend || patch.AnspVersion != 3 || patch.EndsAt == nil || !patch.EndsAt.Equal(end) || patch.Feature == nil {
		t.Fatalf("extend %s", req.Body)
	}
	s.op(r.ID, "end", map[string]string{"reason": "rescue complete"})
	req = s.cisp.await(t, "/v1/restrictions", 4, 5*time.Second)
	patch = cispclient.RestrictionPatch{}
	s.verifyPublication(req, &patch)
	if patch.Op != cispclient.RestrictionPatchOpEnd || patch.AnspVersion != 4 {
		t.Fatalf("end %s", req.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, out := s.c.do(http.MethodGet, "/v1/restrictions/"+r.ID, s.watch, nil, nil)
		var got struct {
			PublishedVersion *int64          `json:"published_version"`
			Deliveries       deliver.Summary `json:"deliveries"`
		}
		_ = json.Unmarshal(out, &got)
		if code == http.StatusOK && got.PublishedVersion != nil && *got.PublishedVersion == 4 && got.Deliveries.CISP.State == "sent" && got.Deliveries.CISP.Attempts == 1 {
			validateResponse(t, http.MethodGet, "/v1/restrictions/{id}", code, out)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restriction %d %s", code, out)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// A replayed job after sent: no second request.
	var actID string
	_ = s.db.Do(s.ctx, func(ctx context.Context, db relational.DBTX, _ *relational.Queries) error {
		return db.QueryRow(ctx, `SELECT id FROM deliveries WHERE restriction_id = $1 AND ansp_version = 2`, r.ID).Scan(&actID)
	})
	data, _ := json.Marshal(deliver.Message{ID: actID, Kind: deliver.KindCISPPublish, Seq: 99})
	if _, err := s.b.JetStream().Publish(s.ctx, deliver.Subject(deliver.KindCISPPublish), data); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if n := len(s.cisp.requests("/v1/restrictions")); n != 4 {
		t.Fatalf("the replay was sent: %d requests", n)
	}
	if !strings.Contains(s.logs.String(), "the job is settled; the message is acknowledged without a request") {
		t.Fatal("the replay is not logged")
	}

	// A cancelled planned restriction: the CISP cancel, and nothing to
	// the DSS (WP-9's channel has no job).
	r2 := s.plan("wp8-2")
	s.cisp.await(t, "/v1/restrictions", 5, 5*time.Second)
	s.op(r2.ID, "cancel", map[string]string{"reason": "planned in error"})
	req = s.cisp.await(t, "/v1/restrictions", 6, 5*time.Second)
	patch = cispclient.RestrictionPatch{}
	s.verifyPublication(req, &patch)
	if patch.Op != cispclient.RestrictionPatchOpCancel || patch.AnspVersion != 2 {
		t.Fatalf("cancel %s", req.Body)
	}
	if n := s.deliveries(`SELECT count(*) FROM deliveries WHERE restriction_id = $1 AND kind IN ('dss_put', 'dss_delete', 'uss_notify')`, r2.ID); n != 0 {
		t.Fatalf("%d DSS jobs for a cancelled planned restriction", n)
	}

	// The heartbeat carries the active ansp_ref (a third restriction,
	// active; within one 15 s period).
	r3 := s.plan("wp8-3")
	s.op(r3.ID, "activate", map[string]string{"reason": "second area"})
	deadline = time.Now().Add(17 * time.Second)
	for !strings.Contains(string(s.cisp.requests(deliver.PathHeartbeat)[len(s.cisp.requests(deliver.PathHeartbeat))-1].Body), r3.AnspRef) {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat with the active ansp_ref")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st, why := probe(s.dw, depCISPPublisher); st != obs.StateOK || !strings.Contains(why, "last heartbeat 204") {
		t.Fatalf("readiness %s %s", st, why)
	}
	if !strings.Contains(s.logs.String(), `"msg":"deliver: cisp heartbeat","process":"api"`) && !strings.Contains(s.logs.String(), `"deliver: cisp heartbeat"`) {
		t.Fatal("204 not logged")
	}

	// The outbox scan publishes a queued row whose publish was lost
	// (written directly, never published) and the worker delivers it.
	body, _ := json.Marshal(map[string]any{"schema": "cis/change/v1", "msg_id": "01K6P0A2C4E6G8J0K2M4N6P8Q9", "dataset": "restrictions"})
	err := store.DeliverRepo{DB: s.db}.Tx(s.ctx, func(ctx context.Context, tx deliver.Tx) error {
		_, err := tx.Insert(ctx, deliver.Job{ID: "01K6P0A2C4E6G8J0K2M4N6P8Q9", Kind: deliver.KindDirect, RestrictionID: r3.ID, AnspRef: r3.AnspRef,
			AnspVersion: 2, Op: deliver.OpNotify, Target: s.ussps[0].srv.URL, Body: body}, 10, time.Hour)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got := s.ussps[0].await(t, deliver.PathNotifications, 1, 15*time.Second)
	if got.Header.Get("Content-Type") != deliver.ContentTypeJOSE {
		t.Fatalf("scan delivery %v", got.Header)
	}
	if !strings.Contains(s.logs.String(), "published by the outbox scan") {
		t.Fatal("the repaired gap is not logged")
	}
	if n := s.deliveries(`SELECT count(*) FROM deliveries WHERE id = '01K6P0A2C4E6G8J0K2M4N6P8Q9' AND state = 'sent' AND bus_seq = 1`); n != 1 {
		t.Fatal("the scanned row is not sent")
	}
}

// probe is one readiness line of the outbox.
func probe(dw *deliverWiring, name string) (obs.State, string) {
	for _, c := range dw.checks {
		if c.Name == name {
			return c.Probe(context.Background())
		}
	}
	return "", "no check " + name
}

// The CISP down for 15 s: the publication is retried and counted, the
// readiness says unreachable since T (never lost); the alarm fires at
// cisp_alarm_after_s (10 s) on restr.v1; both USSPs and the authority
// receive the signed change at /v1/cis/notifications as
// application/jose, verified with the served JWKS, aud their host, sub
// the restriction id. The CISP returns: the publication goes, the alarm
// clears with its duration, the direct job still queued (a USSP that
// answers 503) is superseded_by_cisp. Then a 400 from the CISP is
// failed, not retried, with an alarm a watch supervisor acknowledges.
func TestIntegrationDegradedPathAndReconciliation(t *testing.T) {
	s := newDeliverStack(t)
	r := s.plan("wp8-d1")
	s.cisp.await(t, "/v1/restrictions", 1, 5*time.Second)
	var down atomic.Bool
	s.cisp.answer.Store(func(req peerRequest) int {
		if down.Load() {
			return http.StatusServiceUnavailable
		}
		switch {
		case req.Path == deliver.PathHeartbeat:
			return http.StatusNoContent
		case req.Method == http.MethodPost:
			if strings.Contains(string(req.Body), "refuse-me") {
				return http.StatusBadRequest
			}
			return http.StatusCreated
		}
		return http.StatusOK
	})
	s.ussps[1].answer.Store(func(peerRequest) int { return http.StatusServiceUnavailable })
	down.Store(true)
	s.op(r.ID, "activate", map[string]string{"reason": "rescue helicopter on scene"})
	activatedAt := s.changedAt(r.ID, 2)

	alarm := s.awaitBody(20*time.Second, func(b map[string]any) bool {
		a, ok := b["alarm"].(map[string]any)
		return ok && a["kind"] == "cisp_not_published" && a["state"] == "open"
	})["alarm"].(map[string]any)
	raised, _ := time.Parse(time.RFC3339Nano, alarm["raised_at"].(string))
	t.Logf("cisp_not_published raised %v after the activation's commit (cisp_alarm_after_s 10)", raised.Sub(activatedAt))
	if d := raised.Sub(activatedAt); d < 10*time.Second || d > 13*time.Second {
		t.Fatalf("the alarm fired %v after the activation", d)
	}
	if !strings.Contains(alarm["detail"].(string), "not yet published to the CISP since") {
		t.Fatalf("detail %v", alarm["detail"])
	}
	for _, p := range []*peer{s.ussps[0], s.ussps[1], s.authority} {
		req := p.await(t, deliver.PathNotifications, 1, 10*time.Second)
		if req.Header.Get("Content-Type") != deliver.ContentTypeJOSE || req.Header.Get("Authorization") != "" {
			t.Fatalf("%s: %v", p.host(), req.Header)
		}
		v, err := coreauth.NewCompactVerifier(s.ctx, coreauth.CompactConfig{
			Issuers:   map[string]coreauth.IssuerConfig{"https://ansp.test": {JWKSURL: s.jwksURL()}},
			Audiences: []string{p.host()}})
		if err != nil {
			t.Fatal(err)
		}
		cl, body, err := v.Verify(s.ctx, string(req.Body))
		if err != nil {
			t.Fatalf("%s refuses the delivery: %v", p.host(), err)
		}
		var ch cispclient.Change
		strict(t, body, &ch)
		if cl.Audience != p.host() || cl.Subject != r.ID || ch.Reason != cispclient.ChangeReasonRestrictionActivated ||
			ch.PullUrl != "https://ansp.test/v1/restrictions/"+r.ID || ch.MsgId != cl.JTI || ch.Version != 2 {
			t.Fatalf("%s: claims %+v change %+v", p.host(), cl, ch)
		}
	}
	// A heartbeat falls in the outage (every 15 s from the start): the
	// readiness says unreachable since T, never lost.
	for {
		st, why := probe(s.dw, depCISPPublisher)
		if st == obs.StateDown {
			if !strings.HasPrefix(why, "unreachable since ") || strings.Contains(strings.ToLower(why+s.logs.String()), "lost") {
				t.Fatalf("readiness while down: %q", why)
			}
			t.Logf("readiness while the CISP is down: cisp_publisher: %s", why)
			break
		}
		if time.Now().After(activatedAt.Add(15 * time.Second)) {
			t.Fatalf("no failed heartbeat in the outage: %s %s", st, why)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The CISP returns 15 s after the activation.
	time.Sleep(time.Until(activatedAt.Add(15 * time.Second)))
	down.Store(false)
	cleared := s.awaitBody(45*time.Second, func(b map[string]any) bool {
		a, ok := b["alarm"].(map[string]any)
		return ok && a["kind"] == "cisp_not_published" && a["state"] == "cleared"
	})["alarm"].(map[string]any)
	if cleared["clear_reason"] != "published" || cleared["duration_s"].(float64) < 15 {
		t.Fatalf("cleared %v", cleared)
	}
	t.Logf("cisp_not_published cleared after %.3f s", cleared["duration_s"])
	attempts := s.deliveries(`SELECT count(*) FROM delivery_attempts a JOIN deliveries d ON d.id = a.delivery_id
		WHERE d.restriction_id = $1 AND d.ansp_version = 2 AND d.kind = 'cisp_publish'`, r.ID)
	if attempts < 2 {
		t.Fatalf("%d attempts logged for the activation", attempts)
	}
	if n := s.deliveries(`SELECT count(*) FROM deliveries WHERE restriction_id = $1 AND kind = 'direct_degraded'
		AND state = 'cancelled' AND cancel_reason = 'superseded_by_cisp' AND target = $2`, r.ID, s.ussps[1].srv.URL); n != 1 {
		t.Fatalf("%d superseded direct jobs", n)
	}
	if !strings.Contains(s.logs.String(), `"cancel_reason":"superseded_by_cisp"`) {
		t.Fatal("the superseded job is not logged")
	}

	// A 400: failed, not retried, an alarm a person acknowledges.
	before := len(s.cisp.requests("/v1/restrictions"))
	r4 := s.planWithReason("wp8-d4", "refuse-me (synthetic)")
	s.cisp.await(t, "/v1/restrictions", before+1, 5*time.Second)
	var alarmID string
	deadline := time.Now().Add(5 * time.Second)
	for alarmID == "" {
		code, out := s.c.do(http.MethodGet, "/v1/delivery-alarms", s.watch, nil, nil)
		validateResponse(t, http.MethodGet, "/v1/delivery-alarms", code, out)
		var list struct {
			Alarms []deliver.AlarmBody `json:"alarms"`
		}
		_ = json.Unmarshal(out, &list)
		for _, a := range list.Alarms {
			if a.Kind == "delivery_failed" && a.RestrictionID == r4.ID && strings.Contains(a.Detail, "HTTP 400") {
				alarmID = a.ID
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no delivery_failed alarm: %s", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	if n := len(s.cisp.requests("/v1/restrictions")); n != before+1 {
		t.Fatalf("a 400 was retried: %d requests", n-before)
	}
	code, out := s.c.do(http.MethodPost, "/v1/delivery-alarms/"+alarmID+"/acknowledge", s.watch, nil, map[string]string{"reason": "the CISP refused the area; planned again"})
	validateResponse(t, http.MethodPost, "/v1/delivery-alarms/{id}/acknowledge", code, out)
	if code != http.StatusOK || !strings.Contains(string(out), `"state":"cleared"`) || !strings.Contains(string(out), `"acknowledged_by":"watch_supervisor"`) {
		t.Fatalf("acknowledge: %d %s", code, out)
	}
	if code, _ := s.c.do(http.MethodPost, "/v1/delivery-alarms/"+alarmID+"/acknowledge", s.watch, nil, map[string]string{"reason": "again"}); code != http.StatusConflict {
		t.Fatalf("second acknowledge: %d", code)
	}
	if n := s.deliveries(`SELECT count(*) FROM events WHERE entity_type = 'delivery_alarm' AND entity_id = $1 AND event_type = 'delivery_alarm_acknowledged'`, alarmID); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
}

func (s *deliverStack) planWithReason(key, reason string) restrictionWire {
	s.t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond)
	body := map[string]any{
		"uspace_airspace_id": "GEOTU01", "zone_type": "PROHIBITED",
		"geometry": map[string]any{"type": "Polygon", "coordinates": [][][2]float64{{{44.70, 41.65}, {44.74, 41.65}, {44.74, 41.68}, {44.70, 41.68}, {44.70, 41.65}}}},
		"lower_m":  0, "lower_ref": "WGS84", "upper_m": 120, "upper_ref": "WGS84",
		"starts_at": restriction.Stamp(start), "ends_at": restriction.Stamp(start.Add(2 * time.Hour)), "reason_text": reason,
	}
	code, out := s.c.do(http.MethodPost, "/v1/restrictions", s.watch, map[string]string{"Idempotency-Key": key}, body)
	var r restrictionWire
	if code != http.StatusCreated || json.Unmarshal(out, &r) != nil {
		s.t.Fatalf("plan: %d %s", code, out)
	}
	return r
}

// strict decodes body refusing unknown members (the CISP's closed
// schemas through the generated types).
func strict(t *testing.T, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("not the CISP's type: %v: %s", err, body)
	}
}
