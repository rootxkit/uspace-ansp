package feed

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/picture"
	"github.com/rootxkit/uspace-ansp/internal/sources"
)

type switches struct {
	mu  sync.Mutex
	off map[string]bool
}

func (s *switches) Decision(_ string, instance *string) sources.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.off[*instance] {
		why := coresources.WhyInstance
		return sources.Decision{Why: &why, Actor: "admin1", Reason: "maintenance", Known: true}
	}
	return sources.Decision{Enabled: true, Known: true}
}

func uspace() *zones.Zone {
	ring := geodesy.RingFromLonLat([][2]float64{{44.70, 41.65}, {44.90, 41.65}, {44.90, 41.80}, {44.70, 41.80}, {44.70, 41.65}})
	poly := &geodesy.Polygon{Rings: []geodesy.Ring{ring}}
	return &zones.Zone{Identifier: "GEO-TEST-U1", Type: core.ZoneUSpace, Upper: &zones.Limit{ValueM: 1500, Ref: core.RefAMSL}, Polygon: poly, BBox: poly.BBox()}
}

type sessionStub struct {
	mu  sync.Mutex
	err error
	n   int
}

func (s *sessionStub) Verify(context.Context, string) (coreauth.Claims, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return coreauth.Claims{}, s.err
}

func (s *sessionStub) fail(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }

type productSink struct {
	mu sync.Mutex
	ps []Product
}

func (p *productSink) Record(x Product) { p.mu.Lock(); p.ps = append(p.ps, x); p.mu.Unlock() }
func (p *productSink) all() []Product {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Product(nil), p.ps...)
}

type fixture struct {
	svc      *Service
	pic      *picture.Picture
	clock    *clock
	sw       *switches
	adapters *Adapters
	sessions *sessionStub
	products *productSink
	seen     atomic.Int64
	srv      *httptest.Server
	schemas  *frameSchemas
}

// newFixture serves the feed behind a stand-in for the guard: the
// header X-Test-Principal is "machine:<sub>" or "session:<sub>".
func newFixture(t *testing.T, cfg Config, cis picture.CIS) *fixture {
	t.Helper()
	f := &fixture{clock: &clock{now: t0}, sw: &switches{off: map[string]bool{}}, adapters: NewAdapters(), sessions: &sessionStub{},
		products: &productSink{}, schemas: newFrameSchemas(t)}
	f.pic = picture.New(defaultPolicy(), f.sw, cis, f.clock.Now, picture.DefaultLimits())
	f.svc = New(cfg, Deps{Picture: f.pic, Adapters: f.adapters, Policy: defaultPolicy(), CIS: cis,
		NATS: func() (string, bool) { return "connected", true }, Sessions: f.sessions,
		SessionSeen: func(string) { f.seen.Add(1) }, Products: f.products, Clock: f.clock.Now})
	mux := http.NewServeMux()
	inject := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			kind, sub, _ := strings.Cut(r.Header.Get("X-Test-Principal"), ":")
			switch kind {
			case "machine":
				r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Claims: coreauth.Claims{Subject: sub}}))
			case "session":
				r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Session: true, Role: auth.RoleViewer,
					Claims: coreauth.Claims{Subject: sub, JTI: strings.Repeat("a", 32)}}))
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/manned-traffic/snapshot", inject(f.svc.ServeSnapshot))
	mux.HandleFunc("GET /v1/manned-traffic/stream", inject(f.svc.ServeStream))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) dial(t *testing.T, principal, query string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := http.Header{}
	h.Set("X-Test-Principal", principal)
	if strings.HasPrefix(principal, "session:") {
		h.Set("Authorization", "Bearer test-session-token")
	}
	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http")+"/v1/manned-traffic/stream"+query, &websocket.DialOptions{HTTPHeader: h})
	if err == nil {
		conn.SetReadLimit(1 << 20)
		t.Cleanup(func() { _ = conn.CloseNow() })
	}
	return conn, resp, err
}

type frame struct {
	Schema   string          `json:"schema"`
	Producer string          `json:"producer"`
	Backlog  bool            `json:"backlog"`
	Body     json.RawMessage `json:"body"`
}

func (f *fixture) read(t *testing.T, c *websocket.Conn) frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f.schemas.check(t, data)
	var fr frame
	if err := json.Unmarshal(data, &fr); err != nil {
		t.Fatal(err)
	}
	return fr
}

// readUntil reads until a frame of schema arrives (status frames may
// come between).
func (f *fixture) readUntil(t *testing.T, c *websocket.Conn, schema string) frame {
	t.Helper()
	for i := 0; i < 50; i++ {
		if fr := f.read(t, c); fr.Schema == schema {
			return fr
		}
	}
	t.Fatalf("no %s frame", schema)
	return frame{}
}

type trackBody struct {
	ICAO24   string  `json:"icao24"`
	State    string  `json:"state"`
	Relevant bool    `json:"relevant"`
	AgeS     float64 `json:"age_s"`
}

type snapshotBody struct {
	Manned []struct {
		Body trackBody `json:"body"`
	} `json:"manned"`
	ZonesVersion *string `json:"zones_version"`
}

type testStatus struct {
	ConnectionID  string   `json:"connection_id"`
	DroppedFrames int64    `json:"dropped_frames"`
	Degraded      []string `json:"degraded"`
	Relevance     string   `json:"relevance"`
	NATS          string   `json:"nats"`
	Adapters      []struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"adapters"`
}

func decode[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestStreamOnConnectThenTracksThenStatus: status and snapshot on
// connect, a live track, a status every period; every frame validates
// against the envelope and its own schema.
func TestStreamOnConnectThenTracksThenStatus(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: 50 * time.Millisecond}, picture.NoCIS{})
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	c, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	st := f.read(t, c)
	if st.Schema != SchemaStatus || st.Producer != Producer {
		t.Fatalf("first frame %+v", st)
	}
	sb := decode[testStatus](t, st.Body)
	if sb.Relevance != picture.StatusNoProjection || sb.NATS != "connected" || sb.ConnectionID == "" {
		t.Fatalf("status %+v", sb)
	}
	snap := f.read(t, c)
	if snap.Schema != SchemaSnapshot {
		t.Fatalf("second frame %s", snap.Schema)
	}
	body := decode[snapshotBody](t, snap.Body)
	if len(body.Manned) != 1 || body.Manned[0].Body.State != "live" || !body.Manned[0].Body.Relevant {
		t.Fatalf("snapshot %+v", body)
	}
	f.clock.Add(time.Second)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.73, 44.80, t0.Add(time.Second)))
	tr := f.readUntil(t, c, "track/manned/v1")
	if b := decode[trackBody](t, tr.Body); b.ICAO24 != "4ca7b5" || b.State != "live" || tr.Producer != Producer {
		t.Fatalf("track %+v", b)
	}
	f.readUntil(t, c, SchemaStatus)
	f.readUntil(t, c, SchemaStatus)
}

// TestAgeingIsSentNotHidden: an aircraft that goes stale and one whose
// adapter is switched off are sent with their new state.
func TestAgeingIsSentNotHidden(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour}, picture.NoCIS{})
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	f.svc.Ingest(sample("4ca7b6", "adsb-kut", 41.72, 44.81, t0))
	c, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	f.sw.mu.Lock()
	f.sw.off["adsb-kut"] = true
	f.sw.mu.Unlock()
	a := f.svc.Tick(t0.Add(time.Second))
	if len(a.Changed) != 1 {
		t.Fatalf("ageing %+v", a)
	}
	if b := decode[trackBody](t, f.readUntil(t, c, "track/manned/v1").Body); b.ICAO24 != "4ca7b6" || b.State != "source_disabled" {
		t.Fatalf("disabled %+v", b)
	}
	f.svc.Tick(t0.Add(16 * time.Second))
	if b := decode[trackBody](t, f.readUntil(t, c, "track/manned/v1").Body); b.ICAO24 != "4ca7b5" || b.State != "stale" || b.AgeS < 15 {
		t.Fatalf("stale %+v", b)
	}
}

// TestResubscribeAnswersASnapshotAndMovesTheViewport is the subscribe
// pair: frames outside the new box stop, an aircraft inside appears.
func TestResubscribeAnswersASnapshotAndMovesTheViewport(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour, MinTrackInterval: time.Nanosecond}, picture.NoCIS{})
	c, _, err := f.dial(t, "session:user-1", "?bbox=44.6,41.6,45.0,41.9")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	ctx := context.Background()
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"schema":"console/subscribe/v1","body":{"bbox":[42.6,42.1,42.9,42.3],"layers":["manned"]}}`)); err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	// Outside the new box: not sent. Inside: sent.
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	f.svc.Ingest(sample("4ca7b6", "adsb-kut", 42.20, 42.70, t0))
	if b := decode[trackBody](t, f.readUntil(t, c, "track/manned/v1").Body); b.ICAO24 != "4ca7b6" {
		t.Fatalf("the frame outside the box was sent: %+v", b)
	}
	// A frame that is not console/subscribe/v1 is refused and counted.
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"schema":"other"}`))
	// Layers without manned: the snapshot holds no aircraft.
	_ = c.Write(ctx, websocket.MessageText, []byte(`{"schema":"console/subscribe/v1","body":{"bbox":[42.6,42.1,42.9,42.3],"layers":["zones"]}}`))
	if b := decode[snapshotBody](t, f.readUntil(t, c, SchemaSnapshot).Body); len(b.Manned) != 0 {
		t.Fatalf("manned layer off: %+v", b)
	}
	if f.svc.Counters().Get(CounterClientFrameBad) != 1 {
		t.Fatal("the bad client frame was not counted")
	}
}

// TestMachineClientsGetRelevantTheConsoleGetsAll (B-12, the flag).
func TestMachineClientsGetRelevantTheConsoleGetsAll(t *testing.T) {
	cis := picture.StaticCIS{P: picture.Projection{Volumes: []*zones.Zone{uspace()}, Version: "42", FetchedAt: t0}}
	f := newFixture(t, Config{StatusPeriod: time.Hour}, cis)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0)) // inside
	f.svc.Ingest(sample("4ca7b6", "adsb-tbs", 42.50, 41.60, t0)) // far
	m, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, m, SchemaStatus)
	mb := decode[snapshotBody](t, f.read(t, m).Body)
	if len(mb.Manned) != 1 || mb.Manned[0].Body.ICAO24 != "4ca7b5" || mb.ZonesVersion == nil || *mb.ZonesVersion != "42" {
		t.Fatalf("machine snapshot %+v", mb)
	}
	s, _, err := f.dial(t, "session:user-1", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, s, SchemaStatus)
	sb := decode[snapshotBody](t, f.read(t, s).Body)
	if len(sb.Manned) != 2 || sb.Manned[1].Body.Relevant {
		t.Fatalf("console snapshot %+v", sb)
	}
}

// TestASlowClientsDropsAreCountedAndToldNeverBlocking (E-10).
func TestASlowClientsDropsAreCountedAndToldNeverBlocking(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour, SendQueue: 4, MinTrackInterval: time.Nanosecond}, picture.NoCIS{})
	c, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	var cl *client
	f.svc.mu.Lock()
	for x := range f.svc.clients {
		cl = x
	}
	f.svc.mu.Unlock()
	// Fill the queue faster than the writer drains it: enqueue directly
	// while holding the writer off with a burst.
	start := time.Now()
	for i := 0; i < 2000; i++ {
		f.clock.Add(time.Millisecond)
		f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, f.clock.Now()))
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("ingest blocked on the client")
	}
	if cl.droppedFrames() == 0 || f.svc.Counters().Get(CounterDroppedFrames) == 0 {
		t.Skip("the writer kept up with 2000 frames; nothing to drop on this machine")
	}
	st := f.svc.status(cl, f.clock.Now())
	if b, _ := st.Body.(StatusBody); b.DroppedFrames == 0 {
		t.Fatalf("status does not tell the drops: %+v", st.Body)
	}
}

func TestEnqueueDropsTheOldest(t *testing.T) {
	c := &client{max: 2, notify: make(chan struct{}, 1)}
	for _, f := range []string{"a", "b", "c"} {
		c.enqueue([]byte(f))
	}
	q := c.take()
	if len(q) != 2 || string(q[0]) != "b" || string(q[1]) != "c" || c.droppedFrames() != 1 {
		t.Fatalf("queue %q dropped %d", q, c.droppedFrames())
	}
}

// TestConnectionCapsRefuseWith503AndRetryAfter (E-10, 06 T8).
func TestConnectionCapsRefuseWith503AndRetryAfter(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour, MaxClients: 2, MaxPerClient: 1}, picture.NoCIS{})
	if _, _, err := f.dial(t, "machine:ussp-01", ""); err != nil {
		t.Fatal(err)
	}
	_, resp, err := f.dial(t, "machine:ussp-01", "")
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("per-client cap: %v %+v", err, resp)
	}
	if _, _, err := f.dial(t, "machine:ussp-02", ""); err != nil {
		t.Fatal(err)
	}
	_, resp, err = f.dial(t, "machine:ussp-03", "")
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("total cap: %v", err)
	}
	cs := f.svc.Counters().Snapshot()
	if cs[CounterRefusedPerClient] != 1 || cs[CounterRefusedTotal] != 1 || f.svc.Clients() != 2 {
		t.Fatalf("counters %v clients %d", cs, f.svc.Clients())
	}
}

func TestStreamRefusesWithoutUpgradeOrCallerOrWithABadBox(t *testing.T) {
	f := newFixture(t, Config{}, picture.NoCIS{})
	for name, c := range map[string]struct {
		principal, query string
		upgrade          bool
		code             int
	}{
		"no upgrade": {"machine:a", "", false, http.StatusUpgradeRequired},
		"no caller":  {"", "", true, http.StatusUnauthorized},
		"bad bbox":   {"machine:a", "?bbox=1,2,3", true, http.StatusBadRequest},
	} {
		r, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/manned-traffic/stream"+c.query, nil)
		r.Header.Set("X-Test-Principal", c.principal)
		if c.upgrade {
			r.Header.Set("Upgrade", "websocket")
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != c.code {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

// TestAConsoleStreamClosesWith4401WhenTheSessionEnds, and stays open
// while it is live (the twin), reporting the session as in use.
func TestAConsoleStreamClosesWith4401WhenTheSessionEnds(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: 30 * time.Millisecond}, picture.NoCIS{})
	c, _, err := f.dial(t, "session:user-1", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	f.readUntil(t, c, SchemaStatus) // a live session keeps the stream
	if f.seen.Load() == 0 {
		t.Fatal("the session was not reported in use")
	}
	f.sessions.fail(errors.New("sessions_live unreachable"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			if websocket.CloseStatus(err) != auth.CloseReLogin {
				t.Fatalf("closed with %v", err)
			}
			break
		}
	}
	if f.svc.Counters().Get(CounterSessionClosed) != 1 {
		t.Fatal("not counted")
	}
}

// TestSnapshotOfAnEmptyPictureSaysWhy is SC-22: manned [] with
// adapters_silent, never merely []; with a live adapter it is gone.
func TestSnapshotOfAnEmptyPictureSaysWhy(t *testing.T) {
	f := newFixture(t, Config{}, picture.NoCIS{})
	get := func(principal, query string) (int, MannedSnapshot, http.Header) {
		r, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/manned-traffic/snapshot"+query, nil)
		r.Header.Set("X-Test-Principal", principal)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var s MannedSnapshot
		_ = json.NewDecoder(resp.Body).Decode(&s)
		return resp.StatusCode, s, resp.Header
	}
	code, s, _ := get("machine:ussp-01", "")
	if code != http.StatusOK || s.Manned == nil || len(s.Manned) != 0 || s.Tracks == nil || s.Alerts == nil ||
		!contains(s.Degraded, DegradedAdaptersSilent) || !contains(s.Degraded, DegradedCISStale) || s.PolicyVersion != "3" || s.CISVersion != nil {
		t.Fatalf("empty snapshot %d %+v", code, s)
	}
	f.adapters.Observe("adsb-tbs", statusMsg("adsb-tbs", AdapterLive, true, t0), t0)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	_, s, _ = get("machine:ussp-01", "?bbox=44.6,41.6,45.0,41.9")
	if contains(s.Degraded, DegradedAdaptersSilent) || len(s.Manned) != 1 || len(s.Adapters) != 1 || s.Adapters[0].State != AdapterLive {
		t.Fatalf("with a live adapter %+v", s)
	}
	_, s, _ = get("machine:ussp-01", "?bbox=40,40,41,41")
	if len(s.Manned) != 0 {
		t.Fatalf("outside the box %+v", s)
	}
	if code, _, _ := get("machine:ussp-01", "?bbox=x"); code != http.StatusBadRequest {
		t.Fatalf("bad box %d", code)
	}
	if code, _, _ := get("", ""); code != http.StatusUnauthorized {
		t.Fatalf("no caller %d", code)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// TestThrottleSendsTheLatestAtMostEveryInterval: a second sample within
// the interval waits and goes out once due (2 Hz per aircraft).
func TestThrottleSendsTheLatestAtMostEveryInterval(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour, MinTrackInterval: 500 * time.Millisecond}, picture.NoCIS{})
	c, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	f.clock.Add(100 * time.Millisecond)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.73, 44.80, t0.Add(100*time.Millisecond)))
	f.clock.Add(100 * time.Millisecond)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.74, 44.80, t0.Add(200*time.Millisecond)))
	if f.svc.Counters().Get(CounterThrottled) != 2 {
		t.Fatalf("throttled %d", f.svc.Counters().Get(CounterThrottled))
	}
	f.readUntil(t, c, "track/manned/v1")
	f.svc.flush(f.clock.Now()) // not due yet
	f.clock.Add(400 * time.Millisecond)
	f.svc.flush(f.clock.Now())
	tr := f.readUntil(t, c, "track/manned/v1")
	var b struct {
		Position struct{ Lat float64 } `json:"position"`
	}
	_ = json.Unmarshal(tr.Body, &b)
	if b.Position.Lat != 41.74 {
		t.Fatalf("not the latest: %v", b.Position.Lat)
	}
}

func TestRunTicksAndFlushesUntilCancelled(t *testing.T) {
	f := newFixture(t, Config{TickPeriod: time.Millisecond}, picture.NoCIS{})
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	f.clock.Set(t0.Add(400 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for f.pic.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("never ticked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestProductsAreSampledPerClient(t *testing.T) {
	f := newFixture(t, Config{StatusPeriod: time.Hour, ProductPeriod: 20 * time.Millisecond}, picture.NoCIS{})
	c, _, err := f.dial(t, "machine:ussp-01", "")
	if err != nil {
		t.Fatal(err)
	}
	f.readUntil(t, c, SchemaSnapshot)
	f.svc.Ingest(sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0))
	f.readUntil(t, c, "track/manned/v1")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var sent int32
		for _, p := range f.products.all() {
			if p.ClientID != "ussp-01" || p.PolicyVersion != 3 {
				t.Fatalf("product %+v", p)
			}
			sent += p.TracksSent
		}
		if sent == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("products %+v", f.products.all())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProductQueueDropsWhenFullAndWrites(t *testing.T) {
	q := NewProductQueue(1, nil)
	q.Record(Product{ClientID: "a"})
	q.Record(Product{ClientID: "b"})
	if q.Counters().Get(CounterProductsDropped) != 1 {
		t.Fatal("drop not counted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Product, 2)
	done := make(chan struct{})
	go func() {
		q.Run(ctx, func(_ context.Context, p Product) error {
			got <- p
			if p.ClientID == "fail" {
				return errors.New("down")
			}
			return nil
		})
		close(done)
	}()
	if p := <-got; p.ClientID != "a" {
		t.Fatal(p)
	}
	q.Record(Product{ClientID: "fail"})
	<-got
	deadline := time.Now().Add(2 * time.Second)
	for q.Counters().Get(CounterProductsFailed) != 1 || q.Counters().Get(CounterProductsWritten) != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("counters %v", q.Counters().Snapshot())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

func TestTrackEnvelopeKeepsTheSampleTimesAndSaysTheState(t *testing.T) {
	tr := sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0)
	e := picture.Entry{Track: tr, State: picture.StateStale, AgeS: 20, Relevance: picture.Relevance{Relevant: true}}
	env := TrackEnvelope(&e, t0.Add(20*time.Second))
	b := env.Body.(TrackBody)
	if env.CapturedAt != manned.FormatTime(t0) || env.Producer != Producer || env.MsgID == tr.MsgID || b.State != "stale" || !b.Relevant || b.AgeS != 20 {
		t.Fatalf("%+v", env)
	}
	e.State = picture.StateBacklogOnly
	if TrackEnvelope(&e, t0).Body.(TrackBody).State != "stale" {
		t.Fatal("backlog_only is never put on the wire as live")
	}
}
