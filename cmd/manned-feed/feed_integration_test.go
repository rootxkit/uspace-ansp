//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

// issuer is a lab token service: an RS256 key whose JWKS an httptest
// server publishes on loopback (core allows plain http there only). The
// key is generated at run time and never written anywhere.
type issuer struct {
	iss *coreauth.Issuer
	url string
}

const (
	issuerName = "https://authority.test"
	audience   = "ansp.test"
)

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := auth.NewSigningKey(k)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := coreauth.NewKeyRing(sk)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(ring.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	iss, err := ring.Issuer(issuerName)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{iss: iss, url: srv.URL + "/jwks"}
}

func (i *issuer) token(t *testing.T, sub string, scopes ...string) string {
	t.Helper()
	tok, err := i.iss.Issue(sub, audience, scopes, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// feedProcess runs manned-feed against the real NATS and a migrated
// scratch timeseries database until the test ends.
type feedProcess struct {
	addr string
	ts   string
	out  *syncBuffer
	iss  *issuer
	b    *bus.Bus
}

func startFeed(t *testing.T) *feedProcess {
	t.Helper()
	natsURL := os.Getenv("ANSP_NATS_URL")
	if natsURL == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ts := storetest.Scratch(t, store.TreeTimeseries, true)
	// The api declares the streams and buckets; here the test does.
	logger := testLogger()
	b, err := bus.ConnectWith(context.Background(), bus.Settings{URL: natsURL, Name: "feed-test"}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	p := &feedProcess{addr: freeAddr(t), ts: ts, out: &syncBuffer{}, iss: newIssuer(t), b: b}
	env := []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + p.addr, "ANSP_MTLS_MODE=off", "ANSP_NATS_URL=" + natsURL,
		"ANSP_TIMESERIES_DSN=" + ts, "ANSP_TOKEN_ISSUERS=" + issuerName + "=" + p.iss.url, "ANSP_AUDIENCES=" + audience}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(runCtx, nil, env, p.out) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("manned-feed did not drain")
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, body := get(t, "http://"+p.addr+"/readyz")
		if strings.Contains(body, `"nats: ok"`) && strings.Contains(body, `"timeseries: ok"`) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz %s; log:\n%s", body, p.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// publish puts one sample on man.v1.<adapter>.<icao24> exactly as the
// adapter does (manned.Track's own encoding).
func (p *feedProcess) publish(t *testing.T, tr manned.Track) {
	t.Helper()
	b, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.b.Conn().Publish(tr.Subject(bus.SubjectMannedPrefix), b); err != nil {
		t.Fatal(err)
	}
}

func (p *feedProcess) status(t *testing.T, adapter, state string) {
	t.Helper()
	now := time.Now().UTC()
	at := manned.FormatTime(now)
	msg := fmt.Sprintf(`{"schema":"source/status/v1","msg_id":%q,"producer":"ansp/manned-adapter","ts":null,"rx_ts":%q,"captured_at":%q,`+
		`"time_source":"system","backlog":false,"body":{"source":"ansp_feed","source_instance":%q,"state":%q,"since":%q,"age_s":0,`+
		`"disabled_by":null,"disabled_by_who":null,"counters":{"accepted":1,"refused":0},"enabled":true,"last_frame_at":%q}}`,
		manned.NewULID(now), at, at, adapter, state, at, at)
	if err := p.b.Conn().Publish(bus.SubjectSourceStatusPrefix+adapter, []byte(msg)); err != nil {
		t.Fatal(err)
	}
}

func liveSample(adapter, icao string, lat, lon float64, at time.Time) manned.Track {
	alt, gs := 1524.0, 70.0
	return manned.Track{Schema: manned.SchemaTrack, MsgID: manned.NewULID(at), Producer: manned.Producer,
		Times: core.Times{RxTS: at, CapturedAt: at, Source: core.TimeReceiver}, Trust: core.TrustSurveillance,
		Source: manned.SourceANSPFeed, SourceInstance: adapter, ICAO24: icao, Position: core.LatLon{LatDeg: lat, LonDeg: lon},
		AltPressureM: &alt, GSMS: &gs, SourceClass: manned.SourceClassADSB, PolicyVersion: 1}
}

func (p *feedProcess) snapshot(t *testing.T, token, query string) (int, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, "http://"+p.addr+"/v1/manned-traffic/snapshot"+query, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (p *feedProcess) dial(t *testing.T, token string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	c, _, err := websocket.Dial(ctx, "ws://"+p.addr+"/v1/manned-traffic/stream", &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatalf("dial: %v; log:\n%s", err, p.out.String())
	}
	c.SetReadLimit(1 << 20)
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func (p *feedProcess) rows(t *testing.T, adapter string) int64 {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), p.ts)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var n int64
	if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM manned_tracks WHERE adapter_id = $1`, adapter).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (p *feedProcess) metric(t *testing.T, name string) float64 {
	t.Helper()
	_, body := get(t, "http://"+p.addr+"/metrics")
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return f
		}
	}
	return 0
}

// frameValidator validates every frame against the envelope and the
// schema it names (schemas/, offline).
type frameValidator struct {
	envelope *jsonschema.Schema
	byName   map[string]*jsonschema.Schema
}

type offline struct{}

func (offline) Load(url string) (any, error) {
	return nil, &os.PathError{Op: "load", Path: url, Err: fs.ErrNotExist}
}

func newFrameValidator(t *testing.T) *frameValidator {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "schemas")
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(offline{})
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") || strings.HasPrefix(filepath.ToSlash(rel), "examples/") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		id, _ := doc.(map[string]any)["$id"].(string)
		return c.AddResource(id, doc)
	})
	if err != nil {
		t.Fatal(err)
	}
	v := &frameValidator{byName: map[string]*jsonschema.Schema{}}
	for _, n := range []string{"envelope/v1", "track/manned/v1", "console/status/v1", "console/snapshot/v1"} {
		s, err := c.Compile("https://schemas.uspace.ge/" + n + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if n == "envelope/v1" {
			v.envelope = s
		} else {
			v.byName[n] = s
		}
	}
	return v
}

func (v *frameValidator) check(raw []byte) (string, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	if err := v.envelope.Validate(doc); err != nil {
		return "", fmt.Errorf("envelope: %w", err)
	}
	name, _ := doc.(map[string]any)["schema"].(string)
	s, ok := v.byName[name]
	if !ok {
		return name, fmt.Errorf("unexpected schema %q", name)
	}
	return name, s.Validate(doc)
}

type wireFrame struct {
	Schema string `json:"schema"`
	RxTS   string `json:"rx_ts"`
	Body   struct {
		ICAO24        string   `json:"icao24"`
		State         string   `json:"state"`
		DroppedFrames int64    `json:"dropped_frames"`
		Degraded      []string `json:"degraded"`
	} `json:"body"`
}

// TestIntegrationFeedEndToEnd: an empty picture's snapshot says why; a
// replay adapter's samples reach a WebSocket client within 250 ms p99
// over 60 s (measured on the adapter's rx_ts, printed); every frame
// validates and dispatches on schema; a console/status/v1 arrives within
// 2 s of connect and every 2 s after; every sample sent is a row of
// manned_tracks; a token without ansp.traffic is refused 403.
func TestIntegrationFeedEndToEnd(t *testing.T) {
	p := startFeed(t)
	adapter := fmt.Sprintf("replay-e2e-%d", time.Now().UnixNano()%100000)
	token := p.iss.token(t, "ussp-geo-01", "ansp.traffic")

	// The twin pair of the scope: refused without it, served with it.
	if code, _ := p.snapshot(t, p.iss.token(t, "ussp-geo-01", "cis.read"), ""); code != http.StatusForbidden {
		t.Fatalf("without ansp.traffic: %d", code)
	}
	code, snap := p.snapshot(t, token, "")
	degraded, _ := snap["degraded"].([]any)
	manned, isList := snap["manned"].([]any)
	if code != http.StatusOK || !isList || len(manned) != 0 || !containsAny(degraded, "adapters_silent") {
		t.Fatalf("empty snapshot %d %v", code, snap)
	}

	v := newFrameValidator(t)
	c := p.dial(t, token)
	connected := time.Now()
	type got struct {
		f  wireFrame
		at time.Time
	}
	frames := make(chan got, 4096)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := c.Read(context.Background())
			at := time.Now()
			if err != nil {
				readErr <- err
				return
			}
			if _, err := v.check(data); err != nil {
				readErr <- fmt.Errorf("%w: %s", err, data)
				return
			}
			var f wireFrame
			_ = json.Unmarshal(data, &f)
			frames <- got{f: f, at: at}
		}
	}()

	const aircraft, seconds = 10, 60
	sent := 0
	var statusAt []time.Time
	var latencies []time.Duration
	var mu sync.Mutex
	stop := make(chan struct{})
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for {
			select {
			case g := <-frames:
				mu.Lock()
				switch g.f.Schema {
				case "console/status/v1":
					statusAt = append(statusAt, g.at)
				case "track/manned/v1":
					if rx, err := time.Parse(time.RFC3339Nano, g.f.RxTS); err == nil {
						latencies = append(latencies, g.at.Sub(rx))
					}
				}
				mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	start := time.Now()
	tick := time.NewTicker(100 * time.Millisecond)
	for i := 0; time.Since(start) < seconds*time.Second; i++ {
		<-tick.C
		if i%20 == 0 {
			p.status(t, adapter, "live")
		}
		now := time.Now().UTC()
		n := i % aircraft
		p.publish(t, liveSample(adapter, fmt.Sprintf("a0%04x", n), 41.70+float64(n)*0.01, 44.80, now))
		sent++
	}
	tick.Stop()
	time.Sleep(time.Second)
	close(stop)
	<-collected
	select {
	case err := <-readErr:
		t.Fatalf("stream: %v", err)
	default:
	}

	mu.Lock()
	defer mu.Unlock()
	if len(latencies) != sent {
		t.Fatalf("%d samples sent, %d track frames received", sent, len(latencies))
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50, p99, worst := sorted[len(sorted)/2], sorted[len(sorted)*99/100], sorted[len(sorted)-1]
	t.Logf("adapter rx_ts -> WS frame over %d s: n=%d p50=%v p99=%v max=%v (budget p99 <= 250ms)", seconds, len(sorted), p50, p99, worst)
	if p99 > 250*time.Millisecond {
		t.Errorf("p99 %v is over the 250 ms budget", p99)
	}
	if len(statusAt) == 0 || statusAt[0].Sub(connected) > 2*time.Second {
		t.Fatalf("no console/status/v1 within 2 s of connect: %v", statusAt)
	}
	for i := 2; i < len(statusAt); i++ { // [0] is on connect
		if gap := statusAt[i].Sub(statusAt[i-1]); gap < 1500*time.Millisecond || gap > 3*time.Second {
			t.Fatalf("status frames %v apart", gap)
		}
	}
	// Every sample is a row (B-07, B-12): count them once the writer
	// has caught up.
	deadline := time.Now().Add(20 * time.Second)
	for p.rows(t, adapter) != int64(sent) {
		if time.Now().After(deadline) {
			t.Fatalf("manned_tracks holds %d rows of %d samples; log:\n%s", p.rows(t, adapter), sent, p.out.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if v := p.metric(t, "writer_rows_written"); v < float64(sent) {
		t.Fatalf("writer_rows_written %v", v)
	}
	// With a live adapter the snapshot is no longer adapters_silent.
	_, snap = p.snapshot(t, token, "")
	if degraded, _ := snap["degraded"].([]any); containsAny(degraded, "adapters_silent") {
		t.Fatalf("still silent: %v", snap["degraded"])
	}
}

func containsAny(xs []any, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestIntegrationStalledAdapterIsNeverShownLive is SC-15 end to end: a
// replay paused 30 s on its feed clock delivers samples whose
// captured_at is 30 s old; none is shown live, the stream says stale,
// the stall counter moves, and they are still recorded. The twin: a
// fresh sample of the same aircraft is live.
func TestIntegrationStalledAdapterIsNeverShownLive(t *testing.T) {
	p := startFeed(t)
	adapter := fmt.Sprintf("replay-stall-%d", time.Now().UnixNano()%100000)
	token := p.iss.token(t, "ussp-geo-01", "ansp.traffic")
	c := p.dial(t, token)
	before := p.metric(t, "picture_arrived_stale")
	paused := time.Now().UTC().Add(-30 * time.Second)
	for i := 0; i < 5; i++ {
		p.publish(t, liveSample(adapter, "b00001", 41.7, 44.8, paused.Add(time.Duration(i)*time.Second)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	seen := 0
	for seen < 1 {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v; log:\n%s", err, p.out.String())
		}
		var f wireFrame
		_ = json.Unmarshal(data, &f)
		if f.Schema == "track/manned/v1" && f.Body.ICAO24 == "b00001" {
			if f.Body.State == "live" {
				t.Fatalf("a stalled sample was shown live: %s", data)
			}
			seen++
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.metric(t, "picture_arrived_stale") < before+5 {
		if time.Now().After(deadline) {
			t.Fatalf("picture_arrived_stale %v (before %v)", p.metric(t, "picture_arrived_stale"), before)
		}
		time.Sleep(50 * time.Millisecond)
	}
	p.publish(t, liveSample(adapter, "b00001", 41.7, 44.8, time.Now().UTC()))
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var f wireFrame
		_ = json.Unmarshal(data, &f)
		if f.Schema == "track/manned/v1" && f.Body.ICAO24 == "b00001" && f.Body.State == "live" {
			break
		}
	}
	deadline = time.Now().Add(20 * time.Second)
	for p.rows(t, adapter) != 6 {
		if time.Now().After(deadline) {
			t.Fatalf("rows %d", p.rows(t, adapter))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestIntegrationSlowClientDropsAreToldInItsStatus: a client that never
// reads while thousands of frames are offered is not waited for; its
// drops are counted and said in its next console/status/v1.
func TestIntegrationSlowClientDropsAreToldInItsStatus(t *testing.T) {
	p := startFeed(t)
	adapter := fmt.Sprintf("replay-slow-%d", time.Now().UnixNano()%100000)
	token := p.iss.token(t, "ussp-geo-02", "ansp.traffic")
	c := p.dial(t, token)
	// Many aircraft so the per-aircraft throttle passes every one.
	for i := 0; i < 20000; i++ {
		p.publish(t, liveSample(adapter, fmt.Sprintf("c%05x", i), 41.7, 44.8, time.Now().UTC()))
	}
	deadline := time.Now().Add(10 * time.Second)
	for p.metric(t, "feed_stream_dropped_frames") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no drop counted; log:\n%s", p.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var f wireFrame
		_ = json.Unmarshal(data, &f)
		if f.Schema == "console/status/v1" && f.Body.DroppedFrames > 0 {
			t.Logf("dropped_frames %d said in the status", f.Body.DroppedFrames)
			return
		}
	}
}

func testLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }
