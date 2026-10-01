package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func cfg() config.Config {
	return config.Config{Process: "api", Instance: "i-1", LogLevel: "info", HTTPAddr: "127.0.0.1:0", MTLSMode: config.MTLSRequired}
}

func TestLoggerCarriesProcessAndInstance(t *testing.T) {
	var buf bytes.Buffer
	c := cfg()
	c.LogLevel = "warn"
	l := LoggerTo(&buf, c)
	l.Info("hidden")
	l.Warn("shown", "icao24", "4b1801")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("%v: %q", err, buf.String())
	}
	if line["msg"] != "shown" || line["process"] != "api" || line["instance"] != "i-1" || line["icao24"] != "4b1801" {
		t.Fatalf("line %v", line)
	}
	c.LogLevel = "nonsense"
	buf.Reset()
	LoggerTo(&buf, c).Info("info is the fallback")
	if !strings.Contains(buf.String(), "info is the fallback") {
		t.Fatal("fallback level is not info")
	}
	if Logger(cfg()) == nil {
		t.Fatal("nil logger")
	}
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// Every core.Counters name is a Prometheus counter of the same name,
// including one first incremented after registration (E-09).
func TestCounters(t *testing.T) {
	reg := Metrics()
	var c core.Counters
	c.Add("rejected_backlog", 3)
	if err := Counters(reg, "", &c); err != nil {
		t.Fatal(err)
	}
	var d core.Counters
	d.Inc("dropped")
	if err := Counters(reg, "ansp_bus", &d); err != nil {
		t.Fatal(err)
	}
	c.Inc("stalled")
	body := scrape(t, MetricsHandler(reg))
	for _, want := range []string{"\nrejected_backlog 3\n", "\nstalled 1\n", "\nansp_bus_dropped 1\n", "# TYPE rejected_backlog counter", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q:\n%s", want, body)
		}
	}
	// A name that is not a metric name is reported, and the rest served.
	c.Inc("bad-name")
	rec := httptest.NewRecorder()
	MetricsHandler(reg).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "\nstalled 1\n") {
		t.Fatalf("a bad name hid the rest:\n%s", rec.Body.String())
	}
	if _, err := reg.Gather(); err == nil || !strings.Contains(err.Error(), "bad-name") {
		t.Fatalf("gather error %v", err)
	}
}

func TestTracer(t *testing.T) {
	tr, stop, err := Tracer(context.Background(), cfg())
	if err != nil || tr == nil {
		t.Fatal(err)
	}
	if err := stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := cfg()
	c.OTLPEndpoint = "http://127.0.0.1:1/v1/traces"
	tr, stop, err = Tracer(context.Background(), c)
	if err != nil || tr == nil {
		t.Fatal(err)
	}
	_, span := tr.Start(context.Background(), "probe")
	span.End()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = stop(ctx) // the endpoint is closed; shutting down must still return
}

func probe(s State, reason string) func(context.Context) (State, string) {
	return func(context.Context) (State, string) { return s, reason }
}

func TestReadiness(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	h := &Health{Process: "api", Instance: "i-1", Timeout: 50 * time.Millisecond, Now: func() time.Time { return now }}
	slow := func(ctx context.Context) (State, string) {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		return StateOK, ""
	}
	for _, tc := range []struct {
		name    string
		checks  []Check
		code    int
		summary []string
	}{
		{"all ok", []Check{{DepNATS, true, probe(StateOK, "")}, {DepRelational, true, probe(StateOK, "")}}, 200,
			[]string{"nats: ok", "relational: ok"}},
		{"required degraded is ready", []Check{{DepNATS, true, probe(StateDegraded, "draining")}}, 200,
			[]string{"nats: degraded (draining)"}},
		{"required down", []Check{{DepNATS, true, probe(StateDown, "reconnecting")}, {DepDSS, false, probe(StateOK, "")}}, 503,
			[]string{"nats: down (reconnecting)", "dss: ok"}},
		{"optional down is listed and ready", []Check{{DepNATS, true, probe(StateOK, "")}, {DepJWKS, false, probe(StateDown, "fetch failed")}}, 200,
			[]string{"nats: ok", "jwks: down (fetch failed)"}},
		{"timeout", []Check{{DepCISP, true, slow}}, 503, []string{"cisp: down (check did not answer within 50ms)"}},
		{"no probe", []Check{{DepTimeseries, true, nil}}, 503, []string{"timeseries: down (no probe)"}},
		{"unknown state", []Check{{DepNATS, true, probe("up", "")}}, 503, []string{"nats: down (probe returned the unknown state up)"}},
		{"nothing to check", nil, 200, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Readiness(tc.checks...).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			var rep Report
			if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.code || !slices.Equal(rep.Summary, tc.summary) || len(rep.Checks) != len(tc.checks) ||
				!rep.CheckedAt.Equal(now) || rep.Process != "api" || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLiveness(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Health{Process: "manned-feed", Instance: "x"}).Liveness().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"alive"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// The default timeout and clock are used when unset.
	if rep := (&Health{}).Check(context.Background(), Check{DepNATS, true, probe(StateOK, "")}); rep.Status != StatusReady || rep.CheckedAt.IsZero() {
		t.Fatalf("%+v", rep)
	}
}

// Serve answers on its address, logs the status every period (and mTLS
// off at error level every period, M25), and drains on cancel.
func TestServe(t *testing.T) {
	c := cfg()
	c.MTLSMode = config.MTLSOff
	logs := &syncBuffer{}
	addrCh := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, "finished")
	})
	s := &Server{
		Config: c, Logger: LoggerTo(logs, c), Registry: Metrics(), Mux: mux,
		Checks:       []Check{{DepNATS, true, probe(StateDown, "reconnecting")}},
		StatusPeriod: 20 * time.Millisecond, DrainTimeout: 2 * time.Second,
		ready: func(a string) { addrCh <- a },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	addr := <-addrCh
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d", resp.StatusCode)
	}
	time.Sleep(60 * time.Millisecond)
	// A request in flight when the drain starts still finishes.
	slowDone := make(chan string, 1)
	go func() {
		r, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			slowDone <- err.Error()
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		slowDone <- string(b)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-slowDone; got != "finished" {
		t.Fatalf("in-flight request: %q", got)
	}
	log := logs.String()
	if n := strings.Count(log, "mTLS is off"); n < 2 {
		t.Fatalf("mTLS off logged %d times:\n%s", n, log)
	}
	if !strings.Contains(log, `"checks":["nats: down (reconnecting)"]`) || !strings.Contains(log, `"level":"WARN","msg":"status"`) {
		t.Fatalf("status line:\n%s", log)
	}
	if !strings.Contains(log, `"msg":"drained"`) {
		t.Fatalf("no drain:\n%s", log)
	}
}

// With every check ok the status line is at info level and mTLS
// required logs nothing about it (E-02: the healthy branch, read).
func TestServeHealthyStatus(t *testing.T) {
	c := cfg()
	logs := &syncBuffer{}
	addrCh := make(chan string, 1)
	s := &Server{Config: c, Logger: LoggerTo(logs, c), Registry: Metrics(),
		Checks: []Check{{DepNATS, true, probe(StateOK, "")}}, ready: func(a string) { addrCh <- a }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	<-addrCh
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(logs.String(), `"msg":"status"`); {
		if time.Now().After(deadline) {
			t.Fatal("no status line")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	log := logs.String()
	if !strings.Contains(log, `"level":"INFO","msg":"status","process":"api","instance":"i-1","status":"ready","checks":["nats: ok"]`) || strings.Contains(log, "mTLS") {
		t.Fatalf("log:\n%s", log)
	}
}

func TestServeListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := cfg()
	c.HTTPAddr = ln.Addr().String()
	s := &Server{Config: c, Logger: LoggerTo(io.Discard, c), Registry: Metrics()}
	if err := s.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "ANSP_HTTP_ADDR") {
		t.Fatalf("got %v", err)
	}
}

func TestCheckCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := func(ctx context.Context) (State, string) {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		return StateOK, ""
	}
	rep := (&Health{}).Check(ctx, Check{DepNATS, true, slow})
	if rep.Summary[0] != "nats: down (check cancelled)" {
		t.Fatalf("%v", rep.Summary)
	}
}
