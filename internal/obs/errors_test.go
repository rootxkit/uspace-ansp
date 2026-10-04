package obs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// errorsMux serves the four answers ServerErrors tells apart.
func errorsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/things", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("answer") {
		case "created":
			w.WriteHeader(http.StatusCreated)
		case "refused":
			apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("Idempotency-Key", "is not a key")))
		case "unavailable":
			apierr.WriteError(w, r, apierr.Unavailable(time.Second, "later"))
		case "internal":
			// A database error that is no refusal (the 500 of
			// ussp-wp12-restriction).
			apierr.WriteError(w, r, errors.New(`ERROR: new row violates check constraint "restrictions_idempotency_key_check" (SQLSTATE 23514)`))
		case "internal-written":
			apierr.WriteInternal(w, r, errors.New("the store answered nonsense"))
		case "internal-unnoted":
			apierr.WriteError(w, r, apierr.Internal())
		}
	})
	mux.HandleFunc("GET /v1/panic", func(http.ResponseWriter, *http.Request) { panic("a nil map") })
	mux.HandleFunc("GET /v1/panic-after-write", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"half":`)
		_ = http.NewResponseController(w).Flush()
		panic("half way")
	})
	return mux
}

func post(t *testing.T, base, answer string) int {
	t.Helper()
	resp, err := http.Post(base+"/v1/things?answer="+answer+"&secret=hunter2", "application/json", strings.NewReader(`{"password":"hunter2"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// A 500 is logged once at error level with its route and cause and
// counted; nothing of the query or body is logged.
func TestServerErrorsLogsAndCountsA500(t *testing.T) {
	logs := &syncBuffer{}
	var c core.Counters
	srv := httptest.NewServer(ServerErrors(LoggerTo(logs, cfg()), &c)(errorsMux()))
	defer srv.Close()

	if code := post(t, srv.URL, "internal"); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	log := logs.String()
	if strings.Count(log, MsgInternalError) != 1 || c.Get(CounterInternalErrors) != 1 {
		t.Fatalf("one line and one count, got %d and %d:\n%s", strings.Count(log, MsgInternalError), c.Get(CounterInternalErrors), log)
	}
	for _, want := range []string{`"level":"ERROR"`, `"method":"POST"`, `"route":"POST /v1/things"`, `"path":"/v1/things"`, `"status":500`, `restrictions_idempotency_key_check`, `"process":"api"`} {
		if !strings.Contains(log, want) {
			t.Fatalf("no %s in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "hunter2") {
		t.Fatalf("the query or body was logged:\n%s", log)
	}

	if code := post(t, srv.URL, "internal-written"); code != http.StatusInternalServerError || !strings.Contains(logs.String(), "the store answered nonsense") {
		t.Fatalf("WriteInternal: %d\n%s", code, logs.String())
	}
	// A 500 with no cause noted is still logged and counted, and says so.
	if code := post(t, srv.URL, "internal-unnoted"); code != http.StatusInternalServerError || !strings.Contains(logs.String(), `"error":"not noted"`) {
		t.Fatalf("unnoted: %d\n%s", code, logs.String())
	}
	if c.Get(CounterInternalErrors) != 3 {
		t.Fatalf("counted %d", c.Get(CounterInternalErrors))
	}
}

// The absence half: a success, a refusal and a 503 are neither logged
// nor counted as internal errors.
func TestServerErrorsLeavesOtherAnswers(t *testing.T) {
	logs := &syncBuffer{}
	var c core.Counters
	srv := httptest.NewServer(ServerErrors(LoggerTo(logs, cfg()), &c)(errorsMux()))
	defer srv.Close()
	for answer, want := range map[string]int{"created": http.StatusCreated, "refused": http.StatusBadRequest, "unavailable": http.StatusServiceUnavailable} {
		if code := post(t, srv.URL, answer); code != want {
			t.Fatalf("%s: %d", answer, code)
		}
	}
	if strings.Contains(logs.String(), MsgInternalError) || c.Get(CounterInternalErrors) != 0 {
		t.Fatalf("a non-500 was logged or counted (%d):\n%s", c.Get(CounterInternalErrors), logs.String())
	}
	// The same server does log a 500 (the pair's presence).
	if post(t, srv.URL, "internal"); c.Get(CounterInternalErrors) != 1 {
		t.Fatal("the 500 after them was not counted")
	}
}

// A panic is recovered as 500 internal, logged with its stack and
// counted; one after the header is written is logged with that status,
// counted, and aborts the connection so the client sees a transport
// error, not a truncated 200.
func TestServerErrorsRecoversAPanic(t *testing.T) {
	logs := &syncBuffer{}
	var c core.Counters
	srv := httptest.NewServer(ServerErrors(LoggerTo(logs, cfg()), &c)(errorsMux()))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/panic")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("Content-Type") != "application/problem+json" ||
		!strings.Contains(string(body), "problems/internal") {
		t.Fatalf("%d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	log := logs.String()
	if !strings.Contains(log, `"error":"panic: a nil map"`) || !strings.Contains(log, `"stack":"goroutine`) || !strings.Contains(log, `"route":"GET /v1/panic"`) ||
		c.Get(CounterPanics) != 1 || c.Get(CounterInternalErrors) != 1 {
		t.Fatalf("panics %d, internal %d:\n%s", c.Get(CounterPanics), c.Get(CounterInternalErrors), log)
	}
	// The header and half a body are on the wire when the handler
	// panics: the client must not read that as a complete 200.
	resp, err = http.Get(srv.URL + "/v1/panic-after-write")
	if err == nil {
		body, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil {
			t.Fatalf("after write: a complete %d %q, no transport error", resp.StatusCode, body)
		}
	}
	if c.Get(CounterPanics) != 2 || c.Get(CounterInternalErrors) != 2 || !strings.Contains(logs.String(), `"status":200,"duration_ms"`) ||
		!strings.Contains(logs.String(), "panic: half way") {
		t.Fatalf("after write: panics %d, internal %d:\n%s", c.Get(CounterPanics), c.Get(CounterInternalErrors), logs.String())
	}
}

// http.ErrAbortHandler is net/http's own abort: passed on, not counted.
func TestServerErrorsPassesTheAbort(t *testing.T) {
	var c core.Counters
	h := ServerErrors(LoggerTo(io.Discard, cfg()), &c)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // the sentinel, as net/http compares it
			t.Fatalf("recovered %v", v)
		}
		if c.Get(CounterPanics) != 0 || c.Get(CounterInternalErrors) != 0 {
			t.Fatal("the abort was counted")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

// A WebSocket upgrade passes through the status writer (Hijack).
func TestServerErrorsKeepsTheUpgrade(t *testing.T) {
	var c core.Counters
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/stream", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Write(r.Context(), websocket.MessageText, []byte("hello"))
		_ = conn.Close(websocket.StatusNormalClosure, "")
	})
	srv := httptest.NewServer(ServerErrors(LoggerTo(io.Discard, cfg()), &c)(mux))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if _, msg, err := conn.Read(ctx); err != nil || string(msg) != "hello" {
		t.Fatalf("%q %v", msg, err)
	}
}

// Through Serve: a 500 on a business route is counted on /metrics.
func TestServeCountsInternalErrorsOnMetrics(t *testing.T) {
	c := cfg()
	logs := &syncBuffer{}
	addrCh := make(chan string, 1)
	s := &Server{Config: c, Logger: LoggerTo(logs, c), Registry: Metrics(), Mux: errorsMux(), ready: func(a string) { addrCh <- a }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	base := "http://" + <-addrCh
	if code := post(t, base, "internal"); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metrics, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metrics), "\nhttp_internal_errors 1\n") || !strings.Contains(logs.String(), MsgInternalError) {
		t.Fatalf("metrics:\n%s\nlog:\n%s", metrics, logs.String())
	}
}

// A Server served twice (a restart in the same process) registers its
// error counters once: the second Serve starts and /metrics still
// gathers, without a duplicate-metric error. No Mux: Serve's own routes
// go on a fresh mux each time.
func TestServeTwiceStillGathersMetrics(t *testing.T) {
	c := cfg()
	reg := Metrics()
	s := &Server{Config: c, Logger: LoggerTo(io.Discard, c), Registry: reg}
	for round := 1; round <= 2; round++ {
		addrCh := make(chan string, 1)
		s.ready = func(a string) { addrCh <- a }
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Serve(ctx) }()
		var base string
		select {
		case a := <-addrCh:
			base = "http://" + a
		case err := <-done:
			cancel()
			t.Fatalf("round %d: Serve returned %v", round, err)
		}
		s.errs.Inc(CounterInternalErrors)
		resp, err := http.Get(base + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		metrics, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("\nhttp_internal_errors %d\n", round); resp.StatusCode != http.StatusOK || !strings.Contains(string(metrics), want) {
			t.Fatalf("round %d: %d, no %q in:\n%s", round, resp.StatusCode, want, metrics)
		}
		if _, err := reg.Gather(); err != nil {
			t.Fatalf("round %d: gather: %v", round, err)
		}
	}
}
