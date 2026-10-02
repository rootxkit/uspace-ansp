package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
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

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The stub starts without NATS, stays up, answers /healthz 200 and
// /readyz 503 naming nats as down with the reason, serves /metrics, and
// drains to exit 0 when the context ends (B-08, E-02).
func TestRunServesHealthWithoutNATSAndDrains(t *testing.T) {
	addr := freeAddr(t)
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, nil, []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + addr, "ANSP_MTLS_MODE=off"}, out)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _ := get(t, "http://"+addr+"/healthz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no /healthz; log:\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, body := get(t, "http://"+addr+"/readyz")
	var rep struct {
		Process string   `json:"process"`
		Status  string   `json:"status"`
		Summary []string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatal(err)
	}
	// Every dependency is named, none hidden (E-02): the bus, the
	// database, the CIS projection, the switches and the policy.
	want := []string{
		"nats: down (ANSP_NATS_URL is not set)",
		"timeseries: down (ANSP_TIMESERIES_DSN is not set: samples are not written)",
		"cis_projection: degraded (relevance: not evaluated (no CIS projection))",
		"source_control: degraded (unknown, nothing read (every source enabled)",
		"policy: degraded (policy: defaults, KV empty)",
	}
	if code != http.StatusServiceUnavailable || rep.Process != process || rep.Status != "not_ready" || len(rep.Summary) != len(want) {
		t.Fatalf("/readyz %d %s", code, body)
	}
	for i, w := range want {
		if !strings.HasPrefix(rep.Summary[i], w) {
			t.Fatalf("/readyz check %d: %q, want %q", i, rep.Summary[i], w)
		}
	}
	if code, body := get(t, "http://"+addr+"/metrics"); code != http.StatusOK || !strings.Contains(body, "go_goroutines") {
		t.Fatalf("/metrics %d", code)
	}
	cancel()
	select {
	case c := <-done:
		if c != 0 {
			t.Fatalf("exit %d; log:\n%s", c, out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no drain")
	}
	log := out.String()
	for _, want := range []string{`"msg":"starting"`, `"msg":"draining"`, `"msg":"drained"`, `"msg":"status"`, "mTLS is off", `"process":"` + process + `"`} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %s:\n%s", want, log)
		}
	}
}

func TestRunRefusesConfiguration(t *testing.T) {
	for name, environ := range map[string][]string{
		"wrong process":    {"ANSP_PROCESS=not-" + process},
		"unknown variable": {"ANSP_PROCESS=" + process, "ANSP_MIGRATE_ON_START=true"},
	} {
		t.Run(name, func(t *testing.T) {
			out := &syncBuffer{}
			if code := run(context.Background(), nil, environ, out); code != 2 {
				t.Fatalf("exit %d; log:\n%s", code, out.String())
			}
		})
	}
}

func TestRunListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	out := &syncBuffer{}
	if code := run(context.Background(), nil, []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + ln.Addr().String(), "ANSP_MTLS_MODE=off"}, out); code != 1 {
		t.Fatalf("exit %d; log:\n%s", code, out.String())
	}
}

func TestMigrateSubcommand(t *testing.T) {
	unreachable := "postgres://u:p@127.0.0.1:1/ansp?sslmode=disable&connect_timeout=1"
	for _, tc := range []struct {
		env  []string
		args []string
		code int
		want string
	}{
		{nil, []string{"migrate", "timeseries"}, 2, `"variable":"ANSP_TIMESERIES_DSN"`},
		{nil, []string{"migrate", "relational"}, 2, "unknown tree"},
		{[]string{"ANSP_TIMESERIES_DSN=" + unreachable}, []string{"migrate", "timeseries"}, 1, `"msg":"migrate: failed","process":"manned-feed","instance":"local","tree":"timeseries"`},
		{nil, []string{"migrate"}, 2, "usage"},
		{nil, []string{"serve"}, 2, "usage"},
		{nil, []string{"migrate", "events"}, 2, "unknown tree"},
	} {
		out := &syncBuffer{}
		env := append([]string{"ANSP_PROCESS=" + process}, tc.env...)
		if code := run(context.Background(), tc.args, env, out); code != tc.code || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v: exit %d; log:\n%s", tc.args, code, out.String())
		}
		if strings.Contains(out.String(), ":p@") {
			t.Fatalf("the log repeats a password:\n%s", out.String())
		}
	}
}

// A timeseries database that cannot be reached is a refusal at start,
// not a process that serves without it.
func TestRunRefusesUnreachableDatabase(t *testing.T) {
	out := &syncBuffer{}
	env := []string{"ANSP_PROCESS=" + process, "ANSP_HTTP_ADDR=" + freeAddr(t), "ANSP_DB_ACQUIRE_TIMEOUT_S=1",
		"ANSP_TIMESERIES_DSN=postgres://u:p@127.0.0.1:1/ansp_ts?sslmode=disable"}
	if code := run(context.Background(), nil, env, out); code != 1 || !strings.Contains(out.String(), "timeseries database refused") {
		t.Fatalf("exit %d; log:\n%s", code, out.String())
	}
}
