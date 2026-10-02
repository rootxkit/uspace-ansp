package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// replayEnv is a replay adapter on the synthetic stale-then-resume file.
func replayEnv(extra ...string) []string {
	return append([]string{
		"ANSP_PROCESS=" + process, "ANSP_MTLS_MODE=off",
		"ANSP_ADAPTER_KIND=replay", "ANSP_ADAPTER_ID=replay", "ANSP_ADAPTER_SOURCE_CLASS=ads_b",
		"ANSP_ADAPTER_REPLAY_FILE=" + filepath.Join("..", "..", "testdata", "replay", "stale-then-resume.ndjson"),
		"ANSP_ADAPTER_REPLAY_ALLOWED=true", "ANSP_ADAPTER_REPLAY_SPEED=100",
	}, extra...)
}

// The process starts without NATS, stays up, answers /healthz 200 and
// /readyz 503 naming nats as down with the reason and the feed as ok
// (the replay is read), serves /metrics with the adapter's counters,
// and drains to exit 0 when the context ends (B-08, E-02).
func TestRunServesHealthWithoutNATSAndDrains(t *testing.T) {
	addr := freeAddr(t)
	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, nil, replayEnv("ANSP_HTTP_ADDR="+addr), out)
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
	if code != http.StatusServiceUnavailable || rep.Process != process || rep.Status != "not_ready" ||
		len(rep.Summary) != 2 || rep.Summary[0] != "nats: down (ANSP_NATS_URL is not set)" || rep.Summary[1] != "feed: ok" {
		t.Fatalf("/readyz %d %s", code, body)
	}
	for {
		code, body := get(t, "http://"+addr+"/metrics")
		if code == http.StatusOK && strings.Contains(body, "go_goroutines") && strings.Contains(body, "manned_adapter_normalised") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("/metrics %d %s", code, body)
		}
		time.Sleep(20 * time.Millisecond)
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
	for _, want := range []string{
		`"msg":"starting"`, `"msg":"draining"`, `"msg":"drained"`, `"msg":"status"`, "mTLS is off", `"process":"` + process + `"`,
		`"msg":"feed connected"`, `"adapter_id":"replay"`, "status says unknown, policy defaults",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %s:\n%s", want, log)
		}
	}
}

func TestRunRefusesConfiguration(t *testing.T) {
	for name, environ := range map[string][]string{
		"wrong process":      {"ANSP_PROCESS=not-" + process},
		"unknown variable":   {"ANSP_PROCESS=" + process, "ANSP_MIGRATE_ON_START=true"},
		"no adapter kind":    {"ANSP_PROCESS=" + process},
		"bad adapter id":     replayEnv("ANSP_ADAPTER_ID=Replay_1"),
		"replay not allowed": replayEnv("ANSP_ADAPTER_REPLAY_ALLOWED=false"),
		"sbs without addr":   replayEnv("ANSP_ADAPTER_KIND=dump1090_sbs"),
		"sbs bad zone":       replayEnv("ANSP_ADAPTER_KIND=dump1090_sbs", "ANSP_ADAPTER_SBS_ADDR=127.0.0.1:30003", "ANSP_ADAPTER_SBS_TIMEZONE=Mars/Olympus"),
		"json without url":   replayEnv("ANSP_ADAPTER_KIND=dump1090_json"),
		"replay no file":     replayEnv("ANSP_ADAPTER_REPLAY_FILE="),
		"replay speed":       replayEnv("ANSP_ADAPTER_REPLAY_SPEED=0"),
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
	if code := run(context.Background(), nil, replayEnv("ANSP_HTTP_ADDR="+ln.Addr().String()), out); code != 1 {
		t.Fatalf("exit %d; log:\n%s", code, out.String())
	}
}

func TestMigrateSubcommand(t *testing.T) {
	env := replayEnv()
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"migrate", "relational", "timeseries"}, 2, "never opens PostgreSQL"},
		{[]string{"migrate"}, 2, "usage"},
		{[]string{"serve"}, 2, "usage"},
	} {
		out := &syncBuffer{}
		if code := run(context.Background(), tc.args, env, out); code != tc.code || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v: exit %d; log:\n%s", tc.args, code, out.String())
		}
	}
}

// asterix_cat021 starts, then stops at once with exit 1, naming the
// deferral: a misconfigured deployment fails loudly (WP-4).
func TestRunAsterixFailsLoudly(t *testing.T) {
	out := &syncBuffer{}
	env := replayEnv("ANSP_ADAPTER_KIND=asterix_cat021", "ANSP_HTTP_ADDR="+freeAddr(t))
	done := make(chan int, 1)
	go func() { done <- run(context.Background(), nil, env, out) }()
	select {
	case code := <-done:
		if code != 1 || !strings.Contains(out.String(), "asterix_cat021 is deferred") || !strings.Contains(out.String(), `"msg":"adapter stopped"`) {
			t.Fatalf("exit %d; log:\n%s", code, out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("still running; log:\n%s", out.String())
	}
}

// Every kind builds from its settings (presence twin of the refusals
// above).
func TestBuildEveryKind(t *testing.T) {
	for _, env := range [][]string{
		replayEnv("ANSP_ADAPTER_KIND=dump1090_sbs", "ANSP_ADAPTER_SBS_ADDR=127.0.0.1:30003", "ANSP_ADAPTER_SBS_TIMEZONE=Asia/Tbilisi"),
		replayEnv("ANSP_ADAPTER_KIND=dump1090_json", "ANSP_ADAPTER_JSON_URL=http://127.0.0.1:8080/data/aircraft.json"),
		replayEnv(),
		replayEnv("ANSP_ADAPTER_KIND=asterix_cat021"),
	} {
		cfg, err := config.LoadFrom(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		a, err := build(cfg)
		if err != nil || a.Kind() != cfg.AdapterKind {
			t.Fatal(cfg.AdapterKind, err)
		}
	}
}

// CLAUDE.md rule 6: manned-adapter never opens PostgreSQL. Its build has
// no PostgreSQL driver and no store package; api's has one (the presence
// twin, so the check can fail).
func TestNoPostgreSQLInTheBuild(t *testing.T) {
	deps := func(pkg string) string {
		goBin, err := exec.LookPath("go")
		if err != nil {
			t.Skipf("no go on PATH: %v", err)
		}
		out, err := exec.Command(goBin, "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		return string(out)
	}
	adapterDeps := deps("github.com/rootxkit/uspace-ansp/cmd/manned-adapter")
	for _, forbidden := range []string{"github.com/jackc/pgx", "github.com/rootxkit/uspace-ansp/internal/store", "github.com/lib/pq"} {
		if strings.Contains(adapterDeps, forbidden) {
			t.Errorf("manned-adapter imports %s", forbidden)
		}
	}
	if !strings.Contains(deps("github.com/rootxkit/uspace-ansp/cmd/api"), "github.com/jackc/pgx") {
		t.Fatal("the check cannot see a PostgreSQL driver where there is one")
	}
}
