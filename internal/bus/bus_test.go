package bus

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// The names of docs/PLAN.md section 7, listed so that a rename is a
// visible change to this test.
func TestNames(t *testing.T) {
	subjects := []string{SubjectMannedPrefix, SubjectSourceStatusPrefix, SubjectRestrictionPrefix,
		SubjectDeliverPrefix, SubjectCISPrefix, SubjectCoordPrefix, SubjectControlSources, SubjectControlPolicy}
	if want := []string{"man.v1.", "src.v1.manned.", "restr.v1.", "deliver.v1.", "cis.v1.", "coord.v1.", "ctl.sources", "ctl.policy"}; !slices.Equal(subjects, want) {
		t.Fatalf("subjects %v", subjects)
	}
	var streams []string
	for _, sc := range StreamConfigs() {
		streams = append(streams, sc.Name+" "+strings.Join(sc.Subjects, ",")+" "+sc.MaxAge.String()+" "+sc.Retention.String())
	}
	if want := []string{
		"MAN_MIRROR man.v1.> 1h0m0s Limits",
		"RESTR restr.v1.> 720h0m0s Limits",
		"DELIVER deliver.v1.> 24h0m0s WorkQueue",
		"COORD coord.v1.> 720h0m0s Limits",
	}; !slices.Equal(streams, want) {
		t.Fatalf("streams %q", streams)
	}
	var buckets []string
	for _, kc := range BucketConfigs() {
		buckets = append(buckets, kc.Bucket)
		if kc.Storage != jetstream.FileStorage {
			t.Fatalf("bucket %s is not on file storage", kc.Bucket)
		}
	}
	if want := []string{"cis_current", "source_control", "policy"}; !slices.Equal(buckets, want) {
		t.Fatalf("buckets %v", buckets)
	}
}

// syncBuffer is a log sink safe for the client's handler goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

func testLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// fakeNATS speaks just enough of the NATS client protocol (INFO, then
// PONG for every PING) for a client to count as connected.
type fakeNATS struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

func startFake(t *testing.T, addr string) *fakeNATS {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 { // the port of a stopped fake may take a moment to free
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNATS{ln: ln}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				_, _ = c.Write([]byte(`INFO {"server_id":"fake","version":"2.10.0","proto":1,"max_payload":1048576,"headers":true}` + "\r\n"))
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(line, "PING") {
						_, _ = c.Write([]byte("PONG\r\n"))
					}
				}
			}()
		}
	}()
	return f
}

func (f *fakeNATS) addr() string { return f.ln.Addr().String() }

func (f *fakeNATS) stop() {
	_ = f.ln.Close()
	f.mu.Lock()
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
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

func fast(url string) Settings {
	return Settings{URL: url, Name: "test", StartBackoff: 10 * time.Millisecond, ConnectTimeout: 200 * time.Millisecond, ReconnectWait: 20 * time.Millisecond}
}

func waitLog(t *testing.T, logs *syncBuffer, sub string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for logs.count(sub) != n {
		if time.Now().After(deadline) {
			t.Fatalf("%s logged %d times, want %d", sub, logs.count(sub), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitStatus(t *testing.T, b *Bus, want obs.State) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, reason := b.Status()
		if s == want {
			return reason
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %s (%s), want %s", s, reason, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Nothing listens: three attempts, then a degraded Bus (no error) that
// reports nats: down (reconnecting); when NATS appears it connects and
// reports ok; when NATS goes away it says reconnecting again; each
// transition is logged once (B-08, E-01, E-02).
func TestDegradedStartThenConnectThenLoseAgain(t *testing.T) {
	addr := freeAddr(t)
	logger, logs := testLogger()
	b, err := ConnectWith(context.Background(), fast("nats://"+addr), logger)
	if err != nil {
		t.Fatalf("a missing NATS must not fail the start: %v", err)
	}
	defer b.Close()
	if s, reason := b.Status(); s != obs.StateDown || reason != "reconnecting" {
		t.Fatalf("status %s (%s)", s, reason)
	}
	h := obs.Health{Process: "api", Instance: "t"}
	if rep := h.Check(context.Background(), b.Check()); rep.Status != obs.StatusNotReady || rep.Summary[0] != "nats: down (reconnecting)" {
		t.Fatalf("report %+v", rep)
	}
	if n := logs.count(`"msg":"nats: connect failed"`); n != DefaultStartAttempts {
		t.Fatalf("%d failed attempts logged, want %d", n, DefaultStartAttempts)
	}

	f := startFake(t, addr)
	waitStatus(t, b, obs.StateOK)
	if rep := h.Check(context.Background(), b.Check()); rep.Status != obs.StatusReady || rep.Summary[0] != "nats: ok" {
		t.Fatalf("report %+v", rep)
	}
	f.stop()
	if reason := waitStatus(t, b, obs.StateDown); reason != "reconnecting" {
		t.Fatalf("reason %q", reason)
	}
	// Many failed reconnect attempts happen while the fake is down; the
	// state change is logged once.
	time.Sleep(200 * time.Millisecond)
	// Logged twice: the degraded start, then the loss.
	waitLog(t, logs, `"msg":"nats: reconnecting"`, 2)
	f = startFake(t, addr)
	defer f.stop()
	waitStatus(t, b, obs.StateOK)
	// The client reports the reconnect through an asynchronous callback.
	waitLog(t, logs, `"msg":"nats: connected"`, 2)
	b.Close()
	if s, reason := b.Status(); s != obs.StateDown || reason != "closed" {
		t.Fatalf("after Close: %s (%s)", s, reason)
	}
}

// NATS is there at the first attempt: no failed attempt is logged.
func TestConnectFirstAttempt(t *testing.T) {
	f := startFake(t, "127.0.0.1:0")
	defer f.stop()
	logger, logs := testLogger()
	b, err := ConnectWith(context.Background(), fast("nats://"+f.addr()), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if s, _ := b.Status(); s != obs.StateOK {
		t.Fatalf("status %s", s)
	}
	if logs.count("connect failed") != 0 || logs.count(`"msg":"nats: connected"`) != 1 {
		t.Fatalf("unexpected log lines: %s", logs.b.String())
	}
	if b.Conn() == nil || b.JetStream() == nil {
		t.Fatal("no connection")
	}
	if err := b.Drain(); err != nil {
		t.Fatal(err)
	}
}

func TestNoURL(t *testing.T) {
	logger, logs := testLogger()
	b, err := Connect(context.Background(), config.Config{Process: "api", Instance: "t"}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if s, reason := b.Status(); s != obs.StateDown || reason != "ANSP_NATS_URL is not set" {
		t.Fatalf("status %s (%s)", s, reason)
	}
	if logs.count("ANSP_NATS_URL is not set") != 1 {
		t.Fatal("not logged")
	}
	if err := b.EnsureStreams(context.Background()); err == nil {
		t.Fatal("EnsureStreams without a connection succeeded")
	}
	if err := b.Drain(); err != nil {
		t.Fatal(err)
	}
	b.Close()
}

func TestCredsFile(t *testing.T) {
	dir := t.TempDir()
	logger, _ := testLogger()
	if _, err := ConnectWith(context.Background(), Settings{URL: "nats://127.0.0.1:1", CredsFile: filepath.Join(dir, "missing")}, logger); err == nil ||
		!strings.HasPrefix(err.Error(), "ANSP_NATS_CREDS: cannot be read") || strings.Contains(err.Error(), dir) {
		t.Fatalf("got %v", err)
	}
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ConnectWith(context.Background(), Settings{URL: "nats://127.0.0.1:1", CredsFile: junk}, logger); err == nil ||
		!strings.HasPrefix(err.Error(), "ANSP_NATS_CREDS: neither") {
		t.Fatalf("got %v", err)
	}
	// A seed file (the throwaway seed of the nkeys documentation shape,
	// generated here) is accepted and the connection proceeds.
	seed := filepath.Join(dir, "api.nk")
	if err := os.WriteFile(seed, []byte(testSeed(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	f := startFake(t, "127.0.0.1:0")
	defer f.stop()
	b, err := ConnectWith(context.Background(), Settings{URL: "nats://" + f.addr(), CredsFile: seed}, logger)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if opt, err := credsOption(""); opt != nil || err != nil {
		t.Fatal("an empty path must mean no credentials")
	}
}

func TestStartCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger, _ := testLogger()
	s := fast("nats://" + freeAddr(t))
	s.StartBackoff = time.Hour
	if _, err := ConnectWith(ctx, s, logger); err == nil {
		t.Fatal("a cancelled start returned a Bus")
	}
}

// testSeed is a user NKey seed generated for this run and discarded.
func testSeed(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return string(seed)
}

// blackhole accepts connections and never answers, so a client's
// reconnect attempt holds the connection lock until its dial timeout.
func blackhole(t *testing.T, addr string) func() {
	t.Helper()
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}
}

// Readiness answers at once while a reconnect attempt is stuck dialling
// (seen on the development stack: a probe that read the connection's
// own status waited for the dial and timed out instead of saying
// "reconnecting").
func TestStatusDoesNotWaitForAReconnectAttempt(t *testing.T) {
	f := startFake(t, "127.0.0.1:0")
	addr := f.addr()
	logger, logs := testLogger()
	s := fast("nats://" + addr)
	s.ConnectTimeout = 2 * time.Second
	b, err := ConnectWith(context.Background(), s, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	f.stop()
	waitLog(t, logs, `"msg":"nats: reconnecting"`, 1)
	stop := blackhole(t, addr)
	defer stop()
	time.Sleep(100 * time.Millisecond) // a reconnect attempt is now dialling the black hole
	for range 10 {
		start := time.Now()
		st, reason := b.Status()
		if took := time.Since(start); took > 100*time.Millisecond {
			t.Fatalf("Status took %s", took)
		}
		if st != obs.StateDown || reason != "reconnecting" {
			t.Fatalf("status %s (%s)", st, reason)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Drain while NATS is gone closes at once instead of waiting.
	if err := b.Drain(); err != nil {
		t.Fatal(err)
	}
	if st, reason := b.Status(); st != obs.StateDown || reason != "closed" {
		t.Fatalf("after Drain: %s (%s)", st, reason)
	}
}
