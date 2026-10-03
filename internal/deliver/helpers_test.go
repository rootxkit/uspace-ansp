package deliver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/auth"
)

// The restriction of the tests (synthetic).
const (
	testRID  = "01K6P0A1B2C3D4E5F6G7H8J9KM"
	testRef  = "ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM"
	testFeat = `{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.78,41.7],[44.82,41.7],[44.82,41.73],[44.78,41.7]]]},"properties":{"identifier":"DAR7K2Q","type":"PROHIBITED","reason":["DAR"],"limitedApplicability":[{"startDateTime":"2026-10-02T12:00:00.000Z","endDateTime":"2026-10-02T16:00:00.000Z"}]}}`
)

var testStart = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func version(n int64, state string) VersionInfo {
	return VersionInfo{RestrictionID: testRID, AnspRef: testRef, Identifier: "DAR7K2Q", UspaceAirspaceID: "GEOTU01",
		Version: n, State: state, StartsAt: testStart, EndsAt: testStart.Add(4 * time.Hour), Feature: json.RawMessage(testFeat)}
}

var (
	keyOnce sync.Once
	keyRing *coreauth.KeyRing
)

// testRing is a delivery key generated at test time (CLAUDE.md rule 11).
func testRing(t testing.TB) *coreauth.KeyRing {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		sk, err := auth.NewSigningKey(k)
		if err != nil {
			panic(err)
		}
		if keyRing, err = coreauth.NewKeyRing(sk); err != nil {
			panic(err)
		}
	})
	return keyRing
}

// jwksServer serves the ring's public part on plain http to 127.0.0.1
// (core allows that for loopback only).
func jwksServer(t testing.TB, ring *coreauth.KeyRing) string {
	t.Helper()
	keys := auth.NewPublicKeys()
	if err := keys.Add("delivery", ring); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(keys)
	t.Cleanup(srv.Close)
	return srv.URL + "/.well-known/jwks.json"
}

type recorded struct {
	Method, Path, Query string
	Header              http.Header
	Body                []byte
	At                  time.Time
}

// stub is a peer recording every request and answering with answer.
type stub struct {
	mu     sync.Mutex
	reqs   []recorded
	answer func(n int, r recorded) (int, string)
	srv    *httptest.Server
	// gate, when set, holds every request until it is closed.
	gate chan struct{}
}

func newStub(t testing.TB, answer func(n int, r recorded) (int, string)) *stub {
	t.Helper()
	s := &stub{answer: answer}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body, At: time.Now()}
		s.mu.Lock()
		s.reqs = append(s.reqs, rec)
		n := len(s.reqs)
		gate := s.gate
		s.mu.Unlock()
		if gate != nil {
			<-gate
		}
		code, text := http.StatusCreated, `{"replay":false}`
		if r.Method == http.MethodPatch {
			code = http.StatusOK
		}
		if s.answer != nil {
			code, text = s.answer(n, rec)
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) requests() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.reqs...)
}

// tokens is a fake token client; deadlines records each ask's context
// deadline (zero when it had none).
type tokens struct {
	mu        sync.Mutex
	err       error
	asks      []string
	deadlines []time.Time
}

func (k *tokens) TokenFor(ctx context.Context, aud string, scopes []string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	dl, _ := ctx.Deadline()
	k.deadlines = append(k.deadlines, dl)
	k.asks = append(k.asks, aud+" "+strings.Join(scopes, " "))
	if k.err != nil {
		return "", k.err
	}
	return "test-token-for-" + aud, nil
}

// harness is the outbox with fakes around it.
type harness struct {
	t        *testing.T
	clock    *fakeClock
	repo     *fakeRepo
	bus      *fakeBus
	counters *core.Counters
	outbox   *Outbox
	events   *Events
	worker   *Worker
	cisp     *stub
	tokens   *tokens
	ring     *coreauth.KeyRing
	logs     *strings.Builder
	logMu    *sync.Mutex
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func newHarness(t *testing.T, answer func(n int, r recorded) (int, string)) *harness {
	t.Helper()
	h := &harness{t: t, clock: &fakeClock{now: testStart}, bus: &fakeBus{}, counters: &core.Counters{}, tokens: &tokens{},
		ring: testRing(t), logs: &strings.Builder{}, logMu: &sync.Mutex{}}
	h.repo = newFakeRepo(h.clock)
	logger := slog.New(slog.NewJSONHandler(lockedWriter{h.logMu, h.logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	pol := DefaultPolicy()
	pol.HTTPTimeout = 2 * time.Second
	h.outbox = &Outbox{Repo: h.repo, Bus: h.bus, Policy: pol, Logger: logger, Counters: h.counters}
	h.events = &Events{Repo: h.repo, Bus: h.bus, Producer: "ansp/api", Logger: logger, Counters: h.counters, Now: h.clock.Now}
	h.cisp = newStub(t, answer)
	cisp := &CISP{BaseURL: h.cisp.srv.URL, Client: NewHTTPClient(pol.HTTPTimeout, nil, nil), Tokens: h.tokens, Signer: h.ring, Policy: pol, Now: h.clock.Now}
	direct := &Direct{Issuer: "https://ansp.test", Client: NewHTTPClient(pol.HTTPTimeout, nil, nil), Signer: h.ring, Policy: pol, Now: h.clock.Now}
	h.worker = &Worker{Repo: h.repo, CISP: cisp, Direct: direct, Events: h.events, Policy: pol, Logger: logger, Counters: h.counters, Clock: h.clock.Now}
	return h
}

func (h *harness) log() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return h.logs.String()
}

// enqueue writes a cisp_publish job of version v with op in a
// transaction and publishes it.
func (h *harness) enqueue(v int64, op string) string {
	h.t.Helper()
	var id string
	err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		var err error
		id, _, err = h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: testRID, AnspRef: testRef, AnspVersion: v, Op: op, Target: TargetCISP})
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.outbox.Publish(context.Background(), Pending{ID: id, Kind: KindCISPPublish}); err != nil {
		h.t.Fatal(err)
	}
	return id
}

// deliver hands the newest message of id to the worker and returns it.
func (h *harness) deliver(id string) *fakeMsg {
	h.t.Helper()
	var data []byte
	for _, m := range h.bus.all() {
		if strings.HasPrefix(m.id, id+".") {
			data = m.data
		}
	}
	if data == nil {
		h.t.Fatalf("no message for %s", id)
	}
	m := &fakeMsg{data: data}
	h.worker.Handle(context.Background(), m)
	return m
}
