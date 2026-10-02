package cis_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// The notification issuer, this system's host and its lab alias.
const (
	cispIssuer = "https://cisp.example.invalid"
	ourHost    = "ansp.example.invalid"
	labAlias   = "ansp"
)

// Test keys, generated at run time (CLAUDE.md rule 11), once per binary.
var (
	keysOnce                          sync.Once
	authorityRing, anspRing, cispRing *coreauth.KeyRing
	otherRing                         *coreauth.KeyRing
)

func rings(t *testing.T) {
	t.Helper()
	keysOnce.Do(func() {
		mk := func(kid string) *coreauth.KeyRing {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			r, err := coreauth.NewKeyRing(coreauth.SigningKey{KID: kid, Key: k})
			if err != nil {
				panic(err)
			}
			return r
		}
		authorityRing, anspRing, cispRing, otherRing = mk("authority-1"), mk("ansp-1"), mk("cisp-1"), mk("other-1")
	})
}

// publisherVerifier is core's detached verifier over the test rings.
func publisherVerifier(t *testing.T) cis.PublisherVerifier {
	t.Helper()
	rings(t)
	v, err := coreauth.NewDetachedVerifier(context.Background(), coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{
			cis.PublisherAuthority: {Keys: authorityRing.JWKS()},
			cis.PublisherANSP:      {Keys: anspRing.JWKS()},
		},
		MaxAge: 366 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// fixture reads testdata/fixtures/<d>.json with cis_version set to v
// (0 keeps it).
func fixture(t *testing.T, d cis.Dataset, v int64) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/" + string(d) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if v == 0 {
		return b
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["cis_version"] = json.RawMessage(strconv.FormatInt(v, 10))
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reqLog is one request the stub received.
type reqLog struct {
	Method, Path, Query, IfNoneMatch, Auth string
	Body                                   string
}

// stubDataset is what the stub serves for one dataset.
type stubDataset struct {
	version int64
	etag    string
	body    []byte
	// sig is the publisher's X-Publisher-Signature over body ("": none).
	sig string
}

// stub is an in-test CISP (httptest, TLS) that records every request so
// presence is asserted.
type stub struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	ds      map[cis.Dataset]*stubDataset
	log     []reqLog
	down    bool
	subs    map[string]*cispclient.Subscription
	nextSub int
	// stale makes every dataset answer carry X-CIS-Stale.
	stale bool
	// tooLarge makes the next dataset answer a body of this many bytes.
	tooLarge int
}

func newStub(t *testing.T) *stub {
	t.Helper()
	rings(t)
	s := &stub{t: t, ds: map[cis.Dataset]*stubDataset{}, subs: map[string]*cispclient.Subscription{}}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// publish makes body version v of d, signed by its publisher (or not,
// or by the wrong key).
func (s *stub) publish(d cis.Dataset, v int64, body []byte, sign string) {
	s.t.Helper()
	sd := &stubDataset{version: v, etag: fmt.Sprintf("%q", fmt.Sprintf("%s:%d", d, v)), body: body}
	ring := authorityRing
	if d == cis.Restrictions {
		ring = anspRing
	}
	switch sign {
	case "publisher":
	case "other":
		ring = otherRing
	case "none":
		ring = nil
	default:
		s.t.Fatalf("sign %q", sign)
	}
	if ring != nil {
		h, err := ring.SignDetached(body, time.Now())
		if err != nil {
			s.t.Fatal(err)
		}
		sd.sig = h
	}
	s.mu.Lock()
	s.ds[d] = sd
	s.mu.Unlock()
}

// publishAll publishes the three fixtures at versions 3, 2, 7.
func (s *stub) publishAll() {
	s.t.Helper()
	for _, d := range cis.Datasets {
		s.publish(d, 0, fixture(s.t, d, 0), "publisher")
	}
	s.mu.Lock()
	s.ds[cis.USpaceAirspace].version, s.ds[cis.USSPList].version, s.ds[cis.Restrictions].version = 3, 2, 7
	for d, sd := range s.ds {
		sd.etag = fmt.Sprintf("%q", fmt.Sprintf("%s:%d", d, sd.version))
	}
	s.mu.Unlock()
}

func (s *stub) setDown(down bool) {
	s.mu.Lock()
	s.down = down
	s.mu.Unlock()
}

// requests returns the log entries whose method and path match (path ""
// matches every path).
func (s *stub) requests(method, path string) []reqLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []reqLog
	for _, r := range s.log {
		if r.Method == method && (path == "" || r.Path == path) {
			out = append(out, r)
		}
	}
	return out
}

func (s *stub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	s.log = append(s.log, reqLog{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, IfNoneMatch: r.Header.Get("If-None-Match"),
		Auth: r.Header.Get("Authorization"), Body: string(body)})
	down := s.down
	s.mu.Unlock()
	if down {
		// The CISP is gone: the connection is dropped without an answer.
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				return
			}
		}
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) >= 2 && parts[1] == "subscriptions":
		s.serveSubscriptions(w, r, parts, body)
	case len(parts) == 2 && r.Method == http.MethodGet:
		s.serveDataset(w, r, cis.Dataset(parts[1]))
	case len(parts) == 4 && parts[2] == "versions" && r.Method == http.MethodGet:
		s.serveVersion(w, cis.Dataset(parts[1]), parts[3])
	default:
		problem(w, http.StatusNotFound, "not_found")
	}
}

func problem(w http.ResponseWriter, status int, slug string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"https://schemas.uspace.ge/problems/%s","title":"x","status":%d,"detail":"stub","instance":"/","errors":[]}`, slug, status)
}

func (s *stub) serveDataset(w http.ResponseWriter, r *http.Request, d cis.Dataset) {
	s.mu.Lock()
	sd, stale, big := s.ds[d], s.stale, s.tooLarge
	s.tooLarge = 0
	s.mu.Unlock()
	if sd == nil {
		problem(w, http.StatusNotFound, "no_version")
		return
	}
	if stale {
		w.Header().Set(cis.HeaderStale, "true")
	}
	w.Header().Set("ETag", sd.etag)
	w.Header().Set(cis.HeaderVersion, strconv.FormatInt(sd.version, 10))
	if r.Header.Get("If-None-Match") == sd.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/geo+json")
	if big > 0 {
		// In 64 KiB writes: the reader stops past the bound, and a
		// write after that fails, which ends the answer.
		chunk := bytes.Repeat([]byte{'a'}, 64<<10)
		if _, err := w.Write([]byte(`{"pad":"`)); err != nil {
			return
		}
		for sent := 0; sent < big; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
		return
	}
	_, _ = w.Write(sd.body)
}

func (s *stub) serveVersion(w http.ResponseWriter, d cis.Dataset, raw string) {
	s.mu.Lock()
	sd := s.ds[d]
	s.mu.Unlock()
	if sd == nil || raw != strconv.FormatInt(sd.version, 10) {
		problem(w, http.StatusNotFound, "not_found")
		return
	}
	if sd.sig != "" {
		w.Header().Set(cis.HeaderPublisherSignature, sd.sig)
	}
	w.Header().Set(cis.HeaderVersion, raw)
	_, _ = w.Write(sd.body)
}

func (s *stub) serveSubscriptions(w http.ResponseWriter, r *http.Request, parts []string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		list := cispclient.SubscriptionList{Subscriptions: []cispclient.Subscription{}}
		for _, sub := range s.subs {
			list.Subscriptions = append(list.Subscriptions, *sub)
		}
		writeJSON(http.StatusOK, list)
	case len(parts) == 2 && r.Method == http.MethodPost:
		var c cispclient.SubscriptionCreate
		if err := json.Unmarshal(body, &c); err != nil {
			problem(w, http.StatusBadRequest, "validation")
			return
		}
		s.nextSub++
		id := fmt.Sprintf("sub-%d", s.nextSub)
		sub := &cispclient.Subscription{Id: id, ClientId: "ansp-01", CallbackUrl: c.CallbackUrl, Status: cispclient.SubscriptionStatusPendingVerification,
			CreatedAt: time.Now().UTC()}
		for _, d := range c.Datasets {
			sub.Datasets = append(sub.Datasets, cispclient.SubscriptionDatasets(d))
		}
		s.subs[id] = sub
		writeJSON(http.StatusCreated, sub)
	case len(parts) == 3:
		sub := s.subs[parts[2]]
		if sub == nil {
			problem(w, http.StatusNotFound, "not_found")
			return
		}
		if r.Method == http.MethodPatch {
			var p cispclient.SubscriptionPatch
			if err := json.Unmarshal(body, &p); err != nil {
				problem(w, http.StatusBadRequest, "validation")
				return
			}
			if p.Datasets != nil {
				sub.Datasets = nil
				for _, d := range *p.Datasets {
					sub.Datasets = append(sub.Datasets, cispclient.SubscriptionDatasets(d))
				}
			}
			sub.Status = cispclient.SubscriptionStatusPendingVerification
		}
		writeJSON(http.StatusOK, sub)
	default:
		problem(w, http.StatusMethodNotAllowed, "method")
	}
}

// forgetSubscriptions makes the CISP lose every subscription (its
// database recreated).
func (s *stub) forgetSubscriptions() {
	s.mu.Lock()
	s.subs = map[string]*cispclient.Subscription{}
	s.mu.Unlock()
}

func (s *stub) suspend(id string) {
	s.mu.Lock()
	s.subs[id].Status = cispclient.SubscriptionStatusSuspended
	s.mu.Unlock()
}

// tokens is a token source that hands out a fixed token.
type tokens struct{}

func (tokens) Token(context.Context, string, ...string) (string, error) { return "test-token", nil }

// client is a cis.Client on the stub.
func (s *stub) client(t *testing.T) *cis.Client {
	t.Helper()
	c, err := cis.NewClient(cis.ClientConfig{BaseURL: s.srv.URL, Tokens: tokens{}, HTTPClient: s.srv.Client(), Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// freePort is an address nothing listens on.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// waitFor polls cond until it holds or d passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
