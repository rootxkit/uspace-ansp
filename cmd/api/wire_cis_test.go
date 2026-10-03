package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func cisProbe(t *testing.T, w *cisWiring) (obs.State, string) {
	t.Helper()
	for _, c := range w.checks {
		if c.Name == obs.DepCISP {
			return c.Probe(context.Background())
		}
	}
	t.Fatal("no cisp check")
	return "", ""
}

// Without a CISP the projection is none, every placement is refused as
// no projection, the receiver is not mounted, and the readiness line
// says why (E-02: the empty branch named, never hidden).
func TestWireCISWithoutCISP(t *testing.T) {
	w, err := wireCIS(config.Config{}, nil, nil, prometheus.NewRegistry(), discard())
	if err != nil {
		t.Fatal(err)
	}
	if w.receiver != nil {
		t.Fatal("a receiver without issuers")
	}
	if _, err := w.airspaces.Current(context.Background()); !errors.Is(err, restriction.ErrNoProjection) {
		t.Fatalf("%v", err)
	}
	st, line := cisProbe(t, w)
	if st != obs.StateDegraded || !strings.HasPrefix(line, cis.StatusNoProjection) || !strings.Contains(line, "ANSP_CISP_URL") {
		t.Fatalf("%s %s", st, line)
	}
}

// With a CISP, publisher keys and notification issuers but no database,
// the receiver is not mounted (delivery ids need it) and the checks name
// the keys; a bad publisher entry refuses the start.
func TestWireCISConfigurations(t *testing.T) {
	cfg := config.Config{
		CISPURL: "https://cisp.example.invalid", PublicBaseURL: "https://ansp.example.invalid", Audiences: []string{"ansp.example.invalid"},
		CISNotifyIssuers: []config.Issuer{{Issuer: "https://cisp.example.invalid", JWKSURL: "https://cisp.example.invalid/.well-known/jwks.json"}},
		CISPublisherKeys: []string{"authority=https://authority.example.invalid/.well-known/jwks.json"}, CISPublisherSigMaxAgeS: 3600,
	}
	w, err := wireCIS(cfg, nil, nil, prometheus.NewRegistry(), discard())
	if err != nil {
		t.Fatal(err)
	}
	if w.receiver != nil {
		t.Fatal("a receiver without the relational database")
	}
	names := map[string]bool{}
	for _, c := range w.checks {
		names[c.Name] = true
	}
	if !names[obs.DepCISP] || !names[depCISPublisherKeys] {
		t.Fatalf("checks %v", names)
	}
	for _, c := range w.checks {
		if c.Name == depCISPublisherKeys {
			if st, why := c.Probe(context.Background()); st != obs.StateDegraded || why == "" {
				t.Fatalf("keys before a fetch: %s %s", st, why)
			}
		}
	}
	bad := cfg
	bad.CISPublisherKeys = []string{"cisp=https://cisp.example.invalid/jwks"}
	if _, err := wireCIS(bad, nil, nil, prometheus.NewRegistry(), discard()); err == nil || !strings.Contains(err.Error(), "ANSP_CIS_PUBLISHER_KEYS") {
		t.Fatalf("%v", err)
	}
	withTokens := cfg
	withTokens.TokenURL, withTokens.ClientID, withTokens.ClientSecret = "https://authority.example.invalid/oauth/token", "ansp-01", "s"
	if _, err := wireCIS(withTokens, nil, nil, prometheus.NewRegistry(), discard()); err != nil {
		t.Fatal(err)
	}
	badURL := cfg
	badURL.CISPURL = "cisp"
	if _, err := wireCIS(badURL, nil, nil, prometheus.NewRegistry(), discard()); err == nil {
		t.Fatal("a bad ANSP_CISP_URL was taken")
	}
}

// fixtureStore serves the uspace_airspace fixture from "cis_cache".
type fixtureStore struct {
	cis.Store
	body []byte
	at   time.Time
}

func (s fixtureStore) Load(context.Context) ([]cis.Stored, error) {
	return []cis.Stored{{Dataset: cis.USpaceAirspace, Version: 3, ETag: "e", Body: s.body, FetchedAt: s.at}}, nil
}

// Presence: a projection holding a designation gives the restriction
// service its version, fetched_at and features.
func TestProjectionAirspaces(t *testing.T) {
	body, err := os.ReadFile("../../testdata/fixtures/uspace_airspace.json")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UTC()
	p := cis.New(cis.Config{Store: fixtureStore{body: body, at: at}})
	p.Warm(context.Background())
	snap, err := projectionAirspaces{p: p}.Current(context.Background())
	if err != nil || snap.Version != "3" || !snap.FetchedAt.Equal(at) || len(snap.Airspaces) != 1 || snap.Airspaces[0].Properties.Identifier != "TSTU01" {
		t.Fatalf("%+v %v", snap, err)
	}
}

// The policy is read at most every policyCacheFor and the last one read
// serves while the database cannot answer; before any, the defaults.
func TestCachedPolicy(t *testing.T) {
	calls := 0
	fail := false
	c := &cachedPolicy{latest: func(context.Context) (policy.Policy, error) {
		calls++
		if fail {
			return policy.Policy{}, errors.New("db down")
		}
		th := policy.Defaults()
		th.CISStaleBoundS = 123
		return policy.Policy{Version: 2, Thresholds: th}, nil
	}}
	first, second := c.get(context.Background()), c.get(context.Background())
	if first.CISStaleBoundS != 123 || second.CISStaleBoundS != 123 || calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	c.at = time.Now().Add(-2 * policyCacheFor)
	fail = true
	if c.get(context.Background()).CISStaleBoundS != 123 || calls != 2 {
		t.Fatal("the last row read was not served")
	}
	empty := &cachedPolicy{latest: func(context.Context) (policy.Policy, error) { return policy.Policy{}, errors.New("db down") }}
	if empty.get(context.Background()) != policy.Defaults() {
		t.Fatal("not the defaults")
	}
	if (&cachedPolicy{}).get(context.Background()) != policy.Defaults() {
		t.Fatal("no database: not the defaults")
	}
}

// The console streams read the policy through the cache: three status
// frames, one database read (ansp audit N-6); a failed read past the
// cache period still says policy_unreadable (the degraded twin).
func TestStreamsReadTheCachedPolicy(t *testing.T) {
	calls, fail := 0, false
	c := &cachedPolicy{latest: func(context.Context) (policy.Policy, error) {
		calls++
		if fail {
			return policy.Policy{}, errors.New("db down")
		}
		return policy.Policy{Version: 4, Thresholds: policy.Defaults()}, nil
	}}
	st := newRestrictionStream(&restriction.Service{Airspaces: restriction.NoProjection{}}, c.policy, nil, producer)
	cl := &streamClient{send: make(chan []byte, 1)}
	for range 3 {
		var env struct {
			Body statusBody `json:"body"`
		}
		_ = json.Unmarshal(st.status(context.Background(), "conn-1", cl), &env)
		if env.Body.PolicyVersion != "4" {
			t.Fatalf("%+v", env.Body)
		}
	}
	if calls != 1 {
		t.Fatalf("%d policy reads for 3 status frames", calls)
	}
	c.mu.Lock()
	c.atPolicy = time.Now().Add(-2 * policyCacheFor)
	c.mu.Unlock()
	fail = true
	var env struct {
		Body statusBody `json:"body"`
	}
	_ = json.Unmarshal(st.status(context.Background(), "conn-1", cl), &env)
	if !contains(env.Body.Degraded, "policy_unreadable") {
		t.Fatalf("%+v", env.Body)
	}
}

// Presence twin of the fail-closed case in TestUnimplementedAndRefusals:
// with a receiver mounted, POST /v1/cis/notifications reaches it without
// a bearer (jws:cisp), within the body bound of the route.
func TestCISReceiverMounted(t *testing.T) {
	mtls, err := auth.NewMTLS(config.MTLSOff, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	mux := http.NewServeMux()
	if _, err := mountAPI(mux, &auth.Guard{Machine: scopeVerifier{}, MTLS: mtls}, nil, nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusAccepted) })); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, cis.NotificationsPath, strings.NewReader("aGVhZGVy.cGF5bG9hZA.c2lnbmF0dXJl"))
	r.Header.Set("Content-Type", cis.ContentTypeJOSE)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || !reached {
		t.Fatalf("%d %v", w.Code, reached)
	}
}
