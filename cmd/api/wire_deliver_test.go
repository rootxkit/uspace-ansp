package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

func checkOf(w *deliverWiring, name string) (obs.State, string, bool) {
	for _, c := range w.checks {
		if c.Name == name {
			st, why := c.Probe(context.Background())
			return st, why, true
		}
	}
	return "", "", false
}

// Without the database there is no outbox; with it and nothing else,
// the jobs are still written with their versions (the hook is there)
// and the readiness names every missing piece (E-02).
func TestWireDeliverWithoutDependencies(t *testing.T) {
	w, err := wireDeliver(config.Config{}, nil, nil, auth.NewPublicKeys(), deliverOptions{}, prometheus.NewRegistry(), discard())
	if err != nil || w.hook != nil || len(w.run) != 0 {
		t.Fatalf("no database: %+v %v", w, err)
	}
	var logs strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	w, err = wireDeliver(config.Config{}, &store.Relational{}, nil, auth.NewPublicKeys(), deliverOptions{}, prometheus.NewRegistry(), logger)
	if err != nil || w.hook == nil || w.api == nil || w.api.alarms == nil {
		t.Fatalf("no dependencies: %v", err)
	}
	if st, why, ok := checkOf(w, depDeliveryKey); !ok || st != obs.StateDown || !strings.Contains(why, "ANSP_DELIVERY_KEY_FILE") {
		t.Fatalf("delivery key check %s %s", st, why)
	}
	if st, why, ok := checkOf(w, depCISPPublisher); !ok || st != obs.StateDown || !strings.Contains(why, "ANSP_CISP_URL") {
		t.Fatalf("cisp check %s %s", st, why)
	}
	for _, want := range []string{"ANSP_DELIVERY_KEY_FILE", "ANSP_CISP_CLIENT_CERT_FILE", "ANSP_TOKEN_URL", "ANSP_CISP_URL", "ANSP_PUBLIC_BASE_URL", "ANSP_NATS_URL"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("the log does not name %s:\n%s", want, logs.String())
		}
	}
}

// With a key, a client certificate, a token service and a CISP: the
// delivery key is in the JWKS, the certificate's subject is logged, the
// publisher's readiness waits for its first heartbeat. A key or a
// certificate that cannot be read refuses the start.
func TestWireDeliverConfigured(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "delivery.pem")
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	certKey, cert, subject := writeClientCert(t, dir)
	cfg := config.Config{DeliveryKeyFile: keyFile, CISPURL: "https://cisp.example.invalid", TokenURL: "https://authority.example.invalid/oauth/token",
		ClientID: "ansp-01", ClientSecret: "synthetic", CISPClientCertFile: cert, CISPClientKeyFile: certKey, PublicBaseURL: "https://ansp.example.invalid"}
	keys := auth.NewPublicKeys()
	var logs strings.Builder
	w, err := wireDeliver(cfg, &store.Relational{}, nil, keys, deliverOptions{targets: directTargets(nil, "")}, prometheus.NewRegistry(), slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if names := keys.Names(); len(names) != 1 || names[0] != "delivery" {
		t.Fatalf("rings %v", names)
	}
	if st, why, _ := checkOf(w, depCISPPublisher); st != obs.StateDegraded || why != "no heartbeat answered yet" {
		t.Fatalf("cisp check %s %s", st, why)
	}
	if _, _, ok := checkOf(w, depDeliveryKey); ok {
		t.Fatal("a delivery-key check with the key loaded")
	}
	if !strings.Contains(logs.String(), `"subject":"`+subject+`"`) {
		t.Fatalf("the certificate subject is not logged:\n%s", logs.String())
	}
	// The same ring twice is refused (one kid, one ring).
	if _, err := wireDeliver(cfg, &store.Relational{}, nil, keys, deliverOptions{}, prometheus.NewRegistry(), discard()); err == nil {
		t.Fatal("the delivery ring added twice")
	}
	bad := cfg
	bad.DeliveryKeyFile = filepath.Join(dir, "missing.pem")
	if _, err := wireDeliver(bad, &store.Relational{}, nil, auth.NewPublicKeys(), deliverOptions{}, prometheus.NewRegistry(), discard()); err == nil || !strings.Contains(err.Error(), "ANSP_DELIVERY_KEY_FILE") {
		t.Fatalf("missing key: %v", err)
	}
	bad = cfg
	bad.CISPClientKeyFile = keyFile // another key than the certificate's
	if _, err := wireDeliver(bad, &store.Relational{}, nil, auth.NewPublicKeys(), deliverOptions{}, prometheus.NewRegistry(), discard()); err == nil || !strings.Contains(err.Error(), "ANSP_CISP_CLIENT_CERT_FILE") {
		t.Fatalf("mismatched pair: %v", err)
	}
}

func writeClientCert(t *testing.T, dir string) (keyFile, certFile, subject string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := clientTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, certFile = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.crt")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return keyFile, certFile, tmpl.Subject.String()
}

func clientTemplate() *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "ansp-01", Organization: []string{"Synthetic ANSP"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

// The direct path's receivers: the authority once, by base URL.
func TestDirectTargets(t *testing.T) {
	ts := directTargets(nil, "https://authority.example.invalid/")(context.Background())
	if len(ts) != 1 || ts[0].BaseURL != "https://authority.example.invalid" || ts[0].Name != "authority" {
		t.Fatalf("%+v", ts)
	}
	if ts := directTargets(nil, "")(context.Background()); len(ts) != 0 {
		t.Fatalf("%+v", ts)
	}
}

// The outbox's operations fail closed without an outbox (503), the
// JWKS is served from the delivery ring alone when sign-in is not
// configured, and 503 with no key at all; the summary without an
// outbox is none on every channel.
func TestDeliveryOperationsWithoutOutbox(t *testing.T) {
	s := apiServer{}
	rec := httptest.NewRecorder()
	s.ListDeliveryAlarms(rec, httptest.NewRequest(http.MethodGet, "/v1/delivery-alarms", nil), gen.ListDeliveryAlarmsParams{})
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("list %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.AcknowledgeDeliveryAlarm(rec, httptest.NewRequest(http.MethodPost, "/v1/delivery-alarms/x/acknowledge", strings.NewReader("{}")), "x")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("acknowledge %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.GetJwks(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "ANSP_DELIVERY_KEY_FILE") {
		t.Fatalf("jwks without keys %d %s", rec.Code, rec.Body)
	}
	dir := t.TempDir()
	keyFile, _, _ := writeClientCert(t, dir)
	keys := auth.NewPublicKeys()
	if _, err := wireDeliver(config.Config{DeliveryKeyFile: keyFile}, &store.Relational{}, nil, keys, deliverOptions{}, prometheus.NewRegistry(), discard()); err != nil {
		t.Fatal(err)
	}
	s = apiServer{rs: &restrictionAPI{dl: &deliveryAPI{keys: keys}}}
	rec = httptest.NewRecorder()
	s.GetJwks(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"use":"sig"`) {
		t.Fatalf("jwks %d %s", rec.Code, rec.Body)
	}
	if sum := (&restrictionAPI{}).deliveries(context.Background(), restriction.Restriction{}); sum != deliver.NoSummary() {
		t.Fatalf("%+v", sum)
	}
	attachDeliver(nil, nil)
}
