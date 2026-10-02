package cis_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-ansp/internal/cis"
)

// The SSRF guard (M5): only an https URL on the CISP's host and port,
// without user information, passes.
func TestCheckPullURL(t *testing.T) {
	c, err := cis.NewClient(cis.ClientConfig{BaseURL: "https://cisp.example.invalid", Tokens: tokens{}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host() != "cisp.example.invalid" {
		t.Fatal(c.Host())
	}
	for raw, ok := range map[string]bool{
		"https://cisp.example.invalid/v1/uspace_airspace?since_version=3": true,
		"https://CISP.example.invalid:443/v1/uspace_airspace":             true,
		"http://cisp.example.invalid/v1/uspace_airspace":                  false,
		"https://evil.example.invalid/v1/uspace_airspace":                 false,
		"https://cisp.example.invalid:8443/v1/uspace_airspace":            false,
		"https://user:pw@cisp.example.invalid/v1/uspace_airspace":         false,
		"/v1/uspace_airspace": false,
		"::not a url":         false,
		"https://cisp.example.invalid.evil.example/v1/uspace_airspace":         false,
		"ftp://cisp.example.invalid/v1/uspace_airspace":                        false,
		"https://cisp.example.invalid@evil.example.invalid/v1/uspace_airspace": false,
	} {
		err := c.CheckPullURL(raw)
		if (err == nil) != ok {
			t.Fatalf("%s: %v", raw, err)
		}
		if err != nil && !errors.Is(err, cis.ErrPullURLRefused) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	// A CISP configured on plain http (a lab) never has a pull_url
	// followed.
	lab, _ := cis.NewClient(cis.ClientConfig{BaseURL: "http://cisp:8080", Tokens: tokens{}})
	if lab.CheckPullURL("http://cisp:8080/v1/uspace_airspace") == nil || lab.CheckPullURL("https://cisp:8080/v1/uspace_airspace") == nil {
		t.Fatal("followed on a plain-http CISP")
	}
}

func TestNewClientRefusesBadBase(t *testing.T) {
	for _, raw := range []string{"", "cisp.example.invalid", "ftp://x", "https://u:p@cisp.example.invalid", "https://"} {
		if _, err := cis.NewClient(cis.ClientConfig{BaseURL: raw}); err == nil || !strings.Contains(err.Error(), "ANSP_CISP_URL") {
			t.Fatalf("%q: %v", raw, err)
		}
	}
}

// Without a token source no request leaves; the error says why.
func TestClientWithoutTokens(t *testing.T) {
	s := newStub(t)
	c, err := cis.NewClient(cis.ClientConfig{BaseURL: s.srv.URL, HTTPClient: s.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetDataset(context.Background(), cis.USpaceAirspace, ""); !errors.Is(err, cis.ErrNoTokenSource) {
		t.Fatal(err)
	}
	if len(s.requests("GET", "")) != 0 {
		t.Fatal("an unauthenticated request left")
	}
}

// Answers other than the expected ones are a StatusError with the
// problem's slug; a redirect is never followed.
func TestClientStatusErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/uspace_airspace":
			problem(w, http.StatusForbidden, "forbidden")
		case "/v1/ussp_list":
			http.Redirect(w, r, "https://elsewhere.example.invalid/", http.StatusFound)
		case "/v1/restrictions":
			w.Header().Set(cis.HeaderVersion, "minus-one")
			w.WriteHeader(http.StatusOK)
		case "/v1/subscriptions/x":
			w.WriteHeader(http.StatusInternalServerError)
		case "/v1/subscriptions":
			_, _ = w.Write([]byte("not json"))
		default:
			problem(w, http.StatusNotFound, "not_found")
		}
	}))
	defer srv.Close()
	c, err := cis.NewClient(cis.ClientConfig{BaseURL: srv.URL, Tokens: tokens{}})
	if err != nil {
		t.Fatal(err)
	}
	// The default client does not trust the test certificate: a
	// transport error, not an answer.
	if _, err := c.GetDataset(context.Background(), cis.USpaceAirspace, ""); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	c, _ = cis.NewClient(cis.ClientConfig{BaseURL: srv.URL, Tokens: tokens{}, HTTPClient: noRedirect(srv.Client())})
	var se *cis.StatusError
	if _, err := c.GetDataset(context.Background(), cis.USpaceAirspace, ""); !errors.As(err, &se) || se.Status != 403 || se.Slug != "forbidden" ||
		!strings.Contains(se.Error(), "403 forbidden: stub") {
		t.Fatalf("%v", err)
	}
	if _, err := c.GetDataset(context.Background(), cis.USSPList, ""); !errors.As(err, &se) || se.Status != http.StatusFound {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := c.GetDataset(context.Background(), cis.Restrictions, ""); err == nil || !strings.Contains(err.Error(), cis.HeaderVersion) {
		t.Fatalf("bad version header: %v", err)
	}
	if _, err := c.GetVersion(context.Background(), cis.Restrictions, 3); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("version: %v", err)
	}
	if _, err := c.GetSubscription(context.Background(), "x"); !errors.As(err, &se) || se.Status != 500 {
		t.Fatalf("subscription: %v", err)
	}
	if _, err := c.GetSubscription(context.Background(), "gone"); !errors.Is(err, cis.ErrSubscriptionUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := c.Subscribe(context.Background(), "https://a.example.invalid/cb", cis.Datasets); err == nil || !strings.Contains(err.Error(), "does not decode") {
		t.Fatalf("list: %v", err)
	}
	if _, err := c.Reactivate(context.Background(), "gone", cis.Datasets); !errors.Is(err, cis.ErrSubscriptionUnknown) {
		t.Fatalf("reactivate: %v", err)
	}
}

func noRedirect(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}
