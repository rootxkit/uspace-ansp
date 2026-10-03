package dss

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/dss/dsstest"
)

// tokens is a fake token client recording what it was asked.
type tokens struct {
	mu   sync.Mutex
	asks []string
	err  error
}

func (k *tokens) TokenFor(_ context.Context, aud string, scopes []string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.asks = append(k.asks, aud+" "+strings.Join(scopes, " "))
	if k.err != nil {
		return "", k.err
	}
	return "tok-" + aud, nil
}

func (k *tokens) asked() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.asks...)
}

func noRedirect() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func volumes() []f3548.Volume4D {
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return []f3548.Volume4D{{
		Volume: f3548.Volume3D{
			OutlinePolygon: &f3548.Polygon{Vertices: []f3548.LatLngPoint{{Lat: 41.7, Lng: 44.78}, {Lat: 41.7, Lng: 44.82}, {Lat: 41.73, Lng: 44.82}}},
			AltitudeLower:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 120},
		},
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: start},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: start.Add(4 * time.Hour)},
	}}
}

// The three operations against a DSS with ovn semantics: a create, an
// update at the current ovn, a stale ovn and a create of an existing
// reference are 409, a read gives the ovn, a delete at the ovn, then 404.
// Every call carries a token of utm.constraint_management for the DSS's
// host; the readiness view says the DSS answered.
func TestClientAgainstAnOVNStub(t *testing.T) {
	d := dsstest.New(dsstest.Subscriber{BaseURL: "https://ussp-a.test", Subscriptions: []string{"78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"}})
	defer d.Close()
	tk := &tokens{}
	c := &Client{BaseURL: d.URL(), HTTP: noRedirect(), Tokens: tk}
	ctx := context.Background()
	if h := c.Health(); h.Known {
		t.Fatal("health known before a call")
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("ping (404 is reachable): %v", err)
	}
	body, err := PutBody(volumes(), "https://ansp.test/")
	if err != nil {
		t.Fatal(err)
	}
	var p f3548.PutConstraintReferenceParameters
	if err := json.Unmarshal(body, &p); err != nil || p.UssBaseUrl != "https://ansp.test" {
		t.Fatalf("uss_base_url without the trailing '/': %s", body)
	}
	resp, call, err := c.PutReference(ctx, testID, body, nil)
	if err != nil || call.Status != http.StatusCreated || resp.ConstraintReference.Ovn == nil || len(resp.Subscribers) != 1 {
		t.Fatalf("create: %+v %+v %v", resp, call, err)
	}
	ovn := *resp.ConstraintReference.Ovn
	if _, _, err := c.PutReference(ctx, testID, body, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("a create of an existing reference: %v", err)
	}
	resp, call, err = c.PutReference(ctx, testID, body, &ovn)
	if err != nil || call.Status != http.StatusOK || *resp.ConstraintReference.Ovn == ovn || resp.ConstraintReference.Version != 2 {
		t.Fatalf("update: %+v %v", resp.ConstraintReference, err)
	}
	if _, _, err := c.PutReference(ctx, testID, body, &ovn); !errors.Is(err, ErrConflict) || CallOf(err).Status != http.StatusConflict {
		t.Fatalf("a stale ovn: %v", err)
	}
	got, _, err := c.GetReference(ctx, testID)
	if err != nil || got.Ovn == nil || *got.Ovn != d.OVN(testID) {
		t.Fatalf("read: %+v %v", got, err)
	}
	if _, _, err := c.DeleteReference(ctx, testID, ovn); !errors.Is(err, ErrConflict) {
		t.Fatalf("a delete at a stale ovn: %v", err)
	}
	del, _, err := c.DeleteReference(ctx, testID, *got.Ovn)
	if err != nil || len(del.Subscribers) != 1 {
		t.Fatalf("delete: %+v %v", del, err)
	}
	if _, _, err := c.DeleteReference(ctx, testID, *got.Ovn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a delete of a deleted reference: %v", err)
	}
	if _, _, err := c.PutReference(ctx, testID, body, got.Ovn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an update of a deleted reference: %v", err)
	}
	for _, a := range tk.asked() {
		if a != d.Host()+" utm.constraint_management" {
			t.Fatalf("token asked %q", a)
		}
	}
	for _, r := range d.Requests() {
		if r.Header.Get("Authorization") != "Bearer tok-"+d.Host() {
			t.Fatalf("%s %s with %q", r.Method, r.Path, r.Header.Get("Authorization"))
		}
	}
	if h := c.Health(); !h.Known || !h.Up {
		t.Fatalf("health %+v", h)
	}
}

// The DSS down: unreachable since T (once, kept through repeated
// failures), then up again when it answers (E-02, both branches).
func TestClientHealth(t *testing.T) {
	d := dsstest.New()
	defer d.Close()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c := &Client{BaseURL: d.URL(), HTTP: noRedirect(), Tokens: &tokens{}, Now: func() time.Time { return now }}
	d.Down.Store(true)
	_, _, err := c.GetReference(context.Background(), testID)
	if !errors.Is(err, ErrUnavailable) || CallOf(err).Status != http.StatusServiceUnavailable {
		t.Fatalf("down: %v", err)
	}
	h := c.Health()
	if !h.Known || h.Up || !h.Since.Equal(now) || h.Reason != "HTTP 503" {
		t.Fatalf("health %+v", h)
	}
	now = now.Add(time.Minute)
	_, _, _ = c.GetReference(context.Background(), testID)
	if h := c.Health(); !h.Since.Equal(now.Add(-time.Minute)) {
		t.Fatalf("since moved while down: %+v", h)
	}
	d.Down.Store(false)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := c.Health(); !h.Up || !h.Since.Equal(now) {
		t.Fatalf("back: %+v", h)
	}
	// Nothing listening: a transport failure is unreachable too.
	d.Close()
	if err := c.Ping(context.Background()); !errors.Is(err, ErrUnavailable) || c.Health().Up {
		t.Fatalf("closed: %v %+v", err, c.Health())
	}
}

// Answers the client refuses: a refusal (4xx), a redirect (never
// followed), a success it cannot use, an answer past the byte bound, 429
// with Retry-After; and calls it cannot make: no token client, a token
// that cannot be had, a base URL that is not one.
func TestClientRefusals(t *testing.T) {
	var answer func(w http.ResponseWriter)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		answer(w)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: noRedirect(), Tokens: &tokens{}, MaxResponseBytes: 2048, ExcerptBytes: 64}
	body, _ := PutBody(volumes(), "https://ansp.test")
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		kind   error
	}{
		{"400", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"message":"bad"}`)
		}, ErrRefused},
		{"redirect", func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://elsewhere")
			w.WriteHeader(http.StatusFound)
		}, ErrRefused},
		{"unusable 201", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"constraint_reference":{}}`)
		}, ErrMalformed},
		{"past the bound", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, strings.Repeat("x", 4096))
		}, ErrMalformed},
		{"429", func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer = tc.answer
			_, call, err := c.PutReference(context.Background(), testID, body, nil)
			if !errors.Is(err, tc.kind) {
				t.Fatalf("got %v, want %v", err, tc.kind)
			}
			if call.Status == 0 || err.Error() == "" {
				t.Fatalf("call %+v", call)
			}
			if tc.name == "429" && call.RetryAfter != 7*time.Second {
				t.Fatalf("retry after %v", call.RetryAfter)
			}
			if tc.name == "past the bound" && !strings.Contains(call.Excerpt, "truncated") {
				t.Fatalf("excerpt %q", call.Excerpt)
			}
		})
	}
	answer = func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK); _, _ = io.WriteString(w, `{}`) }
	if _, _, err := c.DeleteReference(context.Background(), testID, "o"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an unusable delete answer: %v", err)
	}
	if _, _, err := c.GetReference(context.Background(), testID); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an unusable read: %v", err)
	}
	if _, _, err := (&Client{BaseURL: srv.URL, HTTP: noRedirect()}).GetReference(context.Background(), testID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no token client: %v", err)
	}
	if _, _, err := (&Client{BaseURL: srv.URL, HTTP: noRedirect(), Tokens: &tokens{err: errors.New("issuer down")}}).GetReference(context.Background(), testID); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "token") {
		t.Fatalf("no token: %v", err)
	}
	if _, _, err := (&Client{BaseURL: "dss.example", HTTP: noRedirect(), Tokens: &tokens{}}).GetReference(context.Background(), testID); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a base URL that is not one: %v", err)
	}
	if _, err := PutBody(nil, "https://ansp.test"); err == nil {
		t.Fatal("a reference without extents")
	}
}

func TestHelpers(t *testing.T) {
	if Excerpt([]byte("héllo"), 2, false) != "h... (truncated)" {
		t.Fatalf("%q", Excerpt([]byte("héllo"), 2, false))
	}
	if Excerpt([]byte("ok"), 10, false) != "ok" {
		t.Fatal("short")
	}
	for v, want := range map[string]time.Duration{"": 0, "x": 0, "-1": 0, "5": 5 * time.Second, "99999": time.Minute, "12345678901": 0} {
		if got := retryAfter(v, 0); got != want {
			t.Errorf("Retry-After %q: %v", v, got)
		}
	}
	if TransportReason(context.DeadlineExceeded) != "timeout" || TransportReason(context.Canceled) != "cancelled" {
		t.Fatal("reasons")
	}
	if got := TransportReason(errors.New(strings.Repeat("e", 400))); len(got) != 300 {
		t.Fatal(len(got))
	}
	if clip("aé", 2) != "a" {
		t.Fatal("clip on a rune boundary")
	}
	e := &Error{Kind: ErrRefused, Call: Call{Method: "PUT", Path: "/p"}, Reason: "r"}
	if e.Error() != "PUT /p: r" || CallOf(errors.New("x")).Method != "" {
		t.Fatal(e.Error())
	}
}
