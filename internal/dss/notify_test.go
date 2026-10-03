package dss

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/dss/dsstest"
)

// One notification per uss_base_url (a trailing '/' is the same USS),
// carrying every subscription once, in the order the DSS named them.
func TestSubscribersGrouped(t *testing.T) {
	a1 := f3548.SubscriptionState{SubscriptionId: "78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", NotificationIndex: 1}
	a2 := f3548.SubscriptionState{SubscriptionId: "88ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", NotificationIndex: 4}
	b1 := f3548.SubscriptionState{SubscriptionId: "98ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", NotificationIndex: 2}
	got := Subscribers([]f3548.SubscriberToNotify{
		{UssBaseUrl: "https://a.test/utm", Subscriptions: []f3548.SubscriptionState{a1}},
		{UssBaseUrl: "https://b.test", Subscriptions: []f3548.SubscriptionState{b1}},
		{UssBaseUrl: "https://a.test/utm/", Subscriptions: []f3548.SubscriptionState{a1, a2}},
	})
	if len(got) != 2 || got[0].USSBaseURL != "https://a.test/utm" || len(got[0].Subscriptions) != 2 || got[0].Subscriptions[1] != a2 ||
		got[1].USSBaseURL != "https://b.test" || len(got[1].Subscriptions) != 1 {
		t.Fatalf("%+v", got)
	}
	if Subscribers(nil) != nil {
		t.Fatal("none")
	}
}

func TestNotificationBody(t *testing.T) {
	subs := []f3548.SubscriptionState{{SubscriptionId: "78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", NotificationIndex: 3}}
	ovn := "ovn-1"
	typ := "DAR"
	c := &f3548.Constraint{Reference: f3548.ConstraintReference{Id: testID, Ovn: &ovn}, Details: f3548.ConstraintDetails{Volumes: volumes(), Type: &typ}}
	b, err := NotificationBody(testID, c, subs)
	if err != nil {
		t.Fatal(err)
	}
	var p f3548.PutConstraintDetailsParameters
	if err := json.Unmarshal(b, &p); err != nil || p.ConstraintId != testID || p.Constraint == nil || *p.Constraint.Reference.Ovn != "ovn-1" ||
		len(p.Subscriptions) != 1 || p.Subscriptions[0].NotificationIndex != 3 {
		t.Fatalf("%s", b)
	}
	// A deletion: the constraint omitted.
	b, err = NotificationBody(testID, nil, subs)
	if err != nil || strings.Contains(string(b), `"constraint"`) {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := NotificationBody(testID, nil, nil); err == nil {
		t.Fatal("no subscriptions")
	}
	c.Reference.Ovn = nil
	if _, err := NotificationBody(testID, c, subs); err == nil {
		t.Fatal("a reference without its ovn")
	}
}

// A notification goes to {uss_base_url}/uss/v1/constraints with a token
// whose aud is that USS's host and whose scope is the operation's
// (utm.constraint_management in the pinned utm.yaml); the answer is
// reported as it was. Calls that cannot be made say why.
func TestNotifier(t *testing.T) {
	u := dsstest.NewUSS()
	defer u.Close()
	tk := &tokens{}
	n := &Notifier{HTTP: noRedirect(), Tokens: tk, AllowPrivate: true}
	call := n.Notify(context.Background(), u.URL(), []byte(`{"constraint_id":"x","subscriptions":[]}`))
	if call.Status != http.StatusNoContent || call.Err != "" {
		t.Fatalf("%+v", call)
	}
	reqs := u.Requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPost || reqs[0].Path != "/uss/v1/constraints" ||
		reqs[0].Header.Get("Authorization") != "Bearer tok-"+u.Host() || reqs[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%+v", reqs)
	}
	if a := tk.asked(); len(a) != 1 || a[0] != u.Host()+" utm.constraint_management" {
		t.Fatalf("token %v", a)
	}
	u.Answer(func(int, dsstest.Request) int { return http.StatusServiceUnavailable })
	if call := n.Notify(context.Background(), u.URL()+"/", []byte(`{}`)); call.Status != http.StatusServiceUnavailable {
		t.Fatalf("%+v", call)
	}
	if call := n.Notify(context.Background(), "not a url", nil); !strings.HasPrefix(call.Err, "target") {
		t.Fatalf("%+v", call)
	}
	if call := (&Notifier{HTTP: noRedirect(), AllowPrivate: true}).Notify(context.Background(), u.URL(), nil); !strings.Contains(call.Err, "no token client") {
		t.Fatalf("%+v", call)
	}
	if call := (&Notifier{HTTP: noRedirect(), Tokens: &tokens{err: errors.New("x")}, AllowPrivate: true}).Notify(context.Background(), u.URL(), nil); !strings.HasPrefix(call.Err, "token") {
		t.Fatalf("%+v", call)
	}
	u.Close()
	if call := n.Notify(context.Background(), u.URL(), nil); call.Status != 0 || call.Err == "" {
		t.Fatalf("closed: %+v", call)
	}
}

// A uss_base_url is whatever a DSS participant wrote: without
// AllowPrivate (production) a notification goes only to https on a
// public address, checked on the literal and again at dial time on the
// resolved address, and a refused target is reported Refused with no
// request and no token asked (ansp audit S-2). Its twin: the same
// loopback subscriber is notified when AllowPrivate is set (above).
func TestNotifierRefusesNonPublicTargets(t *testing.T) {
	u := dsstest.NewUSS()
	defer u.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer tls.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(tls.URL, "https://"))
	tk := &tokens{}
	client := tls.Client()
	GuardTransport(client)
	n := &Notifier{HTTP: client, Tokens: tk}
	for _, base := range []string{
		u.URL(),                      // http
		"http://10.0.0.5:9200",       // http, RFC 1918
		"https://169.254.169.254",    // link-local (metadata)
		"https://10.1.2.3",           // RFC 1918
		"https://[fd00::1]",          // ULA
		"https://[::ffff:127.0.0.1]", // mapped loopback
		tls.URL,                      // https, loopback literal
		"https://localhost:" + port,  // https, a name that resolves to loopback
	} {
		call := n.Notify(context.Background(), base, []byte(`{}`))
		if !call.Refused || call.Status != 0 || !strings.HasPrefix(call.Err, "target") {
			t.Fatalf("%s: %+v", base, call)
		}
	}
	if len(u.Requests()) != 0 || len(tk.asked()) != 0 {
		t.Fatalf("a refused target was called: %d requests, tokens %v", len(u.Requests()), tk.asked())
	}
	for _, a := range []string{"93.184.216.34:443", "[2606:2800:220:1:248:1893:25c8:1946]:443"} {
		if err := refuseNonPublic("tcp", a, nil); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "192.168.1.1:443", "100.64.0.1:443", "0.0.0.0:443", "224.0.0.1:443"} {
		if err := refuseNonPublic("tcp", a, nil); !errors.Is(err, ErrTargetRefused) {
			t.Fatalf("%s: %v", a, err)
		}
	}
}
