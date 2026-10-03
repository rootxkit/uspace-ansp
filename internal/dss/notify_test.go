package dss

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	n := &Notifier{HTTP: noRedirect(), Tokens: tk}
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
	if call := (&Notifier{HTTP: noRedirect()}).Notify(context.Background(), u.URL(), nil); !strings.Contains(call.Err, "no token client") {
		t.Fatalf("%+v", call)
	}
	if call := (&Notifier{HTTP: noRedirect(), Tokens: &tokens{err: errors.New("x")}}).Notify(context.Background(), u.URL(), nil); !strings.HasPrefix(call.Err, "token") {
		t.Fatalf("%+v", call)
	}
	u.Close()
	if call := n.Notify(context.Background(), u.URL(), nil); call.Status != 0 || call.Err == "" {
		t.Fatalf("closed: %+v", call)
	}
}
