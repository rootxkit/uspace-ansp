package dsstest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"
)

const id = "2f8343be-6482-4d1b-a474-16847e01af1e"

func do(t *testing.T, method, url string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// The stub's ovn semantics and its injections, as the tests of the
// constraint manager rely on them.
func TestStub(t *testing.T) {
	d := New(Subscriber{BaseURL: "https://u.test", Subscriptions: []string{"78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"}})
	defer d.Close()
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	put, _ := json.Marshal(f3548.PutConstraintReferenceParameters{UssBaseUrl: "https://ansp.test", Extents: []f3548.Volume4D{{
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: &f3548.Time{Format: f3548.RFC3339, Value: start.Add(time.Hour)}}}})
	base := d.URL() + "/dss/v1/constraint_references/" + id
	if c, _ := do(t, "GET", base, nil); c != 404 {
		t.Fatal(c)
	}
	if c, _ := do(t, "PUT", base, []byte("{")); c != 400 {
		t.Fatal(c)
	}
	c, b := do(t, "PUT", base, put)
	var ch f3548.ChangeConstraintReferenceResponse
	if c != 201 || json.Unmarshal(b, &ch) != nil || ch.ConstraintReference.Ovn == nil || ch.Subscribers[0].Subscriptions[0].NotificationIndex != 1 ||
		!ch.ConstraintReference.TimeEnd.Value.Equal(start.Add(time.Hour)) {
		t.Fatalf("%d %s", c, b)
	}
	ovn := *ch.ConstraintReference.Ovn
	if c, _ := do(t, "PUT", base, put); c != 409 {
		t.Fatal(c)
	}
	if !d.Bump(id) || d.OVN(id) == ovn || d.Bump("x") || d.OVN("x") != "" {
		t.Fatal("bump")
	}
	if c, _ := do(t, "PUT", base+"/"+ovn, put); c != 409 {
		t.Fatal(c)
	}
	if c, _ := do(t, "DELETE", base+"/"+ovn, nil); c != 409 {
		t.Fatal(c)
	}
	d.AnswerRaw(`{"raw":true}`)
	if c, b := do(t, "PUT", base+"/"+d.OVN(id), put); c != 200 || string(b) != `{"raw":true}` {
		t.Fatalf("%d %s", c, b)
	}
	d.SetSubscribers()
	if c, b := do(t, "DELETE", base+"/"+d.OVN(id), nil); c != 200 || !bytes.Contains(b, []byte(`"subscribers":[]`)) {
		t.Fatalf("%d %s", c, b)
	}
	for _, m := range []string{"PUT", "DELETE"} {
		if c, _ := do(t, m, base+"/o", put); c != 404 {
			t.Fatal(m, c)
		}
	}
	if c, _ := do(t, "POST", base, nil); c != 400 {
		t.Fatal(c)
	}
	if c, _ := do(t, "GET", d.URL()+"/other", nil); c != 404 {
		t.Fatal(c)
	}
	d.Down.Store(true)
	if c, _ := do(t, "GET", base, nil); c != 503 {
		t.Fatal(c)
	}
	if len(d.Requests()) != 13 || d.Host() == "" {
		t.Fatalf("%d requests", len(d.Requests()))
	}

	u := NewUSS()
	defer u.Close()
	if c, _ := do(t, "POST", u.URL()+"/uss/v1/constraints", []byte("{}")); c != 204 {
		t.Fatal(c)
	}
	u.Answer(func(n int, _ Request) int { return 500 + n })
	if c, _ := do(t, "POST", u.URL()+"/uss/v1/constraints", nil); c != 502 {
		t.Fatal(c)
	}
	if len(u.Requests()) != 2 || u.Host() == "" {
		t.Fatal("uss requests")
	}
}
