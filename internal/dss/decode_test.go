package dss

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

const testID = "2f8343be-6482-4d1b-a474-16847e01af1e"

// change is a ChangeConstraintReferenceResponse as a tree to mutate.
func change() map[string]any {
	return map[string]any{
		"constraint_reference": map[string]any{
			"id": testID, "manager": "ansp-01", "ovn": "ovn-1", "version": 1, "uss_availability": "Unknown",
			"uss_base_url": "https://ansp.test",
			"time_start":   map[string]any{"format": "RFC3339", "value": "2026-10-02T12:00:00Z"},
			"time_end":     map[string]any{"format": "RFC3339", "value": "2026-10-02T16:00:00Z"},
		},
		"subscribers": []any{
			map[string]any{"uss_base_url": "https://ussp-a.test/utm", "subscriptions": []any{
				map[string]any{"subscription_id": "78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", "notification_index": 3}}},
		},
	}
}

func raw(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ref(m map[string]any) map[string]any { return m["constraint_reference"].(map[string]any) }

func TestDecodeChange(t *testing.T) {
	// Presence: a well-formed answer, and an unknown member ignored.
	m := change()
	m["future_member"] = true
	got, err := DecodeChange(raw(t, m), testID, true, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConstraintReference.Ovn == nil || *got.ConstraintReference.Ovn != "ovn-1" || len(got.Subscribers) != 1 ||
		got.Subscribers[0].Subscriptions[0].NotificationIndex != 3 {
		t.Fatalf("%+v", got)
	}
	// A delete's answer may omit the ovn.
	m = change()
	delete(ref(m), "ovn")
	if _, err := DecodeChange(raw(t, m), testID, false, 1<<20, 10); err != nil {
		t.Fatal(err)
	}
	// An upper-case id is the same UUID.
	m = change()
	ref(m)["id"] = strings.ToUpper(testID)
	if _, err := DecodeChange(raw(t, m), testID, true, 1<<20, 10); err != nil {
		t.Fatal(err)
	}

	// Absence: each check refuses with the member named.
	for _, tc := range []struct {
		name  string
		edit  func(m map[string]any)
		field string
	}{
		{"another id", func(m map[string]any) { ref(m)["id"] = "00000000-0000-4000-8000-000000000000" }, "constraint_reference.id"},
		{"no manager", func(m map[string]any) { ref(m)["manager"] = "" }, "constraint_reference.manager"},
		{"long manager", func(m map[string]any) { ref(m)["manager"] = strings.Repeat("m", MaxManagerBytes+1) }, "constraint_reference.manager"},
		{"negative version", func(m map[string]any) { ref(m)["version"] = -1 }, "constraint_reference.version"},
		{"availability", func(m map[string]any) { ref(m)["uss_availability"] = "Sideways" }, "constraint_reference.uss_availability"},
		{"base url", func(m map[string]any) { ref(m)["uss_base_url"] = "ftp://x" }, "constraint_reference.uss_base_url"},
		{"time format", func(m map[string]any) { ref(m)["time_start"].(map[string]any)["format"] = "ISO" }, "constraint_reference.time_start"},
		{"end format", func(m map[string]any) { ref(m)["time_end"].(map[string]any)["format"] = "ISO" }, "constraint_reference.time_end"},
		{"times out of order", func(m map[string]any) { ref(m)["time_end"].(map[string]any)["value"] = "2026-10-02T11:00:00Z" }, "constraint_reference.time_end"},
		{"empty ovn", func(m map[string]any) { ref(m)["ovn"] = "" }, "constraint_reference.ovn"},
		{"long ovn", func(m map[string]any) { ref(m)["ovn"] = strings.Repeat("o", MaxOVNBytes+1) }, "constraint_reference.ovn"},
		{"no ovn on a write", func(m map[string]any) { delete(ref(m), "ovn") }, "constraint_reference.ovn"},
		{"no subscribers", func(m map[string]any) { delete(m, "subscribers") }, "subscribers"},
		{"subscriber url", func(m map[string]any) {
			m["subscribers"].([]any)[0].(map[string]any)["uss_base_url"] = "https://x.test/?q=1"
		}, "subscribers[0].uss_base_url"},
		{"subscriber without subscriptions", func(m map[string]any) {
			m["subscribers"].([]any)[0].(map[string]any)["subscriptions"] = []any{}
		}, "subscribers[0].subscriptions"},
		{"subscription id", func(m map[string]any) {
			m["subscribers"].([]any)[0].(map[string]any)["subscriptions"].([]any)[0].(map[string]any)["subscription_id"] = "x"
		}, "subscribers[0].subscriptions[0].subscription_id"},
		{"negative index", func(m map[string]any) {
			m["subscribers"].([]any)[0].(map[string]any)["subscriptions"].([]any)[0].(map[string]any)["notification_index"] = -1
		}, "subscribers[0].subscriptions[0].notification_index"},
		{"wrong type", func(m map[string]any) { m["subscribers"] = "many" }, "subscribers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := change()
			tc.edit(m)
			_, err := DecodeChange(raw(t, m), testID, true, 1<<20, 10)
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != tc.field {
				t.Fatalf("got %v, want a refusal of %s", err, tc.field)
			}
		})
	}
	for name, data := range map[string]string{"empty": "", "not json": "{", "trailing": `{}{}`, "array": `[]`} {
		if _, err := DecodeChange([]byte(data), testID, true, 1<<20, 10); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// E-10: the byte bound and the subscriber bound, each refused one past
// it and accepted at it.
func TestDecodeChangeBounds(t *testing.T) {
	m := change()
	data := raw(t, m)
	if _, err := DecodeChange(data, testID, true, len(data), 10); err != nil {
		t.Fatalf("at the byte bound: %v", err)
	}
	if _, err := DecodeChange(data, testID, true, len(data)-1, 10); err == nil {
		t.Fatal("past the byte bound")
	}
	subs := func(n, per int) []byte {
		m := change()
		list := make([]any, 0, n)
		for i := range n {
			var ss []any
			for j := range per {
				ss = append(ss, map[string]any{"subscription_id": fmt.Sprintf("78ea3fe8-71c2-4f5c-9b44-%012d", i*per+j), "notification_index": 0})
			}
			list = append(list, map[string]any{"uss_base_url": fmt.Sprintf("https://uss%d.test", i), "subscriptions": ss})
		}
		m["subscribers"] = list
		return raw(t, m)
	}
	if _, err := DecodeChange(subs(10000, 1), testID, true, f3548.MaxMessageBytes, 10000); err != nil {
		t.Fatalf("10 000 subscribers at the bound: %v", err)
	}
	_, err := DecodeChange(subs(10001, 1), testID, true, f3548.MaxMessageBytes, 10000)
	if !errors.Is(err, ErrTooManySubscribers) {
		t.Fatalf("10 001 subscribers: %v", err)
	}
	// The bound counts subscriptions, not only subscribers.
	if _, err := DecodeChange(subs(3, 4), testID, true, 1<<20, 10); !errors.Is(err, ErrTooManySubscribers) {
		t.Fatalf("12 subscriptions past 10: %v", err)
	}
}

func TestDecodeReference(t *testing.T) {
	m := map[string]any{"constraint_reference": ref(change())}
	r, err := DecodeReference(raw(t, m), testID, 1<<20)
	if err != nil || r.Ovn == nil {
		t.Fatalf("%+v %v", r, err)
	}
	delete(m["constraint_reference"].(map[string]any), "manager")
	if _, err := DecodeReference(raw(t, m), testID, 1<<20); err == nil {
		t.Fatal("a reference without a manager")
	}
	if _, err := DecodeReference([]byte(`{`), testID, 1<<20); err == nil {
		t.Fatal("not JSON")
	}
}

// FuzzDecodeChange: no input panics, and an accepted answer holds every
// check the outbox rests on.
func FuzzDecodeChange(f *testing.F) {
	f.Add(raw(f, change()))
	m := change()
	delete(ref(m), "ovn")
	f.Add(raw(f, m))
	f.Add([]byte(`{"constraint_reference":{},"subscribers":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeChange(data, testID, true, 1<<16, 50)
		if err != nil {
			return
		}
		r := got.ConstraintReference
		if !strings.EqualFold(r.Id, testID) || r.Ovn == nil || *r.Ovn == "" || len(*r.Ovn) > MaxOVNBytes || r.Manager == "" {
			t.Fatalf("accepted %+v", r)
		}
		n := 0
		for _, s := range got.Subscribers {
			if checkBaseURL("x", s.UssBaseUrl) != nil || len(s.Subscriptions) == 0 {
				t.Fatalf("accepted subscriber %+v", s)
			}
			n += len(s.Subscriptions)
		}
		if n > 50 {
			t.Fatalf("accepted %d subscriptions", n)
		}
	})
}
