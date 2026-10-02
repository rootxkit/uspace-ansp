package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func goodEvent() Event {
	return Event{
		ActorType: ActorUser, ActorID: "u-1", Purpose: "restriction planned", EntityType: "restriction",
		EntityID: "01J", EventType: "restriction_planned", Payload: map[string]any{"b": 1, "a": "x"},
	}
}

func TestValidate(t *testing.T) {
	ev := goodEvent()
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("x", MaxPurposeBytes+1)
	for field, mutate := range map[string]func(*Event){
		"actor_type":  func(e *Event) { e.ActorType = "robot" },
		"actor_id":    func(e *Event) { e.ActorID = "" },
		"purpose":     func(e *Event) { e.Purpose = long },
		"entity_type": func(e *Event) { e.EntityType = "" },
		"entity_id":   func(e *Event) { e.EntityID = long },
		"event_type":  func(e *Event) { e.EventType = "Restriction-Planned" },
	} {
		ev := goodEvent()
		mutate(&ev)
		err := ev.Validate()
		var fe *core.FieldError
		if !errors.As(err, &fe) || !strings.Contains(err.Error(), field) {
			t.Fatalf("%s: %v", field, err)
		}
	}
}

// Record refuses an invalid event, an unencodable or oversized payload
// before touching the database (nil here: touching it would panic).
func TestRecordRefusesBeforeTheDatabase(t *testing.T) {
	ctx := context.Background()
	bad := goodEvent()
	bad.ActorID = ""
	if _, err := Record(ctx, nil, bad); err == nil {
		t.Fatal("invalid event recorded")
	}
	ev := goodEvent()
	ev.Payload = map[string]any{"f": func() {}}
	if _, err := Record(ctx, nil, ev); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("unencodable: %v", err)
	}
	ev.Payload = map[string]string{"x": strings.Repeat("a", MaxPayloadBytes)}
	if _, err := Record(ctx, nil, ev); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("oversized: %v", err)
	}
}

func TestCanonicalAndHash(t *testing.T) {
	r := Row{
		ID: 7, TS: time.Date(2026, 10, 2, 8, 0, 0, 123456789, time.FixedZone("x", 4*3600)),
		ActorType: "user", ActorID: "u", Purpose: "p", EntityType: "e", EntityID: "1", EventType: "t",
		Payload: json.RawMessage(`{"b": 2, "a": {"z": 1.50, "y": "<x>"}}`), PrevHash: GenesisHash,
	}
	c, err := Canonical(&r)
	want := `{"id":7,"ts":"2026-10-02T04:00:00.123456Z","actor_type":"user","actor_id":"u","purpose":"p","entity_type":"e","entity_id":"1","event_type":"t","payload":{"a":{"y":"<x>","z":1.50},"b":2}}`
	if err != nil || string(c) != want {
		t.Fatalf("canonical\n got %s\nwant %s (%v)", c, want, err)
	}
	h1, err := Hash(&r)
	if err != nil || len(h1) != 64 {
		t.Fatal(h1, err)
	}
	r2 := r
	r2.Payload = json.RawMessage(`{"a":{"z":1.50,"y":"<x>"},"b":2}`)
	if h2, _ := Hash(&r2); h2 != h1 {
		t.Fatal("key order changed the hash")
	}
	r2.PrevHash = strings.Repeat("1", 64)
	if h3, _ := Hash(&r2); h3 == h1 {
		t.Fatal("prev_hash not covered")
	}
	r2.PrevHash, r2.EntityID = r.PrevHash, "2"
	if h4, _ := Hash(&r2); h4 == h1 {
		t.Fatal("entity_id not covered")
	}
	for _, bad := range []string{`[1]`, `{"a":1} {}`, `{`} {
		r2.Payload = json.RawMessage(bad)
		if _, err := Hash(&r2); err == nil {
			t.Fatalf("payload %s accepted", bad)
		}
	}
}

func TestMonthStart(t *testing.T) {
	got := MonthStart(time.Date(2026, 11, 1, 1, 0, 0, 0, time.FixedZone("x", 4*3600)))
	if !got.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || monthLockName(got) != "events:2026-10" {
		t.Fatalf("%s", got)
	}
}

func TestQueryRefusesBeforeTheDatabase(t *testing.T) {
	ctx := context.Background()
	for name, f := range map[string]Filter{
		"limit":     {Limit: MaxPageSize + 1},
		"negative":  {Limit: -1},
		"entity id": {EntityID: "1"},
		"before":    {Before: -1},
	} {
		if _, err := Query(ctx, nil, f); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
