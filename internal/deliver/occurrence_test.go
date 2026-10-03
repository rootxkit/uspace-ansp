package deliver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// occSender posts a fixed body through the Authority poster, as
// internal/coord's sender does with the report it builds.
type occSender struct {
	a    *Authority
	seen []Delivery
}

func (s *occSender) SendOccurrence(ctx context.Context, d Delivery) Response {
	s.seen = append(s.seen, d)
	return s.a.Post(ctx, PathOccurrences, []byte(`{"schema":"occurrence/v1"}`))
}

func (h *harness) enqueueOccurrence(id, ref string) string {
	h.t.Helper()
	var out string
	err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		var err error
		out, _, err = h.outbox.Enqueue(ctx, tx, Job{Kind: KindOccurrence, Op: "report", Target: TargetAuthority, Subject: id, Key: ref})
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.outbox.Publish(context.Background(), Pending{ID: out, Kind: KindOccurrence}); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// A job of no restriction (an occurrence report) needs its subject and
// key and no version; a restriction's job needs its version.
func TestEnqueueJobOfNoRestriction(t *testing.T) {
	h := newHarness(t, nil)
	id := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNP", "ANSP-OCC-2026-0007")
	r := h.repo.row(id)
	if r.SubjectRef != "01K6P4B2C3D4E5F6G7H8J9KMNP" || r.IdempotencyKey != "ANSP-OCC-2026-0007" || r.RestrictionID != "" {
		t.Fatalf("%+v", r.Delivery)
	}
	for _, j := range []Job{
		{Kind: KindOccurrence, Op: "report", Target: TargetAuthority, Key: "k"},
		{Kind: KindOccurrence, Op: "report", Target: TargetAuthority, Subject: "s", Key: "k", RestrictionID: testRID, AnspVersion: 1},
		{Kind: KindCISPPublish, Op: OpCreate, Target: TargetCISP},
		{Kind: "nope", Op: "x", Target: "y"},
	} {
		err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
			_, _, err := h.outbox.Enqueue(ctx, tx, j)
			return err
		})
		if err == nil {
			t.Errorf("%+v accepted", j)
		}
	}
}

// The worker sends an occurrence job through its sender: the row keeps
// the method and the path and no body (the report's body holds the
// reporter reference in clear); a 4xx fails it with an alarm of no
// restriction; without a sender the job is retried (E-01 pair).
func TestWorkerSendsOccurrences(t *testing.T) {
	h := newHarness(t, nil)
	auth := newStub(t, func(n int, _ recorded) (int, string) {
		if n == 2 {
			return http.StatusBadRequest, `{"title":"bad"}`
		}
		return http.StatusAccepted, `{}`
	})
	pol := DefaultPolicy()
	sender := &occSender{a: &Authority{BaseURL: auth.srv.URL, Client: NewHTTPClient(pol.HTTPTimeout, nil, nil), Tokens: h.tokens, Policy: pol}}
	h.worker.Occurrences = sender
	id := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNP", "ANSP-OCC-2026-0007")
	if m := h.deliver(id); !m.acked {
		t.Fatal("not acknowledged")
	}
	r := h.repo.row(id)
	if r.State != StateSent || r.Method != http.MethodPost || r.URL != PathOccurrences || r.Body != nil || len(sender.seen) != 1 {
		t.Fatalf("%+v", r.Delivery)
	}
	req := auth.requests()[0]
	if req.Path != PathOccurrences || req.Header.Get("Authorization") != "Bearer test-token-for-"+strings.TrimPrefix(auth.srv.URL, "http://") {
		t.Fatalf("%+v", req)
	}
	if h.tokens.asks[len(h.tokens.asks)-1] != strings.TrimPrefix(auth.srv.URL, "http://")+" "+ScopeOccurrences {
		t.Fatal(h.tokens.asks)
	}
	id2 := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNQ", "ANSP-OCC-2026-0008")
	h.deliver(id2)
	if r := h.repo.row(id2); r.State != StateFailed {
		t.Fatalf("%+v", r.Delivery)
	}
	var alarm *Alarm
	for _, a := range h.repo.alarms {
		if a.DeliveryID == id2 {
			alarm = a
		}
	}
	if alarm == nil || alarm.Kind != AlarmFailed || alarm.RestrictionID != "" {
		t.Fatalf("%+v", alarm)
	}
	h.worker.Occurrences = nil
	id3 := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNR", "ANSP-OCC-2026-0009")
	if m := h.deliver(id3); len(m.naked) != 1 || h.repo.row(id3).State != StateQueued {
		t.Fatal("not retried without a sender")
	}
}

func TestAuthorityPostRefusals(t *testing.T) {
	ctx := context.Background()
	var nilAuth *Authority
	if r := nilAuth.Post(ctx, PathOccurrences, nil); !strings.Contains(r.Err, "ANSP_AUTHORITY_URL") {
		t.Fatal(r)
	}
	if r := (&Authority{BaseURL: "https://authority.test"}).Post(ctx, PathOccurrences, nil); !strings.Contains(r.Err, "token client") {
		t.Fatal(r)
	}
	if r := (&Authority{BaseURL: "::not a url", Tokens: &tokens{}}).Post(ctx, PathOccurrences, nil); !strings.HasPrefix(r.Err, "target") {
		t.Fatal(r)
	}
	if r := (&Authority{BaseURL: "https://authority.test", Tokens: &tokens{err: errors.New("down")}}).Post(ctx, PathOccurrences, nil); !strings.HasPrefix(r.Err, "token") {
		t.Fatal(r)
	}
}
