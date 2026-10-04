package deliver

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// The authority's intake is not served yet (system audit F-2: a 404 on
// /v1/occurrences): the report is held, queued and undelivered, with no
// failure alarm per report, and is never abandoned, neither past its
// attempt count nor past its window; it is retried every
// OccurrenceHold. Its twin: once the authority takes it, it is sent.
func TestOccurrenceHeldWhileIntakeAbsent(t *testing.T) {
	h := newHarness(t, nil)
	var served atomic.Bool
	auth := newStub(t, func(int, recorded) (int, string) {
		if served.Load() {
			return http.StatusAccepted, `{}`
		}
		return http.StatusNotFound, `{"type":"https://schemas.uspace.ge/problems/not_found","status":404}`
	})
	pol := DefaultPolicy()
	h.worker.Occurrences = &occSender{a: &Authority{BaseURL: auth.srv.URL, Client: NewHTTPClient(pol.HTTPTimeout, nil, nil), Tokens: h.tokens, Policy: pol}}
	id := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNP", "ANSP-OCC-2026-0007")
	h.repo.rows[id].MaxAttempts = 2
	for i := range 3 {
		m := h.deliver(id)
		r := h.repo.row(id)
		if r.State != StateQueued || m.acked || len(m.naked) != 1 || !strings.Contains(r.LastError, "intake") {
			t.Fatalf("attempt %d: state %s acked %v naked %v error %q", i+1, r.State, m.acked, m.naked, r.LastError)
		}
		if want := testStart.Add(time.Duration(i) * 25 * time.Hour).Add(h.worker.Policy.OccurrenceHold); r.NextRetryAt.Before(want) {
			t.Fatalf("attempt %d: next retry %s, before the hold %s", i+1, r.NextRetryAt, want)
		}
		h.clock.Advance(25 * time.Hour)
	}
	if len(h.repo.alarms) != 0 || h.counters.Get(CounterOccurrenceIntakeAbsent) != 3 {
		t.Fatalf("alarms %+v counters %v", h.repo.alarms, h.counters.Snapshot())
	}
	served.Store(true)
	if m := h.deliver(id); !m.acked || h.repo.row(id).State != StateSent {
		t.Fatalf("not sent once the intake is served: %s", h.repo.row(id).State)
	}
}

// The authority's 409 (report_ref_conflict: this report_ref was taken
// with another body) is permanent: the same report sent again gets the
// same answer forever. It fails on its first attempt, past neither its
// attempt count nor its window, with a failure alarm that says why, is
// counted, and is never retried. Its twin: a 503 on the same report is
// held and tried again (E-01 pair).
func TestOccurrenceConflictFailsWithAlarm(t *testing.T) {
	h := newHarness(t, nil)
	var status atomic.Int32
	status.Store(http.StatusConflict)
	auth := newStub(t, func(int, recorded) (int, string) {
		s := int(status.Load())
		return s, `{"type":"https://schemas.uspace.ge/problems/report_ref_conflict","status":` + strconv.Itoa(s) + `}`
	})
	pol := DefaultPolicy()
	h.worker.Occurrences = &occSender{a: &Authority{BaseURL: auth.srv.URL, Client: NewHTTPClient(pol.HTTPTimeout, nil, nil), Tokens: h.tokens, Policy: pol}}

	id := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNP", "ANSP-OCC-2026-0007")
	m := h.deliver(id)
	r := h.repo.row(id)
	if r.State != StateFailed || !m.acked || len(m.naked) != 0 || r.Attempt != 1 {
		t.Fatalf("state %s acked %v naked %v attempt %d", r.State, m.acked, m.naked, r.Attempt)
	}
	if !strings.Contains(r.LastError, "409") || !strings.Contains(r.LastError, "not retried") {
		t.Fatalf("last error %q", r.LastError)
	}
	var alarm *Alarm
	for _, a := range h.repo.alarms {
		if a.DeliveryID == id {
			alarm = a
		}
	}
	if alarm == nil || alarm.Kind != AlarmFailed || alarm.RestrictionID != "" || !strings.Contains(alarm.Detail, "not retried") {
		t.Fatalf("alarm %+v", alarm)
	}
	if h.counters.Get(CounterOccurrenceConflict) != 1 || h.counters.Get(CounterRetried) != 0 {
		t.Fatalf("counters %v", h.counters.Snapshot())
	}
	// A repeated message after the failure sends nothing more.
	if m := h.deliver(id); !m.acked || len(auth.requests()) != 1 {
		t.Fatalf("sent again after a 409: %d requests", len(auth.requests()))
	}

	status.Store(http.StatusServiceUnavailable)
	id2 := h.enqueueOccurrence("01K6P4B2C3D4E5F6G7H8J9KMNQ", "ANSP-OCC-2026-0008")
	if m := h.deliver(id2); m.acked || len(m.naked) != 1 || h.repo.row(id2).State != StateQueued {
		t.Fatalf("a 503 is not held for a retry: %s", h.repo.row(id2).State)
	}
	if h.counters.Get(CounterOccurrenceConflict) != 1 {
		t.Fatalf("a 503 counted as a conflict: %v", h.counters.Snapshot())
	}
}
