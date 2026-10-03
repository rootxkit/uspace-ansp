package deliver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
)

// verifyDetached checks a request's X-JWS-Signature with the served
// JWKS, as the CISP does (core's DetachedVerifier).
func verifyDetached(t *testing.T, h *harness, r recorded) coreauth.Signature {
	t.Helper()
	v, err := coreauth.NewDetachedVerifier(context.Background(), coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{"ansp-01": {JWKSURL: jwksServer(t, h.ring)}}, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := v.Verify(context.Background(), "ansp-01", r.Header.Get(HeaderSignature), r.Body)
	if err != nil {
		t.Fatalf("the CISP refuses the signature: %v", err)
	}
	return sig
}

// A planned create, then activate, extend and end: each one request,
// the body the CISP's generated type with the pair (ansp_ref,
// ansp_version), signed detached over the exact bytes; each row sent;
// published_version moves; restr.v1 says published.
func TestWorkerPublishesEveryVersion(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	steps := []struct {
		op, state, method, path string
		code                    int
	}{
		{OpCreate, "planned", http.MethodPost, "/v1/restrictions", 201},
		{OpActivate, "active", http.MethodPatch, "/v1/restrictions/" + "ansp-01:" + testRID, 200},
		{OpExtend, "active", http.MethodPatch, "/v1/restrictions/" + "ansp-01:" + testRID, 200},
		{OpEnd, "ended", http.MethodPatch, "/v1/restrictions/" + "ansp-01:" + testRID, 200},
	}
	for i, s := range steps {
		v := int64(i + 1)
		vi := version(v, s.state)
		if s.op == OpExtend {
			vi.EndsAt = testStart.Add(5 * time.Hour)
		}
		h.repo.addVersion(vi)
		id := h.enqueue(v, s.op)
		m := h.deliver(id)
		if !m.acked || len(m.naked) > 0 {
			t.Fatalf("%s: acked %v naked %v", s.op, m.acked, m.naked)
		}
		reqs := h.cisp.requests()
		if len(reqs) != i+1 {
			t.Fatalf("%s: %d requests", s.op, len(reqs))
		}
		r := reqs[i]
		if r.Method != s.method || r.Path != s.path {
			t.Fatalf("%s: %s %s", s.op, r.Method, r.Path)
		}
		if s.method == http.MethodPatch && r.Query != "by=ansp_ref" {
			t.Fatalf("%s: query %q", s.op, r.Query)
		}
		if r.Header.Get("Authorization") != "Bearer test-token-for-"+strings.TrimPrefix(h.cisp.srv.URL, "http://") ||
			r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != IdempotencyKey(testRef, v) {
			t.Fatalf("%s: headers %v", s.op, r.Header)
		}
		sig := verifyDetached(t, h, r)
		if sig.KID != h.ring.ActiveKID() || !sig.IssuedAt.Equal(testStart) {
			t.Fatalf("%s: signature %+v", s.op, sig)
		}
		var body map[string]any
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatal(err)
		}
		if body["ansp_version"] != float64(v) || body["version"] != nil {
			t.Fatalf("%s: the pair is not (ansp_ref, ansp_version): %s", s.op, r.Body)
		}
		switch s.op {
		case OpCreate:
			var c cispclient.RestrictionCreate
			strict(t, r.Body, &c)
			if c.AnspRef != testRef || c.State != cispclient.RestrictionCreateStatePlanned || c.UspaceAirspaceId != "GEOTU01" || !c.StartsAt.Equal(testStart) {
				t.Fatalf("create %+v", c)
			}
		case OpExtend:
			var p cispclient.RestrictionPatch
			strict(t, r.Body, &p)
			if p.Op != cispclient.RestrictionPatchOpExtend || p.EndsAt == nil || !p.EndsAt.Equal(testStart.Add(5*time.Hour)) || p.Feature == nil {
				t.Fatalf("extend %s", r.Body)
			}
		default:
			var p cispclient.RestrictionPatch
			strict(t, r.Body, &p)
			if string(p.Op) != s.op || p.EndsAt != nil || p.Feature != nil {
				t.Fatalf("%s %s", s.op, r.Body)
			}
		}
		row := h.repo.row(id)
		if row.State != StateSent || row.StatusCode == nil || *row.StatusCode != s.code || row.Method != s.method {
			t.Fatalf("%s: row %+v", s.op, row.Delivery)
		}
		if p := h.repo.restrictions[testRID].published; p == nil || *p != v {
			t.Fatalf("%s: published_version %v", s.op, p)
		}
	}
	bodies := h.bus.bodies("restr.v1.")
	if len(bodies) != 4 || bodies[3]["published"] != true || bodies[3]["state"] != "ended" {
		t.Fatalf("restr.v1 outcomes %v", bodies)
	}
	if n, _ := h.repo.Attempts(ctx, h.repo.order[0]); n != 1 {
		t.Fatalf("attempts logged %d", n)
	}
	if got := h.counters.Get(CounterSent); got != 4 {
		t.Fatalf("sent %d", got)
	}
}

// strict decodes body into v refusing unknown members: the CISP's
// closed schema, through the generated type.
func strict(t *testing.T, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("not the CISP's type: %v: %s", err, body)
	}
}

// The generated type refuses a body whose member is named version (M4):
// the twin of the strict decode above.
func TestGeneratedTypeRefusesVersion(t *testing.T) {
	body := []byte(`{"ansp_ref":"a","version":2,"uspace_airspace_id":"GEOTU01","state":"active","starts_at":"2026-10-02T12:00:00Z","ends_at":"2026-10-02T13:00:00Z","feature":{}}`)
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var c cispclient.RestrictionCreate
	if err := dec.Decode(&c); err == nil {
		t.Fatal("a body with version decoded into cis/restriction/v1")
	}
	good := bytes.Replace(body, []byte(`"version"`), []byte(`"ansp_version"`), 1)
	strict(t, good, &c)
	if c.AnspVersion != 2 {
		t.Fatalf("ansp_version %d", c.AnspVersion)
	}
}

// 503, 503, 201: three attempts logged, one publication; the waits are
// the backoff (1 s, then 2 s) on the fake clock, and a message that
// comes back before its time is deferred, never sent early.
func TestWorkerRetriesWithBackoff(t *testing.T) {
	h := newHarness(t, func(n int, _ recorded) (int, string) {
		if n <= 2 {
			return 503, `{"type":"https://schemas.uspace.ge/problems/database_unavailable"}`
		}
		return 201, `{}`
	})
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	m := h.deliver(id)
	if m.acked || len(m.naked) != 1 || m.naked[0] != time.Second {
		t.Fatalf("first 503: acked %v naked %v", m.acked, m.naked)
	}
	// Redelivered too early: deferred, no request.
	m = h.deliver(id)
	if len(h.cisp.requests()) != 1 || len(m.naked) != 1 || m.naked[0] != time.Second {
		t.Fatalf("early: %d requests, naked %v", len(h.cisp.requests()), m.naked)
	}
	h.clock.Advance(time.Second)
	m = h.deliver(id)
	if len(m.naked) != 1 || m.naked[0] != 2*time.Second {
		t.Fatalf("second 503: naked %v", m.naked)
	}
	h.clock.Advance(2 * time.Second)
	m = h.deliver(id)
	if !m.acked || len(h.cisp.requests()) != 3 {
		t.Fatalf("201: acked %v, %d requests", m.acked, len(h.cisp.requests()))
	}
	atts := h.repo.attempts[id]
	if len(atts) != 3 || atts[0].Outcome != "retry" || atts[1].Outcome != "retry" || atts[2].Outcome != "sent" ||
		*atts[0].StatusCode != 503 || *atts[2].StatusCode != 201 {
		t.Fatalf("attempts %+v", atts)
	}
	// Every retry sends the same bytes (the CISP's replay rule).
	reqs := h.cisp.requests()
	if !bytes.Equal(reqs[0].Body, reqs[2].Body) {
		t.Fatal("the retry sent other bytes")
	}
	if h.counters.Get(CounterRetried) != 2 || h.counters.Get(CounterDeferred) != 1 {
		t.Fatalf("counters %v", h.counters.Snapshot())
	}
	if !strings.Contains(h.log(), `"next_retry_at":"2026-10-02T12:00:01.000Z"`) {
		t.Fatalf("the retry is not logged with its time:\n%s", h.log())
	}
}

// A 400 is failed at once with the excerpt and an alarm, never retried;
// so is a CISP 409 (the pair with another body, or a lower ansp_version:
// an answer no retry changes, system audit F-3); its twin, a 429, is
// retried.
func TestWorkerPermanentAndRetriedConflict(t *testing.T) {
	for _, tc := range []struct {
		code  int
		state State
	}{{400, StateFailed}, {409, StateFailed}, {429, StateQueued}, {404, StateFailed}} {
		h := newHarness(t, func(int, recorded) (int, string) {
			return tc.code, `{"type":"https://schemas.uspace.ge/problems/restriction_refused","detail":"refused"}`
		})
		h.repo.addVersion(version(1, "planned"))
		id := h.enqueue(1, OpCreate)
		m := h.deliver(id)
		row := h.repo.row(id)
		if row.State != tc.state {
			t.Fatalf("%d: state %s", tc.code, row.State)
		}
		if tc.state == StateFailed {
			if !m.acked || len(m.naked) != 0 || !strings.Contains(row.Excerpt, "restriction_refused") {
				t.Fatalf("%d: acked %v naked %v excerpt %q", tc.code, m.acked, m.naked, row.Excerpt)
			}
			if len(h.repo.alarms) != 1 || h.repo.alarms[0].Kind != AlarmFailed || !strings.Contains(h.repo.alarms[0].Detail, "HTTP") {
				t.Fatalf("%d: alarms %+v", tc.code, h.repo.alarms)
			}
			alarm := h.bus.bodies("restr.v1.")
			if len(alarm) != 1 || alarm[0]["alarm"] == nil {
				t.Fatalf("%d: restr.v1 %v", tc.code, alarm)
			}
		} else if m.acked || len(m.naked) != 1 || len(h.repo.alarms) != 0 {
			t.Fatalf("%d: acked %v naked %v alarms %d", tc.code, m.acked, m.naked, len(h.repo.alarms))
		}
	}
}

// A job past its count is abandoned with an alarm; a timeout counts as
// an attempt that is retried.
func TestWorkerAbandons(t *testing.T) {
	h := newHarness(t, func(int, recorded) (int, string) { return 503, "" })
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	h.repo.rows[id].MaxAttempts = 2
	h.deliver(id)
	h.clock.Advance(time.Second)
	m := h.deliver(id)
	if row := h.repo.row(id); row.State != StateAbandoned || !m.acked {
		t.Fatalf("state %s acked %v", row.State, m.acked)
	}
	if len(h.repo.alarms) != 1 || h.repo.alarms[0].Kind != AlarmAbandoned {
		t.Fatalf("alarms %+v", h.repo.alarms)
	}
	// The window over: abandoned without a request.
	h2 := newHarness(t, nil)
	h2.repo.addVersion(version(1, "planned"))
	id = h2.enqueue(1, OpCreate)
	h2.clock.Advance(25 * time.Hour)
	h2.deliver(id)
	if row := h2.repo.row(id); row.State != StateAbandoned || len(h2.cisp.requests()) != 0 {
		t.Fatalf("past the window: %s, %d requests", row.State, len(h2.cisp.requests()))
	}
}

// A replayed message after the row is sent sends nothing (counted); its
// twin, the first message, sends one request.
func TestReplayAfterSentDoesNothing(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	h.deliver(id)
	if n := len(h.cisp.requests()); n != 1 {
		t.Fatalf("first: %d requests", n)
	}
	m := h.deliver(id)
	if n := len(h.cisp.requests()); n != 1 || !m.acked || h.counters.Get(CounterReplayIgnored) != 1 {
		t.Fatalf("replay: %d requests, acked %v", n, m.acked)
	}
	// Re-enqueuing the same pair writes nothing new.
	err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		_, ok, err := h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: testRID, AnspRef: testRef, AnspVersion: 1, Op: OpCreate, Target: TargetCISP})
		if ok {
			t.Fatal("the same job was written twice")
		}
		return err
	})
	if err != nil || h.counters.Get(CounterEnqueueRepeated) != 1 {
		t.Fatal(err)
	}
	// A message for a row that never committed is acknowledged, counted.
	m = &fakeMsg{data: []byte(`{"id":"01K6P0A1B2C3D4E5F6G7H8J9KZ","kind":"cisp_publish","bus_seq":1}`)}
	h.worker.Handle(context.Background(), m)
	if !m.acked || h.counters.Get(CounterOrphan) != 1 {
		t.Fatal("orphan message")
	}
	// A malformed message is terminated, counted.
	m = &fakeMsg{data: []byte(`{"id":"x"}`)}
	h.worker.Handle(context.Background(), m)
	if !m.termed || h.counters.Get(CounterMalformed) != 1 {
		t.Fatal("malformed message")
	}
}

// Versions of one restriction go in order: version 2 waits while
// version 1 is queued, then goes.
func TestWorkerKeepsVersionsInOrder(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	h := newHarness(t, func(int, recorded) (int, string) {
		if fail.Load() {
			return 503, ""
		}
		return 200, "{}"
	})
	h.repo.addVersion(version(1, "planned"))
	h.repo.addVersion(version(2, "active"))
	id1 := h.enqueue(1, OpCreate)
	id2 := h.enqueue(2, OpActivate)
	h.deliver(id1)
	m := h.deliver(id2)
	if len(h.cisp.requests()) != 1 || len(m.naked) != 1 || h.repo.row(id2).Attempt != 0 {
		t.Fatalf("version 2 went before version 1: %d requests", len(h.cisp.requests()))
	}
	fail.Store(false)
	h.clock.Advance(time.Second)
	h.deliver(id1)
	h.clock.Advance(time.Second)
	h.deliver(id2)
	reqs := h.cisp.requests()
	if len(reqs) != 3 || reqs[1].Method != http.MethodPost || reqs[2].Method != http.MethodPatch {
		t.Fatalf("requests %v", reqs)
	}
}

// A CISP 409 on one version fails it on its first attempt, counted,
// and does not hold the restriction's next operation behind it in the
// ordered channel: the activation that follows is sent (system audit F-3).
func TestCISPConflictFailsAndNextOpGoes(t *testing.T) {
	h := newHarness(t, func(n int, _ recorded) (int, string) {
		if n == 1 {
			return http.StatusConflict, `{"type":"https://schemas.uspace.ge/problems/reference_mismatch","status":409}`
		}
		return 200, "{}"
	})
	h.repo.addVersion(version(1, "planned"))
	h.repo.addVersion(version(2, "active"))
	id1 := h.enqueue(1, OpCreate)
	id2 := h.enqueue(2, OpActivate)
	m := h.deliver(id1)
	if r := h.repo.row(id1); r.State != StateFailed || r.Attempt != 1 || !m.acked || len(m.naked) != 0 {
		t.Fatalf("state %s attempt %d acked %v naked %v", r.State, r.Attempt, m.acked, m.naked)
	}
	if h.counters.Get(CounterCISPConflict) != 1 || len(h.repo.alarms) != 1 || h.repo.alarms[0].Kind != AlarmFailed {
		t.Fatalf("counters %v alarms %+v", h.counters.Snapshot(), h.repo.alarms)
	}
	h.clock.Advance(time.Second)
	h.deliver(id2)
	reqs := h.cisp.requests()
	if len(reqs) != 2 || !strings.HasPrefix(reqs[1].Path, "/v1/restrictions") || h.repo.row(id2).State != StateSent {
		t.Fatalf("the next operation did not go: %d requests, state %s", len(reqs), h.repo.row(id2).State)
	}
}

// An activation of a restriction the CISP never confirmed is its first
// publication (POST active); an end of one the CISP never held is not
// sent; the twin, an end of a published restriction, is.
func TestFirstPublicationAndNeverPublished(t *testing.T) {
	h := newHarness(t, func(int, recorded) (int, string) { return 400, "no" })
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	h.deliver(id) // 400: failed, never published
	h.cisp.answer = func(int, recorded) (int, string) { return 201, "{}" }
	h.repo.addVersion(version(2, "active"))
	id = h.enqueue(2, OpActivate)
	h.deliver(id)
	reqs := h.cisp.requests()
	var c cispclient.RestrictionCreate
	strict(t, reqs[1].Body, &c)
	if reqs[1].Method != http.MethodPost || c.State != cispclient.RestrictionCreateStateActive || c.AnspVersion != 2 {
		t.Fatalf("first publication %s %s", reqs[1].Method, reqs[1].Body)
	}

	h2 := newHarness(t, nil)
	h2.repo.addVersion(version(1, "planned"))
	h2.repo.addVersion(version(2, "cancelled"))
	id = h2.enqueue(2, OpCancel)
	m := h2.deliver(id)
	if row := h2.repo.row(id); row.State != StateCancelled || row.CancelReason != CancelNeverPublished || len(h2.cisp.requests()) != 0 || !m.acked {
		t.Fatalf("never published: %+v", row.Delivery)
	}
	one := int64(1)
	h2.repo.restrictions[testRID].published = &one
	h2.repo.addVersion(version(3, "cancelled"))
	id = h2.enqueue(3, OpCancel)
	h2.deliver(id)
	if reqs := h2.cisp.requests(); len(reqs) != 1 || !strings.Contains(string(reqs[0].Body), `"op":"cancel"`) {
		t.Fatalf("the cancel of a published restriction: %v", reqs)
	}
}

// Without a token, without a CISP, without a key: the attempt is
// retried with the reason, nothing is sent.
func TestWorkerWithoutDependencies(t *testing.T) {
	h := newHarness(t, nil)
	h.tokens.err = errBoom
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	h.deliver(id)
	if row := h.repo.row(id); row.State != StateQueued || !strings.Contains(row.LastError, "token") || len(h.cisp.requests()) != 0 {
		t.Fatalf("no token: %+v", row.Delivery)
	}
	h.tokens.err = nil
	h.worker.CISP.Signer = nil
	h.clock.Advance(time.Second)
	h.deliver(id)
	if row := h.repo.row(id); !strings.Contains(row.LastError, "ANSP_DELIVERY_KEY_FILE") {
		t.Fatalf("no key: %+v", row.Delivery)
	}
	h.worker.CISP = nil
	h.clock.Advance(2 * time.Second)
	h.deliver(id)
	if row := h.repo.row(id); !strings.Contains(row.LastError, "ANSP_CISP_URL") || len(h.cisp.requests()) != 0 {
		t.Fatalf("no CISP: %+v", row.Delivery)
	}
	// A version that cannot be read fails with the reason, an alarm.
	h.repo.failNext["Version"] = errBoom
	h.repo.addVersion(version(2, "active"))
	id2 := h.enqueue(2, OpActivate)
	h.repo.rows[id].State = StateFailed
	h.deliver(id2)
	if row := h.repo.row(id2); row.State != StateFailed || !strings.Contains(row.LastError, "boom") {
		t.Fatalf("no version: %+v", row.Delivery)
	}
}

// The store failing around an attempt: the claim and the outcome come
// back as a Nak, the lease lost is acknowledged, counted.
func TestWorkerStoreFailures(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "planned"))
	id := h.enqueue(1, OpCreate)
	h.repo.failNext["Claim"] = errBoom
	if m := h.deliver(id); len(m.naked) != 1 || h.counters.Get(CounterStoreFailed) != 1 {
		t.Fatal("claim failure")
	}
	h.repo.failNext["Tx"] = errBoom
	if m := h.deliver(id); len(m.naked) != 1 || h.counters.Get(CounterStoreFailed) != 2 {
		t.Fatal("outcome failure")
	}
	// The lease taken by another attempt meanwhile.
	h.clock.Advance(time.Minute)
	h.worker.Policy.Lease = time.Millisecond
	h.cisp.answer = func(int, recorded) (int, string) {
		h.repo.mu.Lock()
		h.repo.rows[id].leaseToken = "another"
		h.repo.mu.Unlock()
		return 201, "{}"
	}
	if m := h.deliver(id); !m.acked || h.counters.Get(CounterLeaseLost) != 1 {
		t.Fatal("lease lost")
	}
	// A leased row is deferred until the lease ends.
	h.repo.rows[id].leaseToken, h.repo.rows[id].leaseUntil = "x", h.clock.Now().Add(10*time.Second)
	if m := h.deliver(id); len(m.naked) != 1 || m.naked[0] != 10*time.Second {
		t.Fatalf("leased: %v", m.naked)
	}
}

// E-10: the worker runs at most InFlight attempts at once, and drains
// them when its context ends.
func TestWorkerInFlightBound(t *testing.T) {
	h := newHarness(t, nil)
	h.worker.Policy.InFlight = 3
	var cur, peak atomic.Int32
	release := make(chan struct{})
	h.cisp.answer = func(int, recorded) (int, string) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		cur.Add(-1)
		return 201, "{}"
	}
	var ids []string
	for i := range 10 {
		rid := testRID[:24] + string(rune('A'+i)) + "Z"
		v := version(1, "planned")
		v.RestrictionID, v.AnspRef = rid, "ansp-01:"+rid
		h.repo.addVersion(v)
		err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
			id, _, err := h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: rid, AnspRef: v.AnspRef, AnspVersion: 1, Op: OpCreate, Target: TargetCISP})
			ids = append(ids, id)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	msgs := make(chan Msg, len(ids))
	for _, id := range ids {
		msgs <- &fakeMsg{data: []byte(`{"id":"` + id + `","kind":"cisp_publish","bus_seq":1}`)}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.worker.Run(ctx, func(ctx context.Context) (Msg, error) {
			select {
			case m := <-msgs:
				return m, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.cisp.requests()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(h.cisp.requests()); got != 3 {
		t.Fatalf("%d requests in flight, bound 3", got)
	}
	close(release)
	for len(h.cisp.requests()) < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if peak.Load() != 3 || len(h.cisp.requests()) != 10 {
		t.Fatalf("peak %d, %d requests", peak.Load(), len(h.cisp.requests()))
	}
}

// Run survives a source that fails (it waits and asks again) and stops
// with its context.
func TestWorkerRunSourceFailure(t *testing.T) {
	h := newHarness(t, nil)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.worker.Run(ctx, func(context.Context) (Msg, error) {
			if calls.Add(1) == 2 {
				cancel()
			}
			return nil, errBoom
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if calls.Load() < 2 || !strings.Contains(h.log(), "the work queue did not answer") {
		t.Fatalf("calls %d", calls.Load())
	}
}

var _ sync.Locker = (*sync.Mutex)(nil)
