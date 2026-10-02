package deliver

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

func heartbeatOf(h *harness, onRecover func(ctx context.Context)) *Heartbeat {
	return &Heartbeat{CISP: h.worker.CISP, Repo: h.repo, Policy: h.outbox.Policy, Logger: h.worker.Logger, Counters: h.counters,
		Period: func(context.Context) time.Duration { return 15 * time.Second }, OnRecover: onRecover, Now: h.clock.Now}
}

// E-02, the success path: over one minute the CISP receives a heartbeat
// every 15 s (sent_at 15 s apart on the clock, within 1 s), each with
// the active ansp_refs, each 204 logged; readiness is ok and says when.
// The twin: the CISP failing shows "unreachable since T" with the
// answer, never data-loss wording, and its return reconciles once.
func TestHeartbeatEvery15Seconds(t *testing.T) {
	h := newHarness(t, func(int, recorded) (int, string) { return 204, "" })
	h.repo.addVersion(version(1, "active"))
	var recovered atomic.Int32
	hb := heartbeatOf(h, func(context.Context) { recovered.Add(1) })
	if st, why := hb.Status(); st != obs.StateDegraded || why != "no heartbeat answered yet" {
		t.Fatalf("before the first: %s %s", st, why)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var beats int
	hb.After = func(d time.Duration) <-chan time.Time {
		beats++
		if beats > 4 {
			cancel()
			return nil // never fires: Run ends on the cancel
		}
		h.clock.Advance(d)
		c := make(chan time.Time, 1)
		c <- h.clock.Now()
		return c
	}
	hb.Run(ctx)
	reqs := h.cisp.requests()
	if len(reqs) != 5 {
		t.Fatalf("%d heartbeats in one minute", len(reqs))
	}
	var prev time.Time
	for i, r := range reqs {
		if r.Method != "POST" || r.Path != PathHeartbeat || r.Header.Get("X-JWS-Signature") != "" {
			t.Fatalf("heartbeat %d: %s %s", i, r.Method, r.Path)
		}
		var b cispclient.PublisherHeartbeat
		strict(t, r.Body, &b)
		if b.ActiveRefs == nil || len(*b.ActiveRefs) != 1 || (*b.ActiveRefs)[0] != testRef {
			t.Fatalf("active_refs %s", r.Body)
		}
		if i > 0 && math.Abs(b.SentAt.Sub(prev).Seconds()-15) > 1 {
			t.Fatalf("heartbeat %d %v after the one before", i, b.SentAt.Sub(prev))
		}
		prev = b.SentAt
	}
	if st, why := hb.Status(); st != obs.StateOK || !strings.HasPrefix(why, "ok (last heartbeat 204 at 2026-10-02T12:01:00.000Z") {
		t.Fatalf("readiness %s %s", st, why)
	}
	if strings.Count(h.log(), `"msg":"deliver: cisp heartbeat","status_code":204`) != 5 || recovered.Load() != 1 {
		t.Fatalf("204 not logged five times, or recovered %d:\n%s", recovered.Load(), h.log())
	}

	h.cisp.answer = func(int, recorded) (int, string) { return 503, "" }
	h.clock.Advance(15 * time.Second)
	hb.Beat(context.Background())
	h.clock.Advance(15 * time.Second)
	hb.Beat(context.Background())
	st, why := hb.Status()
	if st != obs.StateDown || why != "unreachable since 2026-10-02T12:01:15.000Z (HTTP 503); publications are queued and retried" {
		t.Fatalf("failure readiness %s %q", st, why)
	}
	if strings.Contains(strings.ToLower(why+h.log()), "lost") || h.counters.Get(CounterHeartbeatFailed) != 2 {
		t.Fatal("data-loss wording, or the failures not counted")
	}
	h.cisp.answer = nil
	hb.Beat(context.Background())
	if recovered.Load() != 2 || !strings.Contains(h.log(), "reachable again") {
		t.Fatalf("recovered %d", recovered.Load())
	}
	// A transport failure names itself; the refs unreadable send none.
	h.cisp.srv.Close()
	h.repo.failNext["ActiveRefs"] = errBoom
	r := hb.Beat(context.Background())
	if r.Err == "" {
		t.Fatal("no transport error")
	}
	if _, why := hb.Status(); !strings.Contains(why, "unreachable since") {
		t.Fatal(why)
	}
}

// More active restrictions than a heartbeat carries: the first 1000,
// counted.
func TestHeartbeatRefsBound(t *testing.T) {
	h := newHarness(t, func(int, recorded) (int, string) { return 204, "" })
	hb := heartbeatOf(h, nil)
	hb.Policy.MaxActiveRefs = 2
	for i := range 3 {
		v := version(1, "active")
		v.RestrictionID, v.AnspRef = testRID[:25]+string(rune('A'+i)), "ansp-01:r"+string(rune('a'+i))
		h.repo.addVersion(v)
	}
	hb.Beat(context.Background())
	var b struct {
		ActiveRefs []string `json:"active_refs"`
	}
	_ = json.Unmarshal(h.cisp.requests()[0].Body, &b)
	if len(b.ActiveRefs) != 2 || h.counters.Get(CounterRefsTruncated) != 1 {
		t.Fatalf("refs %v", b.ActiveRefs)
	}
	h.tokens.err = errBoom
	if r := hb.Beat(context.Background()); !strings.Contains(r.Err, "token") {
		t.Fatal(r.Err)
	}
}

// The reconciliation makes a queued job due now, reopens an abandoned
// one, and queues a version without a job; a published restriction is
// left alone.
func TestReconcile(t *testing.T) {
	h := newHarness(t, nil)
	rec := &Reconciler{Repo: h.repo, Outbox: h.outbox, Policy: h.outbox.Policy, Logger: h.worker.Logger, Counters: h.counters}
	mk := func(i int, state string) string {
		rid := testRID[:25] + string(rune('A'+i))
		v := version(1, "planned")
		v.RestrictionID, v.AnspRef = rid, "ansp-01:"+rid
		h.repo.addVersion(v)
		v = version(2, state)
		v.RestrictionID, v.AnspRef = rid, "ansp-01:"+rid
		h.repo.addVersion(v)
		return rid
	}
	queued, abandoned, missing, done := mk(0, "active"), mk(1, "active"), mk(2, "active"), mk(3, "active")
	two := int64(2)
	h.repo.restrictions[done].published = &two
	var qid, aid string
	_ = h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		qid, _, _ = h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: queued, AnspRef: "ansp-01:" + queued, AnspVersion: 2, Op: OpActivate, Target: TargetCISP})
		aid, _, _ = h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: abandoned, AnspRef: "ansp-01:" + abandoned, AnspVersion: 2, Op: OpActivate, Target: TargetCISP})
		return nil
	})
	h.repo.rows[qid].NextRetryAt = h.clock.Now().Add(time.Minute)
	h.repo.rows[aid].State, h.repo.rows[aid].Attempt = StateAbandoned, 1445
	n, err := rec.Reconcile(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("reconciled %d %v", n, err)
	}
	if !h.repo.rows[qid].NextRetryAt.Equal(h.clock.Now()) || h.repo.rows[aid].State != StateQueued || h.repo.rows[aid].MaxAttempts <= 1445 {
		t.Fatal("not expedited or not reopened")
	}
	found := false
	for _, id := range h.repo.order {
		if r := h.repo.row(id); r.RestrictionID == missing && r.Op == OpActivate && r.AnspVersion == 2 {
			found = true
		}
	}
	if !found || !strings.Contains(h.log(), `"how":"enqueued"`) || len(h.bus.all()) < 3 {
		t.Fatalf("the missing job: found %v, %d messages", found, len(h.bus.all()))
	}
	h.repo.failNext["Unpublished"] = errBoom
	if _, err := rec.Reconcile(context.Background()); err == nil {
		t.Fatal("no error")
	}
	h.repo.failNext["Expedite"] = errBoom
	if n, _ := rec.Reconcile(context.Background()); h.counters.Get(CounterReconcileFailed) != 2 || n != 2 {
		t.Fatalf("a failing reconciliation of one: n %d", n)
	}
}
