package deliver

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// receiver is a USSP or the authority receiving the degraded direct
// delivery: it verifies the compact JWS with the served JWKS, as their
// receivers do with core's CompactVerifier, aud its own host.
type receiver struct {
	*stub
	host string
}

func newReceiver(t *testing.T, _ *harness, answer func(n int, r recorded) (int, string)) *receiver {
	t.Helper()
	s := newStub(t, answer)
	u, _ := url.Parse(s.srv.URL)
	return &receiver{stub: s, host: u.Host}
}

func (rc *receiver) verify(t *testing.T, h *harness, jwksURL string, r recorded) (coreauth.CompactClaims, cispclient.Change) {
	t.Helper()
	v, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
		Issuers:   map[string]coreauth.IssuerConfig{"https://ansp.test": {JWKSURL: jwksURL}},
		Audiences: []string{rc.host}, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	cl, body, err := v.Verify(context.Background(), string(r.Body))
	if err != nil {
		t.Fatalf("the receiver refuses the delivery: %v", err)
	}
	var ch cispclient.Change
	strict(t, body, &ch)
	return cl, ch
}

func monitorOf(h *harness, targets ...Target) *Monitor {
	return &Monitor{Repo: h.repo, Outbox: h.outbox, Events: h.events, Policy: h.outbox.Policy, PublicBase: "https://ansp.test",
		AlarmAfter: func(context.Context) time.Duration { return 10 * time.Second },
		Targets:    func(context.Context) []Target { return targets }, Logger: h.worker.Logger, Counters: h.counters}
}

// handAll gives the worker every published message of direct jobs.
func (h *harness) handDirect() {
	for _, id := range h.repo.order {
		if r := h.repo.row(id); r.Kind == KindDirect && r.State == StateQueued {
			h.deliver(id)
		}
	}
}

// The CISP down: no alarm before cisp_alarm_after_s (the absence), the
// alarm at it (the presence) on restr.v1 with "not yet published to the
// CISP since T"; both USSPs and the authority receive the signed change
// at /v1/cis/notifications (aud their host, sub the restriction id, jti
// the delivery id); the CISP returns: the publication clears the alarm
// with its duration and the direct job still queued is
// superseded_by_cisp.
func TestAlarmAndDegradedDirectDelivery(t *testing.T) {
	h := newHarness(t, func(int, recorded) (int, string) { return 503, "down" })
	jwks := jwksServer(t, h.ring)
	ussp1 := newReceiver(t, h, func(int, recorded) (int, string) { return 204, "" })
	ussp2 := newReceiver(t, h, func(int, recorded) (int, string) { return 503, "busy" })
	authority := newReceiver(t, h, func(int, recorded) (int, string) { return 204, "" })
	mon := monitorOf(h, Target{"ussp-a", ussp1.srv.URL}, Target{"ussp-b", ussp2.srv.URL}, Target{"authority", authority.srv.URL})

	one := int64(1)
	h.repo.addVersion(version(1, "planned"))
	h.repo.restrictions[testRID].published = &one
	h.repo.addVersion(version(2, "active"))
	id := h.enqueue(2, OpActivate)
	h.deliver(id)

	h.clock.Advance(9 * time.Second)
	rep, err := mon.Tick(context.Background())
	if err != nil || rep.Raised != 0 || len(h.repo.alarms) != 0 {
		t.Fatalf("an alarm before 10 s: %+v %v", rep, err)
	}
	h.clock.Advance(time.Second)
	rep, err = mon.Tick(context.Background())
	if err != nil || rep.Raised != 1 || rep.DirectQueued != 3 {
		t.Fatalf("at 10 s: %+v %v", rep, err)
	}
	al := h.repo.alarms[0]
	if al.Kind != AlarmCISPNotPublished || !strings.Contains(al.Detail, "not yet published to the CISP since 2026-10-02T12:00:00.000Z") ||
		strings.Contains(strings.ToLower(al.Detail), "lost") {
		t.Fatalf("alarm %+v", al)
	}
	var raised map[string]any
	for _, b := range h.bus.bodies("restr.v1.active.") {
		if a, ok := b["alarm"].(map[string]any); ok && a["state"] == "open" {
			raised = b
		}
	}
	if raised == nil || raised["published"] != false {
		t.Fatalf("restr.v1 carries no open cisp_not_published: %v", h.bus.bodies("restr.v1."))
	}
	// Again: nothing new (one alarm, the same jobs).
	if rep, _ := mon.Tick(context.Background()); rep.Raised != 0 || rep.DirectQueued != 0 {
		t.Fatalf("raised twice: %+v", rep)
	}
	h.handDirect()
	for _, rc := range []*receiver{ussp1, ussp2, authority} {
		reqs := rc.requests()
		if len(reqs) != 1 || reqs[0].Path != PathNotifications || reqs[0].Header.Get("Content-Type") != ContentTypeJOSE ||
			reqs[0].Header.Get("Authorization") != "" {
			t.Fatalf("%s: %v", rc.host, reqs)
		}
		cl, ch := rc.verify(t, h, jwks, reqs[0])
		if cl.Audience != rc.host || cl.Subject != testRID || cl.Issuer != "https://ansp.test" {
			t.Fatalf("claims %+v", cl)
		}
		row := h.repo.row(cl.JTI)
		if row == nil || ch.MsgId != cl.JTI || ch.Reason != cispclient.ChangeReasonRestrictionActivated ||
			ch.PullUrl != "https://ansp.test/v1/restrictions/"+testRID || ch.Dataset != cispclient.ChangeDatasetRestrictions ||
			ch.Version != 2 || len(ch.FeatureIds) != 1 || ch.FeatureIds[0] != "DAR7K2Q" || ch.Schema != cispclient.ChangeSchemaCischangev1 {
			t.Fatalf("change %+v", ch)
		}
	}
	// The CISP returns: the publication clears the alarm, the direct
	// job still queued (ussp-b answered 503) is superseded.
	h.cisp.answer = func(int, recorded) (int, string) { return 200, "{}" }
	h.clock.Advance(5 * time.Second)
	h.deliver(id)
	if h.repo.alarms[0].ClearedAt == nil || h.repo.alarms[0].ClearReason != "published" {
		t.Fatalf("not cleared: %+v", h.repo.alarms[0])
	}
	var cleared map[string]any
	for _, b := range h.bus.bodies("restr.v1.") {
		if a, ok := b["alarm"].(map[string]any); ok && a["state"] == "cleared" {
			cleared = a
		}
	}
	if cleared == nil || cleared["duration_s"] != 15.0 {
		t.Fatalf("the clear carries no duration: %v", cleared)
	}
	superseded := 0
	for _, rid := range h.repo.order {
		if r := h.repo.row(rid); r.Kind == KindDirect && r.State == StateCancelled && r.CancelReason == CancelSupersededByCISP {
			superseded++
		}
	}
	if superseded != 1 || !strings.Contains(h.log(), CancelSupersededByCISP) {
		t.Fatalf("superseded %d", superseded)
	}
}

// A new version while the alarm is open moves it and delivers the new
// version directly; the restriction ending clears it (not active), and
// the direct jobs still queued are cancelled.
func TestAlarmAdvancesAndClearsWhenNotActive(t *testing.T) {
	h := newHarness(t, nil)
	ussp := newReceiver(t, h, func(int, recorded) (int, string) { return 503, "" })
	mon := monitorOf(h, Target{"ussp-a", ussp.srv.URL})
	h.repo.addVersion(version(1, "active"))
	h.clock.Advance(11 * time.Second)
	if rep, _ := mon.Tick(context.Background()); rep.Raised != 1 {
		t.Fatal("not raised")
	}
	v2 := version(2, "active")
	v2.EndsAt = testStart.Add(5 * time.Hour)
	h.repo.addVersion(v2)
	h.clock.Advance(11 * time.Second)
	rep, _ := mon.Tick(context.Background())
	if rep.Advanced != 1 || rep.DirectQueued != 1 || h.repo.alarms[0].AnspVersion != 2 {
		t.Fatalf("advance %+v %+v", rep, h.repo.alarms[0])
	}
	var ch cispclient.Change
	for _, id := range h.repo.order {
		if r := h.repo.row(id); r.AnspVersion == 2 && r.Kind == KindDirect {
			_ = json.Unmarshal(r.Body, &ch)
		}
	}
	if ch.Reason != cispclient.ChangeReasonRestrictionExtended {
		t.Fatalf("reason %s", ch.Reason)
	}
	h.repo.addVersion(version(3, "ended"))
	rep, _ = mon.Tick(context.Background())
	if rep.Cleared != 1 || h.repo.alarms[0].ClearReason != CancelNotActive {
		t.Fatalf("clear %+v %+v", rep, h.repo.alarms[0])
	}
	for _, id := range h.repo.order {
		if r := h.repo.row(id); r.Kind == KindDirect && r.State != StateCancelled {
			t.Fatalf("direct %s still %s", id, r.State)
		}
	}
	// No target at all: counted and said.
	h2 := newHarness(t, nil)
	mon2 := monitorOf(h2)
	h2.repo.addVersion(version(1, "active"))
	h2.clock.Advance(11 * time.Second)
	if rep, _ := mon2.Tick(context.Background()); rep.Raised != 1 || h2.counters.Get(CounterDirectNoTargets) != 1 {
		t.Fatalf("no targets %+v", rep)
	}
	// The store failing: the tick says so.
	h2.repo.failNext["Overdue"] = errBoom
	h2.repo.failNext["Clearable"] = errBoom
	if _, err := mon2.Tick(context.Background()); err == nil {
		t.Fatal("no error from a failing store")
	}
}

// The cis/change/v1 record of every op, and the op of every version.
func TestBuildChangeAndOps(t *testing.T) {
	for _, tc := range []struct {
		state, prev, op string
		reason          cispclient.ChangeReason
		removed         bool
	}{
		{"planned", "", OpCreate, cispclient.ChangeReasonRestrictionCreated, false},
		{"active", "planned", OpActivate, cispclient.ChangeReasonRestrictionActivated, false},
		{"active", "", OpActivate, cispclient.ChangeReasonRestrictionActivated, false},
		{"active", "active", OpExtend, cispclient.ChangeReasonRestrictionExtended, false},
		{"ended", "active", OpEnd, cispclient.ChangeReasonRestrictionEnded, true},
		{"cancelled", "planned", OpCancel, cispclient.ChangeReasonRestrictionCancelled, true},
	} {
		v := version(2, tc.state)
		v.PrevState = tc.prev
		if got := OpOfVersion(v); got != tc.op {
			t.Fatalf("%s after %s: %s", tc.state, tc.prev, got)
		}
		raw, err := BuildChange(v, tc.op, "01K6P0A1B2C3D4E5F6G7H8J9KZ", "https://ansp.test/")
		if err != nil {
			t.Fatal(err)
		}
		var ch cispclient.Change
		strict(t, raw, &ch)
		if ch.Reason != tc.reason || (len(ch.RemovedIds) == 1) != tc.removed || ch.Etag != `"ansp-01:01K6P0A1B2C3D4E5F6G7H8J9KM:2"` ||
			ch.Producer != Producer || ch.PullUrl != "https://ansp.test/v1/restrictions/"+testRID {
			t.Fatalf("%s: %+v", tc.op, ch)
		}
	}
	if OpOfVersion(version(1, "unknown")) != "" {
		t.Fatal("an unknown state has an op")
	}
	if _, err := BuildChange(version(1, "active"), "expire", "x", "https://a"); err == nil {
		t.Fatal("expire has no reason")
	}
	if _, err := BuildChange(version(1, "active"), OpActivate, "x", ""); err == nil {
		t.Fatal("no public base")
	}
	// The degraded path without a key or with a bad target says why.
	d := &Direct{Issuer: "https://ansp.test", Policy: DefaultPolicy()}
	if r := d.Send(context.Background(), "https://ussp.test", testRID, "x", []byte("{}")); !strings.Contains(r.Err, "ANSP_DELIVERY_KEY_FILE") {
		t.Fatal(r.Err)
	}
	d.Signer = testRing(t)
	if r := d.Send(context.Background(), "not a url", testRID, "x", []byte("{}")); !strings.Contains(r.Err, "target") {
		t.Fatal(r.Err)
	}
	if r := d.Send(context.Background(), "https://ussp.test", testRID, "", []byte("{}")); !strings.Contains(r.Err, "signature") {
		t.Fatal(r.Err)
	}
}

// The publication of every op, with and without a version the CISP
// holds, and what cannot be built.
func TestBuildPublication(t *testing.T) {
	one := int64(1)
	pub := func(state string, published bool) VersionInfo {
		v := version(2, state)
		if published {
			v.PublishedVersion = &one
		}
		return v
	}
	for _, tc := range []struct {
		v      VersionInfo
		op     string
		method string
		cancel string
	}{
		{version(1, "planned"), OpCreate, "POST", ""},
		{pub("active", true), OpActivate, "PATCH", ""},
		{pub("active", false), OpActivate, "POST", ""},
		{pub("active", true), OpExtend, "PATCH", ""},
		{pub("active", false), OpExtend, "POST", ""},
		{pub("ended", true), OpEnd, "PATCH", ""},
		{pub("ended", false), OpEnd, "", CancelNeverPublished},
		{pub("cancelled", true), OpCancel, "PATCH", ""},
	} {
		p, err := BuildPublication(tc.v, tc.op)
		if err != nil || p.Method != tc.method || p.Cancel != tc.cancel {
			t.Fatalf("%s: %+v %v", tc.op, p, err)
		}
		if p.Method == "PATCH" && p.Path != "/v1/restrictions/ansp-01:"+testRID+"?by=ansp_ref" {
			t.Fatalf("path %s", p.Path)
		}
	}
	for _, tc := range []struct {
		v  VersionInfo
		op string
	}{{version(1, "active"), OpCreate}, {version(1, "active"), "expire"}, {VersionInfo{}, OpCreate}} {
		if _, err := BuildPublication(tc.v, tc.op); err == nil {
			t.Fatalf("%s of %s built", tc.op, tc.v.State)
		}
	}
	if PublicationOp(restriction.OpExpire) != "" || PublicationOp(restriction.OpPlan) != OpCreate || PublicationOp(restriction.Op("x")) != "" {
		t.Fatal("publication ops")
	}
}

// The loops run their pass every period and stop with their context;
// a pass that fails is said and the loop goes on.
func TestLoopsRunAndStop(t *testing.T) {
	h := newHarness(t, nil)
	h.outbox.Policy.ScanEvery = 5 * time.Millisecond
	h.outbox.Policy.AlarmEvery = 5 * time.Millisecond
	h.repo.failNext["Pending"] = errBoom
	mon := monitorOf(h)
	mon.Policy = h.outbox.Policy
	h.repo.failNext["Overdue"] = errBoom
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { h.outbox.RunScan(ctx); done <- struct{}{} }()
	go func() { mon.Run(ctx); done <- struct{}{} }()
	<-done
	<-done
	if !strings.Contains(h.log(), "outbox scan failed") || !strings.Contains(h.log(), "alarm monitor did not finish") {
		t.Fatalf("not said:\n%s", h.log())
	}
	// Nil loggers and counters are quiet, never a panic.
	o := &Outbox{Repo: h.repo, Bus: h.bus, Policy: h.outbox.Policy}
	o.count("x")
	o.log().Info("quiet")
	(&Worker{}).log().Info("quiet")
	(&Monitor{}).log().Info("quiet")
	(&Heartbeat{}).log().Info("quiet")
	(&Reconciler{}).log().Info("quiet")
	if (&Monitor{}).targets(context.Background()) != nil || Kind("x").Valid() {
		t.Fatal("nothing configured")
	}
	// A failing raise is reported by the tick.
	h.repo.addVersion(version(1, "active"))
	h.clock.Advance(11 * time.Second)
	h.repo.failNext["RaiseAlarm"] = errBoom
	if _, err := monitorOf(h, Target{"a", "https://a.test"}).Tick(context.Background()); err == nil {
		t.Fatal("no error")
	}
	big := monitorOf(h, Target{"a", "https://a.test"}, Target{"b", "https://b.test"})
	big.Policy.MaxTargets = 1
	if ts := big.targets(context.Background()); len(ts) != 1 {
		t.Fatal("not bounded")
	}
}
