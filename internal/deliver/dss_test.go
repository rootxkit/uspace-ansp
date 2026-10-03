package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/dss"
	"github.com/rootxkit/uspace-ansp/internal/dss/dsstest"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

const (
	testCID = "2f8343be-6482-4d1b-a474-16847e01af1e"
	subA    = "78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"
	subB    = "88ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"
)

// testVolumes is the F3548 volume of the test restriction for its
// window (what WP-5's restriction.Volumes derives; W84 metres).
func testVolumes(end time.Time) []f3548.Volume4D {
	return []f3548.Volume4D{{
		Volume: f3548.Volume3D{
			OutlinePolygon: &f3548.Polygon{Vertices: []f3548.LatLngPoint{{Lat: 41.7, Lng: 44.78}, {Lat: 41.7, Lng: 44.82}, {Lat: 41.73, Lng: 44.82}}},
			AltitudeLower:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 120.5},
		},
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: testStart},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: end},
	}}
}

func constraintDoc(t testing.TB, end time.Time) json.RawMessage {
	typ := restriction.ConstraintType
	b, err := json.Marshal(restriction.StoredConstraint{Details: f3548.ConstraintDetails{Volumes: testVolumes(end), Type: &typ}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dssHarness is the outbox with an in-test DSS (ovn semantics) naming
// two subscribers, each an in-test USS.
type dssHarness struct {
	*harness
	dss        *dsstest.DSS
	ussA, ussB *dsstest.USS
	monitor    *Monitor
}

func newDSSHarness(t *testing.T) *dssHarness {
	t.Helper()
	h := &dssHarness{harness: newHarness(t, nil), ussA: dsstest.NewUSS(), ussB: dsstest.NewUSS()}
	t.Cleanup(h.ussA.Close)
	t.Cleanup(h.ussB.Close)
	h.dss = dsstest.New(dsstest.Subscriber{BaseURL: h.ussA.URL(), Subscriptions: []string{subA}},
		dsstest.Subscriber{BaseURL: h.ussB.URL(), Subscriptions: []string{subB}})
	t.Cleanup(h.dss.Close)
	pol := h.outbox.Policy
	client := NewHTTPClient(pol.HTTPTimeout, nil, nil)
	h.worker.DSS = &DSS{Client: &dss.Client{BaseURL: h.dss.URL(), HTTP: client, Tokens: h.tokens, MaxSubscribers: pol.MaxSubscribers},
		Notifier: &dss.Notifier{HTTP: client, Tokens: h.tokens, AllowPrivate: true}, USSBaseURL: "https://ansp.test", Logger: h.worker.Logger, Counters: h.counters}
	h.worker.Outbox = h.outbox
	h.monitor = &Monitor{Repo: h.repo, Outbox: h.outbox, Events: h.events, Policy: pol, Logger: h.worker.Logger, Counters: h.counters,
		AlarmAfter: func(context.Context) time.Duration { return time.Hour }}
	h.repo.addVersion(version(1, "planned"))
	h.repo.setConstraint(testRID, testCID, 1, constraintDoc(t, testStart.Add(4*time.Hour)))
	return h
}

// step writes version n made by op, queues its jobs as the restriction
// hook does and publishes them; it returns the DSS job's id.
func (h *dssHarness) step(n int64, state string, op restriction.Op, end time.Time) string {
	h.t.Helper()
	v := version(n, state)
	v.EndsAt = end
	h.repo.addVersion(v)
	h.repo.setConstraint(testRID, testCID, n, constraintDoc(h.t, end))
	err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		return h.outbox.EnqueueVersion(ctx, tx, restriction.Version{RestrictionID: testRID, AnspRef: testRef, Version: n}, op, 0)
	})
	if err != nil {
		h.t.Fatal(err)
	}
	ps, _ := h.repo.QueuedOf(context.Background(), testRID, n)
	h.outbox.PublishAll(context.Background(), ps)
	return h.job(n, KindDSSPut, KindDSSDelete)
}

// job is the id of the version's job of one of kinds ("" when none).
func (h *dssHarness) job(n int64, kinds ...Kind) string {
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	for _, id := range h.repo.order {
		r := h.repo.rows[id]
		for _, k := range kinds {
			if r.AnspVersion == n && r.Kind == k {
				return id
			}
		}
	}
	return ""
}

// notifyJobs is the uss_notify jobs of version n by target.
func (h *dssHarness) notifyJobs(n int64) map[string]string {
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	out := map[string]string{}
	for _, id := range h.repo.order {
		if r := h.repo.rows[id]; r.Kind == KindUSSNotify && r.AnspVersion == n {
			out[r.Target] = id
		}
	}
	return out
}

// putBody is the PutConstraintReferenceParameters of a DSS request.
func putBody(t *testing.T, r dsstest.Request) f3548.PutConstraintReferenceParameters {
	t.Helper()
	var p f3548.PutConstraintReferenceParameters
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatalf("%s %s: %v", r.Method, r.Path, err)
	}
	return p
}

// notification is a subscriber's PutConstraintDetailsParameters.
func notification(t *testing.T, r dsstest.Request) f3548.PutConstraintDetailsParameters {
	t.Helper()
	var p f3548.PutConstraintDetailsParameters
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// The activation writes the reference with the version's volumes as its
// extents (deep equal, W84) and this system's uss_base_url; the ovn,
// version and reference are stored, the standing is written, restr.v1
// says so; one notification per subscriber the DSS named is queued and
// published at once, and each subscriber gets the full Constraint (the
// reference with its ovn and the details) with its notification_index,
// under a token for its own host of utm.constraint_management.
func TestDSSWriteNotifiesEverySubscriber(t *testing.T) {
	h := newDSSHarness(t)
	end := testStart.Add(4 * time.Hour)
	id := h.step(2, "active", restriction.OpActivate, end)
	if d := h.repo.dssOf(testRID); d.state != DSSPending || d.since == nil {
		t.Fatalf("pending before the write: %+v", d)
	}
	m := h.deliver(id)
	if !m.acked {
		t.Fatal("not acked")
	}
	reqs := h.dss.Requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodPut || reqs[0].Path != "/dss/v1/constraint_references/"+testCID {
		t.Fatalf("%+v", reqs)
	}
	p := putBody(t, reqs[0])
	if !reflect.DeepEqual(p.Extents, testVolumes(end)) || p.UssBaseUrl != "https://ansp.test" {
		t.Fatalf("extents %s", reqs[0].Body)
	}
	d := h.repo.dssOf(testRID)
	if d.state != DSSWritten || d.since != nil || d.ovn == nil || *d.ovn != h.dss.OVN(testCID) || *d.putVersion != 2 || *d.dssVersion != 1 {
		t.Fatalf("stored %+v", d)
	}
	if r := h.repo.row(id); r.State != StateSent || r.Method != http.MethodPut || r.URL != "/dss/v1/constraint_references/"+testCID {
		t.Fatalf("row %+v", r.Delivery)
	}
	jobs := h.notifyJobs(2)
	if len(jobs) != 2 || jobs[h.ussA.URL()] == "" || jobs[h.ussB.URL()] == "" {
		t.Fatalf("notification jobs %v", jobs)
	}
	for target, nid := range jobs {
		if r := h.repo.row(nid); r.busPublished == nil || r.Op != OpDSSPut {
			t.Fatalf("%s: not published at once: %+v", target, r.Delivery)
		}
		h.deliver(nid)
	}
	for _, c := range []struct {
		uss *dsstest.USS
		sub string
	}{{h.ussA, subA}, {h.ussB, subB}} {
		reqs := c.uss.Requests()
		if len(reqs) != 1 || reqs[0].Path != "/uss/v1/constraints" || reqs[0].Header.Get("Authorization") != "Bearer test-token-for-"+c.uss.Host() {
			t.Fatalf("%s: %+v", c.uss.URL(), reqs)
		}
		n := notification(t, reqs[0])
		if n.ConstraintId != testCID || n.Constraint == nil || n.Constraint.Reference.Ovn == nil || *n.Constraint.Reference.Ovn != *d.ovn ||
			!reflect.DeepEqual(n.Constraint.Details.Volumes, testVolumes(end)) || *n.Constraint.Details.Type != "DAR" ||
			len(n.Subscriptions) != 1 || n.Subscriptions[0].SubscriptionId != c.sub || n.Subscriptions[0].NotificationIndex != 1 {
			t.Fatalf("%s: %s", c.uss.URL(), reqs[0].Body)
		}
	}
	asked := strings.Join(h.tokens.asks, "\n")
	for _, host := range []string{h.dss.Host(), h.ussA.Host(), h.ussB.Host()} {
		if !strings.Contains(asked, host+" utm.constraint_management") {
			t.Fatalf("no token for %s: %s", host, asked)
		}
	}
	for _, n := range h.repo.notificationRows() {
		if n.status != StateSent || n.sentAt == nil || n.Op != OpDSSPut || n.ConstraintID != testCID {
			t.Fatalf("row %+v", n)
		}
	}
	if h.counters.Get(CounterDSSWritten) != 1 || h.counters.Get(CounterNotifyQueued) != 2 || h.counters.Get(CounterNotifySent) != 2 {
		t.Fatal("counters")
	}
	var written bool
	for _, b := range h.bus.bodies("restr.v1.") {
		if s, ok := b["dss"].(map[string]any); ok && s["state"] == DSSWritten && s["ansp_version"] == 2.0 {
			written = true
		}
	}
	if !written {
		t.Fatal("restr.v1 does not say written")
	}
	if !strings.Contains(h.log(), "the DSS accepted the constraint reference") {
		t.Fatal("not logged")
	}
}

// An extension updates the reference at the stored ovn; when another
// writer moved the ovn (the DSS answers 409) the reference is read once
// and the update retried with its ovn, then written. A planned
// restriction and a cancel queue no DSS job.
func TestDSSExtendRereadsAStaleOVN(t *testing.T) {
	h := newDSSHarness(t)
	h.deliver(h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	first := *h.repo.dssOf(testRID).ovn
	end := testStart.Add(6 * time.Hour)
	id := h.step(3, "active", restriction.OpExtend, end)
	if !h.dss.Bump(testCID) {
		t.Fatal("no reference")
	}
	h.deliver(id)
	reqs := h.dss.Requests()
	if len(reqs) != 4 || reqs[1].Path != "/dss/v1/constraint_references/"+testCID+"/"+first || reqs[2].Method != http.MethodGet ||
		reqs[3].Path != "/dss/v1/constraint_references/"+testCID+"/"+strings.TrimPrefix(reqs[3].Path, "/dss/v1/constraint_references/"+testCID+"/") {
		t.Fatalf("%+v", reqs)
	}
	if !reflect.DeepEqual(putBody(t, reqs[3]).Extents, testVolumes(end)) {
		t.Fatal("the extension's volume")
	}
	if d := h.repo.dssOf(testRID); d.state != DSSWritten || *d.putVersion != 3 || *d.ovn != h.dss.OVN(testCID) {
		t.Fatalf("%+v", d)
	}
	if h.counters.Get(CounterDSSOVNReread) != 1 || h.repo.row(id).State != StateSent {
		t.Fatal("not re-read once and written")
	}
	// Absence: a plan and a cancel are never in the DSS.
	for _, op := range []restriction.Op{restriction.OpPlan, restriction.OpCancel} {
		if k, _ := DSSOp(op); k != "" {
			t.Fatalf("%s queues %s", op, k)
		}
	}
}

// A 409 that survives the re-read fails loudly: failed, an alarm, the
// standing failed since T, counted.
func TestDSSConflictAfterRereadFails(t *testing.T) {
	h := newDSSHarness(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"constraint_reference":{"id":%q,"manager":"ansp-01","ovn":"o2","version":2,"uss_availability":"Unknown","uss_base_url":"https://ansp.test","time_start":{"format":"RFC3339","value":"2026-10-02T12:00:00Z"},"time_end":{"format":"RFC3339","value":"2026-10-02T16:00:00Z"}}}`, testCID)
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	h.worker.DSS.Client.BaseURL = srv.URL
	id := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h.deliver(id)
	if r := h.repo.row(id); r.State != StateFailed || !strings.Contains(r.LastError, "409 again after one re-read") {
		t.Fatalf("%+v", r.Delivery)
	}
	if h.counters.Get(CounterDSSConflict) != 1 || len(h.repo.alarms) != 1 || h.repo.alarms[0].Kind != AlarmFailed {
		t.Fatal("not alarmed")
	}
	if d := h.repo.dssOf(testRID); d.state != DSSFailed || d.since == nil {
		t.Fatalf("%+v", d)
	}
	if len(h.notifyJobs(2)) != 0 {
		t.Fatal("notified a write the DSS never accepted")
	}
}

// The end deletes the reference at its ovn after the put (one channel:
// the delete waits for the put still queued); every subscriber is told
// with the constraint omitted; the standing is deleted.
func TestDSSEndDeletesAndNotifies(t *testing.T) {
	h := newDSSHarness(t)
	put := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	del := h.step(3, "ended", restriction.OpEnd, testStart.Add(4*time.Hour))
	// The delete first: blocked behind the put of the same channel.
	if m := h.deliver(del); m.acked || len(m.naked) != 1 || len(h.dss.Requests()) != 0 {
		t.Fatalf("the delete went before the put: %+v", m)
	}
	h.clock.Advance(2 * time.Second)
	// The restriction is ended now: the put of its activation is not
	// sent (not active), and the delete then finds nothing to delete.
	h.deliver(put)
	if r := h.repo.row(put); r.State != StateCancelled || r.CancelReason != CancelNotActive {
		t.Fatalf("put %+v", r.Delivery)
	}
	h.deliver(del)
	if r := h.repo.row(del); r.State != StateCancelled || r.CancelReason != CancelNeverWritten {
		t.Fatalf("delete %+v", r.Delivery)
	}
	if d := h.repo.dssOf(testRID); d.state != DSSNone || d.since != nil {
		t.Fatalf("%+v", d)
	}

	// Presence: written, then ended: the delete at the ovn, notified.
	h2 := newDSSHarness(t)
	h2.deliver(h2.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	ovn := *h2.repo.dssOf(testRID).ovn
	del = h2.step(3, "ended", restriction.OpEnd, testStart.Add(4*time.Hour))
	h2.deliver(del)
	reqs := h2.dss.Requests()
	if last := reqs[len(reqs)-1]; last.Method != http.MethodDelete || last.Path != "/dss/v1/constraint_references/"+testCID+"/"+ovn {
		t.Fatalf("%+v", last)
	}
	if d := h2.repo.dssOf(testRID); d.state != DSSDeleted || d.ovn != nil || d.reference == nil {
		t.Fatalf("%+v", d)
	}
	jobs := h2.notifyJobs(3)
	if len(jobs) != 2 {
		t.Fatalf("%v", jobs)
	}
	for _, id := range jobs {
		h2.deliver(id)
	}
	for _, u := range []*dsstest.USS{h2.ussA, h2.ussB} {
		reqs := u.Requests()
		n := notification(t, reqs[len(reqs)-1])
		if n.Constraint != nil || n.ConstraintId != testCID || len(n.Subscriptions) != 1 || n.Subscriptions[0].NotificationIndex != 2 {
			t.Fatalf("%s", reqs[len(reqs)-1].Body)
		}
	}
	if h2.counters.Get(CounterDSSDeleted) != 1 {
		t.Fatal("not counted")
	}
	// A delete answered 404 (gone at its end: F3548 needs no delete) is
	// done, with nobody to notify.
	h3 := newDSSHarness(t)
	h3.deliver(h3.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	del = h3.step(3, "ended", restriction.OpExpire, testStart.Add(4*time.Hour))
	h3.dss.SetSubscribers()
	ovn = h3.dss.OVN(testCID)
	if _, _, err := h3.worker.DSS.Client.DeleteReference(context.Background(), testCID, ovn); err != nil {
		t.Fatal(err)
	}
	h3.deliver(del)
	if r := h3.repo.row(del); r.State != StateSent || *r.StatusCode != http.StatusNotFound || len(h3.notifyJobs(3)) != 0 {
		t.Fatalf("%+v", r.Delivery)
	}
}

// The DSS down: the CISP publication of the same version is sent
// regardless (D6), the DSS write is retried, the standing is pending
// since T and restr.v1 says so; the DSS back, it is written.
func TestDSSDownNeverHoldsTheCISP(t *testing.T) {
	h := newDSSHarness(t)
	h.dss.Down.Store(true)
	id := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	cisp := h.job(2, KindCISPPublish)
	h.deliver(cisp)
	if h.repo.row(cisp).State != StateSent || len(h.cisp.requests()) != 1 {
		t.Fatal("the CISP publication waited for the DSS")
	}
	m := h.deliver(id)
	if r := h.repo.row(id); r.State != StateQueued || len(m.naked) != 1 || *r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("%+v %+v", r.Delivery, m)
	}
	d := h.repo.dssOf(testRID)
	if d.state != DSSPending || d.since == nil {
		t.Fatalf("%+v", d)
	}
	var pending bool
	for _, b := range h.bus.bodies("restr.v1.") {
		if s, ok := b["dss"].(map[string]any); ok && s["state"] == DSSPending && s["since"] == restriction.Stamp(*d.since) {
			pending = true
		}
	}
	if !pending {
		t.Fatal("restr.v1 does not say pending since T")
	}
	if strings.Contains(strings.ToLower(h.log()), "lost") {
		t.Fatal("said lost")
	}
	h.dss.Down.Store(false)
	h.clock.Advance(2 * time.Second)
	h.deliver(id)
	if r := h.repo.row(id); r.State != StateSent || h.repo.dssOf(testRID).state != DSSWritten {
		t.Fatalf("%+v", r.Delivery)
	}
}

// One subscriber answering 5xx is retried; the other is unaffected.
// Past CstrPublishedNotificationLatencySeconds the miss is an alarm
// (uss_notify_late) for that subscriber only; a person's acknowledgement
// leaves it open; delivered, it clears.
func TestDSSSubscriberRetriedAndLateAlarm(t *testing.T) {
	h := newDSSHarness(t)
	h.ussB.Answer(func(int, dsstest.Request) int { return http.StatusBadGateway })
	h.deliver(h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	jobs := h.notifyJobs(2)
	h.deliver(jobs[h.ussA.URL()])
	h.deliver(jobs[h.ussB.URL()])
	if h.repo.row(jobs[h.ussA.URL()]).State != StateSent || h.repo.row(jobs[h.ussB.URL()]).State != StateQueued {
		t.Fatal("one subscriber's failure touched the other")
	}
	rep, err := h.monitor.Tick(context.Background())
	if err != nil || rep.LateRaised != 0 {
		t.Fatalf("raised before the latency: %+v %v", rep, err)
	}
	h.clock.Advance(h.outbox.Policy.NotifyLatency + time.Second)
	rep, _ = h.monitor.Tick(context.Background())
	if rep.LateRaised != 1 || len(h.repo.alarms) != 1 || h.repo.alarms[0].Kind != AlarmNotifyLate || h.repo.alarms[0].DeliveryID != jobs[h.ussB.URL()] {
		t.Fatalf("%+v %+v", rep, h.repo.alarms)
	}
	if !strings.Contains(h.repo.alarms[0].Detail, "not delivered within 5s of the DSS answer") || strings.Contains(h.repo.alarms[0].Detail, "lost") {
		t.Fatal(h.repo.alarms[0].Detail)
	}
	al := &Alarms{Repo: h.repo, Events: h.events, Counters: h.counters}
	got, err := al.Acknowledge(context.Background(), Actor{ID: "u1", Role: "watch_supervisor"}, h.repo.alarms[0].ID, "seen; USSP B is restarting")
	if err != nil || got.ClearedAt != nil || AlarmStateOf(got) != AlarmStateAcknowledged {
		t.Fatalf("an acknowledgement closed a live alarm: %+v %v", got, err)
	}
	if rep, _ := h.monitor.Tick(context.Background()); rep.LateRaised != 0 || rep.LateCleared != 0 {
		t.Fatalf("%+v", rep)
	}
	h.ussB.Answer(nil)
	h.deliver(jobs[h.ussB.URL()])
	rep, _ = h.monitor.Tick(context.Background())
	if rep.LateCleared != 1 || h.repo.alarms[0].ClearReason != "delivered" {
		t.Fatalf("%+v %+v", rep, h.repo.alarms[0])
	}
}

// A notification still queued when the DSS names the subscriber for a
// newer version is superseded by the newer one (its rows cancelled); a
// subscriber's 409 (it holds a newer one) fails it at once.
func TestDSSNotificationSupersededAndRefused(t *testing.T) {
	h := newDSSHarness(t)
	h.ussB.Answer(func(int, dsstest.Request) int { return http.StatusServiceUnavailable })
	h.deliver(h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	old := h.notifyJobs(2)[h.ussB.URL()]
	h.deliver(old)
	h.deliver(h.step(3, "active", restriction.OpExtend, testStart.Add(5*time.Hour)))
	if r := h.repo.row(old); r.State != StateCancelled || r.CancelReason != CancelSupersededByNewer {
		t.Fatalf("%+v", r.Delivery)
	}
	for _, n := range h.repo.notificationRows() {
		if n.DeliveryID == old && n.status != StateCancelled {
			t.Fatalf("%+v", n)
		}
	}
	// Both version 2 notifications were still queued (A's never handed
	// to the worker here): both superseded.
	if n := h.counters.Get(CounterNotifySuperseded); n != 2 {
		t.Fatalf("counted %d", n)
	}
	h.ussB.Answer(func(int, dsstest.Request) int { return http.StatusConflict })
	nb := h.notifyJobs(3)[h.ussB.URL()]
	h.deliver(nb)
	if r := h.repo.row(nb); r.State != StateFailed {
		t.Fatalf("%+v", r.Delivery)
	}
}

// A subscriber whose uss_base_url is not https on a public address
// (here loopback http, with private targets not allowed) is refused
// before any request: failed at once with one alarm, counted, never
// retried for the notification window (ansp audit S-2). Its twin is
// every notification test above, with private targets allowed.
func TestDSSNotificationToANonPublicTargetFails(t *testing.T) {
	h := newDSSHarness(t)
	h.worker.DSS.Notifier.AllowPrivate = false
	h.deliver(h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	nb := h.notifyJobs(2)[h.ussB.URL()]
	m := h.deliver(nb)
	if r := h.repo.row(nb); r.State != StateFailed || r.Attempt != 1 || !m.acked || !strings.Contains(r.LastError, "public address") {
		t.Fatalf("%+v", r.Delivery)
	}
	if len(h.ussB.Requests()) != 0 || h.counters.Get(CounterNotifyTargetRefused) != 1 {
		t.Fatalf("requests %d, counters %v", len(h.ussB.Requests()), h.counters.Snapshot())
	}
	alarms := 0
	for _, a := range h.repo.alarms {
		if a.DeliveryID == nb && a.Kind == AlarmFailed {
			alarms++
		}
	}
	if alarms != 1 {
		t.Fatalf("alarms %+v", h.repo.alarms)
	}
}

// An attempt (token fetches and every DSS call of a put or a delete) is
// bounded by Policy.AttemptTimeout, which is shorter than the lease: a
// second worker cannot claim the row while the first is in flight
// (ansp audit S-1).
func TestAttemptBoundedByTheLease(t *testing.T) {
	h := newDSSHarness(t)
	pol := h.worker.Policy
	if pol.AttemptTimeout <= 0 || pol.AttemptTimeout >= pol.Lease || pol.Validate() != nil {
		t.Fatalf("attempt %s lease %s", pol.AttemptTimeout, pol.Lease)
	}
	before := time.Now()
	h.deliver(h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour)))
	h.tokens.mu.Lock()
	defer h.tokens.mu.Unlock()
	if len(h.tokens.deadlines) == 0 {
		t.Fatal("no token asked")
	}
	for _, dl := range h.tokens.deadlines {
		if dl.IsZero() || dl.After(before.Add(pol.AttemptTimeout+time.Second)) {
			t.Fatalf("a token fetch of the attempt is not bounded by %s: deadline %v", pol.AttemptTimeout, dl)
		}
	}
	bad := pol
	bad.AttemptTimeout = pol.Lease
	if bad.Validate() == nil {
		t.Fatal("an attempt as long as the lease is accepted")
	}
}

// The lease lost after the DSS accepted a write (ansp audit S-1, N-1):
// the outcome cannot be recorded under the lost lease, so it is counted,
// logged at error and alarmed (the subscribers the DSS named may never
// be notified), never acknowledged in silence. Twin: a held lease
// records the write (TestDSSWriteNotifiesEverySubscriber).
func TestLeaseLostAfterADSSWriteIsAlarmed(t *testing.T) {
	h := newDSSHarness(t)
	id := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h.repo.mu.Lock()
	h.repo.loseLease = true
	h.repo.mu.Unlock()
	m := h.deliver(id)
	if len(h.dss.Requests()) != 1 || !m.acked {
		t.Fatalf("requests %d acked %v", len(h.dss.Requests()), m.acked)
	}
	if h.counters.Get(CounterLeaseLost) != 1 || len(h.notifyJobs(2)) != 0 {
		t.Fatalf("counters %v", h.counters.Snapshot())
	}
	var alarm *Alarm
	for _, a := range h.repo.alarms {
		if a.DeliveryID == id {
			alarm = a
		}
	}
	if alarm == nil || !strings.Contains(alarm.Detail, "lease") || !strings.Contains(alarm.Detail, "2 subscriber") {
		t.Fatalf("alarm %+v", alarm)
	}
	if !strings.Contains(h.log(), `"level":"ERROR","msg":"deliver: the lease was lost`) {
		t.Fatalf("not logged at error:\n%s", h.log())
	}
}

// E-10: a DSS answer naming more subscriptions than the policy's bound
// is refused whole and alarmed, never cut; nothing is notified. At the
// bound it is accepted (see internal/dss for the 10 000 / 10 001 pair).
func TestDSSTooManySubscribersRefused(t *testing.T) {
	h := newDSSHarness(t)
	h.worker.DSS.Client.MaxSubscribers = 2
	h.dss.SetSubscribers(dsstest.Subscriber{BaseURL: h.ussA.URL(), Subscriptions: []string{subA, subB, "98ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"}})
	id := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h.deliver(id)
	if r := h.repo.row(id); r.State != StateFailed || !strings.Contains(r.LastError, "subscribers") {
		t.Fatalf("%+v", r.Delivery)
	}
	if h.counters.Get(CounterDSSSubscribersRefused) != 1 || len(h.repo.alarms) != 1 || len(h.notifyJobs(2)) != 0 {
		t.Fatal("not refused and alarmed")
	}
	if !strings.Contains(h.log(), "never cut") {
		t.Fatal("not logged")
	}
}

// What the channel cannot do says why: no DSS configured, no public
// base URL, no constraint derived for the version, no notification rows.
func TestDSSLocalFailures(t *testing.T) {
	h := newDSSHarness(t)
	h.worker.DSS.Client = nil
	id := h.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h.deliver(id)
	if r := h.repo.row(id); r.State != StateQueued || !strings.Contains(r.LastError, "ANSP_DSS_URL") {
		t.Fatalf("%+v", r.Delivery)
	}
	h2 := newDSSHarness(t)
	h2.worker.DSS.USSBaseURL = ""
	id = h2.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h2.deliver(id)
	if r := h2.repo.row(id); r.State != StateQueued || !strings.Contains(r.LastError, "ANSP_PUBLIC_BASE_URL") {
		t.Fatalf("%+v", r.Delivery)
	}
	h3 := newDSSHarness(t)
	id = h3.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h3.repo.setConstraint(testRID, testCID, 2, nil)
	h3.deliver(id)
	if r := h3.repo.row(id); r.State != StateFailed || !strings.Contains(r.LastError, "no F3548 constraint") {
		t.Fatalf("%+v", r.Delivery)
	}
	h4 := newDSSHarness(t)
	h4.worker.DSS = nil
	id = h4.step(2, "active", restriction.OpActivate, testStart.Add(4*time.Hour))
	h4.deliver(id)
	if r := h4.repo.row(id); r.State != StateQueued || !strings.Contains(r.LastError, "no DSS channel") {
		t.Fatalf("%+v", r.Delivery)
	}
	// A uss_notify job without its rows cannot be built: failed.
	err := h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		_, _, err := h.outbox.Enqueue(ctx, tx, Job{ID: "01K6P0A2C4E6G8J0K2M4N6P8QA", Kind: KindUSSNotify, RestrictionID: testRID, AnspRef: testRef,
			AnspVersion: 2, Op: OpDSSPut, Target: h.ussA.URL(), Window: time.Minute})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.outbox.Publish(context.Background(), Pending{ID: "01K6P0A2C4E6G8J0K2M4N6P8QA", Kind: KindUSSNotify}); err != nil {
		t.Fatal(err)
	}
	h.deliver("01K6P0A2C4E6G8J0K2M4N6P8QA")
	if r := h.repo.row("01K6P0A2C4E6G8J0K2M4N6P8QA"); r.State != StateFailed || !strings.Contains(r.LastError, "cannot be read") ||
		r.MaxAttempts != h.outbox.Policy.MaxAttemptsIn(time.Minute) {
		t.Fatalf("%+v", r.Delivery)
	}
	if _, err := NotificationBodyOf(NotificationJob{ConstraintID: testCID, Op: OpDSSPut, Reference: json.RawMessage(`[]`)}); err == nil {
		t.Fatal("a reference that is not one")
	}
}
