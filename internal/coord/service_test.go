package coord

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	repo  *fakeRepo
	bus   *fakeBus
	svc   *Service
	local []string
	mu    sync.Mutex
	// listed and projected are the USSP list the service judges by.
	listed    []string
	projected bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{repo: newFakeRepo(), bus: &fakeBus{}, listed: []string{"ussp-01"}, projected: true}
	f.svc = &Service{Repo: f.repo, Bus: f.bus, Producer: "ansp/api", Policy: DefaultPolicy(),
		USSPs: func() ([]string, bool) { return f.listed, f.projected },
		Local: func(key string, _ []byte) { f.mu.Lock(); f.local = append(f.local, key); f.mu.Unlock() }}
	return f
}

func (f *fixture) submit(t *testing.T, sub string, body []byte) (Receipt, bool, error) {
	t.Helper()
	return f.svc.Submit(context.Background(), sub, body)
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var rf *Refusal
	if !errors.As(err, &rf) {
		t.Fatalf("not a refusal: %v", err)
	}
	return rf
}

// A valid notice from a listed USSP: a receipt, one row, one audit
// event, one coord.v1 message after the commit, the local stream told,
// the restrictions recorded.
func TestSubmitReceivesANotice(t *testing.T) {
	f := newFixture(t)
	f.repo.restrictions = []string{"01K6P0A1B2C3D4E5F6G7H8J9KM"}
	rec, replay, err := f.submit(t, "ussp-01", readExample(t, "nonconformance.json"))
	if err != nil || replay || rec.State != "received" || rec.AckID == "" || rec.ReceivedAt != "2026-10-03T12:00:00.000Z" {
		t.Fatalf("%+v %v %v", rec, replay, err)
	}
	n, err := f.repo.Notice(context.Background(), rec.AckID)
	if err != nil || n.Kind != KindNonconformance || !n.AckRequired || n.SenderUnverified || len(n.RestrictionIDs) != 1 || n.USSPID != "ussp-01" {
		t.Fatalf("%+v %v", n, err)
	}
	if len(f.repo.audited("coordination_notice_received")) != 1 {
		t.Fatal("no audit event")
	}
	msgs := f.bus.published()
	if len(msgs) != 1 || msgs[0].subject != "coord.v1.nonconformance."+rec.AckID || msgs[0].id != rec.AckID+".1" {
		t.Fatalf("%+v", msgs)
	}
	var frame struct {
		Schema string     `json:"schema"`
		Body   NoticeBody `json:"body"`
	}
	if err := json.Unmarshal(msgs[0].data, &frame); err != nil || frame.Schema != SchemaNotice || frame.Body.State != "received" || len(frame.Body.Payload) == 0 {
		t.Fatalf("%s %v", msgs[0].data, err)
	}
	if n, _ = f.repo.Notice(context.Background(), rec.AckID); n.BusSeq != 1 {
		t.Fatal("the publish was not recorded")
	}
	if len(f.local) != 1 || f.local[0] != rec.AckID+".1" {
		t.Fatal(f.local)
	}
	if f.svc.Counters().Get(CounterReceived) != 1 {
		t.Fatal("not counted")
	}
}

// The same notice again answers the first receipt and stores nothing;
// the same notice_ref with another body is refused 409.
func TestSubmitReplayAndReuse(t *testing.T) {
	f := newFixture(t)
	body := readExample(t, "nonconformance.json")
	first, _, err := f.submit(t, "ussp-01", body)
	if err != nil {
		t.Fatal(err)
	}
	f.repo.advance(time.Second)
	again, replay, err := f.submit(t, "ussp-01", []byte(" "+string(body)))
	if err != nil || !replay || again != first || len(f.repo.notices) != 1 || len(f.bus.published()) != 1 {
		t.Fatalf("%+v %v %v", again, replay, err)
	}
	m := noticeMap(t)
	m["remarks"] = "a different notice"
	_, _, err = f.submit(t, "ussp-01", encode(t, m))
	if rf := refusalOf(t, err); rf.Status != http.StatusConflict || rf.Slug != SlugRefReused || rf.Fields[0].Field != "notice_ref" {
		t.Fatalf("%+v", rf)
	}
	if len(f.repo.notices) != 1 || f.svc.Counters().Get(CounterRefReused) != 1 || f.svc.Counters().Get(CounterReplayed) != 1 {
		t.Fatal("stored or not counted")
	}
	// Another sender may use the same notice_ref.
	f.listed = append(f.listed, "ussp-02")
	m = noticeMap(t)
	m["ussp_id"] = "ussp-02"
	if _, replay, err := f.submit(t, "ussp-ussp-02-01", encode(t, m)); err != nil || replay {
		t.Fatal(err)
	}
}

// A sender not on the list is refused 403 with an audit row; the body
// claiming another USSP is refused too; with no list projected the
// notice is accepted and flagged (E-02 for the degraded case).
func TestSubmitSender(t *testing.T) {
	f := newFixture(t)
	body := readExample(t, "nonconformance.json")
	_, _, err := f.submit(t, "ussp-99", body)
	if rf := refusalOf(t, err); rf.Status != http.StatusForbidden || rf.Slug != SlugSenderUnknown {
		t.Fatalf("%+v", rf)
	}
	refused := f.repo.audited("coordination_notice_refused")
	if len(refused) != 1 || refused[0].EntityID != "ussp-01-nc-000183" || refused[0].ActorID != "ussp-99" || len(f.repo.notices) != 0 {
		t.Fatalf("%+v", refused)
	}
	f.listed = []string{"ussp-01", "ussp-02"}
	_, _, err = f.submit(t, "ussp-02", body) // body says ussp-01
	if rf := refusalOf(t, err); rf.Status != http.StatusForbidden || rf.Slug != SlugSenderMismatch {
		t.Fatalf("%+v", rf)
	}
	// The audit log cannot take the refusal: 503, never a silent 403.
	f.repo.failAudit = errBoom
	_, _, err = f.submit(t, "ussp-99", []byte(`{"notice_ref":"`+strings.Repeat("x", 200)+`"}`))
	if rf := refusalOf(t, err); rf.Status != http.StatusServiceUnavailable || rf.RetryAfter == 0 {
		t.Fatalf("%+v", rf)
	}
	f.repo.failAudit = nil

	f.projected = false
	rec, _, err := f.submit(t, "anyone", body)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := f.repo.Notice(context.Background(), rec.AckID); !n.SenderUnverified || f.svc.Counters().Get(CounterSenderUnverified) != 1 {
		t.Fatal("not flagged")
	}
	// The twin: listed, it is not flagged.
	f.projected = true
	m := noticeMap(t)
	m["notice_ref"] = "another"
	rec, _, err = f.submit(t, "ussp-01", encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := f.repo.Notice(context.Background(), rec.AckID); n.SenderUnverified {
		t.Fatal("a listed sender flagged")
	}
	// No list function at all is no projection.
	f.svc.USSPs = nil
	m["notice_ref"] = "third"
	if rec, _, err = f.submit(t, "x", encode(t, m)); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.repo.Notice(context.Background(), rec.AckID); !n.SenderUnverified {
		t.Fatal("not flagged")
	}
}

func TestSenderMatches(t *testing.T) {
	for _, tc := range []struct {
		sub, id string
		want    bool
	}{
		{"ussp-01", "ussp-01", true}, {"ussp-abc-01", "abc", true}, {"ussp-abc-1234", "abc", true},
		{"ussp-abc-12345", "abc", false}, {"ussp-abc-", "abc", false}, {"ussp-abc-x1", "abc", false},
		{"ussp-abcd-01", "abc", false}, {"", "abc", false}, {"abc", "", false},
	} {
		if got := SenderMatches(tc.sub, tc.id); got != tc.want {
			t.Errorf("%q %q: %v", tc.sub, tc.id, got)
		}
	}
}

// A refused body stores nothing and publishes nothing.
func TestSubmitRefusedStoresNothing(t *testing.T) {
	f := newFixture(t)
	_, _, err := f.submit(t, "ussp-01", readExample(t, "invalid/unknown-kind.json"))
	if rf := refusalOf(t, err); rf.Status != http.StatusBadRequest || rf.Fields[0].Field != "kind" {
		t.Fatalf("%+v", rf)
	}
	if len(f.repo.notices) != 0 || len(f.bus.published()) != 0 || len(f.repo.audits) != 0 {
		t.Fatal("something was stored")
	}
}

func TestSubmitStoreFailures(t *testing.T) {
	f := newFixture(t)
	body := readExample(t, "nonconformance.json")
	for _, set := range []func(error){
		func(e error) { f.repo.failIntersect = e }, func(e error) { f.repo.failInsert = e },
		func(e error) { f.repo.failAudit = e }, func(e error) { f.repo.failNow = e },
	} {
		set(errBoom)
		if _, _, err := f.submit(t, "ussp-01", body); !errors.Is(err, errBoom) {
			t.Fatal(err)
		}
		set(nil)
		if len(f.repo.notices) != 0 || len(f.bus.published()) != 0 {
			t.Fatal("a failed transaction left a notice or a message")
		}
	}
	// More restrictions than recorded: cut and counted.
	f.svc.Policy.MaxRestrictionIDs = 1
	f.repo.restrictions = []string{"01K6P0A1B2C3D4E5F6G7H8J9KM", "01K6P0A1B2C3D4E5F6G7H8J9KN"}
	rec, _, err := f.submit(t, "ussp-01", body)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := f.repo.Notice(context.Background(), rec.AckID); len(n.RestrictionIDs) != 1 || f.svc.Counters().Get(CounterRestrictionsCut) != 1 {
		t.Fatal(n.RestrictionIDs)
	}
}

// A publish that fails is counted and left behind; the tick puts it on
// the bus (B-05, never forgotten), and the twin: with the bus back, the
// tick republishes nothing more.
func TestBusFailureIsRepublished(t *testing.T) {
	f := newFixture(t)
	f.bus.fail(errBoom)
	rec, _, err := f.submit(t, "ussp-01", readExample(t, "contingent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.svc.Counters().Get(CounterBusFailed) != 1 {
		t.Fatal("not counted")
	}
	rep, err := f.svc.Tick(context.Background())
	if err != nil || rep.Republished != 0 || rep.Behind != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	f.bus.fail(nil)
	if rep, err = f.svc.Tick(context.Background()); err != nil || rep.Republished != 1 || rep.Behind != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if msgs := f.bus.published(); len(msgs) != 1 || msgs[0].id != rec.AckID+".1" {
		t.Fatalf("%+v", msgs)
	}
	if rep, _ = f.svc.Tick(context.Background()); rep.Republished != 0 {
		t.Fatal("republished twice")
	}
	// A record of the publish that fails is counted too.
	before := f.svc.Counters().Get(CounterBusFailed)
	f.repo.failMark = errBoom
	m := noticeMap(t)
	m["notice_ref"] = "mark-fails"
	if _, _, err := f.submit(t, "ussp-01", encode(t, m)); err != nil {
		t.Fatal(err)
	}
	if f.svc.Counters().Get(CounterBusFailed) != before+1 {
		t.Fatal("not counted")
	}
	// No bus at all.
	f.svc.Bus = nil
	if f.svc.publishBus(context.Background(), Notice{AckID: "x"}) {
		t.Fatal("published without a bus")
	}
}

// Escalation on the fake clock: a nonconformance notice not acknowledged
// at 60 s is escalated, again at 90 s, and no more once acknowledged;
// an intent_notice never escalates (E-01 pair).
func TestEscalation(t *testing.T) {
	f := newFixture(t)
	clock := f.repo.now
	f.svc.Clock = func(context.Context) (time.Time, error) { return clock, nil }
	f.svc.Escalation = func(context.Context) (time.Duration, int64) { return 60 * time.Second, 3 }
	nc, _, err := f.submit(t, "ussp-01", readExample(t, "nonconformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	info, _, err := f.submit(t, "ussp-01", readExample(t, "intent-notice-touching-controlled-airspace.json"))
	if err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) TickReport {
		t.Helper()
		clock = f.repo.now.Add(d)
		rep, err := f.svc.Tick(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if rep := at(59 * time.Second); len(rep.Escalated) != 0 {
		t.Fatal("escalated before 60 s")
	}
	rep := at(60 * time.Second)
	if len(rep.Escalated) != 1 || rep.Escalated[0].AckID != nc.AckID || rep.Escalated[0].Escalations != 1 || rep.Escalated[0].State() != StateEscalated {
		t.Fatalf("%+v", rep)
	}
	if rep := at(75 * time.Second); len(rep.Escalated) != 0 {
		t.Fatal("repeated before 30 s")
	}
	if rep := at(90 * time.Second); len(rep.Escalated) != 1 || rep.Escalated[0].Escalations != 2 {
		t.Fatalf("%+v", rep)
	}
	if f.svc.Counters().Get(CounterEscalated) != 2 {
		t.Fatal("not counted")
	}
	// Each escalation is a frame of its own on the bus.
	var esc int
	for _, m := range f.bus.published() {
		if strings.HasPrefix(m.id, nc.AckID+".") && m.id != nc.AckID+".1" {
			esc++
		}
	}
	if esc != 2 {
		t.Fatalf("%d escalation frames", esc)
	}
	if _, err := f.svc.Acknowledge(context.Background(), Actor{ID: "u1", Role: "watch_supervisor"}, nc.AckID, ""); err != nil {
		t.Fatal(err)
	}
	if rep := at(500 * time.Second); len(rep.Escalated) != 0 {
		t.Fatal("escalated after the acknowledgement")
	}
	if n, _ := f.repo.Notice(context.Background(), info.AckID); n.EscalatedAt != nil || n.State() != StateReceived {
		t.Fatal("an intent_notice escalated")
	}
	// Without a policy function the default is 60 s.
	f.svc.Escalation = nil
	m := noticeMap(t)
	m["notice_ref"] = "late"
	late, _, _ := f.submit(t, "ussp-01", encode(t, m))
	clock = clock.Add(61 * time.Second)
	if rep, _ := f.svc.Tick(context.Background()); len(rep.Escalated) != 1 || rep.Escalated[0].AckID != late.AckID {
		t.Fatalf("%+v", rep)
	}
}

func TestTickFailures(t *testing.T) {
	f := newFixture(t)
	f.repo.failNow = errBoom
	if _, err := f.svc.Tick(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.repo.failNow = nil
	f.repo.failEscalate = errBoom
	if _, err := f.svc.Tick(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.repo.failEscalate = nil
	f.repo.failBehind = errBoom
	if _, err := f.svc.Tick(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if !strings.Contains((TickReport{Republished: 2}).String(), "republished 2") {
		t.Fatal("report text")
	}
}

// Run ticks until its context ends and reports each tick.
func TestRun(t *testing.T) {
	f := newFixture(t)
	f.svc.Policy.TickEvery = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan TickReport, 100)
	done := make(chan struct{})
	go func() {
		f.svc.Run(ctx, func(rep TickReport, _ error) {
			select {
			case ticks <- rep:
			default:
			}
		})
		close(done)
	}()
	select {
	case <-ticks:
	case <-time.After(10 * time.Second):
		t.Fatal("no tick")
	}
	cancel()
	<-done
}

func TestGetAndInbox(t *testing.T) {
	f := newFixture(t)
	a, _, _ := f.submit(t, "ussp-01", readExample(t, "nonconformance.json"))
	f.repo.advance(time.Second)
	b, _, _ := f.submit(t, "ussp-01", readExample(t, "ended.json"))
	ctx := context.Background()
	if n, err := f.svc.Get(ctx, a.AckID, "ussp-01"); err != nil || n.AckID != a.AckID {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, a.AckID, "ussp-02"); !errors.Is(err, ErrNotFound) {
		t.Fatal("another sender read the notice")
	}
	if _, err := f.svc.Get(ctx, a.AckID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, "01K6P3Q8Y2D6W4Z1V7R5T9X3MZ", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	actor := Actor{ID: "u1", Role: "viewer"}
	list, more, err := f.svc.Inbox(ctx, actor, Filter{Limit: 1})
	if err != nil || len(list) != 1 || !more || list[0].AckID != b.AckID {
		t.Fatalf("%+v %v %v", list, more, err)
	}
	since := f.repo.now
	list, more, err = f.svc.Inbox(ctx, actor, Filter{Limit: 10, State: "received", Since: &since})
	if err != nil || len(list) != 1 || more {
		t.Fatalf("%+v %v", list, err)
	}
	if v := f.repo.audited("coordination_inbox_viewed"); len(v) != 2 || v[1].ActorID != "u1" {
		t.Fatalf("%+v", v)
	}
	f.repo.failAudit = errBoom
	if _, _, err := f.svc.Inbox(ctx, actor, Filter{Limit: 1}); refusalOf(t, err).Status != http.StatusServiceUnavailable {
		t.Fatal(err)
	}
	f.repo.failAudit = nil
	f.repo.failNotices = errBoom
	if _, _, err := f.svc.Inbox(ctx, actor, Filter{}); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Snapshot(ctx, 1); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.repo.failNotices = nil
	frames, more, err := f.svc.Snapshot(ctx, 1)
	if err != nil || len(frames) != 1 || !more {
		t.Fatal(err)
	}
	if _, err := f.svc.Acknowledge(ctx, Actor{ID: "u2", Role: "watch_supervisor"}, b.AckID, ""); err != nil {
		t.Fatal(err)
	}
	if frames, more, _ = f.svc.Snapshot(ctx, 10); len(frames) != 1 || more {
		t.Fatal("an acknowledged notice is in the snapshot of the open inbox")
	}
}

func TestAcknowledge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rec, _, _ := f.submit(t, "ussp-01", readExample(t, "nonconformance.json"))
	f.repo.advance(38 * time.Second)
	actor := Actor{ID: "acct-7", Role: "watch_supervisor"}
	f.repo.failAudit = errBoom
	if _, err := f.svc.Acknowledge(ctx, actor, rec.AckID, "x"); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if n, _ := f.repo.Notice(ctx, rec.AckID); n.Acknowledged {
		t.Fatal("acknowledged without its audit row")
	}
	f.repo.failAudit = nil
	n, err := f.svc.Acknowledge(ctx, actor, rec.AckID, "aware")
	if err != nil || n.State() != StateAcknowledged || n.AcknowledgedBy != "watch_supervisor" {
		t.Fatalf("%+v %v", n, err)
	}
	ev := f.repo.audited("coordination_notice_acknowledged")
	if len(ev) != 1 || ev[0].Payload.(map[string]any)["seconds_after_receipt"] != 38.0 {
		t.Fatalf("%+v", ev)
	}
	if _, err := f.svc.Acknowledge(ctx, actor, rec.AckID, ""); !errors.Is(err, ErrAcknowledged) {
		t.Fatal(err)
	}
	if _, err := f.svc.Acknowledge(ctx, actor, "01K6P3Q8Y2D6W4Z1V7R5T9X3MZ", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// The sender reads the role and the time, never a name or the note.
	b := BodyOf(n, false)
	if b.AcknowledgedBy == nil || *b.AcknowledgedBy != "watch_supervisor" || b.AcknowledgedAt == nil || b.AcknowledgementNote != nil || b.Payload != nil {
		t.Fatalf("%+v", b)
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "acct-7") {
		t.Fatal("the account id reached the sender")
	}
	if c := BodyOf(n, true); c.AcknowledgementNote == nil || *c.AcknowledgementNote != "aware" || c.Payload == nil {
		t.Fatalf("%+v", c)
	}
	if BodyOf(Notice{Payload: []byte("{")}, true).Payload != nil {
		t.Fatal("a payload that is not JSON was framed")
	}
}

func TestDecodeAcknowledge(t *testing.T) {
	for body, want := range map[string]string{"": "", "  ": "", `{}`: "", `{"note":" aware "}`: "aware", `{"note":null,"x":1}`: ""} {
		if got, fe := DecodeAcknowledge([]byte(body)); fe != nil || got != want {
			t.Errorf("%q: %q %v", body, got, fe)
		}
	}
	for _, body := range []string{"[]", `{"note":1}`, `{"note":"` + strings.Repeat("n", MaxNoteBytes+1) + `"}`, "{"} {
		if _, fe := DecodeAcknowledge([]byte(body)); fe == nil {
			t.Errorf("%q accepted", body)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.EscalationRepeat = 0 }, func(p *Policy) { p.MaxBatch = 0 },
		func(p *Policy) { p.OccurrenceAlarmAfter = OccurrenceDeadline },
	} {
		p := DefaultPolicy()
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("accepted")
		}
	}
	if (&Refusal{Slug: "x", Detail: "y"}).Error() != "x: y" {
		t.Fatal("refusal text")
	}
}
