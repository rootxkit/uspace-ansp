package deliver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// B-05: a row whose publish after the commit was lost is published by
// the scan, counted and logged; a row whose message is overdue is
// published again with the next sequence. The twin: a row published in
// time is left alone.
func TestOutboxScan(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "planned"))
	var id string
	_ = h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		id, _, _ = h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish, RestrictionID: testRID, AnspRef: testRef, AnspVersion: 1, Op: OpCreate, Target: TargetCISP})
		return nil
	})
	if n, _ := h.outbox.Scan(context.Background()); n != 0 {
		t.Fatal("a fresh row was taken for a lost publish")
	}
	h.clock.Advance(3 * time.Second)
	if n, err := h.outbox.Scan(context.Background()); n != 1 || err != nil {
		t.Fatalf("scan %d %v", n, err)
	}
	msgs := h.bus.all()
	if len(msgs) != 1 || msgs[0].id != id+".1" || msgs[0].subject != "deliver.v1.cisp_publish" || h.counters.Get(CounterRepublished) != 1 {
		t.Fatalf("messages %v", msgs)
	}
	m, err := DecodeMessage(msgs[0].data)
	if err != nil || m.ID != id || m.Seq != 1 {
		t.Fatalf("message %+v %v", m, err)
	}
	if n, _ := h.outbox.Scan(context.Background()); n != 0 {
		t.Fatal("a published row was published again at once")
	}
	h.clock.Advance(31 * time.Second)
	if n, _ := h.outbox.Scan(context.Background()); n != 1 || h.counters.Get(CounterStuck) != 1 || h.bus.all()[1].id != id+".2" {
		t.Fatalf("the overdue message: %v", h.bus.all())
	}
	if !strings.Contains(h.log(), "never published after its commit") || !strings.Contains(h.log(), "overdue") {
		t.Fatal("the repaired gaps are not logged")
	}
	// The bus failing: the row stays unpublished, counted.
	h.bus.err = errBoom
	h.clock.Advance(time.Minute)
	if n, _ := h.outbox.Scan(context.Background()); n != 0 || h.counters.Get(CounterBusFailed) == 0 {
		t.Fatal("a failed publish counted as done")
	}
	h.repo.failNext["Pending"] = errBoom
	if _, err := h.outbox.Scan(context.Background()); err == nil || h.counters.Get(CounterScanFailed) != 1 {
		t.Fatal("a failed scan")
	}
	// No bus at all.
	o := &Outbox{Repo: h.repo, Policy: h.outbox.Policy}
	if err := o.Publish(context.Background(), Pending{ID: id, Kind: KindCISPPublish}); err == nil {
		t.Fatal("published without a bus")
	}
}

// The restriction service's hook: a version's job is written in the
// version's transaction and published after the commit; an expiry
// queues no CISP publication (the CISP expires it on its own clock) but
// the DSS delete (WP-9), and the restriction's DSS standing is pending;
// a transaction the outbox cannot write in refuses.
func TestRestrictionHook(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "planned"))
	var tx Tx
	hook := RestrictionHook{Outbox: h.outbox, TxOf: func(restriction.Tx) (Tx, bool) { return tx, tx != nil }}
	v := restriction.Version{RestrictionID: testRID, AnspRef: testRef, Version: 1}
	if err := hook.Versioned(context.Background(), nil, v, restriction.OpPlan); err == nil {
		t.Fatal("a version committed without its delivery")
	}
	err := h.repo.Tx(context.Background(), func(ctx context.Context, t2 Tx) error {
		tx = t2
		if err := hook.Versioned(ctx, nil, v, restriction.OpPlan); err != nil {
			return err
		}
		return hook.Versioned(ctx, nil, restriction.Version{RestrictionID: testRID, AnspRef: testRef, Version: 2}, restriction.OpExpire)
	})
	if err != nil || len(h.repo.order) != 2 || h.repo.row(h.repo.order[0]).Op != OpCreate {
		t.Fatalf("rows %v %v", h.repo.order, err)
	}
	if del := h.repo.row(h.repo.order[1]); del.Kind != KindDSSDelete || del.Target != TargetDSS || del.Op != OpDSSDelete || del.AnspVersion != 2 {
		t.Fatalf("the expiry's job %+v", del.Delivery)
	}
	if d := h.repo.dssOf(testRID); d.state != DSSPending || d.since == nil {
		t.Fatalf("the DSS standing after the expiry %+v", d)
	}
	hook.Committed(context.Background(), []restriction.Version{v})
	if len(h.bus.all()) != 1 {
		t.Fatal("not published after the commit")
	}
	// The read of the committed jobs failing leaves them to the scan.
	h.repo.failNext["QueuedOf"] = errBoom
	h.outbox.Committed(context.Background(), []restriction.Version{v})
	if !strings.Contains(h.log(), "the outbox scan publishes them") {
		t.Fatal("not said")
	}
	// An incomplete or oversized job is refused.
	_ = h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		if _, _, err := h.outbox.Enqueue(ctx, tx, Job{Kind: KindCISPPublish}); err == nil {
			t.Fatal("an incomplete job")
		}
		big := Job{Kind: KindDirect, RestrictionID: testRID, AnspRef: testRef, AnspVersion: 1, Op: OpNotify, Target: "https://x", Body: make([]byte, 300<<10)}
		if _, _, err := h.outbox.Enqueue(ctx, tx, big); err == nil {
			t.Fatal("an oversized body")
		}
		return nil
	})
}

// The acknowledgement of each kind: a failed delivery's alarm closes, a
// cisp_not_published stays open marked acknowledged; a second one is a
// conflict; every one is audited and told on restr.v1.
func TestAlarmsAcknowledge(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "active"))
	al := &Alarms{Repo: h.repo, Events: h.events, Logger: h.worker.Logger, Counters: h.counters}
	_ = h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		_, _, _ = tx.RaiseAlarm(ctx, Alarm{ID: "01K6P0B4M8N2Q6R0S4T8V2W6X0", Kind: AlarmFailed, RestrictionID: testRID, AnspVersion: 1, DeliveryID: "01K6P0A2C4E6G8J0K2M4N6P8Q0", Since: testStart, Detail: "failed"})
		_, _, _ = tx.RaiseAlarm(ctx, Alarm{ID: "01K6P0A9QZ3V1H8M2T6R4W5X7C", Kind: AlarmCISPNotPublished, RestrictionID: testRID, AnspVersion: 1, Since: testStart, Detail: "not yet published"})
		return nil
	})
	list, more, err := al.List(context.Background(), false, 1)
	if err != nil || len(list) != 1 || !more {
		t.Fatalf("list %v %v %v", list, more, err)
	}
	actor := Actor{ID: "u1", Role: "watch_supervisor"}
	a, err := al.Acknowledge(context.Background(), actor, "01K6P0B4M8N2Q6R0S4T8V2W6X0", "seen; replanned")
	if err != nil || AlarmStateOf(a) != AlarmStateCleared || a.ClearReason != "acknowledged" || a.AcknowledgedBy != "watch_supervisor" {
		t.Fatalf("failed alarm %+v %v", a, err)
	}
	a, err = al.Acknowledge(context.Background(), actor, "01K6P0A9QZ3V1H8M2T6R4W5X7C", "the CISP operator is on it")
	if err != nil || AlarmStateOf(a) != AlarmStateAcknowledged || !a.Open() {
		t.Fatalf("cisp alarm %+v %v", a, err)
	}
	if _, err := al.Acknowledge(context.Background(), actor, "01K6P0A9QZ3V1H8M2T6R4W5X7C", "again"); !errors.Is(err, ErrAcknowledged) {
		t.Fatalf("second: %v", err)
	}
	if _, err := al.Acknowledge(context.Background(), actor, "01K6P0A9QZ3V1H8M2T6R4W5X7D", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if len(h.repo.audits) != 2 || h.repo.audits[0].EventType != "delivery_alarm_acknowledged" || h.repo.audits[0].ActorID != "u1" {
		t.Fatalf("audits %+v", h.repo.audits)
	}
	if got := len(h.bus.bodies("restr.v1.")); got != 2 {
		t.Fatalf("restr.v1 %d", got)
	}
	list, _, _ = al.List(context.Background(), true, 10)
	if len(list) != 2 {
		t.Fatalf("all %d", len(list))
	}
	open, _, _ := al.List(context.Background(), false, 10)
	if len(open) != 1 || open[0].Kind != AlarmCISPNotPublished {
		t.Fatalf("open %v", open)
	}
	h.repo.failNext["Alarms"] = errBoom
	if _, _, err := al.List(context.Background(), false, 10); err == nil {
		t.Fatal("no error")
	}
	h.repo.failNext["Audit"] = errBoom
	_ = h.repo.Tx(context.Background(), func(ctx context.Context, tx Tx) error {
		_, _, _ = tx.RaiseAlarm(ctx, Alarm{ID: "01K6P0B4M8N2Q6R0S4T8V2W6X1", Kind: AlarmAbandoned, RestrictionID: testRID, AnspVersion: 1, DeliveryID: "01K6P0A2C4E6G8J0K2M4N6P8Q1", Since: testStart, Detail: "abandoned"})
		return nil
	})
	if _, err := al.Acknowledge(context.Background(), actor, "01K6P0B4M8N2Q6R0S4T8V2W6X1", "x"); err == nil {
		t.Fatal("acknowledged without its audit row")
	}
	if a, _ := h.repo.Alarm(context.Background(), "01K6P0B4M8N2Q6R0S4T8V2W6X1"); a.AcknowledgedAt != nil {
		t.Fatal("the acknowledgement stayed without its audit row")
	}
}

func TestDecodeAcknowledge(t *testing.T) {
	if r, fe := DecodeAcknowledge([]byte(`{"reason":"  seen  "}`)); fe != nil || r != "seen" {
		t.Fatalf("%q %v", r, fe)
	}
	for _, body := range []string{``, `[]`, `{}`, `{"reason":""}`, `{"reason":"x","note":"y"}`, `{"reason":"x"} {}`,
		`{"reason":"` + strings.Repeat("x", 1001) + `"}`} {
		if _, fe := DecodeAcknowledge([]byte(body)); fe == nil {
			t.Fatalf("%q accepted", body)
		}
	}
}

// The outcome messages: a store or bus failure is counted and said, the
// outcome stays in the database.
func TestEventsFailures(t *testing.T) {
	h := newHarness(t, nil)
	h.repo.addVersion(version(1, "active"))
	h.repo.failNext["Version"] = errBoom
	h.events.Published(context.Background(), testRID, 1)
	h.repo.failNext["Channels"] = errBoom
	h.events.Published(context.Background(), testRID, 1)
	h.bus.err = errBoom
	h.events.Published(context.Background(), testRID, 1)
	if h.counters.Get(CounterEventFailed) != 3 || !strings.Contains(h.log(), "GET /v1/delivery-alarms") {
		t.Fatalf("event failures %d", h.counters.Get(CounterEventFailed))
	}
	var nilEvents *Events
	nilEvents.Published(context.Background(), testRID, 1)
	h.events.Alarm(context.Background(), Alarm{}, "raised")
}

func TestSummarise(t *testing.T) {
	now := testStart
	sc := 503
	s := Summarise([]ChannelRow{
		{Kind: KindCISPPublish, State: StateSent, Attempt: 2, LastAttemptAt: &now, StatusCode: &sc},
		{Kind: KindDirect, State: StateSent, Attempt: 1},
		{Kind: KindDirect, State: StateQueued, Attempt: 3, NextRetryAt: now},
		{Kind: KindDirect, State: StateCancelled, Attempt: 1},
		{Kind: KindDSSPut, State: StateFailed, Attempt: 1},
		{Kind: KindUSSNotify, State: StateAbandoned, Attempt: 9},
		{Kind: KindOccurrence, State: StateFailed},
	})
	if s.CISP.State != "sent" || s.CISP.Attempts != 2 || *s.CISP.LastStatusCode != 503 || s.DirectDegraded.State != "queued" ||
		s.DirectDegraded.Attempts != 5 || s.DirectDegraded.NextRetryAt == nil || s.DSS.State != "failed" || s.USSNotify.State != "abandoned" {
		t.Fatalf("%+v", s)
	}
	if n := NoSummary(); n.CISP.State != "none" || n.DirectDegraded.State != "none" {
		t.Fatal("none")
	}
}

func TestPolicy(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	for n := 1; n <= 8; n++ {
		waits = append(waits, p.Backoff(n))
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("backoff %v", waits)
		}
	}
	// 24 h at 1, 2, ... 32 s and then 60 s: 1445 attempts.
	if n := p.MaxAttempts(); n != 1445 {
		t.Fatalf("max attempts %d", n)
	}
	bad := Policy{}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatal(err)
	}
	p.Lease = p.HTTPTimeout
	if err := p.Validate(); err == nil {
		t.Fatal("a lease shorter than the timeout")
	}
}

func TestJudgeExcerptRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   Verdict
	}{{0, Retry}, {200, Sent}, {204, Sent}, {301, Permanent}, {400, Permanent}, {401, Permanent}, {404, Permanent},
		{408, Retry}, {409, Retry}, {429, Retry}, {500, Retry}, {503, Retry}} {
		if got := Judge(Response{Status: tc.status}); got != tc.want {
			t.Fatalf("%d: %v", tc.status, got)
		}
	}
	if Excerpt([]byte("short"), 16, false) != "short" {
		t.Fatal("short")
	}
	if got := Excerpt([]byte("héllo world, a longer text"), 2, false); got != "h... (truncated)" {
		t.Fatalf("%q", got)
	}
	for _, tc := range []struct {
		v    string
		want time.Duration
	}{{"", 0}, {"5", 5 * time.Second}, {"0", 0}, {"-1", 0}, {"x", 0}, {"999999", 60 * time.Second}, {"12345678901", 0}} {
		if got := ParseRetryAfter(tc.v, time.Minute); got != tc.want {
			t.Fatalf("%q: %v", tc.v, got)
		}
	}
}

// E-10: an answer of 1 MiB + 1 is read to the bound and its excerpt
// says it was cut; its twin, 1 MiB exactly, is not marked as cut by the
// bound.
func TestResponseBound(t *testing.T) {
	for _, tc := range []struct {
		n      int
		capped bool
	}{{1<<20 + 1, true}, {1 << 20, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(strings.Repeat("a", tc.n)))
		}))
		req, _ := newRequest(http.MethodPost, srv.URL, []byte("{}"))
		r := do(context.Background(), NewHTTPClient(5*time.Second, nil, nil), req, 1<<20, 1024, time.Minute)
		srv.Close()
		if r.Status != 503 || r.RetryAfter != 7*time.Second || len(r.Excerpt) > 1024+80 {
			t.Fatalf("%d: %+v", tc.n, r.Status)
		}
		if strings.Contains(r.Excerpt, "longer than the read bound") != tc.capped || !strings.Contains(r.Excerpt, "truncated") {
			t.Fatalf("%d: %q", tc.n, r.Excerpt[1000:])
		}
	}
	// A timeout is named, never a URL or a body.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	req, _ := newRequest(http.MethodPost, srv.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if r := do(ctx, NewHTTPClient(5*time.Second, nil, nil), req, 10, 10, time.Minute); r.Status != 0 || r.Err != "timeout" {
		t.Fatalf("%+v", r)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if r := do(ctx2, NewHTTPClient(5*time.Second, nil, nil), req, 10, 10, time.Minute); r.Err != "cancelled" {
		t.Fatalf("%+v", r)
	}
	if transportReason(errors.New(strings.Repeat("e", 400))) != strings.Repeat("e", 300) {
		t.Fatal("not bounded")
	}
}

// The CISP client certificate: its subject is what the CISP's proxy
// forwards; a pair that does not match, one not valid now and one not
// for client authentication are refused. Test certificates are made at
// test time.
func TestLoadClientCert(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) (string, string) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ansp-01", Organization: []string{"Test ANSP"}},
			NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: eku}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cf, kf := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		_ = os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		_ = os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
		return cf, kf
	}
	now := time.Now()
	cf, kf := write("good", now.Add(-time.Hour), now.Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	c, err := LoadClientCert(cf, kf, now)
	if err != nil || c.Subject != "CN=ansp-01,O=Test ANSP" {
		t.Fatalf("%+v %v", c, err)
	}
	if NewHTTPClient(time.Second, &c.Cert, nil) == nil {
		t.Fatal("no client")
	}
	cf2, kf2 := write("old", now.Add(-2*time.Hour), now.Add(-time.Hour), nil)
	if _, err := LoadClientCert(cf2, kf2, now); err == nil || !strings.Contains(err.Error(), "not now") {
		t.Fatalf("expired: %v", err)
	}
	cf3, kf3 := write("server", now.Add(-time.Hour), now.Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, err := LoadClientCert(cf3, kf3, now); err == nil || !strings.Contains(err.Error(), "client authentication") {
		t.Fatalf("server only: %v", err)
	}
	if _, err := LoadClientCert(cf, filepath.Join(dir, "missing.key"), now); err == nil {
		t.Fatal("no key")
	}
}

func TestDecodeMessage(t *testing.T) {
	good := `{"id":"01K6P0A1B2C3D4E5F6G7H8J9KM","kind":"direct_degraded","bus_seq":2}`
	if m, err := DecodeMessage([]byte(good)); err != nil || m.Kind != KindDirect || m.Seq != 2 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, bad := range []string{"", "{", `{"id":"x","kind":"cisp_publish"}`, `{"id":"01K6P0A1B2C3D4E5F6G7H8J9KM","kind":"nope"}`,
		`{"id":"01K6P0A1B2C3D4E5F6G7H8J9KM","kind":"cisp_publish","bus_seq":-1}`, good + good,
		`{"id":"01K6P0A1B2C3D4E5F6G7H8J9KM","kind":"cisp_publish","extra":1}`, strings.Repeat(" ", MaxMessageBytes+1)} {
		if _, err := DecodeMessage([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if clip("héllo", 2) != "h" || clip("ok", 5) != "ok" {
		t.Fatal("clip")
	}
}

func FuzzDecodeMessage(f *testing.F) {
	f.Add([]byte(`{"id":"01K6P0A1B2C3D4E5F6G7H8J9KM","kind":"cisp_publish","bus_seq":1}`))
	f.Add([]byte(`{"id":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeMessage(b)
		if err == nil && (!m.Kind.Valid() || !ulidPattern.MatchString(m.ID) || m.Seq < 0) {
			t.Fatalf("accepted %+v", m)
		}
	})
}

func FuzzExcerpt(f *testing.F) {
	f.Add([]byte("héllo"), 3, false)
	f.Add([]byte{0xff, 0xfe, 'a'}, 1, true)
	f.Fuzz(func(t *testing.T, b []byte, n int, capped bool) {
		n = n%4096 + 1
		if n < 1 {
			n = -n + 1
		}
		s := Excerpt(b, n, capped)
		if !strings.Contains(s, "truncated") && len(s) > len(b)*3 {
			t.Fatalf("grew: %q", s)
		}
		if strings.ToValidUTF8(s, "") != s {
			t.Fatalf("invalid UTF-8 %q", s)
		}
	})
}

func FuzzParseRetryAfter(f *testing.F) {
	for _, s := range []string{"", "1", "60", "-1", "Wed, 21 Oct 2015 07:28:00 GMT", "99999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d := ParseRetryAfter(s, time.Minute); d < 0 || d > time.Minute {
			t.Fatalf("%q: %v", s, d)
		}
	})
}

func FuzzDecodeAcknowledge(f *testing.F) {
	f.Add([]byte(`{"reason":"seen"}`))
	f.Add([]byte(`{"reason":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, fe := DecodeAcknowledge(b)
		if fe == nil && (r == "" || len(r) > MaxAckReasonBytes) {
			t.Fatalf("accepted %q", r)
		}
	})
}
