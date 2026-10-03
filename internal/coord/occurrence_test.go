package coord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
)

const occurrenceBody = `{"channel":"mandatory","occurred_at":"2026-10-03T10:00:00.000Z","became_aware_at":"2026-10-03T10:05:00.000Z",
"category":"airprox","aircraft":[{"serial":"1581F5FHD23440010000","operator_reg":"GEOrz3pa1x0d5ozm"}],
"manned":[{"icao24":"4ca7b5","callsign":"TST123"}],"intent_refs":["2F8343BE-6482-4d1b-a474-16847e01af1e"],
"min_separation":{"h_m":180,"v_m":40,"at":"2026-10-03T10:00:00Z"},
"narrative":"Synthetic airprox between a UAS and a manned aircraft.","reporter_person_ref":"staff-0042","future":1}`

func TestDecodeOccurrence(t *testing.T) {
	in, errs := DecodeOccurrence([]byte(occurrenceBody))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if in.PersonRef != "staff-0042" || in.Category != "airprox" || len(in.Aircraft) != 1 || in.Manned[0].ICAO24 != "4ca7b5" ||
		in.IntentRefs[0] != "2f8343be-6482-4d1b-a474-16847e01af1e" || *in.MinSeparation.HM != 180 || *in.MinSeparation.At != "2026-10-03T10:00:00.000Z" {
		t.Fatalf("%+v", in)
	}
	// The reference is never in what the input encodes to.
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "staff-0042") {
		t.Fatal("the reporter reference is encoded")
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(occurrenceBody), &m)
	for field, mutate := range map[string]func(map[string]any){
		"channel":             func(m map[string]any) { m["channel"] = "gossip" },
		"category":            func(m map[string]any) { m["category"] = "ufo" },
		"occurred_at":         func(m map[string]any) { delete(m, "occurred_at") },
		"became_aware_at":     func(m map[string]any) { m["became_aware_at"] = "2026-10-03T09:00:00Z" },
		"narrative":           func(m map[string]any) { m["narrative"] = "" },
		"reporter_person_ref": func(m map[string]any) { m["reporter_person_ref"] = strings.Repeat("p", 129) },
		"aircraft":            func(m map[string]any) { m["aircraft"] = "x" },
		"aircraft[0]":         func(m map[string]any) { m["aircraft"] = []any{1} },
		"aircraft[0].serial":  func(m map[string]any) { m["aircraft"] = []any{map[string]any{"serial": strings.Repeat("s", 129)}} },
		"manned":              func(m map[string]any) { m["manned"] = make([]any, 51) },
		"manned[0]":           func(m map[string]any) { m["manned"] = []any{"x"} },
		"manned[0].icao24":    func(m map[string]any) { m["manned"] = []any{map[string]any{"icao24": "4CA7B5"}} },
		"manned[0].callsign":  func(m map[string]any) { m["manned"] = []any{map[string]any{"callsign": strings.Repeat("c", 129)}} },
		"intent_refs[0]":      func(m map[string]any) { m["intent_refs"] = []any{"nope"} },
		"min_separation":      func(m map[string]any) { m["min_separation"] = 3 },
		"min_separation.h_m":  func(m map[string]any) { m["min_separation"] = map[string]any{"h_m": -1} },
		"min_separation.at":   func(m map[string]any) { m["min_separation"] = map[string]any{"at": "noon"} },
	} {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		mutate(c)
		raw, _ := json.Marshal(c)
		_, errs := DecodeOccurrence(raw)
		if len(errs) == 0 || errs[0].Field != field {
			t.Errorf("%s: %v", field, errs)
		}
		for _, e := range errs {
			if strings.Contains(e.Reason, "ppp") {
				t.Errorf("%s: the reason echoes the value", field)
			}
		}
	}
	for _, body := range []string{"[]", "{", string(make([]byte, MaxOccurrenceBytes+1))} {
		if _, errs := DecodeOccurrence([]byte(body)); len(errs) != 1 || errs[0].Field != "body" {
			t.Errorf("%.10q: %v", body, errs)
		}
	}
}

type fakeTokens struct{ aud, scope string }

func (f *fakeTokens) TokenFor(_ context.Context, aud string, scopes []string) (string, error) {
	f.aud, f.scope = aud, strings.Join(scopes, " ")
	return "tok", nil
}

// authorityStub records what the authority received and answers code;
// echo writes the body back in the answer.
type authorityStub struct {
	mu   sync.Mutex
	got  [][]byte
	hdr  []http.Header
	code int
	echo bool
	// reply, when set, is written as the answer.
	reply []byte
	srv   *httptest.Server
}

func newAuthority(t *testing.T) *authorityStub {
	t.Helper()
	a := &authorityStub{code: http.StatusAccepted}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.got, a.hdr = append(a.got, b), append(a.hdr, r.Header.Clone())
		code, echo, reply := a.code, a.echo, a.reply
		a.mu.Unlock()
		w.WriteHeader(code)
		if reply != nil {
			_, _ = w.Write(reply)
		}
		if echo {
			_, _ = w.Write(b)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

type occFixture struct {
	repo   *fakeRepo
	occ    *Occurrences
	sealer *auth.Sealer
	auth   *authorityStub
	tokens *fakeTokens
}

func newOccFixture(t *testing.T) *occFixture {
	t.Helper()
	sealer, err := auth.NewSealer(bytes.Repeat([]byte{7}, auth.SealKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	repo := newFakeRepo()
	pol := deliver.DefaultPolicy()
	a := newAuthority(t)
	tok := &fakeTokens{}
	o := &Occurrences{Repo: repo, Sealer: sealer, Outbox: &deliver.Outbox{Repo: nil, Policy: pol}, Org: "ansp-01", Policy: DefaultPolicy(),
		Authority: &deliver.Authority{BaseURL: a.srv.URL, Client: deliver.NewHTTPClient(pol.HTTPTimeout, nil, nil), Tokens: tok, Policy: pol}}
	return &occFixture{repo: repo, occ: o, sealer: sealer, auth: a, tokens: tok}
}

func (f *occFixture) create(t *testing.T, body string) Queued {
	t.Helper()
	in, errs := DecodeOccurrence([]byte(body))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	q, err := f.occ.Create(context.Background(), Actor{ID: "acct-3", Role: "watch_supervisor"}, in)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// A report is stored sealed with its job and audit event; the
// authority receives the reporter reference in clear and no name; the
// stored bytes are not the plaintext (the twin).
func TestOccurrenceCreateAndSend(t *testing.T) {
	f := newOccFixture(t)
	q := f.create(t, occurrenceBody)
	if q.State != "queued" || q.ReportRef != "ANSP-OCC-2026-0001" || q.DeadlineAt != "2026-10-06T10:05:00.000Z" {
		t.Fatalf("%+v", q)
	}
	if len(f.repo.jobs) != 1 {
		t.Fatal("no job")
	}
	j := f.repo.jobs[0]
	if j.Kind != deliver.KindOccurrence || j.Target != deliver.TargetAuthority || j.Subject != q.ID || j.Key != q.ReportRef || j.RestrictionID != "" || len(j.Body) != 0 {
		t.Fatalf("%+v", j)
	}
	rec := f.repo.occ[j.ID]
	if len(rec.PersonRefSealed) == 0 || bytes.Contains(rec.PersonRefSealed, []byte("staff-0042")) || rec.KeyID != f.sealer.KeyID() {
		t.Fatal("the reference is not sealed")
	}
	if p, err := f.sealer.Open(rec.KeyID, rec.PersonRefSealed, []byte(rec.ID)); err != nil || string(p) != "staff-0042" {
		t.Fatal("the sealed reference does not open to the plaintext")
	}
	ev := f.repo.audited("occurrence_report_queued")
	if len(ev) != 1 {
		t.Fatal("no audit event")
	}
	raw, _ := json.Marshal(ev[0])
	if strings.Contains(string(raw), "staff-0042") || !strings.Contains(string(raw), `"has_reporter_ref":true`) {
		t.Fatalf("%s", raw)
	}

	resp := f.occ.SendOccurrence(context.Background(), deliver.Delivery{ID: j.ID})
	if resp.Status != http.StatusAccepted || resp.Err != "" {
		t.Fatalf("%+v", resp)
	}
	var msg map[string]any
	if err := json.Unmarshal(f.auth.got[0], &msg); err != nil {
		t.Fatal(err)
	}
	rep := msg["reporter"].(map[string]any)
	if msg["schema"] != SchemaOccurrence || rep["person_ref"] != "staff-0042" || rep["org"] != "ansp-01" || msg["report_ref"] != q.ReportRef {
		t.Fatalf("%v", msg)
	}
	if strings.Contains(string(f.auth.got[0]), "acct-3") || f.auth.hdr[0].Get("Authorization") != "Bearer tok" || f.tokens.scope != deliver.ScopeOccurrences {
		t.Fatal("a name or the wrong credential")
	}
	// An authority that echoes the body, byte-identical, JSON-escaped or
	// percent-encoded, never returns the reference into the delivery log:
	// nothing of an occurrence answer is kept but its status code
	// (ansp audit S-7).
	f.auth.code = http.StatusBadRequest
	for _, reply := range []string{"", `{"detail":"staff-0042"}`, `{"detail":"staff%2D0042"}`, `{"detail":"staff-004"}`} {
		f.auth.echo, f.auth.reply = reply == "", []byte(reply)
		resp = f.occ.SendOccurrence(context.Background(), deliver.Delivery{ID: j.ID})
		if resp.Status != http.StatusBadRequest || resp.Excerpt != "" || resp.Err != "" {
			t.Fatalf("%q: %+v", reply, resp)
		}
	}
}

func TestOccurrenceWithoutReference(t *testing.T) {
	f := newOccFixture(t)
	f.occ.Sealer = nil
	in, _ := DecodeOccurrence([]byte(occurrenceBody))
	if _, err := f.occ.Create(context.Background(), Actor{ID: "a"}, in); refusalOf(t, err).Status != http.StatusServiceUnavailable {
		t.Fatal(err)
	}
	if len(f.repo.occ) != 0 {
		t.Fatal("stored without a key")
	}
	q := f.create(t, strings.Replace(occurrenceBody, `"reporter_person_ref":"staff-0042",`, "", 1))
	rec := f.repo.occ[f.repo.jobs[0].ID]
	if rec.PersonRefSealed != nil || q.ID == "" {
		t.Fatal("a reference stored")
	}
	resp := f.occ.SendOccurrence(context.Background(), deliver.Delivery{ID: f.repo.jobs[0].ID})
	var msg OccurrenceMessage
	if resp.Status != http.StatusAccepted || json.Unmarshal(f.auth.got[0], &msg) != nil || msg.Reporter.PersonRef != "" {
		t.Fatalf("%+v %s", resp, f.auth.got[0])
	}
	// Without the outbox nothing is accepted.
	f.occ.Outbox = nil
	if _, err := f.occ.Create(context.Background(), Actor{ID: "a"}, OccurrenceInput{}); refusalOf(t, err).Status != http.StatusServiceUnavailable {
		t.Fatal(err)
	}
}

func TestOccurrenceSendFailures(t *testing.T) {
	f := newOccFixture(t)
	f.create(t, occurrenceBody)
	id := f.repo.jobs[0].ID
	ctx := context.Background()
	if r := f.occ.SendOccurrence(ctx, deliver.Delivery{ID: "nope"}); r.Err == "" {
		t.Fatal("an unknown report sent")
	}
	other, _ := auth.NewSealer(bytes.Repeat([]byte{9}, auth.SealKeyBytes))
	f.occ.Sealer = other
	if r := f.occ.SendOccurrence(ctx, deliver.Delivery{ID: id}); !strings.Contains(r.Err, "does not open") {
		t.Fatalf("%+v", r)
	}
	f.occ.Sealer = nil
	if r := f.occ.SendOccurrence(ctx, deliver.Delivery{ID: id}); !strings.Contains(r.Err, "ANSP_SECRETS_KEY_FILE") {
		t.Fatalf("%+v", r)
	}
	f.occ.Sealer = f.sealer
	auth := f.occ.Authority
	f.occ.Authority = nil
	if r := f.occ.SendOccurrence(ctx, deliver.Delivery{ID: id}); !strings.Contains(r.Err, "ANSP_AUTHORITY_URL") {
		t.Fatalf("%+v", r)
	}
	f.occ.Authority = auth
	auth.Tokens = nil
	if r := f.occ.SendOccurrence(ctx, deliver.Delivery{ID: id}); !strings.Contains(r.Err, "token client") {
		t.Fatalf("%+v", r)
	}
	if len(f.auth.got) != 0 {
		t.Fatal("something was sent")
	}
	if f.occ.Counters().Get(CounterOccurrenceSendFailed) != 3 {
		t.Fatal(f.occ.Counters().Get(CounterOccurrenceSendFailed))
	}
	// A store failure in the transaction stores nothing.
	f.repo.failAudit = errBoom
	in, _ := DecodeOccurrence([]byte(occurrenceBody))
	if _, err := f.occ.Create(ctx, Actor{ID: "a"}, in); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if len(f.repo.occ) != 1 || len(f.repo.jobs) != 1 {
		t.Fatal("a failed transaction left a report")
	}
}

// The monitor raises occurrence_undelivered for a late report and
// clears the alarm of a delivered one (E-01 pair).
func TestOccurrenceMonitor(t *testing.T) {
	f := newOccFixture(t)
	aware := f.repo.now.Add(-60 * time.Hour)
	f.repo.undelivered = []Undelivered{{ID: "r1", ReportRef: "ANSP-OCC-2026-0001", DeliveryID: "d1", BecameAwareAt: aware,
		DeadlineAt: aware.Add(OccurrenceDeadline), DeliveryState: "queued"}}
	rep, err := f.occ.Monitor(context.Background())
	if err != nil || len(rep.Raised) != 1 || rep.Raised[0].Kind != deliver.AlarmOccurrenceUndelivered || !rep.Raised[0].Since.Equal(aware) ||
		!strings.Contains(rep.Raised[0].Detail, "not yet delivered") || strings.Contains(rep.Raised[0].Detail, "lost") {
		t.Fatalf("%+v %v", rep, err)
	}
	// Raised once: the same delivery again is the open one.
	f.repo.undelivered = []Undelivered{{ID: "r1", DeliveryID: "d1", BecameAwareAt: aware}}
	if rep, _ = f.occ.Monitor(context.Background()); len(rep.Raised) != 0 {
		t.Fatal("raised twice")
	}
	f.repo.delivered = []AlarmRef{{AlarmID: f.firstAlarm(), DeliveryID: "d1"}}
	if rep, err = f.occ.Monitor(context.Background()); err != nil || len(rep.Cleared) != 1 || rep.Cleared[0].ClearReason != "delivered" {
		t.Fatalf("%+v %v", rep, err)
	}
	if f.occ.Counters().Get(CounterOccurrenceAlarms) != 1 || f.occ.Counters().Get(CounterOccurrenceCleared) != 1 {
		t.Fatal("not counted")
	}
	f.repo.failRaise, f.repo.failClear = errBoom, errBoom
	f.repo.undelivered = []Undelivered{{ID: "r2", DeliveryID: "d2", BecameAwareAt: aware}}
	f.repo.delivered = []AlarmRef{{AlarmID: "x", DeliveryID: "d2"}}
	if _, err := f.occ.Monitor(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.repo.failNow = errBoom
	if _, err := f.occ.Monitor(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.repo.failNow = nil
	f.occ.Clock = func(context.Context) (time.Time, error) { return time.Time{}, errBoom }
	if _, err := f.occ.Monitor(context.Background()); !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	f.occ.Clock = nil
	f.repo.failRaise, f.repo.failClear = nil, nil
	f.occ.Policy.OccurrenceAlarmEvery = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		f.occ.RunMonitor(ctx, func(MonitorReport, error) {
			select {
			case got <- struct{}{}:
			default:
			}
		})
		close(done)
	}()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("no pass")
	}
	cancel()
	<-done
}

func (f *occFixture) firstAlarm() string {
	for id := range f.repo.alarms {
		return id
	}
	return ""
}

// The person reference never reaches a type that is logged, streamed
// or exported: no member of these types is named person_ref, and the
// only one that carries it is the outbound body, built per attempt.
func TestNoPersonRefInWhatIsStreamedOrExported(t *testing.T) {
	for _, v := range []any{NoticeBody{}, Receipt{}, Queued{}, Notice{}, MonitorReport{}, deliver.Alarm{}, deliver.AlarmBody{},
		TickReport{}, Undelivered{}, AlarmRef{}, OccurrenceInput{}, Occurrence{}} {
		walk(t, reflect.TypeOf(v), reflect.TypeOf(v).Name(), map[reflect.Type]bool{})
	}
	// The presence twin: the walk finds it in the outbound body.
	found := false
	visit(reflect.TypeOf(OccurrenceMessage{}), map[reflect.Type]bool{}, func(_, tag string) {
		if tag == "person_ref" {
			found = true
		}
	})
	if !found {
		t.Fatal("the walk does not find person_ref where it is")
	}
}

func walk(t *testing.T, ty reflect.Type, root string, seen map[reflect.Type]bool) {
	t.Helper()
	visit(ty, seen, func(name, tag string) {
		if tag == "person_ref" || tag == "reporter_person_ref" || (strings.Contains(strings.ToLower(name), "personref") && name != "PersonRefSealed" && tag != "-") {
			t.Errorf("%s: member %s (json %q) carries the reporter reference", root, name, tag)
		}
	})
}

func visit(ty reflect.Type, seen map[reflect.Type]bool, f func(name, tag string)) {
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Array || ty.Kind() == reflect.Map {
		ty = ty.Elem()
	}
	if ty.Kind() != reflect.Struct || seen[ty] {
		return
	}
	seen[ty] = true
	for i := range ty.NumField() {
		fl := ty.Field(i)
		tag, _, _ := strings.Cut(fl.Tag.Get("json"), ",")
		f(fl.Name, tag)
		visit(fl.Type, seen, f)
	}
}
