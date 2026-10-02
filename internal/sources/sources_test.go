package sources

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
)

func ptr(s string) *string { return &s }

func docJSON(t *testing.T, d Doc) []byte {
	t.Helper()
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeDocRefusesWhatAFollowerMustNotApply(t *testing.T) {
	good := `{"version":3,"epoch":"e1","default_deny":false,"controls":[{"source_type":"manned","instance_id":"adsb-tbs","enabled":false,"reason":"maintenance","actor":"admin1","changed_at":"2026-10-02T09:00:00Z"}]}`
	d, err := DecodeDoc([]byte(good))
	if err != nil || d.Version != 3 || len(d.Controls) != 1 || *d.Controls[0].InstanceID != "adsb-tbs" {
		t.Fatalf("the good document: %+v %v", d, err)
	}
	many := Doc{Version: 1, Epoch: "e"}
	for i := 0; i <= MaxRows; i++ {
		many.Controls = append(many.Controls, Row{SourceType: "manned", Enabled: true})
	}
	for name, in := range map[string]string{
		"unknown member":   `{"version":1,"epoch":"e","default_deny":false,"controls":[],"extra":1}`,
		"no epoch":         `{"version":1,"epoch":"","default_deny":false,"controls":[]}`,
		"not json":         `{"version":`,
		"trailing":         `{"version":1,"epoch":"e","default_deny":false,"controls":[]} {}`,
		"bad source type":  `{"version":1,"epoch":"e","default_deny":false,"controls":[{"source_type":"Manned!","instance_id":null,"enabled":true,"reason":"","actor":"","changed_at":"2026-10-02T09:00:00Z"}]}`,
		"bad instance":     `{"version":1,"epoch":"e","default_deny":false,"controls":[{"source_type":"manned","instance_id":"a b","enabled":true,"reason":"","actor":"","changed_at":"2026-10-02T09:00:00Z"}]}`,
		"oversized":        `{"version":1,"epoch":"` + strings.Repeat("x", MaxDocBytes) + `"}`,
		"too many rows":    string(docJSON(t, many)),
		"long reason":      `{"version":1,"epoch":"e","default_deny":false,"controls":[{"source_type":"manned","instance_id":null,"enabled":true,"reason":"` + strings.Repeat("r", MaxReasonLen+1) + `","actor":"a","changed_at":"2026-10-02T09:00:00Z"}]}`,
		"long actor":       `{"version":1,"epoch":"e","default_deny":false,"controls":[{"source_type":"manned","instance_id":null,"enabled":true,"reason":"r","actor":"` + strings.Repeat("a", MaxActorLen+1) + `","changed_at":"2026-10-02T09:00:00Z"}]}`,
		"long epoch":       `{"version":1,"epoch":"` + strings.Repeat("e", MaxEpochBytes+1) + `","default_deny":false,"controls":[]}`,
		"controls as text": `{"version":1,"epoch":"e","default_deny":false,"controls":"x"}`,
	} {
		if _, err := DecodeDoc([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEncodeWritesAnEmptyListNotNull(t *testing.T) {
	d := Doc{Version: 1, Epoch: "e"}
	if b := docJSON(t, d); !strings.Contains(string(b), `"controls":[]`) {
		t.Fatalf("got %s", b)
	}
}

// TestFollowerWithoutStateEnablesEverythingAndSaysUnknown is B-09 and
// E-02: nothing read is enabled, and the status says it is unknown.
func TestFollowerWithoutStateEnablesEverythingAndSaysUnknown(t *testing.T) {
	f := NewFollower(nil)
	d := f.Decision(SourceTypeManned, ptr("adsb-tbs"))
	if !d.Enabled || d.Known || d.Why != nil {
		t.Fatalf("got %+v", d)
	}
	if got := f.Status(); got != "unknown, nothing read (every source enabled)" {
		t.Fatalf("status %q", got)
	}
	if _, ok := f.Doc(); ok {
		t.Fatal("a document without one applied")
	}
	if v, e, known := f.Version(); v != 0 || e != "" || known {
		t.Fatalf("version %d %q %v", v, e, known)
	}
	f.MarkKnown()
	if got := f.Status(); got != "empty (every source enabled)" {
		t.Fatalf("status after an empty read %q", got)
	}
}

// TestFollowerDisabledInstanceSaysWhoWhenAndWhy is B-11 and its twin.
func TestFollowerDisabledInstanceSaysWhoWhenAndWhy(t *testing.T) {
	f := NewFollower(nil)
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	doc := Doc{Version: 7, Epoch: "e1", Controls: []Row{
		{SourceType: "manned", InstanceID: ptr("adsb-tbs"), Enabled: false, Reason: "maintenance", Actor: "admin1", ChangedAt: at},
	}}
	if !f.ApplyJSON(docJSON(t, doc)) {
		t.Fatal("not applied")
	}
	off := f.Decision("manned", ptr("adsb-tbs"))
	if off.Enabled || off.Why == nil || *off.Why != coresources.WhyInstance || off.Actor != "admin1" || off.Reason != "maintenance" || !off.ChangedAt.Equal(at) || !off.Known {
		t.Fatalf("disabled: %+v", off)
	}
	// The twin: another instance is untouched.
	on := f.Decision("manned", ptr("adsb-kut"))
	if !on.Enabled || on.Why != nil || on.Actor != "" {
		t.Fatalf("other instance: %+v", on)
	}
	if f.Status() != "version 7" {
		t.Fatalf("status %q", f.Status())
	}
	// The whole type, then default deny.
	f.Apply(Doc{Version: 8, Epoch: "e1", Controls: []Row{{SourceType: "manned", Enabled: false, Reason: "feed contract", Actor: "admin2"}}})
	if d := f.Decision("manned", ptr("adsb-kut")); d.Enabled || *d.Why != coresources.WhyType || d.Actor != "admin2" {
		t.Fatalf("type off: %+v", d)
	}
	f.Apply(Doc{Version: 9, Epoch: "e1", DefaultDeny: true})
	if d := f.Decision("manned", ptr("adsb-kut")); d.Enabled || *d.Why != coresources.WhyDefaultDeny || d.Actor != "default_deny" {
		t.Fatalf("default deny: %+v", d)
	}
	doc2, ok := f.Doc()
	if !ok || doc2.Version != 9 {
		t.Fatalf("doc %+v", doc2)
	}
}

func TestFollowerTakesOnlyNewerStatesWithinAnEpoch(t *testing.T) {
	f := NewFollower(nil)
	if !f.Apply(Doc{Version: 5, Epoch: "e1", Controls: []Row{{SourceType: "manned", InstanceID: ptr("a"), Enabled: false, Reason: "r", Actor: "x"}}}) {
		t.Fatal("first state not applied")
	}
	if f.Apply(Doc{Version: 4, Epoch: "e1"}) || f.Apply(Doc{Version: 5, Epoch: "e1"}) {
		t.Fatal("an older or equal version applied")
	}
	if f.Decision("manned", ptr("a")).Enabled {
		t.Fatal("rolled back by an older version")
	}
	// A restored database: a new epoch is taken whatever its version.
	if !f.Apply(Doc{Version: 1, Epoch: "e2"}) || !f.Decision("manned", ptr("a")).Enabled {
		t.Fatal("new epoch not taken")
	}
	c := f.CoreCounters().Snapshot()
	if c[coresources.CounterIgnoredOlderVersion] != 2 || c[coresources.CounterNewEpoch] != 1 || c[coresources.CounterApplied] != 2 {
		t.Fatalf("core counters %v", c)
	}
	if f.ApplyJSON([]byte(`nope`)) || f.Counters().Snapshot()[CounterUndecodable] != 1 {
		t.Fatal("undecodable not counted")
	}
	if f.Apply(Doc{Version: 9}) || f.Counters().Snapshot()[CounterUndecodable] != 2 {
		t.Fatal("an invalid document applied")
	}
}

func TestFollowerReadAppliesTheKeyAndSaysWhenKVIsGone(t *testing.T) {
	kv := newFakeKV()
	f := NewFollower(nil)
	ctx := context.Background()
	if err := f.Read(ctx, kv); err != nil || f.Status() != "empty (every source enabled)" {
		t.Fatalf("empty bucket: %v %q", err, f.Status())
	}
	kv.set(KVKey, docJSON(t, Doc{Version: 2, Epoch: "e", Controls: []Row{{SourceType: "manned", InstanceID: ptr("a"), Enabled: false, Reason: "r", Actor: "x"}}}))
	if err := f.Read(ctx, kv); err != nil || f.Decision("manned", ptr("a")).Enabled {
		t.Fatalf("read: %v", err)
	}
	kv.fail(errDown, nil)
	if err := f.Read(ctx, kv); err == nil {
		t.Fatal("a failed read said nothing")
	}
	if !strings.HasPrefix(f.Status(), "version 2, KV unreachable since ") {
		t.Fatalf("status %q", f.Status())
	}
	if f.Counters().Snapshot()[CounterReadFailed] != 1 {
		t.Fatal("not counted")
	}
	// The state held is still served (a follower never fails closed and
	// never forgets).
	if f.Decision("manned", ptr("a")).Enabled {
		t.Fatal("the held state was dropped")
	}
	kv.fail(nil, nil)
	if err := f.Read(ctx, kv); err != nil || f.Status() != "version 2" {
		t.Fatalf("recovered: %v %q", err, f.Status())
	}
	if err := f.Read(ctx, nil); err == nil {
		t.Fatal("no bucket said nothing")
	}
}

func TestFollowRetriesAtStartThenRereads(t *testing.T) {
	kv := newFakeKV()
	kv.fail(errDown, nil)
	f := NewFollower(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var errs []error
	errCh := make(chan error, 16)
	done := make(chan struct{})
	go func() {
		f.Follow(ctx, func(context.Context) (KV, error) { return kv, nil }, FollowOptions{StartBackoff: time.Millisecond, Reread: 5 * time.Millisecond,
			OnError: func(err error) { errCh <- err }})
		close(done)
	}()
	for len(errs) < 3 {
		errs = append(errs, <-errCh)
	}
	if !strings.Contains(errs[2].Error(), "attempt 3 of 3") {
		t.Fatalf("third error %v", errs[2])
	}
	// The re-read repairs once KV is back.
	kv.set(KVKey, docJSON(t, Doc{Version: 4, Epoch: "e"}))
	kv.fail(nil, nil)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if v, _, _ := f.Version(); v == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the re-read never applied the state")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if f.Counters().Snapshot()[CounterReread] == 0 {
		t.Fatal("re-reads not counted")
	}
	cancel()
	<-done
}

func TestFollowWithoutABucketKeepsTrying(t *testing.T) {
	f := NewFollower(nil)
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 8)
	done := make(chan struct{})
	go func() {
		f.Follow(ctx, func(context.Context) (KV, error) {
			calls <- struct{}{}
			return nil, errors.New("no bucket yet")
		}, FollowOptions{StartAttempts: 1, Reread: time.Millisecond})
		close(done)
	}()
	<-calls
	<-calls
	cancel()
	<-done
	if !strings.Contains(f.Status(), "KV unreachable since") {
		t.Fatalf("status %q", f.Status())
	}
}

type vecControl struct {
	SourceType string  `json:"source_type"`
	InstanceID *string `json:"instance_id"`
	Enabled    bool    `json:"enabled"`
}

type vecInput struct {
	Controls    []vecControl `json:"controls"`
	DefaultDeny bool         `json:"default_deny"`
	Query       struct {
		SourceType string  `json:"source_type"`
		InstanceID *string `json:"instance_id"`
	} `json:"query"`
}

type vecExpected struct {
	Enabled     bool    `json:"enabled"`
	WhyDisabled *string `json:"why_disabled"`
}

// TestVectorsSourceControl runs every case of source_control.json that
// names ansp through this system's Follower: the document as the writer
// encodes it, decoded and applied, then Decision.
func TestVectorsSourceControl(t *testing.T) {
	file := vectors.Load(t, "source_control.json")
	ran := 0
	file.RunOwned(t, "ansp", func(t *testing.T, c vectors.Case) {
		var in vecInput
		var exp vecExpected
		c.Decode(t, &in, &exp)
		doc := Doc{Version: 1, Epoch: "vectors", DefaultDeny: in.DefaultDeny}
		for _, rc := range in.Controls {
			doc.Controls = append(doc.Controls, Row{SourceType: rc.SourceType, InstanceID: rc.InstanceID, Enabled: rc.Enabled, Reason: "vector", Actor: "vectors"})
		}
		f := NewFollower(nil)
		if !f.ApplyJSON(docJSON(t, doc)) {
			t.Fatal("the vector's state was not applied")
		}
		d := f.Decision(in.Query.SourceType, in.Query.InstanceID)
		if d.Enabled != exp.Enabled {
			t.Errorf("enabled %v, want %v", d.Enabled, exp.Enabled)
		}
		var why *string
		if d.Why != nil {
			s := string(*d.Why)
			why = &s
		}
		vectors.EqualStrPtr(t, "why_disabled", why, exp.WhyDisabled)
		ran++
	})
	t.Logf("source_control.json: %d cases owned by ansp ran through sources.Follower", ran)
	if ran != 8 {
		t.Errorf("ran %d cases, want 8", ran)
	}
}

// TestTheAdapterReadsWhatTheWriterWrites confirms WP-4's proposed
// document (docs/PLAN.md section 15 gap 26): the adapter's switch
// applies the writer's bytes and decides as the follower does.
func TestTheAdapterReadsWhatTheWriterWrites(t *testing.T) {
	kv := newFakeKV()
	repo := &fakeRepo{epoch: "0d6c1f4e-3b2a-4c5d-8e9f-a0b1c2d3e4f5"}
	w := &Writer{Repo: repo, KV: kv}
	if _, _, putErr, err := w.Set(context.Background(), Change{SourceType: "manned", InstanceID: ptr("adsb-tbs"), Enabled: false, Reason: "maintenance", Actor: "admin1"}); err != nil || putErr != nil {
		t.Fatal(err, putErr)
	}
	sw := adapter.NewKVSwitch("adsb-tbs", nil)
	if !sw.ApplyJSON(kv.value(KVKey)) {
		t.Fatal("the adapter refused the writer's document")
	}
	d := sw.Decide()
	if d.Enabled || d.Actor != "admin1" || d.Reason != "maintenance" {
		t.Fatalf("adapter decision %+v", d)
	}
	other := adapter.NewKVSwitch("adsb-kut", nil)
	other.ApplyJSON(kv.value(KVKey))
	if !other.Decide().Enabled {
		t.Fatal("the twin: another adapter is disabled")
	}
	var raw map[string]any
	if err := json.Unmarshal(kv.value(KVKey), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "epoch", "default_deny", "controls"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("member %s missing", k)
		}
	}
}

func TestWriterRefusesWithoutKVAndChangesNothing(t *testing.T) {
	kv := newFakeKV()
	kv.fail(errDown, nil)
	repo := &fakeRepo{epoch: "e"}
	push := &fakePush{}
	w := &Writer{Repo: repo, KV: kv, Push: push}
	_, _, _, err := w.Set(context.Background(), Change{SourceType: "manned", InstanceID: ptr("a"), Enabled: false, Reason: "r", Actor: "admin1"})
	if !errors.Is(err, ErrKVUnavailable) || repo.sets != 0 || push.count() != 0 {
		t.Fatalf("err %v, sets %d, pushes %d", err, repo.sets, push.count())
	}
	if w.Counters().Snapshot()[CounterKVUnavailable] != 1 {
		t.Fatal("not counted")
	}
	// The twin: KV answers, the row is committed, then put and pushed.
	kv.fail(nil, nil)
	row, doc, putErr, err := w.Set(context.Background(), Change{SourceType: "manned", InstanceID: ptr("a"), Enabled: false, Reason: "r", Actor: "admin1"})
	if err != nil || putErr != nil || repo.sets != 1 || push.count() != 1 || row.Actor != "admin1" || doc.Version != 1 {
		t.Fatalf("err %v %v, sets %d, pushes %d", err, putErr, repo.sets, push.count())
	}
	held, err := DecodeDoc(kv.value(KVKey))
	if err != nil || held.Version != 1 || len(held.Controls) != 1 {
		t.Fatalf("kv holds %+v %v", held, err)
	}
	var none Writer
	if _, _, _, err := none.Set(context.Background(), Change{SourceType: "manned", Reason: "r", Actor: "a"}); !errors.Is(err, ErrKVUnavailable) {
		t.Fatalf("an unwired writer: %v", err)
	}
}

func TestWriterValidatesTheChange(t *testing.T) {
	w := &Writer{Repo: &fakeRepo{epoch: "e"}, KV: newFakeKV()}
	for name, c := range map[string]Change{
		"type":     {SourceType: "Bad Type", Reason: "r", Actor: "a"},
		"instance": {SourceType: "manned", InstanceID: ptr("a b"), Reason: "r", Actor: "a"},
		"reason":   {SourceType: "manned", Reason: "  ", Actor: "a"},
		"long":     {SourceType: "manned", Reason: strings.Repeat("r", MaxReasonLen+1), Actor: "a"},
		"actor":    {SourceType: "manned", Reason: "r"},
	} {
		if _, _, _, err := w.Set(context.Background(), c); err == nil || errors.Is(err, ErrKVUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestAPutThatFailsAfterTheCommitIsRepairedByTheRepublish is B-09: the
// row is the record, KV catches up within one period.
func TestAPutThatFailsAfterTheCommitIsRepairedByTheRepublish(t *testing.T) {
	kv := newFakeKV()
	repo := &fakeRepo{epoch: "e"}
	push := &fakePush{}
	w := &Writer{Repo: repo, KV: kv, Push: push}
	kv.fail(nil, errDown)
	row, _, putErr, err := w.Set(context.Background(), Change{SourceType: "manned", InstanceID: ptr("a"), Enabled: false, Reason: "r", Actor: "admin1"})
	if err != nil || putErr == nil || row.Reason != "r" || repo.sets != 1 {
		t.Fatalf("err %v putErr %v", err, putErr)
	}
	if kv.value(KVKey) != nil || w.Counters().Snapshot()[CounterKVPutFailed] != 1 {
		t.Fatal("put or counter")
	}
	if _, err := w.Republish(context.Background()); err == nil {
		t.Fatal("republish against a failing KV said nothing")
	}
	kv.fail(nil, nil)
	wrote, err := w.Republish(context.Background())
	if err != nil || !wrote || push.count() != 1 {
		t.Fatalf("republish: %v %v", wrote, err)
	}
	// Again: KV already holds it, nothing is written.
	if wrote, err := w.Republish(context.Background()); err != nil || wrote {
		t.Fatalf("second republish wrote %v %v", wrote, err)
	}
	c := w.Counters().Snapshot()
	if c[CounterRepublished] != 1 || c[CounterRepublishFailed] != 1 {
		t.Fatalf("counters %v", c)
	}
}

// TestKVNeverMovesBackWithinAnEpoch: a replica that committed version 1
// and puts late must not replace version 2 another replica put first.
func TestKVNeverMovesBackWithinAnEpoch(t *testing.T) {
	kv := newFakeKV()
	kv.set(KVKey, docJSON(t, Doc{Version: 2, Epoch: "e"}))
	repo := &fakeRepo{epoch: "e"} // will commit version 1
	w := &Writer{Repo: repo, KV: kv}
	if _, _, putErr, err := w.Set(context.Background(), Change{SourceType: "manned", Reason: "r", Actor: "a"}); err != nil || putErr != nil {
		t.Fatal(err, putErr)
	}
	held, _ := DecodeDoc(kv.value(KVKey))
	if held.Version != 2 || w.Counters().Snapshot()[CounterKVNewerKept] != 1 {
		t.Fatalf("kv moved back to %d", held.Version)
	}
	// The twin: a new epoch (a database created again) replaces it.
	repo2 := &fakeRepo{epoch: "e2"}
	w2 := &Writer{Repo: repo2, KV: kv}
	if _, _, putErr, err := w2.Set(context.Background(), Change{SourceType: "manned", Reason: "r", Actor: "a"}); err != nil || putErr != nil {
		t.Fatal(err, putErr)
	}
	held, _ = DecodeDoc(kv.value(KVKey))
	if held.Epoch != "e2" {
		t.Fatalf("new epoch not written: %+v", held)
	}
}

// TestALostCompareAndSetIsRetried: another writer moves the key between
// the read and the update; the put reads again and lands.
func TestALostCompareAndSetIsRetried(t *testing.T) {
	kv := newFakeKV()
	kv.set(KVKey, docJSON(t, Doc{Version: 1, Epoch: "e"}))
	repo := &fakeRepo{epoch: "e", version: 4}
	w := &Writer{Repo: repo, KV: kv}
	kv.beforePut = func() { kv.set(KVKey, docJSON(t, Doc{Version: 3, Epoch: "e"})) }
	if _, _, putErr, err := w.Set(context.Background(), Change{SourceType: "manned", Reason: "r", Actor: "a"}); err != nil || putErr != nil {
		t.Fatal(err, putErr)
	}
	held, _ := DecodeDoc(kv.value(KVKey))
	if held.Version != 5 {
		t.Fatalf("kv holds version %d", held.Version)
	}
}

func TestWriterRunRepublishesUntilCancelled(t *testing.T) {
	kv := newFakeKV()
	repo := &fakeRepo{epoch: "e", version: 3}
	w := &Writer{Repo: repo, KV: kv}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, time.Millisecond, nil); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for kv.value(KVKey) == nil {
		if time.Now().After(deadline) {
			t.Fatal("never republished")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	repo.err = errDown
	var got error
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		w.Run(ctx2, time.Hour, func(err error) { got = err; cancel2() })
		close(done2)
	}()
	<-done2
	if !errors.Is(got, errDown) {
		t.Fatalf("onError got %v", got)
	}
	var none Writer
	if _, err := none.Republish(context.Background()); !errors.Is(err, ErrKVUnavailable) {
		t.Fatal(err)
	}
}
