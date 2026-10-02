package feed

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/picture"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// fakeMsg is a JetStream message; only what the recorder calls.
type fakeMsg struct {
	jetstream.Msg
	subject   string
	data      []byte
	seq       uint64
	delivered uint64
	mu        sync.Mutex
	acked     bool
	naked     bool
	termed    bool
}

func (m *fakeMsg) Subject() string { return m.subject }
func (m *fakeMsg) Data() []byte    { return m.data }
func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: m.seq}, NumDelivered: m.delivered}, nil
}
func (m *fakeMsg) Ack() error { m.mu.Lock(); m.acked = true; m.mu.Unlock(); return nil }
func (m *fakeMsg) NakWithDelay(time.Duration) error {
	m.mu.Lock()
	m.naked = true
	m.mu.Unlock()
	return nil
}
func (m *fakeMsg) Term() error { m.mu.Lock(); m.termed = true; m.mu.Unlock(); return nil }

type fakeBatch struct {
	ch  chan jetstream.Msg
	err error
}

func (b *fakeBatch) Messages() <-chan jetstream.Msg { return b.ch }
func (b *fakeBatch) Error() error                   { return b.err }

// fakeFetcher hands out the queued batches, then empty ones.
type fakeFetcher struct {
	mu      sync.Mutex
	batches [][]jetstream.Msg
	err     error
	fetches int
}

func (f *fakeFetcher) Fetch(int, ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	if f.err != nil {
		return nil, f.err
	}
	ch := make(chan jetstream.Msg, BatchRows)
	if len(f.batches) > 0 {
		for _, m := range f.batches[0] {
			ch <- m
		}
		f.batches = f.batches[1:]
	} else {
		time.Sleep(time.Millisecond)
	}
	close(ch)
	return &fakeBatch{ch: ch, err: jetstream.ErrNoMessages}, nil
}

type fakeInserter struct {
	mu    sync.Mutex
	rows  []timeseries.MannedTrackRow
	ids   map[string]bool
	err   error
	calls int
}

func (f *fakeInserter) Insert(_ context.Context, rows []timeseries.MannedTrackRow) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	if f.ids == nil {
		f.ids = map[string]bool{}
	}
	var n int64
	for i := range rows {
		r := &rows[i]
		if r.MsgID != nil && f.ids[*r.MsgID] {
			continue
		}
		if r.MsgID != nil {
			f.ids[*r.MsgID] = true
		}
		f.rows = append(f.rows, *r)
		n++
	}
	return n, nil
}

func (f *fakeInserter) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.rows) }
func (f *fakeInserter) fail(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func msgOf(t *testing.T, tr manned.Track, seq uint64) *fakeMsg {
	return &fakeMsg{subject: "man.v1." + tr.SourceInstance + "." + tr.ICAO24, data: wireOf(t, tr), seq: seq, delivered: 1}
}

func newRecorder(ins Inserter) *Recorder {
	return &Recorder{Insert: ins, Relevance: func(*manned.Track) picture.Relevance { return picture.Relevance{Relevant: false} },
		PolicyVersion: func() int64 { return 3 }}
}

// TestRecorderWritesThenAcks: every valid sample (live and backlog) is
// written with its msg_id, relevance and policy_version, then acked; an
// invalid one is terminated and counted.
func TestRecorderWritesThenAcks(t *testing.T) {
	ins := &fakeInserter{}
	r := newRecorder(ins)
	live := msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0), 1)
	bl := sample("4ca7b6", "adsb-tbs", 41.72, 44.80, t0)
	bl.Times.Backlog = true
	bl.Times.TS = nil
	backlog := msgOf(t, bl, 2)
	bad := &fakeMsg{subject: "man.v1.adsb-tbs.4ca7b7", data: []byte(`{}`), seq: 3, delivered: 1}
	lying := msgOf(t, sample("4ca7b8", "adsb-tbs", 41.72, 44.80, t0), 4)
	lying.subject = "man.v1.adsb-kut.4ca7b8"
	if !r.write(context.Background(), []jetstream.Msg{live, backlog, bad, lying}, time.Millisecond) {
		t.Fatal("batch not written")
	}
	if ins.count() != 2 || !live.acked || !backlog.acked || !bad.termed || !lying.termed || bad.acked {
		t.Fatalf("rows %d, acks %v %v, terms %v %v", ins.count(), live.acked, backlog.acked, bad.termed, lying.termed)
	}
	row := ins.rows[1]
	if !row.Backlog || row.MsgID == nil || row.Relevant || row.PolicyVersion != 3 || !row.TS.Equal(row.CapturedAt) || row.AdapterID != "adsb-tbs" {
		t.Fatalf("backlog row %+v", row)
	}
	if string(ins.rows[0].Quality) != `{"nic":8}` {
		t.Fatalf("quality %s", ins.rows[0].Quality)
	}
	if r.Counters().Get(CounterRefused) != 2 || r.Counters().Get(CounterRecorded) != 2 {
		t.Fatalf("counters %v", r.Counters().Snapshot())
	}
	if ok, line := r.Status(); !ok || !strings.HasPrefix(line, "last batch written at ") || r.Degraded() != nil {
		t.Fatalf("status %v %q", ok, line)
	}
	// Only invalid samples: nothing to insert, acknowledged as handled.
	if !r.write(context.Background(), []jetstream.Msg{&fakeMsg{subject: "x", data: []byte(`[`), seq: 5, delivered: 1}}, 0) {
		t.Fatal("an all-invalid batch")
	}
}

// TestRecorderHandsTheBatchBackWhileTheDatabaseIsDown is B-07: the
// failure is counted and said, nothing is acked, and once the database
// is back every sample lands once (the twin).
func TestRecorderHandsTheBatchBackWhileTheDatabaseIsDown(t *testing.T) {
	ins := &fakeInserter{}
	r := newRecorder(ins)
	if ok, line := r.Status(); !ok || line != "nothing written yet" {
		t.Fatalf("fresh status %v %q", ok, line)
	}
	ins.fail(errors.New("connection refused\nsecond line"))
	m := msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0), 1)
	if r.write(context.Background(), []jetstream.Msg{m}, time.Millisecond) {
		t.Fatal("a failed insert reported written")
	}
	if m.acked || !m.naked {
		t.Fatal("acked while down, or not handed back")
	}
	ok, line := r.Status()
	if ok || !strings.Contains(line, "failing since") || strings.Contains(line, "\n") || len(r.Degraded()) != 1 || r.Degraded()[0] != DegradedWriter {
		t.Fatalf("status %v %q", ok, line)
	}
	if r.Counters().Get(CounterInsertFailed) != 1 || r.Counters().Get(CounterRowsRetried) != 1 {
		t.Fatalf("counters %v", r.Counters().Snapshot())
	}
	ins.fail(nil)
	again := msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0), 1)
	again.data = m.data
	again.delivered = 2
	dup := msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0), 1)
	dup.data, dup.delivered = m.data, 3
	if !r.write(context.Background(), []jetstream.Msg{again, dup}, 0) || ins.count() != 1 || !again.acked || !dup.acked {
		t.Fatalf("after recovery: rows %d", ins.count())
	}
	if r.Counters().Get(CounterDuplicates) != 1 {
		t.Fatal("duplicate not counted")
	}
	if ok, _ := r.Status(); !ok {
		t.Fatal("still failing")
	}
}

// TestAGapIsNeverSilent: a jump in the stream sequence of first
// deliveries, and samples expired before the consumer's floor, are
// counted; redeliveries are not gaps (the twin).
func TestAGapIsNeverSilent(t *testing.T) {
	r := newRecorder(&fakeInserter{})
	var msgs []jetstream.Msg
	for _, seq := range []uint64{1, 2, 5} {
		msgs = append(msgs, msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0.Add(time.Duration(seq)*time.Second)), seq))
	}
	redelivered := msgOf(t, sample("4ca7b6", "adsb-tbs", 41.72, 44.80, t0), 3)
	redelivered.delivered = 2
	msgs = append(msgs, redelivered)
	r.write(context.Background(), msgs, 0)
	if r.Gap() != 2 || r.Counters().Get(CounterGap) != 2 {
		t.Fatalf("gap %d", r.Gap())
	}
	if lost := r.CheckStart(10, 25); lost != 14 || r.Gap() != 16 {
		t.Fatalf("expired %d", lost)
	}
	if r.CheckStart(0, 25) != 0 || r.CheckStart(24, 25) != 0 {
		t.Fatal("no gap counted as one")
	}
}

func TestRecorderRunFetchesUntilCancelled(t *testing.T) {
	ins := &fakeInserter{}
	r := newRecorder(ins)
	f := &fakeFetcher{batches: [][]jetstream.Msg{{msgOf(t, sample("4ca7b5", "adsb-tbs", 41.72, 44.80, t0), 1)}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, f); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for ins.count() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("not written")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// A fetch that fails is counted and retried.
	f2 := &fakeFetcher{err: errors.New("nats down")}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { r.Run(ctx2, f2); close(done2) }()
	for r.Counters().Get(CounterFetchFailed) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel2()
	<-done2
	// A failed insert backs off and retries.
	ins.fail(errors.New("down"))
	f3 := &fakeFetcher{batches: [][]jetstream.Msg{{msgOf(t, sample("4ca7b9", "adsb-tbs", 41.72, 44.80, t0), 9)}}}
	ctx3, cancel3 := context.WithCancel(context.Background())
	done3 := make(chan struct{})
	go func() { r.Run(ctx3, f3); close(done3) }()
	for r.Counters().Get(CounterInsertFailed) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel3()
	<-done3
	r.RunConsumer(context.Background(), nil, "MAN_MIRROR", func(err error) {
		if !strings.Contains(err.Error(), "not configured") {
			t.Errorf("no bus: %v", err)
		}
	})
	if cfg := ConsumerConfig(); cfg.Durable != RecorderDurable || cfg.MaxAckPending != MaxUnwritten || cfg.AckPolicy != jetstream.AckExplicitPolicy {
		t.Fatalf("consumer %+v", cfg)
	}
}
