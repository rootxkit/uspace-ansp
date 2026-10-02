package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/picture"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// The recorder's consumer on MAN_MIRROR and its bounds (docs/PLAN.md
// sections 7 and 9, LESSONS B-07).
const (
	// RecorderDurable is the durable pull consumer of the writer.
	RecorderDurable = "manned-feed-recorder"
	// BatchRows and BatchWait: one insert per 500 rows or 1 s.
	BatchRows = 500
	BatchWait = time.Second
	// MaxUnwritten bounds the samples delivered and not yet written: the
	// consumer's MaxAckPending (B-07's 50 000 rows); the rest wait in
	// the stream (1 h), never in this process.
	MaxUnwritten = 50_000
	// AckWait is how long a delivered sample may stay unwritten before
	// JetStream delivers it again.
	AckWait = 30 * time.Second
	// The retry delay of a failed insert, doubling to the maximum.
	retryMin = 500 * time.Millisecond
	retryMax = 5 * time.Second
)

// DegradedWriter is the degraded slug while inserts fail.
const DegradedWriter = "timeseries_writer"

// Counters of the recorder (E-09: a gap is never silent).
const (
	CounterRecorded       = "writer_rows_written"
	CounterDuplicates     = "writer_duplicates_skipped"
	CounterInsertFailed   = "writer_insert_failed"
	CounterRowsRetried    = "writer_rows_retried"
	CounterRefused        = "writer_samples_refused"
	CounterGap            = "writer_gap_samples"
	CounterFetchFailed    = "writer_fetch_failed"
	CounterConsumerFailed = "writer_consumer_failed"
)

// Inserter writes manned_tracks rows (timeseries.Writer).
type Inserter interface {
	Insert(ctx context.Context, rows []timeseries.MannedTrackRow) (int64, error)
}

// Fetcher is the pull consumer (jetstream.Consumer).
type Fetcher interface {
	Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error)
}

// Recorder writes every valid sample of MAN_MIRROR (live and backlog,
// relevant or not: B-12) to manned_tracks in batches, and acknowledges a
// sample only after its batch committed. While the database is down the
// batch is handed back (NakWithDelay) and JetStream holds the rest:
// nothing is lost while the stream keeps it, and a redelivered sample
// lands once (msg_id). A sample that left the stream unwritten is a gap,
// counted and said, never silent.
type Recorder struct {
	Insert Inserter
	// Relevance judges a sample for the relevant column (at capture).
	Relevance func(t *manned.Track) picture.Relevance
	// PolicyVersion is the followed policy_version.
	PolicyVersion func() int64
	// Policy bounds the decoder (manned.Defaults when zero).
	Policy *manned.Policy

	counters core.Counters

	mu           sync.Mutex
	failingSince time.Time
	lastErr      string
	lastSeq      uint64
	lastWritten  time.Time
	gap          uint64
}

// Counters are the recorder's counters.
func (r *Recorder) Counters() *core.Counters { return &r.counters }

// ConsumerConfig is the durable pull consumer of the recorder.
func ConsumerConfig() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable: RecorderDurable, AckPolicy: jetstream.AckExplicitPolicy, AckWait: AckWait,
		MaxAckPending: MaxUnwritten, MaxDeliver: -1, DeliverPolicy: jetstream.DeliverAllPolicy,
		FilterSubject: "man.v1.>",
	}
}

// Status is the recorder's line for readiness and the status: ok with
// the last write, or failing since when and why.
func (r *Recorder) Status() (ok bool, line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.failingSince.IsZero() {
		return false, "failing since " + manned.FormatTime(r.failingSince) + ": " + r.lastErr
	}
	if r.lastWritten.IsZero() {
		return true, "nothing written yet"
	}
	return true, "last batch written at " + manned.FormatTime(r.lastWritten)
}

// Degraded is DegradedWriter while inserts fail, nothing otherwise.
func (r *Recorder) Degraded() []string {
	if ok, _ := r.Status(); !ok {
		return []string{DegradedWriter}
	}
	return nil
}

// Gap is the samples counted as lost from the stream before they were
// written.
func (r *Recorder) Gap() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gap
}

// CheckStart compares the consumer's acknowledged floor with the
// stream's first sequence: samples that expired from MAN_MIRROR while
// this process was not writing are a gap, counted and returned.
func (r *Recorder) CheckStart(ackFloor, streamFirst uint64) uint64 {
	if ackFloor == 0 || streamFirst <= ackFloor+1 {
		return 0
	}
	lost := streamFirst - ackFloor - 1
	r.noteGap(lost)
	return lost
}

func (r *Recorder) noteGap(n uint64) {
	r.counters.Add(CounterGap, n)
	r.mu.Lock()
	r.gap += n
	r.mu.Unlock()
}

// Run fetches and writes until ctx ends. A fetch that fails (the bus
// down) is counted and retried; an insert that fails hands the batch
// back with a growing delay.
func (r *Recorder) Run(ctx context.Context, f Fetcher) {
	delay := retryMin
	for ctx.Err() == nil {
		batch, err := f.Fetch(BatchRows, jetstream.FetchMaxWait(BatchWait))
		if err != nil {
			r.counters.Inc(CounterFetchFailed)
			if !sleepCtx(ctx, delay) {
				return
			}
			continue
		}
		var msgs []jetstream.Msg
		for m := range batch.Messages() {
			msgs = append(msgs, m)
		}
		if err := batch.Error(); err != nil && !errors.Is(err, jetstream.ErrNoMessages) && len(msgs) == 0 {
			r.counters.Inc(CounterFetchFailed)
		}
		if len(msgs) == 0 {
			continue
		}
		if r.write(ctx, msgs, delay) {
			delay = retryMin
			continue
		}
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(delay*2, retryMax)
	}
}

// write decodes msgs, inserts the valid ones and acknowledges them; an
// undecodable sample is terminated (never redelivered) and counted. It
// reports whether the batch landed.
func (r *Recorder) write(ctx context.Context, msgs []jetstream.Msg, delay time.Duration) bool {
	pol := r.Policy
	if pol == nil {
		d := manned.Defaults()
		pol = &d
	}
	rows := make([]timeseries.MannedTrackRow, 0, len(msgs))
	keep := make([]jetstream.Msg, 0, len(msgs))
	for _, m := range msgs {
		r.noteSequence(m)
		t, err := DecodeTrack(m.Data(), pol)
		if err == nil && SubjectAdapter(m.Subject(), "man.v1.") != t.SourceInstance {
			err = core.Fieldf("subject", "names another adapter than the body")
		}
		if err != nil {
			r.counters.Inc(CounterRefused)
			_ = m.Term()
			continue
		}
		rows = append(rows, r.row(&t))
		keep = append(keep, m)
	}
	if len(rows) == 0 {
		return true
	}
	n, err := r.Insert.Insert(ctx, rows)
	if err != nil {
		r.counters.Inc(CounterInsertFailed)
		r.counters.Add(CounterRowsRetried, uint64(len(rows)))
		r.mu.Lock()
		if r.failingSince.IsZero() {
			r.failingSince = time.Now()
		}
		r.lastErr = clipErr(err)
		r.mu.Unlock()
		for _, m := range keep {
			_ = m.NakWithDelay(delay)
		}
		return false
	}
	for _, m := range keep {
		_ = m.Ack()
	}
	r.counters.Add(CounterRecorded, uint64(max(n, 0)))
	if dup := int64(len(rows)) - n; dup > 0 {
		r.counters.Add(CounterDuplicates, uint64(dup))
	}
	r.mu.Lock()
	r.failingSince, r.lastErr, r.lastWritten = time.Time{}, "", time.Now()
	r.mu.Unlock()
	return true
}

// noteSequence counts a gap in the stream sequence of first deliveries:
// a sample the stream no longer holds was never delivered.
func (r *Recorder) noteSequence(m jetstream.Msg) {
	meta, err := m.Metadata()
	if err != nil || meta.NumDelivered != 1 {
		return
	}
	r.mu.Lock()
	last := r.lastSeq
	if meta.Sequence.Stream > last {
		r.lastSeq = meta.Sequence.Stream
	}
	r.mu.Unlock()
	if last > 0 && meta.Sequence.Stream > last+1 {
		r.noteGap(meta.Sequence.Stream - last - 1)
	}
}

func (r *Recorder) row(t *manned.Track) timeseries.MannedTrackRow {
	ts := t.Times.CapturedAt
	if t.Times.TS != nil {
		ts = *t.Times.TS
	}
	var quality json.RawMessage
	if len(t.Quality) > 0 {
		quality, _ = json.Marshal(t.Quality)
	}
	relevant := true
	if r.Relevance != nil {
		relevant = r.Relevance(t).Relevant
	}
	var version int64
	if r.PolicyVersion != nil {
		version = r.PolicyVersion()
	}
	id := t.MsgID
	return timeseries.MannedTrackRow{
		CapturedAt: t.Times.CapturedAt, TS: ts, RxTS: t.Times.RxTS, TimeSource: string(t.Times.Source),
		Backlog: t.Times.Backlog, AdapterID: t.SourceInstance, ICAO24: t.ICAO24, Callsign: t.Callsign,
		Position: t.Position, AltPressureM: t.AltPressureM, AltWGS84M: t.AltWGS84M, GSMS: t.GSMS,
		TrackDeg: t.TrackDeg, VRateMS: t.VRateMS, Emergency: t.Emergency, Squawk: t.Squawk,
		SourceClass: t.SourceClass, Quality: quality, Relevant: relevant, PolicyVersion: version, MsgID: &id,
	}
}

func clipErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// RunConsumer creates (or keeps) the recorder's durable consumer on
// MAN_MIRROR, counts the samples that expired before they were written,
// and runs the recorder; it retries every few seconds while the stream
// cannot be reached (the api declares it), reporting failures to
// onError.
func (r *Recorder) RunConsumer(ctx context.Context, js jetstream.JetStream, stream string, onError func(error)) {
	if js == nil {
		if onError != nil {
			onError(errors.New("writer: the bus is not configured; no sample is written"))
		}
		return
	}
	for ctx.Err() == nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cons, err := js.CreateOrUpdateConsumer(cctx, stream, ConsumerConfig())
		var info *jetstream.ConsumerInfo
		var sinfo *jetstream.StreamInfo
		if err == nil {
			info, err = cons.Info(cctx)
		}
		if err == nil {
			var s jetstream.Stream
			if s, err = js.Stream(cctx, stream); err == nil {
				sinfo, err = s.Info(cctx)
			}
		}
		cancel()
		if err != nil {
			r.counters.Inc(CounterConsumerFailed)
			if onError != nil {
				onError(fmt.Errorf("writer: consumer on %s: %w", stream, err))
			}
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		if lost := r.CheckStart(info.AckFloor.Stream, sinfo.State.FirstSeq); lost > 0 && onError != nil {
			onError(fmt.Errorf("writer: %d samples expired from %s before they were written (gap)", lost, stream))
		}
		r.Run(ctx, cons)
		return
	}
}
