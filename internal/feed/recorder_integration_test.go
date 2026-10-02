//go:build integration

package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// outage is the writer with the database taken away for a while: every
// insert fails while down is set (the stand-in for a stopped database;
// the pool, the rows and the stream are all real).
type outage struct {
	w    *timeseries.Writer
	down atomic.Bool
}

func (o *outage) Insert(ctx context.Context, rows []timeseries.MannedTrackRow) (int64, error) {
	if o.down.Load() {
		return 0, errors.New("connect: connection refused (database stopped by the test)")
	}
	return o.w.Insert(ctx, rows)
}

// TestIntegrationWriterHoldsThroughA30sOutage is B-07: with the
// database away for 30 s the samples wait in MAN_MIRROR (bounded by the
// consumer's MaxAckPending), the failure counter moves and the status
// says so, and once it returns every sample is a row: the row count
// equals the frames sent, none twice.
func TestIntegrationWriterHoldsThroughA30sOutage(t *testing.T) {
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := storetest.Scratch(t, store.TreeTimeseries, true)
	db := storetest.Timeseries(t, dsn, store.RoleTimeseries)
	b, err := bus.ConnectWith(ctx, bus.Settings{URL: url, Name: "recorder-test"}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	adapter := fmt.Sprintf("outage-%d", time.Now().UnixNano()%1000000)
	cfg := ConsumerConfig()
	cfg.Durable = "recorder-test-" + adapter
	cfg.FilterSubject = bus.SubjectMannedPrefix + adapter + ".>"
	cfg.DeliverPolicy = jetstream.DeliverNewPolicy
	cons, err := b.JetStream().CreateOrUpdateConsumer(ctx, bus.StreamMannedMirror, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.JetStream().DeleteConsumer(context.Background(), bus.StreamMannedMirror, cfg.Durable) }()

	o := &outage{w: db.Writer()}
	o.down.Store(true)
	r := &Recorder{Insert: o}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r.Run(runCtx, cons); close(done) }()

	sent := 0
	publish := func(n int) {
		for i := 0; i < n; i++ {
			tr := sample(fmt.Sprintf("d%05x", sent%50), adapter, 41.7, 44.8, time.Now().UTC())
			raw, _ := json.Marshal(&tr)
			if err := b.Conn().Publish(tr.Subject(bus.SubjectMannedPrefix), raw); err != nil {
				t.Fatal(err)
			}
			sent++
		}
	}
	// 30 s without a database, samples arriving all along.
	outageStart := time.Now()
	for time.Since(outageStart) < 30*time.Second {
		publish(20)
		time.Sleep(500 * time.Millisecond)
	}
	if r.Counters().Get(CounterInsertFailed) == 0 {
		t.Fatal("the failure counter did not move")
	}
	if ok, line := r.Status(); ok {
		t.Fatalf("status during the outage says ok: %q", line)
	}
	info, err := cons.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waiting := int(info.NumPending) + info.NumAckPending
	t.Logf("after a 30 s outage: %d samples sent, %d waiting in MAN_MIRROR, %d failed inserts", sent, waiting,
		r.Counters().Get(CounterInsertFailed))
	if waiting != sent {
		t.Fatalf("the stream holds %d of %d samples", waiting, sent)
	}
	if n := countRows(t, dsn, adapter); n != 0 {
		t.Fatalf("%d rows written while down", n)
	}
	// The database returns: every sample lands, once.
	o.down.Store(false)
	deadline := time.Now().Add(60 * time.Second)
	for countRows(t, dsn, adapter) != int64(sent) {
		if time.Now().After(deadline) {
			t.Fatalf("rows %d of %d after recovery", countRows(t, dsn, adapter), sent)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("recovered: %d rows for %d samples in %v", countRows(t, dsn, adapter), sent, time.Since(outageStart.Add(30*time.Second)))
	if ok, _ := r.Status(); !ok {
		t.Fatal("status still failing")
	}
	stop()
	<-done
	if r.Gap() != 0 {
		t.Fatalf("gap %d", r.Gap())
	}
}

func countRows(t *testing.T, dsn, adapter string) int64 {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var n int64
	if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM manned_tracks WHERE adapter_id = $1`, adapter).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
