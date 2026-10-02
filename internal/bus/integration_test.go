//go:build integration

package bus

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/obs"
)

func integrationBus(t *testing.T) *Bus {
	t.Helper()
	url := os.Getenv("ANSP_NATS_URL")
	if url == "" {
		t.Skip("ANSP_NATS_URL is not set")
	}
	logger, _ := testLogger()
	b, err := ConnectWith(context.Background(), Settings{URL: url, CredsFile: os.Getenv("ANSP_NATS_CREDS"), Name: "integration"}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if s, reason := b.Status(); s != obs.StateOK {
		t.Fatalf("real NATS: %s (%s)", s, reason)
	}
	return b
}

// EnsureStreams against a real JetStream: twice, and the second run
// leaves every stream and bucket as the first created it.
func TestIntegrationEnsureStreams(t *testing.T) {
	b := integrationBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for range 2 {
		if err := b.EnsureStreams(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range StreamConfigs() {
		s, err := b.JetStream().Stream(ctx, want.Name)
		if err != nil {
			t.Fatalf("stream %s: %v", want.Name, err)
		}
		got := s.CachedInfo().Config
		if got.Retention != want.Retention || got.MaxAge != want.MaxAge || got.Storage != want.Storage || got.Subjects[0] != want.Subjects[0] {
			t.Fatalf("stream %s: %+v", want.Name, got)
		}
	}
	for _, want := range BucketConfigs() {
		kv, err := b.JetStream().KeyValue(ctx, want.Bucket)
		if err != nil {
			t.Fatalf("bucket %s: %v", want.Bucket, err)
		}
		if _, err := kv.Put(ctx, "probe", []byte("1")); err != nil {
			t.Fatalf("bucket %s: %v", want.Bucket, err)
		}
		if err := kv.Purge(ctx, "probe"); err != nil {
			t.Fatal(err)
		}
	}
	// A core publish on a manned subject is captured by MAN_MIRROR.
	s, err := b.JetStream().Stream(ctx, StreamMannedMirror)
	if err != nil {
		t.Fatal(err)
	}
	before := s.CachedInfo().State.LastSeq
	if err := b.Conn().Publish(SubjectMannedPrefix+"integration.4b1801", []byte(`{"synthetic":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := s.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.State.LastSeq > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("MAN_MIRROR did not capture the publish")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := s.DeleteMsg(ctx, before+1); err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
		t.Fatal(err)
	}
}

// The lazy KV against a real bucket: resolved on first use, every call
// this system makes, and a missing bucket said rather than hidden.
func TestIntegrationLazyKV(t *testing.T) {
	b := integrationBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}
	kv := b.KeyValue(BucketSessionsLive)
	_ = kv.Delete(ctx, "lazy") // a previous run's key
	if _, err := kv.Get(ctx, "nokey"); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("get: %v", err)
	}
	rev, err := kv.Create(ctx, "lazy", []byte("1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Update(ctx, "lazy", []byte("2"), rev); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "lazy", []byte("3")); err != nil {
		t.Fatal(err)
	}
	w, err := kv.WatchAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for e := range w.Updates() {
		if e == nil {
			break // the end of the initial values
		}
		if e.Key() == "lazy" && e.Operation() == jetstream.KeyValuePut && string(e.Value()) == "3" {
			found = true
		}
	}
	if !found {
		t.Fatal("the watch did not hold the key")
	}
	_ = w.Stop()
	l, err := kv.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range l.Keys() {
		n++
	}
	if n == 0 {
		t.Fatal("no keys listed")
	}
	if err := kv.Delete(ctx, "lazy"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.KeyValue("no_such_bucket").Get(ctx, "k"); err == nil {
		t.Fatal("a missing bucket said nothing")
	}
}
