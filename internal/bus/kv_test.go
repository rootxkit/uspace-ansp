package bus

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// Without ANSP_NATS_URL every call says so; nothing is resolved.
func TestKVWithoutABus(t *testing.T) {
	logger, _ := testLogger()
	b, err := Connect(context.Background(), config.Config{Process: "api", Instance: "t"}, logger)
	if err != nil {
		t.Fatal(err)
	}
	kv := b.KeyValue(BucketSourceControl)
	ctx := context.Background()
	if kv.Bucket() != BucketSourceControl {
		t.Fatal(kv.Bucket())
	}
	_, e1 := kv.Get(ctx, "k")
	_, e2 := kv.Create(ctx, "k", nil)
	_, e3 := kv.Update(ctx, "k", nil, 1)
	_, e4 := kv.Put(ctx, "k", nil)
	e5 := kv.Delete(ctx, "k")
	_, e6 := kv.ListKeys(ctx)
	_, e7 := kv.WatchAll(ctx)
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if !errors.Is(err, ErrNoBus) {
			t.Errorf("call %d: %v", i, err)
		}
	}
}

// forget keeps the bucket on an answer about a key and drops it on
// anything else, so a re-created bucket is found again.
func TestKVForget(t *testing.T) {
	kv := &KV{}
	for _, err := range []error{nil, jetstream.ErrKeyNotFound, jetstream.ErrKeyExists,
		&jetstream.APIError{ErrorCode: jetstream.JSErrCodeStreamWrongLastSequence}} {
		kv.kv = fakeKeyValue{}
		kv.forget(err)
		if kv.kv == nil {
			t.Fatalf("%v dropped the bucket", err)
		}
	}
	kv.forget(errors.New("connection closed"))
	if kv.kv != nil {
		t.Fatal("a connection failure kept the bucket")
	}
}

type fakeKeyValue struct{ jetstream.KeyValue }

// recordingKV answers every call and fails when told to.
type recordingKV struct {
	jetstream.KeyValue
	calls int
	err   error
}

func (r *recordingKV) Get(context.Context, string) (jetstream.KeyValueEntry, error) {
	r.calls++
	return nil, r.err
}
func (r *recordingKV) Create(context.Context, string, []byte, ...jetstream.KVCreateOpt) (uint64, error) {
	r.calls++
	return 1, r.err
}
func (r *recordingKV) Update(context.Context, string, []byte, uint64) (uint64, error) {
	r.calls++
	return 2, r.err
}
func (r *recordingKV) Put(context.Context, string, []byte) (uint64, error) {
	r.calls++
	return 3, r.err
}
func (r *recordingKV) Delete(context.Context, string, ...jetstream.KVDeleteOpt) error {
	r.calls++
	return r.err
}
func (r *recordingKV) ListKeys(context.Context, ...jetstream.WatchOpt) (jetstream.KeyLister, error) {
	r.calls++
	return nil, r.err
}
func (r *recordingKV) WatchAll(context.Context, ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	r.calls++
	return nil, r.err
}

type resolvingJS struct {
	jetstream.JetStream
	kv       *recordingKV
	resolved int
	err      error
}

func (j *resolvingJS) KeyValue(context.Context, string) (jetstream.KeyValue, error) {
	j.resolved++
	if j.err != nil {
		return nil, j.err
	}
	return j.kv, nil
}

// The bucket is resolved once and reused; a failure that is not about a
// key resolves it again on the next call (the twin of TestKVForget).
func TestKVResolvesOnceAndAgainAfterAFailure(t *testing.T) {
	rec := &recordingKV{}
	js := &resolvingJS{kv: rec}
	b := &Bus{js: js}
	kv := b.KeyValue("b")
	ctx := context.Background()
	_, _ = kv.Get(ctx, "k")
	_, _ = kv.Create(ctx, "k", nil)
	_, _ = kv.Update(ctx, "k", nil, 1)
	_, _ = kv.Put(ctx, "k", nil)
	_ = kv.Delete(ctx, "k")
	_, _ = kv.ListKeys(ctx)
	_, _ = kv.WatchAll(ctx)
	if rec.calls != 7 || js.resolved != 1 {
		t.Fatalf("calls %d, resolved %d", rec.calls, js.resolved)
	}
	rec.err = errors.New("connection closed")
	_, _ = kv.Get(ctx, "k")
	rec.err = nil
	_, _ = kv.Get(ctx, "k")
	if js.resolved != 2 {
		t.Fatalf("resolved %d after a failure", js.resolved)
	}
	rec.err = jetstream.ErrNoKeysFound
	_, _ = kv.ListKeys(ctx)
	_, _ = kv.Get(ctx, "k")
	if js.resolved != 2 {
		t.Fatal("no keys dropped the bucket")
	}
	js.err = errors.New("no bucket")
	kv2 := b.KeyValue("missing")
	_, e1 := kv2.Create(ctx, "k", nil)
	_, e2 := kv2.Update(ctx, "k", nil, 1)
	_, e3 := kv2.Put(ctx, "k", nil)
	e4 := kv2.Delete(ctx, "k")
	_, e5 := kv2.ListKeys(ctx)
	_, e6 := kv2.WatchAll(ctx)
	for i, err := range []error{e1, e2, e3, e4, e5, e6} {
		if err == nil {
			t.Errorf("call %d: a missing bucket said nothing", i)
		}
	}
}
