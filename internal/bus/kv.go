package bus

import (
	"context"
	"errors"
	"sync"

	"github.com/nats-io/nats.go/jetstream"
)

// ErrNoBus is a KV call on a process without ANSP_NATS_URL.
var ErrNoBus = errors.New("nats: ANSP_NATS_URL is not set")

// KV is one bucket resolved on first use and again after a failure: the
// api declares the buckets and may start after the process that reads
// them, and the bus may be down at start (B-08). Only the calls this
// system makes are offered. Safe for concurrent use.
type KV struct {
	b      *Bus
	bucket string

	mu sync.Mutex
	kv jetstream.KeyValue
}

// KeyValue is bucket on b, resolved lazily.
func (b *Bus) KeyValue(bucket string) *KV { return &KV{b: b, bucket: bucket} }

// Bucket is the bucket's name.
func (k *KV) Bucket() string { return k.bucket }

func (k *KV) resolve(ctx context.Context) (jetstream.KeyValue, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kv != nil {
		return k.kv, nil
	}
	js := k.b.JetStream()
	if js == nil {
		return nil, ErrNoBus
	}
	kv, err := js.KeyValue(ctx, k.bucket)
	if err != nil {
		return nil, err
	}
	k.kv = kv
	return kv, nil
}

// forget drops the resolved bucket after a failure that is not about a
// key, so the next call resolves it again (a bucket re-created).
func (k *KV) forget(err error) {
	if err == nil || errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyExists) {
		return
	}
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence {
		return
	}
	k.mu.Lock()
	k.kv = nil
	k.mu.Unlock()
}

// Get reads key.
func (k *KV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return nil, err
	}
	e, err := kv.Get(ctx, key)
	k.forget(err)
	return e, err
}

// Create writes key when it does not exist.
func (k *KV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return 0, err
	}
	rev, err := kv.Create(ctx, key, value, opts...)
	k.forget(err)
	return rev, err
}

// Update writes key when its revision is still revision.
func (k *KV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return 0, err
	}
	rev, err := kv.Update(ctx, key, value, revision)
	k.forget(err)
	return rev, err
}

// Put writes key.
func (k *KV) Put(ctx context.Context, key string, value []byte) (uint64, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return 0, err
	}
	rev, err := kv.Put(ctx, key, value)
	k.forget(err)
	return rev, err
}

// Delete deletes key.
func (k *KV) Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	kv, err := k.resolve(ctx)
	if err != nil {
		return err
	}
	err = kv.Delete(ctx, key, opts...)
	k.forget(err)
	return err
}

// ListKeys lists the bucket's keys.
func (k *KV) ListKeys(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyLister, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return nil, err
	}
	l, err := kv.ListKeys(ctx, opts...)
	if !errors.Is(err, jetstream.ErrNoKeysFound) {
		k.forget(err)
	}
	return l, err
}

// WatchAll watches every key.
func (k *KV) WatchAll(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	kv, err := k.resolve(ctx)
	if err != nil {
		return nil, err
	}
	w, err := kv.WatchAll(ctx, opts...)
	k.forget(err)
	return w, err
}
