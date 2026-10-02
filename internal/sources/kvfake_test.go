package sources

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// fakeEntry is one KV entry.
type fakeEntry struct {
	key   string
	value []byte
	rev   uint64
}

func (e *fakeEntry) Bucket() string                  { return "source_control" }
func (e *fakeEntry) Key() string                     { return e.key }
func (e *fakeEntry) Value() []byte                   { return e.value }
func (e *fakeEntry) Revision() uint64                { return e.rev }
func (e *fakeEntry) Created() time.Time              { return time.Time{} }
func (e *fakeEntry) Delta() uint64                   { return 0 }
func (e *fakeEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

var errDown = errors.New("kv down")

// fakeKV is an in-memory bucket with a switch to make it fail, and a
// hook that runs before each Update (to race a concurrent writer).
type fakeKV struct {
	mu        sync.Mutex
	entries   map[string]*fakeEntry
	rev       uint64
	getErr    error
	putErr    error
	gets      int
	puts      int
	beforePut func()
}

func newFakeKV() *fakeKV { return &fakeKV{entries: map[string]*fakeEntry{}} }

func (k *fakeKV) Get(_ context.Context, key string) (jetstream.KeyValueEntry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets++
	if k.getErr != nil {
		return nil, k.getErr
	}
	e, ok := k.entries[key]
	if !ok {
		return nil, jetstream.ErrKeyNotFound
	}
	cp := *e
	return &cp, nil
}

func (k *fakeKV) Create(_ context.Context, key string, value []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.putErr != nil {
		return 0, k.putErr
	}
	if _, ok := k.entries[key]; ok {
		return 0, jetstream.ErrKeyExists
	}
	k.rev++
	k.puts++
	k.entries[key] = &fakeEntry{key: key, value: append([]byte(nil), value...), rev: k.rev}
	return k.rev, nil
}

func (k *fakeKV) Update(_ context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if k.beforePut != nil {
		hook := k.beforePut
		k.beforePut = nil
		hook()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.putErr != nil {
		return 0, k.putErr
	}
	e, ok := k.entries[key]
	if !ok || e.rev != revision {
		return 0, &jetstream.APIError{ErrorCode: jetstream.JSErrCodeStreamWrongLastSequence, Code: 400, Description: "wrong last sequence"}
	}
	k.rev++
	k.puts++
	k.entries[key] = &fakeEntry{key: key, value: append([]byte(nil), value...), rev: k.rev}
	return k.rev, nil
}

func (k *fakeKV) set(key string, value []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rev++
	k.entries[key] = &fakeEntry{key: key, value: value, rev: k.rev}
}

func (k *fakeKV) value(key string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e, ok := k.entries[key]; ok {
		return e.value
	}
	return nil
}

func (k *fakeKV) fail(get, put error) {
	k.mu.Lock()
	k.getErr, k.putErr = get, put
	k.mu.Unlock()
}

// fakeRepo is source_controls in memory.
type fakeRepo struct {
	mu      sync.Mutex
	epoch   string
	version uint64
	rows    []Row
	sets    int
	err     error
}

func (r *fakeRepo) Set(_ context.Context, c Change) (Row, Doc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Row{}, Doc{}, r.err
	}
	r.sets++
	r.version++
	row := Row{SourceType: c.SourceType, InstanceID: c.InstanceID, Enabled: c.Enabled, Reason: c.Reason, Actor: c.Actor,
		ChangedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	replaced := false
	for i := range r.rows {
		if keyOf(r.rows[i].SourceType, r.rows[i].InstanceID) == keyOf(c.SourceType, c.InstanceID) {
			r.rows[i], replaced = row, true
		}
	}
	if !replaced {
		r.rows = append(r.rows, row)
	}
	return row, r.doc(), nil
}

func (r *fakeRepo) Load(context.Context) (Doc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Doc{}, r.err
	}
	return r.doc(), nil
}

func (r *fakeRepo) doc() Doc {
	return Doc{Version: r.version, Epoch: r.epoch, Controls: append([]Row(nil), r.rows...)}
}

type fakePush struct {
	mu   sync.Mutex
	msgs [][]byte
	err  error
}

func (p *fakePush) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if subject != SubjectControl {
		return errors.New("wrong subject " + subject)
	}
	p.msgs = append(p.msgs, data)
	return nil
}

func (p *fakePush) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.msgs)
}
