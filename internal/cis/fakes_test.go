package cis_test

import (
	"context"
	"sync"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// memStore is cis.Store and cis.ReceiverStore in memory, with a clock
// of its own standing in for the database's.
type memStore struct {
	mu     sync.Mutex
	rows   map[cis.Dataset]cis.Stored
	jtis   map[string]time.Time
	now    func() time.Time
	fail   error
	saves  int
	touchs int
}

func newMemStore() *memStore {
	return &memStore{rows: map[cis.Dataset]cis.Stored{}, jtis: map[string]time.Time{}, now: time.Now}
}

func (m *memStore) Save(_ context.Context, v *cis.Version) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return time.Time{}, false, m.fail
	}
	if r, ok := m.rows[v.Dataset]; ok && r.Version > v.Number {
		return time.Time{}, true, nil
	}
	at := m.now().UTC()
	m.rows[v.Dataset] = cis.Stored{Dataset: v.Dataset, Version: v.Number, ETag: v.ETag, Body: v.Body, FetchedAt: at}
	m.saves++
	return at, false, nil
}

func (m *memStore) Touch(_ context.Context, d cis.Dataset, version int64) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return time.Time{}, false, m.fail
	}
	r, ok := m.rows[d]
	if !ok || r.Version != version {
		return time.Time{}, false, nil
	}
	r.FetchedAt = m.now().UTC()
	m.rows[d] = r
	m.touchs++
	return r.FetchedAt, true, nil
}

func (m *memStore) Load(context.Context) ([]cis.Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return nil, m.fail
	}
	out := make([]cis.Stored, 0, len(m.rows))
	for _, d := range cis.Datasets {
		if r, ok := m.rows[d]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) RememberJTI(_ context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return false, false, m.fail
	}
	now := m.now()
	key := issuer + " " + jti
	if exp, ok := m.jtis[key]; ok && exp.After(now) {
		return false, false, nil
	}
	live := int64(0)
	for _, exp := range m.jtis {
		if exp.After(now) {
			live++
		}
	}
	if live >= maxLive {
		return false, true, nil
	}
	m.jtis[key] = now.Add(ttl)
	return true, false, nil
}

func (m *memStore) row(d cis.Dataset) (cis.Stored, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[d]
	return r, ok
}

// memKV is the cis_current bucket in memory, and the push.
type memKV struct {
	mu     sync.Mutex
	vals   map[string][]byte
	puts   int
	fail   error
	pushed []string
}

func newMemKV() *memKV { return &memKV{vals: map[string][]byte{}} }

func (k *memKV) Put(_ context.Context, key string, value []byte) (uint64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return 0, k.fail
	}
	k.vals[key] = append([]byte(nil), value...)
	k.puts++
	return uint64(k.puts), nil
}

func (k *memKV) Publish(subject string, _ []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pushed = append(k.pushed, subject)
	return nil
}

func (k *memKV) value(key string) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.vals[key]
}

func (k *memKV) pushes() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.pushed...)
}

// fixedPolicy returns thresholds with cis_reconcile_s r.
func fixedPolicy(r float64) func(context.Context) policy.Thresholds {
	return func(context.Context) policy.Thresholds {
		t := policy.Defaults()
		t.CISReconcileS = r
		return t
	}
}
