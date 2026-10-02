package cis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
)

// Counter names of the follower.
const (
	CounterFollowerApplied     = "cis_follower_applied"
	CounterFollowerTouched     = "cis_follower_touched"
	CounterFollowerOlder       = "cis_follower_older_ignored"
	CounterFollowerUndecodable = "cis_follower_undecodable"
	CounterFollowerRefused     = "cis_follower_refused"
)

// fstate is what the follower holds of one dataset.
type fstate struct {
	version   int64
	etag      string
	fetchedAt time.Time
	volumes   []*zones.Zone
	ussps     []cispclient.Ussp
}

// Follower is the hot path's copy of the CIS projection (manned-feed,
// WP-6): it applies the KV cis_current values and the cis.v1 push, keeps
// the last state, and serves it with its age; it never blocks and never
// opens a database. A higher version replaces the held one, the same
// version moves fetched_at, an older one is ignored and counted. It
// starts empty, says "no CIS projection" (SC-22) and serves empty, never
// nil, volumes. Safe for concurrent use.
type Follower struct {
	counters *core.Counters

	mu sync.RWMutex
	st map[Dataset]*fstate
}

// NewFollower is an empty follower; counters may be nil.
func NewFollower(counters *core.Counters) *Follower {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Follower{counters: counters, st: map[Dataset]*fstate{}}
}

// Counters are the follower's counters.
func (f *Follower) Counters() *core.Counters { return f.counters }

// ApplyJSON applies one Doc (a KV value or a push) and reports whether
// it changed what the follower holds. A doc that does not decode, names
// no projected dataset, or whose body core refuses is counted and
// ignored: the state held stays.
func (f *Follower) ApplyJSON(raw []byte) bool {
	if len(raw) > MaxDocBytes {
		f.counters.Inc(CounterFollowerUndecodable)
		return false
	}
	var doc Doc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		f.counters.Inc(CounterFollowerUndecodable)
		return false
	}
	if _, ok := ParseDataset(string(doc.Dataset)); !ok || doc.Version < 1 || doc.FetchedAt.IsZero() {
		f.counters.Inc(CounterFollowerUndecodable)
		return false
	}
	f.mu.RLock()
	held := f.st[doc.Dataset]
	f.mu.RUnlock()
	if held != nil && doc.Version == held.version {
		f.mu.Lock()
		defer f.mu.Unlock()
		if cur := f.st[doc.Dataset]; cur != nil && cur.version == doc.Version && doc.FetchedAt.After(cur.fetchedAt) {
			next := *cur
			next.fetchedAt = doc.FetchedAt
			f.st[doc.Dataset] = &next
			f.counters.Inc(CounterFollowerTouched)
			return true
		}
		return false
	}
	if held != nil && doc.Version < held.version {
		f.counters.Inc(CounterFollowerOlder)
		return false
	}
	next := &fstate{version: doc.Version, etag: doc.ETag, fetchedAt: doc.FetchedAt}
	if doc.Dataset != Restrictions {
		v, rf := ParseVersion(doc.Dataset, doc.Body, doc.ETag, doc.Version)
		if rf != nil {
			f.counters.Inc(CounterFollowerRefused)
			return false
		}
		next.volumes = v.Volumes
		if v.USSPList != nil {
			next.ussps = v.USSPList.Ussps
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur := f.st[doc.Dataset]; cur != nil && cur.version >= next.version {
		return false // a concurrent apply won
	}
	f.st[doc.Dataset] = next
	f.counters.Inc(CounterFollowerApplied)
	return true
}

func (f *Follower) get(d Dataset) *fstate {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.st[d]
}

// Version is the uspace_airspace version held, "" while none is.
func (f *Follower) Version() string {
	if s := f.get(USpaceAirspace); s != nil {
		return strconv.FormatInt(s.version, 10)
	}
	return ""
}

// FetchedAt is when the uspace_airspace version held was last confirmed
// by the CISP (zero while none is held).
func (f *Follower) FetchedAt() time.Time {
	if s := f.get(USpaceAirspace); s != nil {
		return s.fetchedAt
	}
	return time.Time{}
}

// Age is how old the uspace_airspace version held is at now; ok is
// false while none is held.
func (f *Follower) Age(now time.Time) (ageS float64, ok bool) {
	s := f.get(USpaceAirspace)
	if s == nil {
		return 0, false
	}
	return math.Max(0, now.Sub(s.fetchedAt).Seconds()), true
}

// USpaceVolumes are the U-space volumes held, never nil.
func (f *Follower) USpaceVolumes() []*zones.Zone {
	if s := f.get(USpaceAirspace); s != nil && s.volumes != nil {
		return s.volumes
	}
	return []*zones.Zone{}
}

// USSPs is the USSP list held, never nil.
func (f *Follower) USSPs() []cispclient.Ussp {
	if s := f.get(USSPList); s != nil && s.ussps != nil {
		return s.ussps
	}
	return []cispclient.Ussp{}
}

// Status is the follower's line: "no CIS projection" while it holds no
// uspace_airspace version, else the version and the age at now.
func (f *Follower) Status(now time.Time) string {
	s := f.get(USpaceAirspace)
	if s == nil {
		return StatusNoProjection
	}
	return fmt.Sprintf("CIS version %d, %d volumes, age %.0f s", s.version, len(s.volumes), math.Max(0, now.Sub(s.fetchedAt).Seconds()))
}

// WatchKV is the part of the KV bucket the follower reads (a
// jetstream.KeyValue).
type WatchKV interface {
	WatchAll(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyWatcher, error)
}

// Run watches every key of cis_current and applies each value until ctx
// ends. It returns ctx's error, or the watcher's when it cannot start or
// stops.
func (f *Follower) Run(ctx context.Context, kv WatchKV) error {
	w, err := kv.WatchAll(ctx)
	if err != nil {
		return fmt.Errorf("cis_current: watch: %w", err)
	}
	defer func() { _ = w.Stop() }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-w.Updates():
			if !ok {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return errors.New("cis_current: the watch ended")
			}
			// A nil entry marks the end of the initial values.
			if e != nil && e.Operation() == jetstream.KeyValuePut {
				f.ApplyJSON(e.Value())
			}
		}
	}
}
