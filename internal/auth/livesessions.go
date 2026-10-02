package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
)

// The live-session projection (docs/PLAN.md section 15 row 21): api
// projects every live console session to the KV bucket sessions_live
// (key = jti, value LiveSession), and manned-feed, which never opens
// PostgreSQL, checks a session there. Absence refuses; an unanswerable
// projection refuses (4401 on a stream); a full resync every
// LiveSessionResync repairs a lost put or delete.
const (
	// LiveSessionResync is the period of api's full rewrite and of the
	// checker's full re-read.
	LiveSessionResync = 60 * time.Second
	// MaxLiveSessions bounds one resync; past it nothing is deleted
	// (counted), so a cut listing never ends a live session.
	MaxLiveSessions = 10_000
	// maxLiveSessionBytes bounds one value.
	maxLiveSessionBytes = 1024
	kvTimeout           = 5 * time.Second
)

// Counters of the projection.
const (
	CounterLivePut           = "sessions_live_put"
	CounterLivePutFailed     = "sessions_live_put_failed"
	CounterLiveDeleted       = "sessions_live_deleted"
	CounterLiveDeleteFailed  = "sessions_live_delete_failed"
	CounterLiveResync        = "sessions_live_resync"
	CounterLiveResyncFailed  = "sessions_live_resync_failed"
	CounterLiveResyncCut     = "sessions_live_resync_truncated"
	CounterLiveUndecodable   = "sessions_live_undecodable"
	CounterLiveUnanswerable  = "sessions_live_unanswerable"
	CounterLiveSeenTouched   = "sessions_seen_touched"
	CounterLiveSeenRefused   = "sessions_seen_refused"
	CounterLiveWatchRestarts = "sessions_live_watch_restarts"
)

// ErrLiveSessionsUnavailable is the projection not answering: the check
// is not a refusal of the session but cannot be made (503 before an
// upgrade, 4401 on an open stream).
var ErrLiveSessionsUnavailable = errors.New("the live-session projection cannot be read")

var jtiPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidJTI reports whether s is a session id as startSession makes it
// (16 random bytes in hex): also a valid KV key.
func ValidJTI(s string) bool { return jtiPattern.MatchString(s) }

// LiveSession is the value of a sessions_live key.
type LiveSession struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DecodeLiveSession decodes a value strictly.
func DecodeLiveSession(b []byte) (LiveSession, error) {
	if len(b) > maxLiveSessionBytes {
		return LiveSession{}, errors.New("live session: too long")
	}
	var v LiveSession
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil || v.UserID == "" || v.Role == "" || v.ExpiresAt.IsZero() {
		return LiveSession{}, errors.New("live session: not a {user_id, role, expires_at} document")
	}
	return v, nil
}

// SessionProjection is what Accounts tells after a commit: a session
// started, sessions ended. Implementations never block on failure and
// never retry inline (the resync repairs).
type SessionProjection interface {
	Started(ctx context.Context, jti string, s LiveSession)
	Ended(ctx context.Context, jtis ...string)
}

// SetProjection makes Accounts tell p of every session it starts and
// ends, after the commit.
func (s *Accounts) SetProjection(p SessionProjection) { s.projection = p }

func (s *Accounts) ended(ctx context.Context, jtis ...string) {
	if s.projection != nil && len(jtis) > 0 {
		s.projection.Ended(ctx, jtis...)
	}
}

// SessionSeen moves last_seen_at of a live session another process saw
// in use (manned-feed's console stream, ctl.sessions.seen; row 21 (4)):
// a watching supervisor is working, not idle. A malformed id is refused
// and counted; an ended session is never touched (TouchSession reads
// only live rows).
func (s *Accounts) SessionSeen(ctx context.Context, jti string) error {
	if !ValidJTI(jti) {
		s.counters.Inc(CounterLiveSeenRefused)
		return errors.New("not a session id")
	}
	if err := s.store.TouchSession(ctx, jti); err != nil {
		return err
	}
	s.counters.Inc(CounterLiveSeenTouched)
	return nil
}

// LiveSessionLister lists the live sessions on the database clock
// (store.AuthRepo).
type LiveSessionLister interface {
	LiveSessions(ctx context.Context, idle time.Duration, limit int) ([]SessionRow, error)
}

// ProjectionKV is the part of a jetstream.KeyValue the projector writes.
type ProjectionKV interface {
	Put(ctx context.Context, key string, value []byte) (uint64, error)
	Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error
	ListKeys(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyLister, error)
}

// SessionProjector is api's writer of sessions_live: write-through after
// each commit (a failure is counted, never retried inline) and a full
// rewrite every LiveSessionResync from user_sessions that deletes every
// key that is not a live session.
type SessionProjector struct {
	KV       ProjectionKV
	Lister   LiveSessionLister
	Idle     time.Duration
	counters core.Counters
}

// Counters are the projector's counters.
func (p *SessionProjector) Counters() *core.Counters { return &p.counters }

// Started puts the session.
func (p *SessionProjector) Started(ctx context.Context, jti string, s LiveSession) {
	if p.KV == nil || !ValidJTI(jti) {
		p.counters.Inc(CounterLivePutFailed)
		return
	}
	b, err := json.Marshal(s)
	if err == nil {
		pctx, cancel := context.WithTimeout(ctx, kvTimeout)
		_, err = p.KV.Put(pctx, jti, b)
		cancel()
	}
	if err != nil {
		p.counters.Inc(CounterLivePutFailed)
		return
	}
	p.counters.Inc(CounterLivePut)
}

// Ended deletes the sessions.
func (p *SessionProjector) Ended(ctx context.Context, jtis ...string) {
	for _, jti := range jtis {
		if p.KV == nil || !ValidJTI(jti) {
			p.counters.Inc(CounterLiveDeleteFailed)
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, kvTimeout)
		err := p.KV.Delete(dctx, jti)
		cancel()
		if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			p.counters.Inc(CounterLiveDeleteFailed)
			continue
		}
		p.counters.Inc(CounterLiveDeleted)
	}
}

// Resync rewrites the bucket from user_sessions: every live session is
// put, every other key deleted. A listing cut at MaxLiveSessions deletes
// nothing (counted).
func (p *SessionProjector) Resync(ctx context.Context) (put, deleted int, err error) {
	if p.KV == nil || p.Lister == nil {
		return 0, 0, ErrLiveSessionsUnavailable
	}
	rows, err := p.Lister.LiveSessions(ctx, p.Idle, MaxLiveSessions+1)
	if err != nil {
		p.counters.Inc(CounterLiveResyncFailed)
		return 0, 0, err
	}
	cut := len(rows) > MaxLiveSessions
	if cut {
		rows = rows[:MaxLiveSessions]
		p.counters.Inc(CounterLiveResyncCut)
	}
	live := make(map[string]bool, len(rows))
	for i := range rows {
		r := &rows[i]
		live[r.JTI] = true
		b, err := json.Marshal(LiveSession{UserID: r.UserID, Role: r.Role, ExpiresAt: r.ExpiresAt.UTC()})
		if err != nil {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, kvTimeout)
		_, err = p.KV.Put(pctx, r.JTI, b)
		cancel()
		if err != nil {
			p.counters.Inc(CounterLiveResyncFailed)
			return put, deleted, fmt.Errorf("sessions_live: put: %w", err)
		}
		put++
	}
	if !cut {
		lctx, cancel := context.WithTimeout(ctx, kvTimeout)
		defer cancel()
		lister, err := p.KV.ListKeys(lctx)
		if err != nil && !errors.Is(err, jetstream.ErrNoKeysFound) {
			p.counters.Inc(CounterLiveResyncFailed)
			return put, deleted, fmt.Errorf("sessions_live: list: %w", err)
		}
		var stale []string
		if lister != nil {
			for k := range lister.Keys() {
				if !live[k] {
					stale = append(stale, k)
				}
			}
			_ = lister.Stop()
		}
		for _, k := range stale {
			dctx, dcancel := context.WithTimeout(ctx, kvTimeout)
			err := p.KV.Delete(dctx, k)
			dcancel()
			if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
				p.counters.Inc(CounterLiveResyncFailed)
				return put, deleted, fmt.Errorf("sessions_live: delete: %w", err)
			}
			deleted++
		}
	}
	p.counters.Inc(CounterLiveResync)
	return put, deleted, nil
}

// Run resyncs at once and then every period until ctx ends.
func (p *SessionProjector) Run(ctx context.Context, period time.Duration, onError func(error)) {
	if period <= 0 {
		period = LiveSessionResync
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		if _, _, err := p.Resync(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// WatchKV is the part of a jetstream.KeyValue the checker reads.
type WatchKV interface {
	WatchAll(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyWatcher, error)
}

// KVSessionChecker is the SessionChecker of manned-feed: the live
// sessions as sessions_live holds them, re-read in full every Resync and
// kept current by the watch between re-reads. A jti with no key, or one
// whose expires_at has passed, is not live (absence refuses). While the
// projection cannot be read for longer than one Resync (the bucket
// unreachable, the watch lost, the bus down) every check fails with
// ErrLiveSessionsUnavailable. Safe for concurrent use.
type KVSessionChecker struct {
	// Resync is the full re-read period (LiveSessionResync).
	Resync time.Duration
	// Up, when set, is the bus: while it is down the projection counts
	// as lost from the first time it is seen down.
	Up  func() bool
	Now func() time.Time

	counters core.Counters

	mu        sync.RWMutex
	live      map[string]LiveSession
	synced    bool
	lostSince time.Time
}

// Counters are the checker's counters.
func (c *KVSessionChecker) Counters() *core.Counters { return &c.counters }

func (c *KVSessionChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *KVSessionChecker) period() time.Duration {
	if c.Resync <= 0 {
		return LiveSessionResync
	}
	return c.Resync
}

// Healthy is whether checks can be answered now, and the reason when
// not.
func (c *KVSessionChecker) Healthy() (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch {
	case !c.synced:
		return false, "sessions_live never read"
	case !c.lostSince.IsZero() && c.now().Sub(c.lostSince) > c.period():
		return false, "sessions_live unreachable since " + c.lostSince.UTC().Format(time.RFC3339)
	}
	return true, ""
}

// CheckSession implements SessionChecker on the projection.
func (c *KVSessionChecker) CheckSession(_ context.Context, jti, sub string) (string, error) {
	if ok, why := c.Healthy(); !ok {
		c.counters.Inc(CounterLiveUnanswerable)
		return "", fmt.Errorf("%w: %s", ErrLiveSessionsUnavailable, why)
	}
	c.mu.RLock()
	s, ok := c.live[jti]
	c.mu.RUnlock()
	switch {
	case !ok:
		return "", fmt.Errorf("%w: no live session", ErrSessionRefused)
	case s.UserID != sub:
		return "", fmt.Errorf("%w: the session is not this account's", ErrSessionRefused)
	case !c.now().Before(s.ExpiresAt):
		return "", fmt.Errorf("%w: the session expired", ErrSessionRefused)
	}
	return s.Role, nil
}

// Len is the number of live sessions held.
func (c *KVSessionChecker) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.live)
}

func (c *KVSessionChecker) lost() {
	c.mu.Lock()
	if c.lostSince.IsZero() {
		c.lostSince = c.now()
	}
	c.mu.Unlock()
}

// Follow keeps the projection until ctx ends: a full read of the bucket
// (its initial values), the watch's updates until Resync has passed,
// then a full read again. A failure marks the projection lost from that
// moment and is retried every second.
func (c *KVSessionChecker) Follow(ctx context.Context, get func(ctx context.Context) (WatchKV, error)) {
	for ctx.Err() == nil {
		if c.Up != nil && !c.Up() {
			c.lost()
			if !sleepFor(ctx, time.Second) {
				return
			}
			continue
		}
		if err := c.cycle(ctx, get); err != nil {
			c.lost()
			c.counters.Inc(CounterLiveWatchRestarts)
			if !sleepFor(ctx, time.Second) {
				return
			}
		}
	}
}

// cycle is one full read and the watch until the next re-read.
func (c *KVSessionChecker) cycle(ctx context.Context, get func(ctx context.Context) (WatchKV, error)) error {
	kv, err := get(ctx)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, c.period())
	defer cancel()
	w, err := kv.WatchAll(wctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Stop() }()
	fresh := map[string]LiveSession{}
	initial := true
	up := time.NewTicker(time.Second)
	defer up.Stop()
	for {
		select {
		case <-wctx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if initial {
				return errors.New("sessions_live: the initial values did not arrive within one resync")
			}
			return nil
		case <-up.C:
			if c.Up != nil && !c.Up() {
				return errors.New("sessions_live: the bus is down")
			}
		case e, ok := <-w.Updates():
			if !ok {
				return errors.New("sessions_live: the watch ended")
			}
			if e == nil {
				initial = false
				c.mu.Lock()
				c.live, c.synced, c.lostSince = fresh, true, time.Time{}
				c.mu.Unlock()
				continue
			}
			c.apply(fresh, initial, e)
		}
	}
}

func (c *KVSessionChecker) apply(fresh map[string]LiveSession, initial bool, e jetstream.KeyValueEntry) {
	target := fresh
	if !initial {
		c.mu.Lock()
		defer c.mu.Unlock()
		target = c.live
	}
	switch e.Operation() {
	case jetstream.KeyValuePut:
		s, err := DecodeLiveSession(e.Value())
		if err != nil {
			c.counters.Inc(CounterLiveUndecodable)
			delete(target, e.Key())
			return
		}
		if len(target) >= MaxLiveSessions {
			c.counters.Inc(CounterLiveResyncCut)
			return
		}
		target[e.Key()] = s
	case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
		delete(target, e.Key())
	}
}

func sleepFor(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
