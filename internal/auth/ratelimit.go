package auth

import (
	"container/list"
	"math"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Counters of the rate limiters.
const (
	CounterRateLimited  = "auth_rate_limited"
	CounterLimiterEvict = "auth_rate_limiter_evicted"
)

// DefaultLimiterKeys bounds the keys a limiter remembers.
const DefaultLimiterKeys = 10_000

// RateLimiter is a token bucket per key (a client address, a username)
// with a bounded key map (E-10): beyond its bound the least recently
// seen key is evicted (counted) and starts again with a full bucket. It
// is per process: the lockout that must hold across replicas lives in
// the database (login_lockouts).
type RateLimiter struct {
	rate     float64 // tokens per second
	burst    float64
	max      int
	counters *core.Counters
	now      func() time.Time

	mu    sync.Mutex
	keys  map[string]*list.Element
	order *list.List // front = most recently seen
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// NewRateLimiter is a limiter of perMinute requests per minute per key,
// all of them available at once, remembering at most maxKeys keys.
func NewRateLimiter(perMinute, maxKeys int, counters *core.Counters, now func() time.Time) *RateLimiter {
	if counters == nil {
		counters = &core.Counters{}
	}
	if now == nil {
		now = time.Now
	}
	perMinute = max(1, perMinute)
	return &RateLimiter{
		rate: float64(perMinute) / 60, burst: float64(perMinute), max: max(1, maxKeys), counters: counters, now: now,
		keys: map[string]*list.Element{}, order: list.New(),
	}
}

// Len is the number of keys remembered.
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// Allow takes one token from key's bucket. When it is empty it returns
// false and how long until a token is available.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *bucket
	if el, ok := l.keys[key]; ok {
		l.order.MoveToFront(el)
		b = el.Value.(*bucket)
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
		}
		b.last = now
	} else {
		if len(l.keys) >= l.max {
			oldest := l.order.Back()
			l.order.Remove(oldest)
			delete(l.keys, oldest.Value.(*bucket).key)
			l.counters.Inc(CounterLimiterEvict)
		}
		b = &bucket{key: key, tokens: l.burst, last: now}
		l.keys[key] = l.order.PushFront(b)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	l.counters.Inc(CounterRateLimited)
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}
