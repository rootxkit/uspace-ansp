package manned

import (
	"sync"
	"time"
)

// RefusalLimiter decides whether a refusal is logged: once per icao24
// per period, never per frame (WP-4). It remembers at most max
// aircraft; when full it forgets the ones logged more than a period ago
// and, if still full, declines: the refusal is still counted by field
// (refused_<field>), only its log line is skipped.
// Safe for concurrent use.
type RefusalLimiter struct {
	period time.Duration
	max    int

	mu   sync.Mutex
	last map[string]time.Time
}

// NewRefusalLimiter logs each aircraft at most once per period and
// remembers at most max aircraft.
func NewRefusalLimiter(period time.Duration, maxAircraft int) *RefusalLimiter {
	if maxAircraft < 1 {
		maxAircraft = 1
	}
	return &RefusalLimiter{period: period, max: maxAircraft, last: map[string]time.Time{}}
}

// Allow reports whether a refusal of icao at now is logged.
func (l *RefusalLimiter) Allow(icao string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if at, ok := l.last[icao]; ok {
		if now.Sub(at) < l.period {
			return false
		}
		l.last[icao] = now
		return true
	}
	if len(l.last) >= l.max {
		for k, at := range l.last {
			if now.Sub(at) >= l.period {
				delete(l.last, k)
			}
		}
		if len(l.last) >= l.max {
			return false
		}
	}
	l.last[icao] = now
	return true
}
