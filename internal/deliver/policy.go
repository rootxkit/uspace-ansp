package deliver

import (
	"errors"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Policy is the outbox's limits and timings, in this one place
// (CLAUDE.md rule 5). cisp_alarm_after_s and cisp_heartbeat_s are the
// ansp_policy row's and are read from it; the rest have no column yet
// (docs/PLAN.md section 15 row 39) and are the defaults below.
type Policy struct {
	// BackoffMin is the wait before the second attempt; it doubles up to
	// BackoffMax (02 F2: 1 s to 60 s).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// Window is how long a job is retried from its queuing (24 h, the
	// DELIVER stream's retention); MaxAttempts counts what fits in it.
	Window time.Duration
	// HTTPTimeout bounds one attempt's request and response.
	HTTPTimeout time.Duration
	// Lease bounds one attempt's hold on its row; it outlives
	// HTTPTimeout.
	Lease time.Duration
	// ScanEvery is the outbox scan (B-05): rows never published, and
	// rows whose message is overdue by StuckGrace, are published again.
	ScanEvery    time.Duration
	PublishGrace time.Duration
	StuckGrace   time.Duration
	// InFlight bounds the attempts one worker runs at once (E-10).
	InFlight int
	// MaxResponseBytes bounds what is read of an answer; ExcerptBytes
	// what is kept of it in the log row.
	MaxResponseBytes int64
	ExcerptBytes     int
	// MaxBodyBytes bounds a request body (the CISP's
	// CISP_MAX_RESTRICTION_BYTES, 256 KiB).
	MaxBodyBytes int
	// MaxActiveRefs bounds a heartbeat's active_refs (the CISP's
	// MaxActiveRefs, 1000).
	MaxActiveRefs int
	// MaxTargets bounds the degraded direct deliveries of one version
	// (the CIS USSP list holds at most 200, plus the authority).
	MaxTargets int
	// AlarmEvery is how often the alarm monitor runs.
	AlarmEvery time.Duration
	// MaxBatch bounds the rows one scan, monitor or reconciliation pass
	// handles; the rest wait for the next.
	MaxBatch int
}

// DefaultPolicy is the outbox's defaults.
func DefaultPolicy() Policy {
	return Policy{
		BackoffMin: time.Second, BackoffMax: 60 * time.Second, Window: 24 * time.Hour,
		HTTPTimeout: 10 * time.Second, Lease: 30 * time.Second,
		ScanEvery: 5 * time.Second, PublishGrace: 2 * time.Second, StuckGrace: 30 * time.Second,
		InFlight: 8, MaxResponseBytes: 1 << 20, ExcerptBytes: 1024, MaxBodyBytes: 256 << 10,
		MaxActiveRefs: 1000, MaxTargets: 201, AlarmEvery: time.Second, MaxBatch: 100,
	}
}

// Validate refuses a policy the outbox cannot run.
func (p Policy) Validate() error {
	var errs []error
	if p.BackoffMin <= 0 || p.BackoffMax < p.BackoffMin {
		errs = append(errs, core.Fieldf("backoff", "min must be positive and at most max"))
	}
	if p.Window < p.BackoffMax {
		errs = append(errs, core.Fieldf("window", "shorter than the longest backoff"))
	}
	if p.HTTPTimeout <= 0 || p.Lease <= p.HTTPTimeout {
		errs = append(errs, core.Fieldf("lease", "must outlive the HTTP timeout"))
	}
	if p.ScanEvery <= 0 || p.PublishGrace <= 0 || p.StuckGrace <= 0 || p.AlarmEvery <= 0 {
		errs = append(errs, core.Fieldf("periods", "must be positive"))
	}
	if p.InFlight < 1 || p.MaxBatch < 1 || p.MaxTargets < 1 || p.MaxActiveRefs < 1 {
		errs = append(errs, core.Fieldf("bounds", "must be at least 1"))
	}
	if p.MaxResponseBytes < 1 || p.ExcerptBytes < 16 || p.MaxBodyBytes < 1 {
		errs = append(errs, core.Fieldf("sizes", "must be positive (an excerpt at least 16 bytes)"))
	}
	return errors.Join(errs...)
}

// Backoff is the wait after attempt n (1-based) failed: BackoffMin
// doubled n-1 times, at most BackoffMax.
func (p Policy) Backoff(n int) time.Duration {
	d := p.BackoffMin
	for i := 1; i < n && d < p.BackoffMax; i++ {
		d *= 2
	}
	return min(d, p.BackoffMax)
}

// MaxAttempts is how many attempts fit in Window with Backoff between
// them: the count bound of every job (max_deliver by policy). It is at
// least 1 and at most 100000.
func (p Policy) MaxAttempts() int {
	var spent time.Duration
	n := 1
	for n < 100000 {
		spent += p.Backoff(n)
		if spent > p.Window {
			break
		}
		n++
	}
	return n
}
