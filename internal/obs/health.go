package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// State is the state of one dependency.
type State string

// The three states of a dependency (docs/WORKPACKAGES/WP-0.md).
const (
	StateOK       State = "ok"
	StateDegraded State = "degraded"
	StateDown     State = "down"
)

// The dependency names a readiness check may carry. A process lists
// every dependency it opens, so none is hidden (E-02, SC-22).
const (
	DepNATS       = "nats"
	DepRelational = "relational"
	DepTimeseries = "timeseries"
	DepCISP       = "cisp"
	DepDSS        = "dss"
	DepJWKS       = "jwks"
)

// DefaultCheckTimeout bounds one probe; a probe that does not answer in
// time is down, with the bound named.
const DefaultCheckTimeout = 2 * time.Second

// Check is one dependency of a process: its name, whether the process
// is not ready without it, and the probe that reports its state and,
// when not ok, why.
type Check struct {
	Name     string
	Required bool
	Probe    func(ctx context.Context) (State, string)
}

// Result is one check as /readyz shows it.
type Result struct {
	Name     string `json:"name"`
	State    State  `json:"state"`
	Required bool   `json:"required"`
	Reason   string `json:"reason,omitempty"`
}

// String is "nats: ok" or "nats: down (reconnecting)".
func (r Result) String() string {
	if r.Reason == "" {
		return r.Name + ": " + string(r.State)
	}
	return r.Name + ": " + string(r.State) + " (" + r.Reason + ")"
}

// Report is the body of /readyz.
type Report struct {
	Process   string    `json:"process"`
	Instance  string    `json:"instance"`
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at"`
	Checks    []Result  `json:"checks"`
	// Summary is every check as one line, in order.
	Summary []string `json:"summary"`
}

// The two readiness statuses.
const (
	StatusReady    = "ready"
	StatusNotReady = "not_ready"
)

// Health serves the liveness and readiness of one process.
type Health struct {
	Process  string
	Instance string
	// Timeout bounds each probe; zero is DefaultCheckTimeout.
	Timeout time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Liveness answers 200 while the process can answer at all. It checks
// no dependency: a process whose NATS is down stays alive (B-08).
func (h *Health) Liveness() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive", "process": h.Process, "instance": h.Instance})
	})
}

// Readiness answers 200 with the list of checks when every required
// check is ok or degraded, and 503 with the same list otherwise. Every
// check is listed, whatever its state.
func (h *Health) Readiness(checks ...Check) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := h.Check(r.Context(), checks...)
		code := http.StatusOK
		if rep.Status != StatusReady {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, rep)
	})
}

// Check runs every probe concurrently, each bounded by the timeout, and
// returns the report in the order of checks.
func (h *Health) Check(ctx context.Context, checks ...Check) Report {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	results := make([]Result, len(checks))
	done := make(chan struct{}, len(checks))
	for i, c := range checks {
		go func() {
			defer func() { done <- struct{}{} }()
			results[i] = runProbe(ctx, c, timeout)
		}()
	}
	for range checks {
		<-done
	}
	rep := Report{
		Process: h.Process, Instance: h.Instance, Status: StatusReady, CheckedAt: now().UTC(),
		Checks: results, Summary: make([]string, 0, len(results)),
	}
	for _, r := range results {
		rep.Summary = append(rep.Summary, r.String())
		if r.Required && !usable(r.State) {
			rep.Status = StatusNotReady
		}
	}
	return rep
}

// usable reports whether a required dependency in state s lets the
// process take traffic.
func usable(s State) bool {
	switch s {
	case StateOK, StateDegraded:
		return true
	case StateDown:
		return false
	default:
		return false
	}
}

func runProbe(ctx context.Context, c Check, timeout time.Duration) Result {
	res := Result{Name: c.Name, Required: c.Required}
	if c.Probe == nil {
		res.State, res.Reason = StateDown, "no probe"
		return res
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type answer struct {
		s      State
		reason string
	}
	ch := make(chan answer, 1)
	go func() {
		s, reason := c.Probe(pctx)
		ch <- answer{s, reason}
	}()
	select {
	case a := <-ch:
		res.State, res.Reason = a.s, a.reason
		if a.s != StateOK && a.s != StateDegraded && a.s != StateDown {
			res.State, res.Reason = StateDown, "probe returned the unknown state "+string(a.s)
		}
	case <-pctx.Done():
		res.State, res.Reason = StateDown, "check did not answer within "+timeout.String()
		if ctx.Err() != nil {
			res.Reason = "check cancelled"
		}
	}
	return res
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
