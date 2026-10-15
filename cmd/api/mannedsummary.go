package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/feed"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// Bounds of the picture's count (E-10).
const (
	// mannedSummaryWait bounds api's wait for manned-feed's reply on
	// bus.SubjectMannedSummary; past it the count is 503.
	mannedSummaryWait = 2 * time.Second
	// mannedSummaryRetry is the Retry-After of a count not answered.
	mannedSummaryRetry = 10 * time.Second
)

// Counters of the picture's count.
const (
	// counterMannedSummaryUnanswered: manned-feed did not answer (no
	// bus, no responder, the wait passed); the console's tile says so.
	counterMannedSummaryUnanswered = "api_manned_summary_unanswered"
	// counterMannedSummaryRefused: manned-feed answered something that
	// is not the summary (feed.DecodeSummary); it is never served.
	counterMannedSummaryRefused = "api_manned_summary_refused"
)

// mannedSummaryAPI serves GET /v1/manned-traffic/summary on api: api
// verifies the console session (the route's x-auth, like every other
// overview summary) and asks manned-feed, the picture's owner, on the
// bus. manned-feed verifies no console session itself, so the count no
// longer depends on manned-feed holding the session key, and a 401 on
// this route is api's verdict on the session and nothing else.
type mannedSummaryAPI struct {
	// ask sends the request and returns the reply's body.
	ask      func(ctx context.Context) ([]byte, error)
	counters core.Counters
}

// busAsk asks on subject over b with an empty body.
func busAsk(b *bus.Bus, subject string) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		nc := b.Conn()
		if nc == nil {
			return nil, bus.ErrNoBus
		}
		m, err := nc.RequestWithContext(ctx, subject, nil)
		if err != nil {
			return nil, err
		}
		return m.Data, nil
	}
}

// wireMannedSummary builds the count on b and exports its counters.
func wireMannedSummary(b *bus.Bus, reg prometheus.Registerer) (*mannedSummaryAPI, error) {
	a := &mannedSummaryAPI{ask: busAsk(b, bus.SubjectMannedSummary)}
	if err := obs.Counters(reg, "", &a.counters); err != nil {
		return nil, err
	}
	return a, nil
}

// unansweredDetail says why manned-feed's count is not known, naming the
// dependency (E-02); never the error's text from the bus.
func unansweredDetail(err error) string {
	switch {
	case errors.Is(err, bus.ErrNoBus):
		return "the picture's count needs the bus (ANSP_NATS_URL is not set)"
	case errors.Is(err, nats.ErrNoResponders):
		return "manned-feed is not answering on the bus (no responder for the picture's count)"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return fmt.Sprintf("manned-feed did not answer within %s", mannedSummaryWait)
	}
	return "the bus could not carry the request for the picture's count"
}

func (a *mannedSummaryAPI) serve(w http.ResponseWriter, r *http.Request) {
	if p, ok := auth.PrincipalFrom(r.Context()); !ok || !p.Session || p.Claims.Subject == "" {
		apierr.WriteError(w, r, apierr.Unauthenticated("no console session"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), mannedSummaryWait)
	defer cancel()
	raw, err := a.ask(ctx)
	if err != nil {
		a.counters.Inc(counterMannedSummaryUnanswered)
		apierr.NoteCause(r, err)
		apierr.WriteError(w, r, apierr.Unavailable(mannedSummaryRetry, unansweredDetail(err)))
		return
	}
	s, err := feed.DecodeSummary(raw)
	if err != nil {
		a.counters.Inc(counterMannedSummaryRefused)
		apierr.NoteCause(r, err)
		apierr.WriteError(w, r, apierr.Unavailable(mannedSummaryRetry, "manned-feed's answer is not the picture's count"))
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// GetMannedTrafficSummary serves GET /v1/manned-traffic/summary (WP-11).
func (s apiServer) GetMannedTrafficSummary(w http.ResponseWriter, r *http.Request) {
	if s.ms == nil {
		apierr.WriteError(w, r, apierr.Unavailable(mannedSummaryRetry, "the picture's count is not configured on this instance"))
		return
	}
	s.ms.serve(w, r)
}
