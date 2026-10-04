package obs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
)

// Defaults of Serve.
const (
	// DefaultStatusPeriod is how often the status line is logged.
	DefaultStatusPeriod = 30 * time.Second
	// DefaultDrainTimeout bounds the drain on SIGTERM.
	DefaultDrainTimeout = 10 * time.Second
)

// Server is the HTTP side of a process: /healthz, /readyz and /metrics
// on ANSP_HTTP_ADDR, a status line every StatusPeriod, and a drain when
// the context ends.
type Server struct {
	Config   config.Config
	Logger   *slog.Logger
	Registry *prometheus.Registry
	Checks   []Check
	// Mux, when set, is served too (business handlers, later WPs);
	// /healthz, /readyz and /metrics are registered on it.
	Mux *http.ServeMux

	StatusPeriod time.Duration
	DrainTimeout time.Duration

	// ready, when set, receives the bound address once listening (tests).
	ready func(addr string)

	// errs are ServerErrors' counters, exported on Registry once
	// (errsOnce) however many times Serve runs: the collector is
	// unchecked, so a second Register would succeed and every scrape
	// would then fail on duplicate metrics.
	errs       core.Counters
	errsOnce   sync.Once
	errsRegErr error
}

// Serve listens and serves until ctx ends, then stops accepting, lets
// in-flight requests finish within DrainTimeout and returns. A listen
// failure is returned at once.
func (s *Server) Serve(ctx context.Context) error {
	period, drain := s.StatusPeriod, s.DrainTimeout
	if period <= 0 {
		period = DefaultStatusPeriod
	}
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}
	h := &Health{Process: s.Config.Process, Instance: s.Config.Instance}
	mux := s.Mux
	if mux == nil {
		mux = http.NewServeMux()
	}
	mux.Handle("GET /healthz", h.Liveness())
	mux.Handle("GET /readyz", h.Readiness(s.Checks...))
	mux.Handle("GET /metrics", MetricsHandler(s.Registry))
	// Every route of the process, these three included: no 500 silent.
	s.errsOnce.Do(func() { s.errsRegErr = Counters(s.Registry, "", &s.errs) })
	if s.errsRegErr != nil {
		return fmt.Errorf("register the server error counters: %w", s.errsRegErr)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.Config.HTTPAddr)
	if err != nil {
		return fmt.Errorf("ANSP_HTTP_ADDR: listen: %w", err)
	}
	srv := &http.Server{Handler: ServerErrors(s.Logger, &s.errs)(mux), ReadHeaderTimeout: 5 * time.Second}
	s.Logger.Info("serving", slog.String("addr", ln.Addr().String()))
	if s.ready != nil {
		s.ready(ln.Addr().String())
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	s.status(ctx, h)
	tick := time.NewTicker(period)
	defer tick.Stop()
	for {
		select {
		case err := <-served:
			return fmt.Errorf("http server: %w", err)
		case <-tick.C:
			s.status(ctx, h)
		case <-ctx.Done():
			return s.drain(ctx, srv, served, drain)
		}
	}
}

// drain stops accepting, lets in-flight requests finish within timeout
// and waits for the server to return.
func (s *Server) drain(ctx context.Context, srv *http.Server, served <-chan error, timeout time.Duration) error {
	s.Logger.Info("draining", slog.Duration("timeout", timeout))
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := srv.Shutdown(dctx); err != nil {
		return fmt.Errorf("drain: %w", err)
	}
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	s.Logger.Info("drained")
	return nil
}

// status logs the readiness of every dependency, and ANSP_MTLS_MODE=off
// at error level every period (M25).
func (s *Server) status(ctx context.Context, h *Health) {
	rep := h.Check(ctx, s.Checks...)
	level := slog.LevelInfo
	if rep.Status != StatusReady {
		level = slog.LevelWarn
	}
	s.Logger.Log(ctx, level, "status", slog.String("status", rep.Status), slog.Any("checks", rep.Summary))
	if s.Config.MTLSMode == config.MTLSOff {
		s.Logger.Error("mTLS is off: ANSP_MTLS_MODE=off, client certificates are not required on /v1/manned-traffic/* and /v1/coordination/*")
	}
}
