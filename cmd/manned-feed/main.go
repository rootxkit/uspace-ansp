// Command manned-feed is the F4 manned traffic information service of
// the ANSP (2021/665 ATS.OR.127(a); docs/PLAN.md section 2, D1): it
// takes every adapter's track/manned/v1 from man.v1.> (core), keeps the
// live picture (internal/picture), serves GET /v1/manned-traffic/
// snapshot and the WebSocket GET /v1/manned-traffic/stream to the USSPs,
// the authority and the console (internal/feed), and writes every valid
// sample to manned_tracks from the MAN_MIRROR stream, acknowledging only
// after the commit (B-07). It follows the policy, the source switches
// and the live console sessions from NATS KV and never opens the
// relational database (CLAUDE.md rule 6). /readyz names nats,
// timeseries, cis_projection, source_control, policy, sessions_live and
// the writer, never hiding one (E-02).
// `manned-feed migrate timeseries` migrates the hypertables.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// version is set at build time (deploy/Dockerfile, -X main.version).
var version = "dev"

const process = config.ProcessMannedFeed

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout)
	stop()
	os.Exit(code)
}

// run is the process: 0 after a clean drain, 1 on a runtime failure, 2
// on a configuration or usage error.
func run(ctx context.Context, args, environ []string, stdout io.Writer) int {
	cfg, err := config.LoadFrom(environ, os.ReadFile)
	if err == nil && cfg.Process != process {
		err = errWrongProcess(cfg.Process)
	}
	if err != nil {
		boot := obs.LoggerTo(stdout, config.Config{Process: process, LogLevel: "info"})
		boot.Error("configuration refused", slog.String("error", err.Error()))
		return 2
	}
	logger := obs.LoggerTo(stdout, cfg)
	if len(args) > 0 {
		return subcommand(ctx, logger, cfg, args)
	}
	logger.Info("starting", slog.String("version", version), slog.Any("config", cfg.Redacted()))

	_, shutdownTracer, err := obs.Tracer(ctx, cfg)
	if err != nil {
		logger.Error("tracer", slog.String("error", err.Error()))
		return 2
	}
	defer func() { _ = shutdownTracer(context.WithoutCancel(ctx)) }()

	b, err := bus.Connect(ctx, cfg, logger)
	if err != nil {
		logger.Error("bus", slog.String("error", err.Error()))
		return 2
	}
	defer func() {
		if err := b.Drain(); err != nil {
			logger.Warn("bus drain", slog.String("error", err.Error()))
		}
	}()

	var db *store.Timeseries
	if cfg.TimeseriesDSN != "" {
		db, err = openTimeseries(ctx, cfg)
		if err != nil {
			// M36: never start on a schema older than this build.
			logger.Error("timeseries database refused", slog.String("error", err.Error()))
			return 1
		}
		defer db.Close()
	} else {
		logger.Error("no timeseries database: ANSP_TIMESERIES_DSN is not set; samples are served but not written")
	}

	reg := obs.Metrics()
	w, err := wire(ctx, cfg, b, db, reg, logger)
	if err != nil {
		logger.Error("feed refused", slog.String("error", err.Error()))
		return 2
	}
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	for _, fn := range w.run {
		go fn(runCtx)
	}

	srv := &obs.Server{Config: cfg, Logger: logger, Registry: reg, Checks: w.checks, Mux: w.mux}
	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", slog.String("error", err.Error()))
		return 1
	}
	return 0
}

// openTimeseries opens the timeseries database as {store.RoleTimeseries} and
// refuses a schema below the newest migration this build embeds (M36).
func openTimeseries(ctx context.Context, cfg config.Config) (*store.Timeseries, error) {
	need, err := store.Latest(store.TreeTimeseries)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenTimeseries(ctx, cfg.TimeseriesDSN, store.FromConfig(cfg, store.RoleTimeseries), nil)
	if err != nil {
		return nil, err
	}
	if err := db.RequireVersion(ctx, need); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
