// Command manned-feed serves the live manned picture (F4 stream and
// snapshot) and writes TimescaleDB (docs/PLAN.md section 2). In WP-0 it
// is a stub: it loads the configuration, connects the bus and serves
// /healthz, /readyz and /metrics until SIGTERM, then drains. It never
// opens the relational database: with ANSP_TIMESERIES_DSN set it opens
// the timeseries database as ansp_ts_app and refuses to start on a
// schema older than this build (M36). WP-6 fills it.
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

	checks := []obs.Check{b.Check()}
	if cfg.TimeseriesDSN != "" {
		db, err := openTimeseries(ctx, cfg)
		if err != nil {
			// M36: never start on a schema older than this build.
			logger.Error("timeseries database refused", slog.String("error", err.Error()))
			return 1
		}
		defer db.Close()
		checks = append(checks, db.Check())
	}

	srv := &obs.Server{Config: cfg, Logger: logger, Registry: obs.Metrics(), Checks: checks}
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
