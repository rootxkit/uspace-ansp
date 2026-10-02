// Command manned-adapter reads one surveillance feed and publishes
// track/manned/v1 on NATS (docs/PLAN.md section 2; one process per feed,
// B-16). In WP-0 it is a stub: it loads the configuration, connects the
// bus and serves /healthz, /readyz and /metrics until SIGTERM, then
// drains. It never opens PostgreSQL. WP-4 adds the adapters.
// `manned-adapter migrate ...` is refused: it has no database.
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
)

// version is set at build time (deploy/Dockerfile, -X main.version).
var version = "dev"

const process = config.ProcessMannedAdapter

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

	srv := &obs.Server{Config: cfg, Logger: logger, Registry: obs.Metrics(), Checks: []obs.Check{b.Check()}}
	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", slog.String("error", err.Error()))
		return 1
	}
	return 0
}
