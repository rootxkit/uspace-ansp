// Command api is the control plane of uspace-ansp (docs/PLAN.md
// section 2): restrictions, coordination, the outbox, the DSS and CIS
// clients, accounts and audit. In WP-0 it is a stub: it loads the
// configuration, connects the bus, declares the streams and buckets
// once connected, and serves /healthz, /readyz and /metrics until
// SIGTERM, then drains. `api migrate <relational|timeseries>...` is the
// one-shot migration subcommand. With ANSP_RELATIONAL_DSN set it opens
// the relational database as ansp_app and refuses to start on a schema
// older than this build (M36).
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// version is set at build time (deploy/Dockerfile, -X main.version).
var version = "dev"

const process = config.ProcessAPI

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
	go ensureStreams(ctx, b, logger)

	checks := []obs.Check{b.Check()}
	if cfg.RelationalDSN != "" {
		db, err := openRelational(ctx, cfg)
		if err != nil {
			// M36: never start on a schema older than this build.
			logger.Error("relational database refused", slog.String("error", err.Error()))
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

// ensureStreams declares the streams and buckets as soon as the bus is
// connected, retrying every few seconds while it is not (the api is the
// one process that owns them, docs/PLAN.md section 7).
func ensureStreams(ctx context.Context, b *bus.Bus, logger *slog.Logger) {
	for {
		if s, _ := b.Status(); s == obs.StateOK {
			ectx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := b.EnsureStreams(ectx)
			cancel()
			if err == nil {
				logger.Info("nats: streams and buckets declared")
				return
			}
			logger.Warn("nats: declaring streams and buckets", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// openRelational opens the relational database as {store.RoleRelational} and
// refuses a schema below the newest migration this build embeds (M36).
func openRelational(ctx context.Context, cfg config.Config) (*store.Relational, error) {
	need, err := store.Latest(store.TreeRelational)
	if err != nil {
		return nil, err
	}
	db, err := store.OpenRelational(ctx, cfg.RelationalDSN, store.FromConfig(cfg, store.RoleRelational), nil)
	if err != nil {
		return nil, err
	}
	if err := db.RequireVersion(ctx, need); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
