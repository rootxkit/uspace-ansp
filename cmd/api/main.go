// Command api is the control plane of uspace-ansp (docs/PLAN.md
// section 2): restrictions, coordination, the outbox, the DSS and CIS
// clients, accounts and audit. In WP-0 it is a stub: it loads the
// configuration, connects the bus, declares the streams and buckets
// once connected, and serves /healthz, /readyz and /metrics until
// SIGTERM, then drains. `api migrate <relational|timeseries>...` is the
// one-shot migration subcommand. With ANSP_RELATIONAL_DSN set it opens
// the relational database as ansp_app and refuses to start on a schema
// older than this build (M36). Every operation of api/openapi.yaml is
// mounted through the generated router behind its x-auth (WP-3,
// cmd/api/server.go); those no work package serves yet answer 501. With
// ANSP_SESSION_KEY_FILE set it serves console sign-in, the user
// operations and the JWKS (WP-2, cmd/api/auth.go); without it they
// answer 503. With the relational database it serves the restrictions,
// the restriction requests and their console stream, and runs the
// ticker that activates scheduled restrictions, expires ended ones and
// republishes restr.v1 (WP-5, cmd/api/wire_restrictions.go); without it
// they answer 503. It runs the CIS projection (WP-7,
// cmd/api/wire_cis.go): the pulls of the CISP's datasets with their
// reconciliation, the subscription, cis_cache, KV cis_current, the
// receiver of POST /v1/cis/notifications, and the readiness line cisp.
// It runs the outbox (WP-8, cmd/api/wire_deliver.go): every restriction
// version queues its CISP publication in its own transaction; the worker
// signs and sends it, the monitor raises cisp_not_published and the
// degraded direct delivery, the heartbeat and the reconciliation keep
// the CISP in step, and the delivery-signing key is in the JWKS. It
// serves the Annex V inbox (WP-10, cmd/api/wire_coord.go): notices with
// their receipts, the person's acknowledgement, the escalation of the
// silent ones, the console stream, and occurrence reports queued to the
// authority through the outbox.
package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
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
	var db *store.Relational
	if cfg.RelationalDSN != "" {
		db, err = openRelational(ctx, cfg)
		if err != nil {
			// M36: never start on a schema older than this build.
			logger.Error("relational database refused", slog.String("error", err.Error()))
			return 1
		}
		defer db.Close()
		checks = append(checks, db.Check())
	}

	reg := obs.Metrics()
	mux := http.NewServeMux()
	aw, err := wireAuth(ctx, cfg, db, reg, logger)
	if err != nil {
		logger.Error("auth refused", slog.String("error", err.Error()))
		return 2
	}
	cw, err := wireCIS(cfg, db, b, reg, logger)
	if err != nil {
		logger.Error("CIS projection refused", slog.String("error", err.Error()))
		return 2
	}
	rw, err := wireRestrictions(cfg, db, b, aw.guard.Sessions, cw.airspaces, reg, logger)
	if err != nil {
		logger.Error("restrictions refused", slog.String("error", err.Error()))
		return 2
	}
	dw, err := wireDeliver(cfg, db, b, aw.keys, deliverOptions{targets: directTargets(cw.proj, cfg.AuthorityURL)}, reg, logger)
	if err != nil {
		logger.Error("outbox refused", slog.String("error", err.Error()))
		return 2
	}
	attachDeliver(rw, dw)
	co, err := wireCoord(cfg, db, b, aw.guard.Sessions, ussps(cw.proj), dw, coordOptions{}, reg, logger)
	if err != nil {
		logger.Error("coordination inbox refused", slog.String("error", err.Error()))
		return 2
	}
	// Every operation of api/openapi.yaml, behind its x-auth (WP-3).
	sw, err := wireSources(db, b, reg, logger)
	if err != nil {
		logger.Error("source switches refused", slog.String("error", err.Error()))
		return 2
	}
	if err := wireLiveSessions(db, b, aw, reg, logger); err != nil {
		logger.Error("live sessions refused", slog.String("error", err.Error()))
		return 2
	}
	if _, err := mountParts(mux, aw.guard, apiParts{auth: aw.handlers, rs: rw.api, src: sw.api, cis: cw.receiver, co: co.api}, aw.realIP); err != nil {
		logger.Error("routes refused", slog.String("error", err.Error()))
		return 2
	}
	checks = append(append(append(append(checks, aw.checks...), cw.checks...), rw.checks...), dw.checks...)
	for _, fn := range append(append(append(append(append(aw.run, rw.run...), sw.run...), cw.run...), dw.run...), co.run...) {
		go fn(ctx)
	}

	srv := &obs.Server{Config: cfg, Logger: logger, Registry: reg, Checks: checks, Mux: mux}
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
