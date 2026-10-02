// Command manned-adapter reads one surveillance feed and publishes
// track/manned/v1 on NATS (docs/PLAN.md section 2; one process per feed,
// B-16): man.v1.<adapter>.<icao24> for every track and
// src.v1.manned.<adapter> (source/status/v1) every status period. The
// kind of feed is ANSP_ADAPTER_KIND (replay, dump1090_sbs,
// dump1090_json; asterix_cat021 refuses to start). It follows the policy
// and its own source switch from NATS KV, serves /healthz, /readyz (nats
// and feed: connected, or reconnecting since T) and /metrics until
// SIGTERM, then drains. It never opens PostgreSQL (CLAUDE.md rule 6) and
// never writes to its feed (rule 1). "manned-adapter migrate ..." is
// refused: it has no database.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // the SBS time columns are in the receiver's zone; the image has no zone database

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/manned/adapter"
	"github.com/rootxkit/uspace-ansp/internal/manned/asterix"
	"github.com/rootxkit/uspace-ansp/internal/manned/dump1090"
	"github.com/rootxkit/uspace-ansp/internal/manned/replay"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// version is set at build time (deploy/Dockerfile, -X main.version).
var version = "dev"

const process = config.ProcessMannedAdapter

// metricsPrefix prefixes the adapter's counters on /metrics.
const metricsPrefix = "manned_adapter"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Environ(), os.Stdout)
	stop()
	os.Exit(code)
}

// run is the process: 0 after a clean drain, 1 on a runtime failure
// (an adapter that fails permanently, a listen failure), 2 on a
// configuration or usage error.
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
	logger = logger.With(slog.String("adapter_id", cfg.AdapterID))
	logger.Info("starting", slog.String("version", version), slog.Any("config", cfg.Redacted()))

	a, err := build(cfg)
	if err != nil {
		logger.Error("adapter refused", slog.String("kind", cfg.AdapterKind), slog.String("error", err.Error()))
		return 2
	}

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

	counters := &core.Counters{}
	follower := policy.NewFollower(counters)
	sw := adapter.NewKVSwitch(cfg.AdapterID, counters)
	runner := &adapter.Runner{
		Adapter: a, Instance: cfg.AdapterID, SourceClass: cfg.AdapterSourceClass,
		Switch: sw, Policy: policySource{follower}, Counters: counters,
		Replay: cfg.AdapterKind == adapter.KindReplay,
	}
	if nc := b.Conn(); nc != nil {
		runner.Publisher = nc
	}
	pol, _ := runner.Policy.Current()
	runner.OnEvent = eventLogger(logger, manned.NewRefusalLimiter(manned.Seconds(pol.RefusalLogEveryS), pol.MaxAircraft))

	reg := obs.Metrics()
	if err := obs.Counters(reg, metricsPrefix, counters); err != nil {
		logger.Error("metrics", slog.String("error", err.Error()))
		return 2
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go follow(ctx, b, follower, sw, logger)
	failed := make(chan error, 1)
	go func() {
		if err := runner.Run(ctx); err != nil {
			failed <- err
			cancel()
		}
	}()

	srv := &obs.Server{Config: cfg, Logger: logger, Registry: reg, Checks: []obs.Check{b.Check(), runner.Check()}}
	if err := srv.Serve(ctx); err != nil {
		logger.Error("serve", slog.String("error", err.Error()))
		return 1
	}
	select {
	case err := <-failed:
		logger.Error("adapter stopped", slog.String("kind", a.Kind()), slog.String("error", err.Error()))
		return 1
	default:
		return 0
	}
}

// build is the adapter of cfg's kind.
func build(cfg config.Config) (adapter.Adapter, error) {
	var reg adapter.Registry
	for kind, f := range map[string]adapter.Factory{
		adapter.KindReplay: func() (adapter.Adapter, error) {
			return replay.New(replay.Config{
				File: cfg.AdapterReplayFile, Allowed: cfg.AdapterReplayAllowed == "true",
				Speed: cfg.AdapterReplaySpeed, Loop: cfg.AdapterReplayLoop == "true",
			})
		},
		adapter.KindDump1090SBS: func() (adapter.Adapter, error) {
			loc, err := time.LoadLocation(cfg.AdapterSBSTimezone)
			if err != nil {
				return nil, err
			}
			return dump1090.NewSBSAdapter(dump1090.SBSConfig{Addr: cfg.AdapterSBSAddr, Location: loc})
		},
		adapter.KindDump1090JSON: func() (adapter.Adapter, error) {
			return dump1090.NewJSONAdapter(dump1090.JSONConfig{URL: cfg.AdapterJSONURL})
		},
		adapter.KindASTERIXCat021: func() (adapter.Adapter, error) { return asterix.Cat021{}, nil },
	} {
		if err := reg.Register(kind, f); err != nil {
			return nil, err
		}
	}
	return reg.Build(cfg.AdapterKind)
}

// policySource is the adapter's policy: the WP-4 defaults with the
// followed ansp_policy row's source_liveness_s and policy_version
// (docs/PLAN.md section 15 gap 25).
type policySource struct{ f *policy.Follower }

func (p policySource) Current() (manned.Policy, uint64) {
	cur, _ := p.f.Current()
	pol := manned.Defaults()
	pol.SourceLivenessS = cur.SourceLivenessS
	if cur.Version < 0 {
		return pol, 0
	}
	return pol, uint64(cur.Version)
}

// followRetry is how long a follower waits before it tries a bucket
// again (the bucket is created by api, which may start later).
const followRetry = 5 * time.Second

// follow keeps the policy and the source switch followed from KV, and
// the switch from its ctl.sources push, until ctx ends; each retries
// until its bucket exists and logs the first failure only.
func follow(ctx context.Context, b *bus.Bus, f *policy.Follower, sw *adapter.KVSwitch, logger *slog.Logger) {
	js := b.JetStream()
	if js == nil {
		logger.Error("source switch and policy not followed: the bus is not configured; status says unknown, policy defaults")
		return
	}
	if nc := b.Conn(); nc != nil {
		if _, err := nc.Subscribe(bus.SubjectControlSources, func(m *nats.Msg) { sw.ApplyJSON(m.Data) }); err != nil {
			logger.Error("ctl.sources: subscribe", slog.String("error", err.Error()))
		}
	}
	go watch(ctx, logger, bus.BucketPolicy, func(ctx context.Context) error {
		kv, err := js.KeyValue(ctx, bus.BucketPolicy)
		if err != nil {
			return err
		}
		return f.Run(ctx, kv)
	})
	watch(ctx, logger, bus.BucketSourceControl, func(ctx context.Context) error {
		kv, err := js.KeyValue(ctx, bus.BucketSourceControl)
		if err != nil {
			return err
		}
		return sw.Watch(ctx, kv)
	})
}

func watch(ctx context.Context, logger *slog.Logger, bucket string, fn func(context.Context) error) {
	logged := false
	for {
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !logged {
			logger.Warn("kv: not followed yet, retrying", slog.String("bucket", bucket), slog.String("error", err.Error()))
			logged = true
		}
		t := time.NewTimer(followRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// eventLogger logs the runner's events; a refusal once per icao24 per
// refusal_log_every_s (never per frame).
func eventLogger(logger *slog.Logger, limiter *manned.RefusalLimiter) func(adapter.Event) {
	return func(e adapter.Event) {
		switch e.Kind {
		case adapter.EventConnected:
			logger.Info("feed connected")
		case adapter.EventLost:
			attrs := []any{}
			if e.Err != nil && !errors.Is(e.Err, context.Canceled) {
				attrs = append(attrs, slog.String("error", e.Err.Error()))
			}
			logger.Error("feed lost; reconnecting", attrs...)
		case adapter.EventRefused:
			if limiter.Allow(e.ICAO24, e.At) {
				logger.Warn("sample refused", slog.String("icao24", e.ICAO24), slog.String("field", e.Field), slog.String("reason", e.Reason))
			}
		case adapter.EventStall:
			logger.Warn("feed stalled", slog.Duration("gap", e.Gap), slog.Int("samples", e.Samples))
		case adapter.EventDisabled:
			logger.Warn("publishing stopped", slog.String("reason", e.Reason))
		case adapter.EventEnabled:
			logger.Info("publishing resumed")
		}
	}
}
