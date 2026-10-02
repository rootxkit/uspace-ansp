package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	cisf "github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/feed"
	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/picture"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/sources"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/timeseries"
)

// Bounds of the process (E-10).
const (
	// maxBodyBytes bounds a request body; the feed's operations take
	// none.
	maxBodyBytes = 16 << 10
	// livePendingMsgs and livePendingBytes bound the live subscription's
	// buffer; past it NATS drops and the drop is counted.
	livePendingMsgs  = 20_000
	livePendingBytes = 64 << 20
	// followRetry is how long a KV watch waits before it tries again.
	followRetry = 5 * time.Second
)

// Counters of the process's own wiring.
const (
	counterSamplesRefused = "feed_samples_refused"
	counterLiveDropped    = "feed_live_dropped"
)

// Readiness check names beside obs's (docs/WORKPACKAGES/WP-6.md).
const (
	depCISProjection = "cis_projection"
	depSourceControl = "source_control"
	depPolicy        = "policy"
	depSessionsLive  = "sessions_live"
	depWriter        = "writer"
)

type wiring struct {
	mux    *http.ServeMux
	checks []obs.Check
	run    []func(ctx context.Context)
	svc    *feed.Service
	pic    *picture.Picture
}

// feedServer is the generated server interface of manned-feed: the two
// manned-traffic operations; every other operation is another
// process's and is not served here (auth.Routes).
type feedServer struct {
	gen.ServerInterface
	svc *feed.Service
}

// GetMannedTrafficSnapshot serves GET /v1/manned-traffic/snapshot.
func (s feedServer) GetMannedTrafficSnapshot(w http.ResponseWriter, r *http.Request, _ gen.GetMannedTrafficSnapshotParams) {
	s.svc.ServeSnapshot(w, r)
}

// StreamMannedTraffic serves GET /v1/manned-traffic/stream.
func (s feedServer) StreamMannedTraffic(w http.ResponseWriter, r *http.Request, _ gen.StreamMannedTrafficParams) {
	s.svc.ServeStream(w, r)
}

// mountFeed registers the operations of manned-feed on mux through the
// generated router, each behind its x-auth (auth.Routes: an operation
// without a rule is not served).
func mountFeed(mux *http.ServeMux, g *auth.Guard, svc *feed.Service, middlewares ...func(http.Handler) http.Handler) (*auth.Routes, error) {
	rt := auth.NewRoutes(mux, process, g, maxBodyBytes, operations(), middlewares...)
	strict := gen.NewStrictHandlerWithOptions(gen.Unimplemented{}, nil, gen.StrictHTTPServerOptions{})
	gen.HandlerWithOptions(feedServer{ServerInterface: strict, svc: svc}, gen.StdHTTPServerOptions{BaseRouter: rt, ErrorHandlerFunc: requestError})
	err := rt.Err()
	return rt, err
}

func operations() []auth.Operation {
	out := make([]auth.Operation, 0, len(gen.Operations))
	for i := range gen.Operations {
		op := &gen.Operations[i]
		out = append(out, auth.Operation{ID: op.ID, Pattern: op.Pattern, Process: op.Process, Auth: op.Auth, WebSocket: op.WebSocket})
	}
	return out
}

// requestError answers a request the generated code could not bind:
// 400 naming the parameter, never echoing the value.
func requestError(w http.ResponseWriter, r *http.Request, err error) {
	var format *gen.InvalidParamFormatError
	field := "request"
	if errors.As(err, &format) {
		field = format.ParamName
	}
	apierr.WriteError(w, r, apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, "the request is not valid",
		apierr.FieldProblem{Field: field, Reason: "is not in the format the operation takes"}))
}

func natsState(b *bus.Bus) func() (string, bool) {
	return func() (string, bool) {
		st, why := b.Status()
		switch {
		case st == obs.StateOK:
			return "connected", true
		case why == "ANSP_NATS_URL is not set":
			return "not_configured", false
		case why == "closed":
			return "closed", false
		}
		return "reconnecting", false
	}
}

// wire builds the feed: the followers, the picture, the service and its
// routes, the recorder, and every readiness check.
func wire(ctx context.Context, cfg config.Config, b *bus.Bus, db *store.Timeseries, reg prometheus.Registerer, logger *slog.Logger) (*wiring, error) {
	pol := policy.NewFollower(nil)
	src := sources.NewFollower(nil)
	cisF := cisf.NewFollower(nil)
	cis := followerCIS{f: cisF}
	pic := picture.New(pol, src, cis, nil, picture.DefaultLimits())
	adapters := feed.NewAdapters()
	own := &core.Counters{}

	g, checker, err := wireGuard(ctx, cfg, b, reg)
	if err != nil {
		return nil, err
	}
	w := &wiring{mux: http.NewServeMux(), pic: pic}

	var recorder *feed.Recorder
	var products *feed.ProductQueue
	if db != nil {
		recorder = &feed.Recorder{Insert: db.Writer(),
			Relevance:     func(t *manned.Track) picture.Relevance { return pic.RelevanceOf(t) },
			PolicyVersion: pol.Version}
		products = feed.NewProductQueue(0, nil)
	}
	deps := feed.Deps{
		Picture: pic, Adapters: adapters, Policy: pol, CIS: cis, NATS: natsState(b),
		SessionSeen: func(jti string) {
			if nc := b.Conn(); nc != nil {
				_ = nc.Publish(bus.SubjectSessionsSeen, []byte(jti))
			}
		},
		Degraded: func() []string {
			if recorder == nil {
				return []string{feed.DegradedWriter}
			}
			return recorder.Degraded()
		},
	}
	if g.Sessions != nil {
		deps.Sessions = g.Sessions
	}
	if products != nil {
		deps.Products = products
	}
	svc := feed.New(feed.Config{}, deps)
	w.svc = svc

	proxies, err := auth.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if _, err := mountFeed(w.mux, g, svc, auth.RealIP(proxies)); err != nil {
		return nil, err
	}

	// Each counter is exported under its own snake_case name (CLAUDE.md
	// rule 10); core's follower counters, which are not prefixed, get one.
	for _, c := range []*core.Counters{svc.Counters(), pic.Counters(), adapters.Counters(), own, src.Counters(), pol.Counters(), cisF.Counters()} {
		if err := obs.Counters(reg, "", c); err != nil {
			return nil, err
		}
	}
	if err := obs.Counters(reg, "source_control_core", src.CoreCounters()); err != nil {
		return nil, err
	}
	if recorder != nil {
		if err := obs.Counters(reg, "", recorder.Counters()); err != nil {
			return nil, err
		}
		if err := obs.Counters(reg, "", products.Counters()); err != nil {
			return nil, err
		}
	}

	w.checks = checks(b, db, pic, src, pol, checker, recorder)
	w.run = append(w.run,
		func(ctx context.Context) { followPolicy(ctx, b, pol, logger) },
		func(ctx context.Context) { followSources(ctx, b, src, logger) },
		func(ctx context.Context) { followCIS(ctx, b, cisF, logger) },
		func(ctx context.Context) { subscribe(ctx, b, svc, adapters, own, logger) },
		svc.Run,
	)
	if checker != nil {
		w.run = append(w.run, func(ctx context.Context) {
			checker.Follow(ctx, func(context.Context) (auth.WatchKV, error) { return b.KeyValue(bus.BucketSessionsLive), nil })
		})
	}
	if recorder != nil {
		w.run = append(w.run, func(ctx context.Context) {
			recorder.RunConsumer(ctx, b.JetStream(), bus.StreamMannedMirror, func(err error) {
				logger.Error("writer", slog.String("error", err.Error()))
			})
		}, func(ctx context.Context) {
			products.Run(ctx, func(ctx context.Context, p feed.Product) error {
				return db.Do(ctx, func(ctx context.Context, q *timeseries.Queries) error {
					return q.InsertFeedProduct(ctx, timeseries.InsertFeedProductParams{ClientID: p.ClientID, TracksSent: p.TracksSent,
						TracksRelevant: p.TracksRelevant, Degraded: p.Degraded, PolicyVersion: p.PolicyVersion})
				})
			})
		})
	}
	return w, nil
}

// wireGuard builds the guard of the feed's routes: machine tokens when
// ANSP_TOKEN_ISSUERS is set, console sessions (the cookie on a
// same-origin upgrade, M22) when ANSP_SESSION_KEY_FILE is set, checked
// against the live-session projection, and the certificate binding of
// ANSP_MTLS_MODE (the subject header believed only from
// ANSP_TRUSTED_PROXIES).
func wireGuard(ctx context.Context, cfg config.Config, b *bus.Bus, reg prometheus.Registerer) (*auth.Guard, *auth.KVSessionChecker, error) {
	proxies, err := auth.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, nil, err
	}
	mtls, err := buildMTLS(cfg, proxies)
	if err != nil {
		return nil, nil, err
	}
	g := &auth.Guard{Origins: cfg.WSAllowedOrigins, MTLS: mtls, UpgradeReLogin: true}
	if err := obs.Counters(reg, "", g.Counters()); err != nil {
		return nil, nil, err
	}
	if err := obs.Counters(reg, "", mtls.Counters()); err != nil {
		return nil, nil, err
	}
	if len(cfg.TokenIssuers) > 0 {
		m, err := auth.NewMachineVerifier(ctx, cfg)
		if err != nil {
			return nil, nil, err
		}
		g.Machine = m
		if err := obs.Counters(reg, "auth_machine", m.Counters()); err != nil {
			return nil, nil, err
		}
	}
	if cfg.SessionKeyFile == "" {
		return g, nil, nil
	}
	if cfg.PublicBaseURL == "" || len(cfg.Audiences) == 0 {
		return nil, nil, core.Fieldf("ANSP_SESSION_KEY_FILE", "needs ANSP_PUBLIC_BASE_URL and ANSP_AUDIENCES to verify console sessions")
	}
	sk, err := auth.LoadKeyFile("ANSP_SESSION_KEY_FILE", cfg.SessionKeyFile)
	if err != nil {
		return nil, nil, err
	}
	ring, err := coreauth.NewKeyRing(sk)
	if err != nil {
		return nil, nil, err
	}
	checker := &auth.KVSessionChecker{Up: func() bool { s, _ := b.Status(); return s == obs.StateOK }}
	sessions, err := auth.NewSessionVerifier(ctx, auth.SessionVerifierConfig{
		Issuer: strings.TrimSuffix(cfg.PublicBaseURL, "/"), Ring: ring, Audiences: cfg.Audiences, Checker: checker,
	})
	if err != nil {
		return nil, nil, err
	}
	g.Sessions = sessions
	for _, pc := range []struct {
		prefix string
		c      *core.Counters
	}{{"", sessions.Counters()}, {"auth_sessions_core", sessions.CoreCounters()}, {"", checker.Counters()}} {
		if err := obs.Counters(reg, pc.prefix, pc.c); err != nil {
			return nil, nil, err
		}
	}
	return g, checker, nil
}

// buildMTLS is api's rule: required needs ANSP_MTLS_BINDINGS_FILE.
func buildMTLS(cfg config.Config, proxies []netip.Prefix) (*auth.MTLS, error) {
	if cfg.MTLSMode != config.MTLSRequired {
		return auth.NewMTLS(cfg.MTLSMode, nil, nil)
	}
	if cfg.MTLSBindingsFile == "" {
		return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE",
			"required when ANSP_MTLS_MODE=required: without bindings no client can pass the mTLS routes (set the file, or ANSP_MTLS_MODE=off outside production)")
	}
	bindings, err := auth.LoadMTLSBindings(cfg.MTLSBindingsFile)
	if err != nil {
		return nil, err
	}
	return auth.NewMTLS(cfg.MTLSMode, bindings, proxies)
}

// checks are the readiness checks, every dependency named (E-02).
func checks(b *bus.Bus, db *store.Timeseries, pic *picture.Picture, src *sources.Follower, pol *policy.Follower,
	sessions *auth.KVSessionChecker, rec *feed.Recorder,
) []obs.Check {
	out := []obs.Check{b.Check()}
	if db != nil {
		out = append(out, db.Check())
	} else {
		out = append(out, obs.Check{Name: obs.DepTimeseries, Probe: func(context.Context) (obs.State, string) {
			return obs.StateDown, "ANSP_TIMESERIES_DSN is not set: samples are not written"
		}})
	}
	out = append(out,
		obs.Check{Name: depCISProjection, Probe: func(context.Context) (obs.State, string) {
			line := pic.RelevanceStatus()
			if line == picture.StatusNoProjection {
				return obs.StateDegraded, line
			}
			return obs.StateOK, line
		}},
		obs.Check{Name: depSourceControl, Probe: func(context.Context) (obs.State, string) {
			_, _, known := src.Version()
			line := src.Status()
			if !known || strings.Contains(line, "unreachable") {
				return obs.StateDegraded, line
			}
			return obs.StateOK, line
		}},
		obs.Check{Name: depPolicy, Probe: func(context.Context) (obs.State, string) {
			if _, fromKV := pol.Current(); !fromKV {
				return obs.StateDegraded, pol.Status()
			}
			return obs.StateOK, pol.Status()
		}},
	)
	if sessions != nil {
		out = append(out, obs.Check{Name: depSessionsLive, Probe: func(context.Context) (obs.State, string) {
			if ok, why := sessions.Healthy(); !ok {
				return obs.StateDegraded, why + ": console sessions are refused (4401)"
			}
			return obs.StateOK, fmt.Sprintf("%d live sessions", sessions.Len())
		}})
	}
	if rec != nil {
		out = append(out, obs.Check{Name: depWriter, Probe: func(context.Context) (obs.State, string) {
			ok, line := rec.Status()
			if !ok {
				return obs.StateDegraded, line
			}
			return obs.StateOK, line
		}})
	}
	return out
}

// followPolicy watches the policy bucket and applies the ctl.policy
// push, retrying while the bucket does not exist.
func followPolicy(ctx context.Context, b *bus.Bus, pol *policy.Follower, logger *slog.Logger) {
	js := b.JetStream()
	if js == nil {
		logger.Error("policy not followed: the bus is not configured; the compiled defaults are served and the status says so")
		return
	}
	if nc := b.Conn(); nc != nil {
		if _, err := nc.Subscribe(bus.SubjectControlPolicy, func(m *nats.Msg) { pol.ApplyJSON(m.Data) }); err != nil {
			logger.Error("ctl.policy: subscribe", slog.String("error", err.Error()))
		}
	}
	logged := false
	for ctx.Err() == nil {
		kv, err := js.KeyValue(ctx, bus.BucketPolicy)
		if err == nil {
			err = pol.Run(ctx, kv)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && !logged {
			logger.Warn("kv: policy not followed yet, retrying", slog.String("error", err.Error()))
			logged = true
		}
		if !sleep(ctx, followRetry) {
			return
		}
	}
}

// followerCIS is picture.CIS on the CIS follower (WP-7): no projection
// while the follower holds no uspace_airspace version.
type followerCIS struct{ f *cisf.Follower }

func (c followerCIS) Projection() (picture.Projection, bool) {
	v := c.f.Version()
	if v == "" {
		return picture.Projection{}, false
	}
	return picture.Projection{Volumes: c.f.USpaceVolumes(), Version: v, FetchedAt: c.f.FetchedAt()}, true
}

// followCIS watches the cis_current bucket api writes and applies the
// cis.v1 push, retrying while the bucket does not exist or the watch
// ends. Until a uspace_airspace version arrives the picture says
// relevance is not evaluated (SC-22).
func followCIS(ctx context.Context, b *bus.Bus, f *cisf.Follower, logger *slog.Logger) {
	if b.JetStream() == nil {
		logger.Error("CIS projection not followed: the bus is not configured; relevance is not evaluated and the status says so")
		return
	}
	if nc := b.Conn(); nc != nil {
		if _, err := nc.Subscribe(bus.SubjectCISPrefix+">", func(m *nats.Msg) { f.ApplyJSON(m.Data) }); err != nil {
			logger.Error("cis.v1: subscribe", slog.String("error", err.Error()))
		}
	}
	kv := b.KeyValue(bus.BucketCISCurrent)
	logged := false
	for ctx.Err() == nil {
		err := f.Run(ctx, kv)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !logged {
			logger.Warn("kv: cis_current not followed yet, retrying; the projection held is served with its age", slog.String("error", err.Error()))
			logged = true
		}
		if !sleep(ctx, followRetry) {
			return
		}
	}
}

// followSources reads the source_control bucket (three attempts at
// start, then every 60 s) and applies the ctl.sources push.
func followSources(ctx context.Context, b *bus.Bus, src *sources.Follower, logger *slog.Logger) {
	if nc := b.Conn(); nc != nil {
		if _, err := nc.Subscribe(bus.SubjectControlSources, func(m *nats.Msg) { src.ApplyJSON(m.Data) }); err != nil {
			logger.Error("ctl.sources: subscribe", slog.String("error", err.Error()))
		}
	}
	kv := b.KeyValue(bus.BucketSourceControl)
	logged := false
	src.Follow(ctx, func(context.Context) (sources.KV, error) { return kv, nil }, sources.FollowOptions{OnError: func(err error) {
		if !logged {
			logger.Warn("source switches: KV not read; every source is enabled and the status says unknown", slog.String("error", err.Error()))
			logged = true
		}
	}})
}

// subscribe takes the live samples (man.v1.>) into the feed and every
// adapter's status (src.v1.manned.>) into the registry, until ctx ends.
// A sample whose subject names another adapter than its body is refused.
func subscribe(ctx context.Context, b *bus.Bus, svc *feed.Service, adapters *feed.Adapters, own *core.Counters, logger *slog.Logger) {
	nc := b.Conn()
	if nc == nil {
		logger.Error("no live samples: the bus is not configured; the picture stays empty and degraded says nats")
		return
	}
	pol := manned.Defaults()
	live, err := nc.Subscribe(bus.SubjectMannedPrefix+">", func(m *nats.Msg) {
		t, err := feed.DecodeTrack(m.Data, &pol)
		if err == nil && feed.SubjectAdapter(m.Subject, bus.SubjectMannedPrefix) != t.SourceInstance {
			err = errors.New("the subject names another adapter")
		}
		if err != nil {
			own.Inc(counterSamplesRefused)
			return
		}
		svc.Ingest(t)
	})
	if err != nil {
		logger.Error("man.v1: subscribe", slog.String("error", err.Error()))
		return
	}
	_ = live.SetPendingLimits(livePendingMsgs, livePendingBytes)
	status, err := nc.Subscribe(bus.SubjectSourceStatusPrefix+">", func(m *nats.Msg) {
		adapters.Observe(feed.SubjectAdapter(m.Subject, bus.SubjectSourceStatusPrefix), m.Data, time.Now())
	})
	if err != nil {
		logger.Error("src.v1.manned: subscribe", slog.String("error", err.Error()))
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var counted int
	for {
		select {
		case <-ctx.Done():
			_ = live.Unsubscribe()
			if status != nil {
				_ = status.Unsubscribe()
			}
			return
		case <-t.C:
			if n, err := live.Dropped(); err == nil && n > counted {
				own.Add(counterLiveDropped, uint64(n-counted))
				logger.Error("man.v1: the live subscription dropped samples (slow consumer); they are still written from MAN_MIRROR",
					slog.Int("dropped", n-counted))
				counted = n
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
