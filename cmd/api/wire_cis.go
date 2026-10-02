package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// Readiness dependencies of the CIS projection besides obs.DepCISP.
const (
	depCISNotifyKeys    = "cis_notify_keys"
	depCISPublisherKeys = "cis_publisher_keys"
)

// policyCacheFor is how long the projection reuses the policy row it
// read: the readiness probe asks for cis_stale_bound_s on every call and
// must not wait on the database each time.
const policyCacheFor = 10 * time.Second

// cisWiring is the CIS side of api: the projection the restriction
// service places restrictions in, the notification receiver, the
// background work and the readiness checks.
type cisWiring struct {
	proj      *cis.Projection
	airspaces restriction.Airspaces
	checks    []obs.Check
	run       []func(ctx context.Context)
}

// cachedPolicy reads the newest ansp_policy row at most every
// policyCacheFor and serves the last one read (or the compiled
// defaults before any) while the database cannot answer.
type cachedPolicy struct {
	latest func(ctx context.Context) (policy.Policy, error)

	mu   sync.Mutex
	at   time.Time
	have policy.Thresholds
	ok   bool
}

func (c *cachedPolicy) get(ctx context.Context) policy.Thresholds {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok && time.Since(c.at) < policyCacheFor {
		return c.have
	}
	if c.latest != nil {
		qctx, cancel := context.WithTimeout(ctx, time.Second)
		p, err := c.latest(qctx)
		cancel()
		if err == nil {
			c.have, c.ok, c.at = p.Thresholds, true, time.Now()
			return c.have
		}
	}
	if c.ok {
		return c.have
	}
	return policy.Defaults()
}

// projectionAirspaces is restriction.Airspaces on the projection.
type projectionAirspaces struct{ p *cis.Projection }

func (a projectionAirspaces) Current(context.Context) (restriction.Snapshot, error) {
	v, at, fs, err := a.p.USpaceAirspace()
	if errors.Is(err, cis.ErrNoProjection) {
		return restriction.Snapshot{}, restriction.ErrNoProjection
	}
	if err != nil {
		return restriction.Snapshot{}, err
	}
	return restriction.Snapshot{Version: v, FetchedAt: at, Airspaces: fs}, nil
}

// wireCIS builds the CIS projection (WP-7) from the configuration. A
// dependency that is down never refuses the start: the projection warms
// from cis_cache, serves it with its age, and the readiness line says
// what is missing. A configuration that cannot be right (the callback
// host not among the audiences, an unknown publisher) does.
func wireCIS(cfg config.Config, db *store.Relational, b *bus.Bus, reg prometheus.Registerer, logger *slog.Logger) (*cisWiring, error) {
	logger = logger.With(slog.String("component", "cis"))
	counters := &core.Counters{}
	if err := obs.Counters(reg, "", counters); err != nil {
		return nil, err
	}
	w := &cisWiring{}
	var client *cis.Client
	if cfg.CISPURL != "" {
		cc := cis.ClientConfig{BaseURL: cfg.CISPURL}
		if cfg.TokenURL != "" && cfg.ClientSecret != "" {
			ts, err := auth.NewTokenSource(auth.TokenSourceFromConfig(cfg))
			if err != nil {
				return nil, err
			}
			cc.Tokens = ts
			if err := obs.Counters(reg, "cis", ts.Counters()); err != nil {
				return nil, err
			}
		} else {
			logger.Error("no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE): every CISP read is refused and the readiness line says so")
		}
		var err error
		if client, err = cis.NewClient(cc); err != nil {
			return nil, err
		}
	} else {
		logger.Error("no CISP configured (ANSP_CISP_URL): the projection is not refreshed; once it is older than cis_stale_bound_s every restriction is refused 503 cis_stale")
	}
	var publishers cis.PublisherVerifier
	if len(cfg.CISPublisherKeys) > 0 {
		pc, err := cfg.PublisherConfig()
		if err != nil {
			return nil, err
		}
		keys := cis.NewLazyPublisherVerifier(pc, 0)
		publishers = keys
		w.checks = append(w.checks, keysCheck(depCISPublisherKeys, keys.Ready))
		w.run = append(w.run, func(ctx context.Context) {
			keys.Run(ctx)
			if c := keys.Counters(); c != nil {
				_ = obs.Counters(reg, "cis_publisher_jws", c)
			}
		})
	} else {
		logger.Error("no publisher keys (ANSP_CIS_PUBLISHER_KEYS): every new CIS version is held untrusted and never used")
	}
	pol := &cachedPolicy{}
	pcfg := cis.Config{Client: client, Publishers: publishers, Counters: counters, Logger: logger, Policy: pol.get}
	if db != nil {
		repo := store.CISRepo{DB: db}
		pcfg.Store = repo
		pol.latest = store.PolicyRepo{DB: db}.Latest
	}
	if b != nil && b.JetStream() != nil {
		pcfg.KV = b.KeyValue(bus.BucketCISCurrent)
		pcfg.Push = natsPush{b: b}
	} else {
		logger.Error("no bus (ANSP_NATS_URL): the CIS projection is not written to KV cis_current; manned-feed judges no relevance")
	}
	notify := len(cfg.CISNotifyIssuers) > 0
	if notify && cfg.PublicBaseURL != "" && client != nil {
		pcfg.CallbackURL = strings.TrimRight(cfg.PublicBaseURL, "/") + cis.NotificationsPath
	}
	w.proj = cis.New(pcfg)
	w.airspaces = projectionAirspaces{p: w.proj}
	w.checks = append(w.checks, obs.Check{Name: obs.DepCISP, Probe: func(ctx context.Context) (obs.State, string) {
		r := w.proj.Status(ctx, time.Now())
		switch r.State {
		case cis.StateOK:
			return obs.StateOK, r.Line()
		case cis.StateDown:
			return obs.StateDown, r.Line()
		}
		return obs.StateDegraded, r.Line()
	}})
	w.run = append(w.run, w.proj.Run)
	if notify {
		logger.Warn("CIS change notifications are not received on this build: the route answers 503 and the reconciliation alone keeps the projection")
	}
	return w, nil
}

// keysCheck is the readiness of a lazily fetched JWKS.
func keysCheck(name string, ready func() (bool, string)) obs.Check {
	return obs.Check{Name: name, Probe: func(context.Context) (obs.State, string) {
		if ok, why := ready(); !ok {
			return obs.StateDegraded, why
		}
		return obs.StateOK, ""
	}}
}
