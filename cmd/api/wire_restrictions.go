package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// TickPeriod is how often the ticker activates scheduled restrictions,
// expires ended ones and republishes what the bus did not take. An
// activation more than two periods after its starts_at is counted late.
const TickPeriod = time.Second

// publishTimeout bounds one restr.v1 publish.
const publishTimeout = 2 * time.Second

// producer is the envelope producer of this process (04 section 2).
const producer = "ansp/api"

// jsPublisher puts restr.v1 on JetStream with the version's dedupe id.
type jsPublisher struct{ b *bus.Bus }

func (p jsPublisher) Publish(ctx context.Context, subject, dedupeID string, data []byte) error {
	js := p.b.JetStream()
	if js == nil {
		return errors.New("no JetStream: ANSP_NATS_URL is not set")
	}
	if s, _ := p.b.Status(); s != obs.StateOK {
		return errors.New("the bus is not connected")
	}
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()
	_, err := js.Publish(ctx, subject, data, jetstream.WithMsgID(dedupeID))
	return err
}

// restrictionWiring is the restriction side of api: the handlers, the
// background work (the ticker, the bus relay) and the readiness checks.
type restrictionWiring struct {
	api *restrictionAPI
	run []func(ctx context.Context)
}

// wireRestrictions builds the restriction service on the relational
// database, the bus, the geoid (ANSP_GEOID_FILE) and the CIS projection
// (none until WP-7: every placement is refused 503 cis_stale, and the
// log and the stream's status say so). Without the database there is
// nothing to serve and the operations answer 503.
func wireRestrictions(cfg config.Config, db *store.Relational, b *bus.Bus, sessions *auth.SessionVerifier, airspaces restriction.Airspaces,
	reg prometheus.Registerer, logger *slog.Logger,
) (*restrictionWiring, error) {
	if db == nil {
		logger.Warn("restrictions are not served: ANSP_RELATIONAL_DSN is not set; the restriction operations answer 503")
		return &restrictionWiring{}, nil
	}
	var g geoid.Undulator
	if cfg.GeoidFile != "" {
		grid, err := geoid.Load(cfg.GeoidFile)
		if err != nil {
			return nil, core.Fieldf("ANSP_GEOID_FILE", "cannot be loaded: %s", err.Error())
		}
		g = grid
	} else {
		logger.Warn("no geoid: ANSP_GEOID_FILE is not set; restrictions with AMSL limits are refused 503 geoid_unavailable")
	}
	if airspaces == nil {
		airspaces = restriction.NoProjection{}
		logger.Error("no CIS projection (WP-7): every restriction is refused 503 cis_stale until the uspace_airspace dataset is projected")
	}
	svc := &restriction.Service{
		Repo: store.RestrictionRepo{DB: db}, Airspaces: airspaces, Geoid: g,
		Feature: restriction.FeatureConfig{
			AuthorityName: cfg.AuthorityName, AuthorityService: cfg.AuthorityService,
			AuthorityEmail: cfg.AuthorityEmail, AuthorityPhone: cfg.AuthorityPhone,
		},
		ClientID: cfg.ClientID, Producer: producer,
	}
	if b != nil && b.JetStream() != nil {
		svc.Bus = jsPublisher{b: b}
	} else {
		logger.Error("restr.v1 is not published: no bus (ANSP_NATS_URL); every version stays unpublished, counted, until one is configured")
	}
	pol := store.PolicyRepo{DB: db}
	st := newRestrictionStream(svc, pol.Latest, sessions, producer)
	svc.Local = func(v restriction.Version, msg []byte) { st.Offer(restriction.DedupeID(v), msg) }
	var unpublished atomic.Int64
	st.degraded = func() []string {
		var out []string
		if b == nil || b.Conn() == nil {
			out = append(out, "bus_not_configured")
		} else if s, _ := b.Status(); s != obs.StateOK {
			out = append(out, "bus_unavailable")
		}
		if unpublished.Load() > 0 {
			out = append(out, "restriction_bus_backlog")
		}
		return out
	}
	st.nats = func() string {
		if b == nil || b.Conn() == nil {
			return "not_configured"
		}
		if s, _ := b.Status(); s == obs.StateOK {
			return "connected"
		}
		return "disconnected"
	}
	for prefix, c := range map[string]*core.Counters{"": svc.Counters(), "api": st.Counters()} {
		if err := obs.Counters(reg, prefix, c); err != nil {
			return nil, err
		}
	}
	w := &restrictionWiring{api: &restrictionAPI{svc: svc, stream: st}}
	w.run = append(w.run, func(ctx context.Context) {
		runTicker(ctx, svc, &unpublished, logger)
	})
	if b != nil && b.Conn() != nil {
		nc := b.Conn()
		w.run = append(w.run, func(ctx context.Context) {
			sub, err := nc.Subscribe(bus.SubjectRestrictionPrefix+">", func(m *nats.Msg) { st.OfferBus(m.Data) })
			if err != nil {
				logger.Error("restr.v1 relay to the console stream not subscribed", slog.String("error", err.Error()))
				return
			}
			<-ctx.Done()
			_ = sub.Unsubscribe()
		})
	}
	return w, nil
}

// runTicker runs svc.Tick every TickPeriod until ctx ends.
func runTicker(ctx context.Context, svc *restriction.Service, unpublished *atomic.Int64, logger *slog.Logger) {
	t := time.NewTicker(TickPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := svc.Tick(ctx, 2*TickPeriod)
		unpublished.Store(int64(rep.Unpublished))
		if rep.Activated > 0 || rep.Expired > 0 || rep.Republished > 0 {
			logger.Info("restriction tick", slog.Int("activated", rep.Activated), slog.Int("expired", rep.Expired),
				slog.Int("republished", rep.Republished), slog.Float64("max_activation_lag_s", rep.MaxActivationLagS))
		}
		if err != nil && ctx.Err() == nil {
			logger.Warn("restriction tick incomplete; it runs again next period", slog.Int("failed", rep.Failed),
				slog.Int("unpublished", rep.Unpublished), slog.String("error", err.Error()))
		}
	}
}
