package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// coordWiring is the coordination side of api (WP-10): the inbox, its
// console stream, the escalation ticker, the occurrence outbox and its
// alarm monitor.
type coordWiring struct {
	api *coordAPI
	run []func(ctx context.Context)
	// relay is the coord.v1 subscription that feeds the console stream
	// (one of run; nil without a bus).
	relay func(ctx context.Context)
}

// coordOptions are what wireCoord takes besides the configuration.
type coordOptions struct {
	// clock replaces the database clock of the escalation and the
	// occurrence alarm (tests).
	clock coord.Clock
	// policy replaces coord.DefaultPolicy (tests).
	policy *coord.Policy
}

// ussps is the USSP list as the inbox judges senders by: the ussp_ids
// of the projected list, and whether a list is projected at all.
func ussps(proj *cis.Projection) func() ([]string, bool) {
	if proj == nil {
		return nil
	}
	return func() ([]string, bool) {
		if proj.Version(cis.USSPList) == 0 {
			return nil, false
		}
		list := proj.USSPs()
		ids := make([]string, 0, len(list))
		for i := range list {
			ids = append(ids, list[i].UsspId)
		}
		return ids, true
	}
}

// wireCoord builds the inbox on the relational database, the bus, the
// CIS USSP list (list, ussps of the projection; while it projects none
// every sender is accepted as sender_unverified, counted) and the outbox
// (dw; without it occurrence reports answer 503). Without the database
// its operations answer 503.
func wireCoord(cfg config.Config, db *store.Relational, b *bus.Bus, sessions *auth.SessionVerifier, list func() ([]string, bool), dw *deliverWiring,
	opt coordOptions, reg prometheus.Registerer, logger *slog.Logger,
) (*coordWiring, error) {
	if db == nil {
		logger.Warn("the coordination inbox is not served: ANSP_RELATIONAL_DSN is not set; its operations answer 503")
		return &coordWiring{}, nil
	}
	logger = logger.With(slog.String("component", "coord"))
	pol := coord.DefaultPolicy()
	if opt.policy != nil {
		pol = *opt.policy
	}
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	repo := store.CoordRepo{DB: db}
	cached := &cachedPolicy{latest: store.PolicyRepo{DB: db}.Latest}
	svc := &coord.Service{
		Repo: repo, USSPs: list, Producer: producer, Policy: pol, Clock: opt.clock,
		Escalation: func(ctx context.Context) (time.Duration, int64) {
			return seconds(cached.get(ctx).NoticeEscalationS), 0
		},
	}
	if list == nil {
		logger.Error("no CIS projection: every Annex V sender is accepted as sender_unverified until the ussp_list dataset is projected")
	}
	if b != nil && b.JetStream() != nil {
		svc.Bus = jsPublisher{b: b}
	} else {
		logger.Error("coord.v1 is not published: no bus (ANSP_NATS_URL); every notice is stored and shown on this replica's stream, and put on the bus once one is configured")
	}
	st := newCoordStream(svc, cached.policy, sessions, producer)
	svc.Local = st.Offer
	st.degraded = func() []string {
		var out []string
		if b == nil || b.Conn() == nil {
			out = append(out, "bus_not_configured")
		} else if s, _ := b.Status(); s != obs.StateOK {
			out = append(out, "bus_unavailable")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if n, err := repo.CountBehindBus(ctx); err != nil {
			out = append(out, "coordination_store_unavailable")
		} else if n > 0 {
			out = append(out, "coordination_bus_backlog")
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
	w := &coordWiring{api: &coordAPI{svc: svc, stream: st}}
	for _, c := range []*core.Counters{svc.Counters(), st.Counters()} {
		if err := obs.Counters(reg, "", c); err != nil {
			return nil, err
		}
	}
	w.run = append(w.run, func(ctx context.Context) {
		svc.Run(ctx, func(rep coord.TickReport, err error) { logTick(logger, rep, err) })
	})
	if b != nil && b.Conn() != nil {
		nc := b.Conn()
		w.relay = func(ctx context.Context) {
			sub, err := nc.Subscribe(bus.SubjectCoordPrefix+">", func(m *nats.Msg) { st.OfferBus(m.Header.Get(nats.MsgIdHdr), m.Data) })
			if err != nil {
				logger.Error("coord.v1 relay to the console stream not subscribed", slog.String("error", err.Error()))
				return
			}
			<-ctx.Done()
			_ = sub.Unsubscribe()
		}
		w.run = append(w.run, w.relay)
	}
	if err := wireOccurrences(cfg, repo, dw, pol, opt, w, reg, logger); err != nil {
		return nil, err
	}
	return w, nil
}

// wireOccurrences gives the outbox its occurrence sender and the API the
// occurrence operation: the reporter reference is sealed under
// ANSP_SECRETS_KEY_FILE (without it a report with a reference answers
// 503; one without is queued), posted to ANSP_AUTHORITY_URL with a token
// of scope occurrences.write, and alarmed 60 h after became_aware_at.
func wireOccurrences(cfg config.Config, repo store.CoordRepo, dw *deliverWiring, pol coord.Policy, opt coordOptions, w *coordWiring,
	reg prometheus.Registerer, logger *slog.Logger,
) error {
	if dw == nil || dw.outbox == nil || dw.worker == nil {
		logger.Error("no outbox: occurrence reports answer 503")
		return nil
	}
	occ := &coord.Occurrences{Repo: repo, Outbox: dw.outbox, Org: cfg.ClientID, Policy: pol, Clock: opt.clock}
	if cfg.SecretsKeyFile != "" {
		sealer, err := auth.LoadSealer(cfg.SecretsKeyFile)
		if err != nil {
			return err
		}
		occ.Sealer = sealer
	} else {
		logger.Error("no secrets key (ANSP_SECRETS_KEY_FILE): an occurrence report with a reporter reference is refused 503; it is never stored in clear")
	}
	if cfg.AuthorityURL != "" {
		occ.Authority = &deliver.Authority{BaseURL: cfg.AuthorityURL, Client: deliver.NewHTTPClient(dw.policy.HTTPTimeout, nil, dw.roots),
			Tokens: dw.tokens, Policy: dw.policy}
	} else {
		logger.Error("no authority (ANSP_AUTHORITY_URL): occurrence reports are queued, retried and alarmed, never sent")
	}
	dw.worker.Occurrences = occ
	w.api.occ = occ
	if err := obs.Counters(reg, "", occ.Counters()); err != nil {
		return err
	}
	w.run = append(w.run, func(ctx context.Context) {
		occ.RunMonitor(ctx, func(rep coord.MonitorReport, err error) { logMonitor(logger, rep, err) })
	})
	return nil
}

// logTick says what the escalation tick did: every escalation at error
// level (a notice that needs a person and has none, Art. 13(2)).
func logTick(logger *slog.Logger, rep coord.TickReport, err error) {
	for i := range rep.Escalated {
		n := &rep.Escalated[i]
		logger.Error("coord: a notice is not acknowledged; escalated until a person acknowledges it",
			slog.String("ack_id", n.AckID), slog.String("kind", string(n.Kind)), slog.String("ussp_id", n.USSPID),
			slog.Int("escalations", n.Escalations), slog.String("received_at", n.ReceivedAt.UTC().Format(time.RFC3339Nano)))
	}
	if rep.Republished > 0 {
		logger.Warn("coord: notice changes that were not on coord.v1 are published", slog.Int("republished", rep.Republished))
	}
	if err != nil {
		logger.Warn("coord: the escalation tick did not complete; it runs again next period", slog.String("error", err.Error()))
	}
}

// logMonitor says what the occurrence monitor did (never the reporter
// reference: it is not in the report it reads).
func logMonitor(logger *slog.Logger, rep coord.MonitorReport, err error) {
	for i := range rep.Raised {
		a := &rep.Raised[i]
		logger.Error("coord: occurrence_undelivered: "+a.Detail, slog.String("alarm_id", a.ID), slog.String("delivery_id", a.DeliveryID))
	}
	for i := range rep.Cleared {
		a := &rep.Cleared[i]
		logger.Info("coord: occurrence_undelivered cleared: the report is delivered", slog.String("alarm_id", a.ID), slog.String("delivery_id", a.DeliveryID))
	}
	if err != nil {
		logger.Warn("coord: the occurrence monitor did not complete; it runs again next period", slog.String("error", err.Error()))
	}
}
