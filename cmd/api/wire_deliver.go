package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// Readiness dependencies of the outbox.
const (
	depCISPPublisher = "cisp_publisher"
	depDeliveryKey   = "delivery_key"
)

// workerConsumer is the durable pull consumer every api replica shares
// on the DELIVER work queue.
const workerConsumer = "deliver-worker"

// deliveryAPI is the outbox as the API sees it: the deliveries summary
// of a restriction and the delivery alarms.
type deliveryAPI struct {
	repo   deliver.Repo
	alarms *deliver.Alarms
	keys   *auth.PublicKeys
}

// deliverWiring is the outbox side of api (WP-8).
type deliverWiring struct {
	hook   restriction.VersionHook
	api    *deliveryAPI
	checks []obs.Check
	run    []func(ctx context.Context)
}

// wireDeliver builds the outbox on the relational database and the bus:
// the delivery key (ANSP_DELIVERY_KEY_FILE, added to keys so the CISP and
// the receivers verify with this system's JWKS), the CISP client with its
// client certificate (ANSP_CISP_CLIENT_CERT_FILE) and token, the
// degraded direct path to the CIS USSP list (proj) and the authority,
// the worker, the alarm monitor, the outbox scan, the heartbeat and the
// reconciliation. A missing dependency never refuses the start: the jobs
// are still written with their versions, the alarm still fires, and the
// log and readiness say what is missing. A certificate or key that
// cannot be read does.
// deliverOptions are what wireDeliver takes besides the configuration.
type deliverOptions struct {
	// targets is the degraded direct path's receivers (directTargets).
	targets func(ctx context.Context) []deliver.Target
	// roots, when set, are the CAs the peers' certificates are checked
	// against instead of the system's (the in-test CISP).
	roots *x509.CertPool
}

func wireDeliver(cfg config.Config, db *store.Relational, b *bus.Bus, keys *auth.PublicKeys, opt deliverOptions,
	reg prometheus.Registerer, logger *slog.Logger,
) (*deliverWiring, error) {
	roots := opt.roots
	if db == nil {
		logger.Warn("the outbox is not run: ANSP_RELATIONAL_DSN is not set")
		return &deliverWiring{}, nil
	}
	logger = logger.With(slog.String("component", "deliver"))
	pol := deliver.DefaultPolicy()
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	if err := obs.Counters(reg, "", counters); err != nil {
		return nil, err
	}
	repo := store.DeliverRepo{DB: db}
	w := &deliverWiring{api: &deliveryAPI{repo: repo, keys: keys}}

	var signer deliver.Signer
	if cfg.DeliveryKeyFile == "" {
		logger.Error("no delivery key (ANSP_DELIVERY_KEY_FILE): nothing is sent to the CISP or the receivers; every job waits, retried and alarmed")
		w.checks = append(w.checks, obs.Check{Name: depDeliveryKey, Probe: func(context.Context) (obs.State, string) {
			return obs.StateDown, "ANSP_DELIVERY_KEY_FILE is not set: publications are not signed and not sent"
		}})
	} else {
		sk, err := auth.LoadKeyFile("ANSP_DELIVERY_KEY_FILE", cfg.DeliveryKeyFile)
		if err != nil {
			return nil, err
		}
		ring, err := coreauth.NewKeyRing(sk)
		if err != nil {
			return nil, err
		}
		if err := keys.Add("delivery", ring); err != nil {
			return nil, err
		}
		signer = ring
		logger.Info("delivery key loaded; its public part is in /.well-known/jwks.json", slog.String("kid", ring.ActiveKID()))
	}

	var cert *deliver.ClientCert
	if cfg.CISPClientCertFile != "" {
		c, err := deliver.LoadClientCert(cfg.CISPClientCertFile, cfg.CISPClientKeyFile, time.Now())
		if err != nil {
			return nil, err
		}
		cert = c
		// The subject the CISP's proxy forwards and the CISP binds to
		// this system's client id (CISP_ANSP_MTLS_SUBJECT, M24).
		logger.Info("CISP client certificate loaded", slog.String("subject", c.Subject), slog.String("not_after", restriction.Stamp(c.NotAfter)))
	} else {
		logger.Warn("no CISP client certificate (ANSP_CISP_CLIENT_CERT_FILE): a CISP with CISP_MTLS_MODE=required refuses every publication and heartbeat")
	}

	var tokens deliver.Tokens
	if cfg.TokenURL != "" && cfg.ClientSecret != "" {
		ts, err := auth.NewTokenSource(auth.TokenSourceFromConfig(cfg))
		if err != nil {
			return nil, err
		}
		if err := obs.Counters(reg, "deliver_tokens", ts.Counters()); err != nil {
			return nil, err
		}
		tokens = ts
	} else {
		logger.Error("no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE): every CISP publication is retried and alarmed")
	}

	var cisp *deliver.CISP
	if cfg.CISPURL != "" {
		var c *http.Client
		if cert != nil {
			c = deliver.NewHTTPClient(pol.HTTPTimeout, &cert.Cert, roots)
		} else {
			c = deliver.NewHTTPClient(pol.HTTPTimeout, nil, roots)
		}
		cisp = &deliver.CISP{BaseURL: cfg.CISPURL, Client: c, Tokens: tokens, Signer: signer, Policy: pol}
	} else {
		logger.Error("no CISP (ANSP_CISP_URL): publications are queued and alarmed, never sent")
	}
	issuer := strings.TrimSuffix(cfg.PublicBaseURL, "/")
	if issuer == "" {
		logger.Error("no ANSP_PUBLIC_BASE_URL: the degraded direct delivery has no issuer and no pull_url; it is not queued")
	}
	direct := &deliver.Direct{Issuer: issuer, Client: deliver.NewHTTPClient(pol.HTTPTimeout, nil, roots), Signer: signer, Policy: pol}

	var pub deliver.BusPublisher
	if b != nil && b.JetStream() != nil {
		pub = jsPublisher{b: b}
	} else {
		logger.Error("no bus (ANSP_NATS_URL): the jobs are written and wait; nothing is delivered until a bus is configured")
	}
	outbox := &deliver.Outbox{Repo: repo, Bus: pub, Policy: pol, Logger: logger, Counters: counters}
	events := &deliver.Events{Repo: repo, Bus: pub, Producer: producer, Logger: logger, Counters: counters}
	w.hook = deliver.RestrictionHook{Outbox: outbox, TxOf: store.DeliverTxOf}
	w.api.alarms = &deliver.Alarms{Repo: repo, Events: events, Logger: logger, Counters: counters}
	worker := &deliver.Worker{Repo: repo, CISP: cisp, Direct: direct, Events: events, Policy: pol, Logger: logger, Counters: counters}

	cached := &cachedPolicy{latest: store.PolicyRepo{DB: db}.Latest}
	monitor := &deliver.Monitor{Repo: repo, Outbox: outbox, Events: events, Policy: pol, PublicBase: issuer, Logger: logger, Counters: counters,
		AlarmAfter: func(ctx context.Context) time.Duration { return seconds(cached.get(ctx).CISPAlarmAfterS) },
		Targets:    opt.targets}
	if issuer == "" {
		monitor.Targets = nil
	}
	w.run = append(w.run, outbox.RunScan, monitor.Run)
	if pub != nil {
		w.run = append(w.run, func(ctx context.Context) { worker.Run(ctx, consumerNext(b, pol, logger)) })
	}
	if cisp != nil {
		rec := &deliver.Reconciler{Repo: repo, Outbox: outbox, Policy: pol, Logger: logger, Counters: counters}
		hb := &deliver.Heartbeat{CISP: cisp, Repo: repo, Policy: pol, Logger: logger, Counters: counters,
			Period: func(ctx context.Context) time.Duration { return seconds(cached.get(ctx).CISPHeartbeatS) },
			OnRecover: func(ctx context.Context) {
				if _, err := rec.Reconcile(ctx); err != nil {
					logger.Warn("deliver: reconciliation incomplete; the next recovery or the outbox scan repeats it", slog.String("error", err.Error()))
				}
			}}
		w.run = append(w.run, hb.Run)
		w.checks = append(w.checks, obs.Check{Name: depCISPPublisher, Probe: func(context.Context) (obs.State, string) { return hb.Status() }})
	} else {
		w.checks = append(w.checks, obs.Check{Name: depCISPPublisher, Probe: func(context.Context) (obs.State, string) {
			return obs.StateDown, "ANSP_CISP_URL is not set: publications are queued and alarmed, never sent"
		}})
	}
	return w, nil
}

// attachDeliver gives the restriction service its outbox and the API
// the outbox's view.
func attachDeliver(rw *restrictionWiring, dw *deliverWiring) {
	if rw == nil || rw.api == nil || dw == nil || dw.hook == nil {
		return
	}
	rw.api.svc.Outbox = dw.hook
	rw.api.dl = dw.api
}

func seconds(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// directTargets is the degraded direct path's receivers: every USSP of
// the CIS USSP list (whatever its status: a suspended USSP may still
// have aircraft in the air) and the authority, once each by base URL.
func directTargets(proj *cis.Projection, authorityURL string) func(ctx context.Context) []deliver.Target {
	return func(context.Context) []deliver.Target {
		seen := map[string]bool{}
		var out []deliver.Target
		add := func(name, base string) {
			base = strings.TrimRight(base, "/")
			if base == "" || seen[base] {
				return
			}
			seen[base] = true
			out = append(out, deliver.Target{Name: name, BaseURL: base})
		}
		if proj != nil {
			ussps := proj.USSPs()
			for i := range ussps {
				add(ussps[i].UsspId, ussps[i].BaseUrl)
			}
		}
		add("authority", authorityURL)
		return out
	}
}

// consumerNext is the worker's source: the durable pull consumer on
// DELIVER, created (or brought to its configuration) when first needed
// and again after its iterator closes.
func consumerNext(b *bus.Bus, pol deliver.Policy, logger *slog.Logger) func(ctx context.Context) (deliver.Msg, error) {
	var it jetstream.MessagesContext
	return func(ctx context.Context) (deliver.Msg, error) {
		if it == nil {
			js := b.JetStream()
			if js == nil {
				return nil, errors.New("no JetStream")
			}
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			cons, err := js.CreateOrUpdateConsumer(cctx, bus.StreamDeliver, jetstream.ConsumerConfig{
				Durable: workerConsumer, FilterSubject: bus.SubjectDeliverPrefix + ">",
				AckPolicy: jetstream.AckExplicitPolicy, AckWait: pol.Lease + 30*time.Second,
				// The row's count bound is MaxAttempts; a deferral (an
				// earlier version still queued, a row not yet due) is a
				// delivery too, hence the margin; a message past it is
				// published again by the outbox scan.
				MaxDeliver: 4 * pol.MaxAttempts(), MaxAckPending: 4 * pol.InFlight,
			})
			cancel()
			if err != nil {
				return nil, err
			}
			if it, err = cons.Messages(jetstream.PullMaxMessages(pol.InFlight)); err != nil {
				it = nil
				return nil, err
			}
			logger.Info("deliver: the worker consumes the DELIVER work queue", slog.String("consumer", workerConsumer), slog.Int("in_flight", pol.InFlight))
			go func(it jetstream.MessagesContext) {
				<-ctx.Done()
				it.Stop()
			}(it)
		}
		m, err := it.Next(jetstream.NextContext(ctx))
		if errors.Is(err, jetstream.ErrMsgIteratorClosed) {
			it = nil
		}
		if err != nil {
			return nil, err
		}
		return m, nil
	}
}

// deliveries is the deliveries summary of x's current version.
func (rs *restrictionAPI) deliveries(ctx context.Context, x restriction.Restriction) deliver.Summary {
	if rs.dl == nil {
		return deliver.NoSummary()
	}
	rows, err := rs.dl.repo.Channels(ctx, x.ID, x.AnspVersion)
	if err != nil {
		// The restriction is still served; its channels say nothing is
		// known rather than a state that was not read.
		return deliver.NoSummary()
	}
	return deliver.Summarise(rows)
}

// deliveryAlarmsUnavailableRetry is the Retry-After while the outbox is
// not run.
const deliveryAlarmsUnavailableRetry = 60 * time.Second

func (s apiServer) deliveryAPI(w http.ResponseWriter, r *http.Request) (*deliveryAPI, bool) {
	if s.rs == nil || s.rs.dl == nil || s.rs.dl.alarms == nil {
		apierr.WriteError(w, r, apierr.Unavailable(deliveryAlarmsUnavailableRetry, "the outbox is not run on this instance (ANSP_RELATIONAL_DSN)"))
		return nil, false
	}
	return s.rs.dl, true
}

type alarmListJSON struct {
	Alarms    []deliver.AlarmBody `json:"alarms"`
	Truncated *bool               `json:"truncated,omitempty"`
}

// ListDeliveryAlarms serves GET /v1/delivery-alarms (WP-8).
func (s apiServer) ListDeliveryAlarms(w http.ResponseWriter, r *http.Request, params gen.ListDeliveryAlarmsParams) {
	dl, ok := s.deliveryAPI(w, r)
	if !ok {
		return
	}
	limit := DefaultListLimit
	if params.Limit != nil {
		limit = min(max(*params.Limit, 1), 1000)
	}
	all := params.All != nil && *params.All
	list, more, err := dl.alarms.List(r.Context(), all, limit)
	if err != nil {
		refusal(w, r, err)
		return
	}
	out := alarmListJSON{Alarms: make([]deliver.AlarmBody, 0, len(list))}
	for i := range list {
		out.Alarms = append(out.Alarms, deliver.BodyOf(list[i]))
	}
	if more {
		out.Truncated = &more
	}
	writeJSON(w, http.StatusOK, out)
}

// AcknowledgeDeliveryAlarm serves POST /v1/delivery-alarms/{id}/acknowledge (WP-8).
func (s apiServer) AcknowledgeDeliveryAlarm(w http.ResponseWriter, r *http.Request, id gen.AlarmID) {
	dl, ok := s.deliveryAPI(w, r)
	if !ok {
		return
	}
	actor, ok := actorOf(r)
	if !ok {
		apierr.WriteError(w, r, apierr.Unauthenticated("no authenticated caller"))
		return
	}
	body, ok := readBody(w, r, true)
	if !ok {
		return
	}
	reason, fe := deliver.DecodeAcknowledge(body)
	if fe != nil {
		apierr.WriteError(w, r, apierr.Invalid(fe))
		return
	}
	a, err := dl.alarms.Acknowledge(r.Context(), deliver.Actor{ID: actor.ID, Role: actor.Role}, id, reason)
	switch {
	case errors.Is(err, deliver.ErrNotFound):
		apierr.WriteError(w, r, apierr.NotFound("no such delivery alarm"))
	case errors.Is(err, deliver.ErrAcknowledged):
		apierr.WriteError(w, r, apierr.Conflict("the alarm is acknowledged or cleared already"))
	case err != nil:
		refusal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, deliver.BodyOf(a))
	}
}
