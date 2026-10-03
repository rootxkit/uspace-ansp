package feed

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-ansp/internal/manned"
	"github.com/rootxkit/uspace-ansp/internal/picture"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// Config bounds and paces the feed; zero values take the defaults.
type Config struct {
	// MaxClients bounds the open streams of the process, MaxPerClient
	// those of one client id (06 T8); past either the upgrade is refused
	// 503 with Retry-After.
	MaxClients   int
	MaxPerClient int
	// SendQueue bounds the frames queued for one client: past it the
	// oldest is dropped, counted and said in its next status frame.
	SendQueue int
	// StatusPeriod is the console/status/v1 period (M29: 2 s).
	StatusPeriod time.Duration
	// TickPeriod is how often the picture ages.
	TickPeriod time.Duration
	// MinTrackInterval is the server-side throttle per aircraft (2 Hz,
	// docs/PLAN.md section 9): a newer sample within it waits, and only
	// the latest is sent.
	MinTrackInterval time.Duration
	// ProductPeriod is the feed_products sampling (0.1 Hz per client).
	ProductPeriod time.Duration
	// RetryAfter is said with a refused upgrade.
	RetryAfter time.Duration
	// WriteTimeout bounds one frame's write; past it the client is
	// closed with 1013.
	WriteTimeout time.Duration
}

// Defaults of Config.
const (
	DefaultMaxClients       = 64
	DefaultMaxPerClient     = 4
	DefaultSendQueue        = 512
	DefaultStatusPeriod     = 2 * time.Second
	DefaultTickPeriod       = time.Second
	DefaultMinTrackInterval = 500 * time.Millisecond
	DefaultProductPeriod    = 10 * time.Second
	DefaultRetryAfter       = 10 * time.Second
	DefaultWriteTimeout     = 5 * time.Second
	flushPeriod             = 100 * time.Millisecond
)

func (c *Config) defaults() {
	set := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	setD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	set(&c.MaxClients, DefaultMaxClients)
	set(&c.MaxPerClient, DefaultMaxPerClient)
	set(&c.SendQueue, DefaultSendQueue)
	setD(&c.StatusPeriod, DefaultStatusPeriod)
	setD(&c.TickPeriod, DefaultTickPeriod)
	setD(&c.MinTrackInterval, DefaultMinTrackInterval)
	setD(&c.ProductPeriod, DefaultProductPeriod)
	setD(&c.RetryAfter, DefaultRetryAfter)
	setD(&c.WriteTimeout, DefaultWriteTimeout)
}

// The degraded slugs (snake_case; console/status/v1 degraded[]).
const (
	DegradedAdaptersSilent = "adapters_silent"
	DegradedCISStale       = "cis_projection_stale"
	DegradedNATS           = "nats"
)

// Counters of the feed (E-09, E-10).
const (
	CounterRefusedTotal     = "feed_stream_refused_total_cap"
	CounterRefusedPerClient = "feed_stream_refused_client_cap"
	CounterDroppedFrames    = "feed_stream_dropped_frames"
	CounterThrottled        = "feed_track_throttled"
	CounterClientFrameBad   = "feed_client_frames_refused"
	CounterSessionClosed    = "feed_stream_session_closed"
	CounterSlowClosed       = "feed_stream_slow_closed"
	CounterFramesSent       = "feed_frames_sent"
	CounterProductsDropped  = "feed_products_dropped"
)

// SessionVerifier re-checks a console session mid-stream
// (auth.SessionVerifier).
type SessionVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.Claims, error)
}

// Product is one feed_products sample: what was served to whom.
type Product struct {
	ClientID       string
	TracksSent     int32
	TracksRelevant int32
	Degraded       []string
	PolicyVersion  int64
}

// ProductSink takes a sample without blocking (ProductQueue).
type ProductSink interface {
	Record(p Product)
}

// Deps are what the feed serves from.
type Deps struct {
	Picture  *picture.Picture
	Adapters *Adapters
	Policy   picture.PolicySource
	CIS      picture.CIS
	// NATS is the bus state as a slug (connected, reconnecting, closed,
	// not_configured) and whether it is up.
	NATS func() (slug string, up bool)
	// Sessions re-checks console sessions every status period; nil
	// closes every cookie stream at its first check (no checker, no
	// session: fail closed).
	Sessions SessionVerifier
	// SessionSeen reports an open console stream's session as in use
	// (docs/PLAN.md section 15 row 21 (4)); may be nil.
	SessionSeen func(jti string)
	// Products records feed_products; may be nil.
	Products ProductSink
	// Degraded adds what the process knows is degraded (the writer).
	Degraded func() []string
	Clock    func() time.Time
}

// Service is the F4 feed: it ages the picture, throttles and fans
// frames out to the stream clients, and answers the snapshot.
type Service struct {
	cfg Config
	d   Deps

	counters core.Counters

	mu       sync.Mutex
	clients  map[*client]struct{}
	perID    map[string]int
	lastSent map[string]time.Time
	pending  map[string]picture.Entry
}

// New is a feed over d.
func New(cfg Config, d Deps) *Service {
	cfg.defaults()
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Adapters == nil {
		d.Adapters = NewAdapters()
	}
	if d.CIS == nil {
		d.CIS = picture.NoCIS{}
	}
	if d.NATS == nil {
		d.NATS = func() (string, bool) { return "not_configured", false }
	}
	return &Service{cfg: cfg, d: d, clients: map[*client]struct{}{}, perID: map[string]int{},
		lastSent: map[string]time.Time{}, pending: map[string]picture.Entry{}}
}

// Counters are the feed's counters.
func (s *Service) Counters() *core.Counters { return &s.counters }

// Config is the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Clients is the number of open streams.
func (s *Service) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *Service) policy() policy.Policy {
	if s.d.Policy == nil {
		return policy.Policy{Thresholds: policy.Defaults()}
	}
	p, _ := s.d.Policy.Current()
	return p
}

// Ingest takes one sample from the bus into the picture and sends it to
// the clients it concerns (throttled per aircraft). It never blocks on a
// client.
func (s *Service) Ingest(t manned.Track) picture.Verdict {
	v, e := s.d.Picture.Observe(t)
	if v != picture.Shown {
		return v
	}
	now := s.d.Clock()
	s.mu.Lock()
	last, ok := s.lastSent[t.ICAO24]
	if ok && now.Sub(last) < s.cfg.MinTrackInterval {
		s.pending[t.ICAO24] = e
		s.mu.Unlock()
		s.counters.Inc(CounterThrottled)
		return v
	}
	s.lastSent[t.ICAO24] = now
	delete(s.pending, t.ICAO24)
	s.mu.Unlock()
	s.broadcast(&e, now)
	return v
}

// Run ages the picture every TickPeriod and flushes throttled samples
// until ctx ends.
func (s *Service) Run(ctx context.Context) {
	flush := time.NewTicker(flushPeriod)
	defer flush.Stop()
	tick := time.NewTicker(s.cfg.TickPeriod)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			s.flush(s.d.Clock())
		case <-tick.C:
			s.Tick(s.d.Clock())
		}
	}
}

// Tick ages the picture at now and tells the clients every change: an
// aircraft that becomes stale or source_disabled is sent with its new
// state (nothing disappears silently).
func (s *Service) Tick(now time.Time) picture.Ageing {
	a := s.d.Picture.Tick(now)
	s.mu.Lock()
	for _, icao := range a.Evicted {
		delete(s.lastSent, icao)
		delete(s.pending, icao)
	}
	for i := range a.Changed {
		icao := a.Changed[i].Track.ICAO24
		delete(s.pending, icao)
		s.lastSent[icao] = now
	}
	s.mu.Unlock()
	for i := range a.Changed {
		s.broadcast(&a.Changed[i], now)
	}
	return a
}

// flush sends the throttled samples whose interval has passed.
func (s *Service) flush(now time.Time) {
	var due []picture.Entry
	s.mu.Lock()
	for icao := range s.pending {
		if now.Sub(s.lastSent[icao]) >= s.cfg.MinTrackInterval {
			due = append(due, s.pending[icao])
			s.lastSent[icao] = now
			delete(s.pending, icao)
		}
	}
	s.mu.Unlock()
	for i := range due {
		due[i].AgeS = math.Max(0, now.Sub(due[i].Track.Times.CapturedAt).Seconds())
		s.broadcast(&due[i], now)
	}
}

func (s *Service) broadcast(e *picture.Entry, now time.Time) {
	if e.State == picture.StateBacklogOnly {
		return
	}
	s.mu.Lock()
	targets := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		targets = append(targets, c)
	}
	s.mu.Unlock()
	var frame []byte
	for _, c := range targets {
		if !c.wants(e) {
			continue
		}
		if frame == nil {
			env := TrackEnvelope(e, now)
			b, err := json.Marshal(env)
			if err != nil {
				return
			}
			frame = b
		}
		if c.enqueue(frame, e.Relevance.Relevant) {
			s.counters.Inc(CounterDroppedFrames)
		}
	}
}

// Degraded is what is degraded at now, sorted: no adapter live
// (adapters_silent), no CIS projection or one older than
// cis_stale_bound_s (cis_projection_stale), the bus (nats), and what the
// process adds (Deps.Degraded).
func (s *Service) Degraded(now time.Time) []string {
	pol := s.policy()
	set := map[string]bool{}
	if s.d.Adapters.Silent(now, pol.SourceLivenessS) {
		set[DegradedAdaptersSilent] = true
	}
	proj, ok := s.d.CIS.Projection()
	if !ok || len(proj.Volumes) == 0 || now.Sub(proj.FetchedAt) > manned.Seconds(pol.CISStaleBoundS) {
		set[DegradedCISStale] = true
	}
	if _, up := s.d.NATS(); !up {
		set[DegradedNATS] = true
	}
	if s.d.Degraded != nil {
		for _, d := range s.d.Degraded() {
			set[d] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cisInfo is the projection's version and age, none without one.
func (s *Service) cisInfo(now time.Time) (version *string, ageS *float64) {
	proj, ok := s.d.CIS.Projection()
	if !ok || proj.Version == "" {
		return nil, nil
	}
	v := proj.Version
	a := math.Max(0, now.Sub(proj.FetchedAt).Seconds())
	return &v, &a
}

func policyVersion(p policy.Policy) string { return strconv.FormatInt(p.Version, 10) }

// status is the console/status/v1 frame for c at now.
func (s *Service) status(c *client, now time.Time) manned.Envelope {
	pol := s.policy()
	slug, _ := s.d.NATS()
	body := StatusBody{
		ConnectionID: c.id, ServerTS: manned.FormatTime(now), PolicyVersion: policyVersion(pol),
		StaleAfterS: pol.StaleAfterS, LiveMaxAgeS: pol.StaleAfterS, DroppedFrames: c.droppedFrames(),
		Degraded: s.Degraded(now), Sources: s.d.Adapters.Sources(), Adapters: s.d.Adapters.States(now, pol.SourceLivenessS),
		NATS: slug, Relevance: s.d.Picture.RelevanceStatus(),
	}
	if v, a := s.cisInfo(now); v != nil {
		body.CISVersion, body.CISAgeS = *v, a
	}
	return systemEnvelope(SchemaStatus, now, body)
}

// entries are the picture's entries a viewer is served: inside bbox, not
// backlog_only, and relevant unless all (the console).
func (s *Service) entries(bbox *geodesy.BBox, all bool) []picture.Entry {
	snap := s.d.Picture.Snapshot(bbox)
	out := snap[:0]
	for i := range snap {
		if snap[i].State == picture.StateBacklogOnly || (!all && !snap[i].Relevance.Relevant) {
			continue
		}
		out = append(out, snap[i])
	}
	return out
}

func (s *Service) snapshotBody(bbox *geodesy.BBox, all bool, now time.Time) SnapshotBody {
	es := s.entries(bbox, all)
	body := SnapshotBody{Tracks: []json.RawMessage{}, Alerts: []json.RawMessage{}, Manned: make([]manned.Envelope, 0, len(es))}
	for i := range es {
		body.Manned = append(body.Manned, TrackEnvelope(&es[i], now))
	}
	body.ZonesVersion, _ = s.cisInfo(now)
	return body
}

// Snapshot is the answer of GET /v1/manned-traffic/snapshot at now.
func (s *Service) Snapshot(bbox *geodesy.BBox, all bool) MannedSnapshot {
	now := s.d.Clock()
	pol := s.policy()
	out := MannedSnapshot{
		SnapshotBody: s.snapshotBody(bbox, all, now), Degraded: s.Degraded(now),
		Adapters: s.d.Adapters.States(now, pol.SourceLivenessS), PolicyVersion: policyVersion(pol),
		GeneratedAt: manned.FormatTime(now),
	}
	out.CISVersion, out.CISAgeS = s.cisInfo(now)
	return out
}

// client is one open stream.
type client struct {
	id       string
	clientID string
	// all: the console sees every aircraft, flagged; a machine client
	// only the relevant ones.
	all bool

	mu       sync.Mutex
	bbox     *geodesy.BBox
	manned   bool
	queue    []queued
	max      int
	notify   chan struct{}
	dropped  atomic.Int64
	sent     int32
	relevant int32
}

func (c *client) wants(e *picture.Entry) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.manned || (!c.all && !e.Relevance.Relevant) {
		return false
	}
	return c.bbox == nil || c.bbox.Contains(e.Track.Position)
}

// queued is a track frame waiting for the writer, with whether its
// aircraft is relevant (for the product, counted once written).
type queued struct {
	frame    []byte
	relevant bool
}

// enqueue adds a frame, dropping the oldest past the bound; it reports
// whether one was dropped.
func (c *client) enqueue(frame []byte, relevant bool) bool {
	c.mu.Lock()
	dropped := false
	if len(c.queue) >= c.max {
		c.queue = c.queue[1:]
		c.dropped.Add(1)
		dropped = true
	}
	c.queue = append(c.queue, queued{frame: frame, relevant: relevant})
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
	return dropped
}

func (c *client) take() []queued {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := c.queue
	c.queue = nil
	return q
}

// written counts a track frame the writer delivered, for the product:
// the Annex V record of what was served counts what was written, never
// a frame dropped from the queue or cleared by a resubscription (ansp
// audit S-5).
func (c *client) written(q queued) {
	c.mu.Lock()
	c.sent++
	if q.relevant {
		c.relevant++
	}
	c.mu.Unlock()
}

func (c *client) takeProduct() (sent, relevant int32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sent, relevant = c.sent, c.relevant
	c.sent, c.relevant = 0, 0
	return sent, relevant
}

func (c *client) droppedFrames() int64 { return c.dropped.Load() }

func (c *client) subscribe(sub Subscribe) {
	c.mu.Lock()
	c.bbox = sub.BBox
	c.manned = false
	for _, l := range sub.Layers {
		if l == "manned" {
			c.manned = true
		}
	}
	c.queue = nil
	c.mu.Unlock()
}

// add registers a client within the caps.
func (s *Service) add(c *client) (ok bool, perClient bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= s.cfg.MaxClients {
		return false, false
	}
	if s.perID[c.clientID] >= s.cfg.MaxPerClient {
		return false, true
	}
	s.clients[c] = struct{}{}
	s.perID[c.clientID]++
	return true, false
}

func (s *Service) remove(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c]; !ok {
		return
	}
	delete(s.clients, c)
	s.perID[c.clientID]--
	if s.perID[c.clientID] <= 0 {
		delete(s.perID, c.clientID)
	}
}
