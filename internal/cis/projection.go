package cis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/policy"
)

// Counter names of the projection (E-09; brief WP-7).
const (
	CounterPulls             = "cis_pulls"
	CounterPullFailed        = "cis_pull_failed"
	CounterNotModified       = "cis_not_modified"
	CounterNoVersion         = "cis_no_version"
	CounterInstalled         = "cis_installed"
	CounterRefused           = "cis_refused"
	CounterTooLarge          = "cis_too_large"
	CounterUntrusted         = "cis_publisher_untrusted"
	CounterVersionReplays    = "cis_version_replays"
	CounterUpstreamStale     = "cis_upstream_stale"
	CounterStoreFailed       = "cis_store_failed"
	CounterStoreNewer        = "cis_store_newer"
	CounterReconcileCatchups = "cis_reconcile_catchups"
	CounterProjectionFailed  = "cis_projection_failed"
	CounterPushFailed        = "cis_push_failed"
	CounterSubscribed        = "cis_subscribed"
	CounterSubscribeFailed   = "cis_subscribe_failed"
	CounterResubscribed      = "cis_resubscribed"
)

// NotificationsPath is the path of the change-notification receiver,
// on this system as on every subscriber (M1); the callback_url ends in it.
const NotificationsPath = "/v1/cis/notifications"

// StatusNoProjection is the status of a projection or a follower that
// holds nothing yet (SC-22: an empty projection never looks current).
const StatusNoProjection = "no CIS projection"

// ErrNoCISP is a pull without ANSP_CISP_URL.
var ErrNoCISP = errors.New("no CISP configured (ANSP_CISP_URL)")

// ErrNoProjection is a read of a dataset the projection holds no
// version of.
var ErrNoProjection = errors.New(StatusNoProjection)

// Stored is one cis_cache row read back.
type Stored struct {
	Dataset   Dataset
	Version   int64
	ETag      string
	Body      []byte
	FetchedAt time.Time
}

// Store is the cis_cache side of the projection (internal/store
// implements it on the relational database). Every time it returns is
// the database's clock.
type Store interface {
	// Save stores v as d's current row when v.Number is not below the
	// stored version (compared under the row's lock, so a slower
	// replica never rolls it back) and returns fetched_at; newer is
	// true, and nothing is written, when the row holds a higher version.
	Save(ctx context.Context, v *Version) (fetchedAt time.Time, newer bool, err error)
	// Touch moves fetched_at of d's row at version to now and returns
	// it; ok is false when the row holds another version.
	Touch(ctx context.Context, d Dataset, version int64) (fetchedAt time.Time, ok bool, err error)
	// Load returns every stored row.
	Load(ctx context.Context) ([]Stored, error)
}

// KV is the bucket cis_current (internal/bus.KV).
type KV interface {
	Put(ctx context.Context, key string, value []byte) (uint64, error)
}

// Pusher publishes the cis.v1.<dataset> push (a *nats.Conn).
type Pusher interface {
	Publish(subject string, data []byte) error
}

// Hint is what a notification asked for.
type Hint struct {
	Version int64
	Issuer  string
	// At is when the notification was received (this process's clock,
	// never the sender's).
	At time.Time
}

// Config configures a Projection.
type Config struct {
	// Client is nil when ANSP_CISP_URL is not set: the projection serves
	// what the database holds, and says so.
	Client *Client
	// Publishers verifies the publisher's signature of every new version
	// (ANSP_CIS_PUBLISHER_KEYS); nil holds every new version.
	Publishers PublisherVerifier
	// Store is nil without a relational database: memory only.
	Store Store
	// KV and Push carry the projection to the hot path; nil writes none.
	KV   KV
	Push Pusher
	// Policy gives cis_reconcile_s and cis_stale_bound_s; nil is the
	// compiled defaults.
	Policy func(ctx context.Context) policy.Thresholds
	// CallbackURL is ANSP_PUBLIC_BASE_URL + /v1/cis/notifications; empty
	// means no subscription (the reconciliation alone).
	CallbackURL string
	// SubscribeRetry is the wait between two failed subscription
	// attempts.
	SubscribeRetry time.Duration
	Counters       *core.Counters
	Logger         *slog.Logger
	Now            func() time.Time
}

// state is what the projection holds of one dataset.
type state struct {
	cur *Version
	// empty is the CISP saying no version was published yet (404
	// no_version), at emptyAt.
	empty   bool
	emptyAt time.Time
	refused *RefusalError
	held    *UntrustedError
	// failingSince is the first failed pull of the current run, lastErr
	// its reason.
	failingSince time.Time
	lastErr      string
	projErr      string
	upstream     bool // the last answer carried X-CIS-Stale
}

// Projection is the writer of the CIS projection in api: it pulls the
// three datasets with If-None-Match, parses them strictly, verifies
// their publisher's signature, stores the current version in cis_cache
// and then (after the commit) puts it to KV cis_current and pushes
// cis.v1.<dataset>. It reconciles every cis_reconcile_s whatever the
// notifications say, holds the subscription, and answers the
// restriction service and the readiness line. Safe for concurrent use.
type Projection struct {
	cfg   Config
	locks map[Dataset]*sync.Mutex
	kick  map[Dataset]chan struct{}

	mu       sync.Mutex
	st       map[Dataset]*state
	hints    map[Dataset]*Hint
	subID    string
	subErr   string
	warmErr  string
	installs map[Dataset][]chan struct{}
}

// New builds a Projection.
func New(cfg Config) *Projection {
	if cfg.Counters == nil {
		cfg.Counters = &core.Counters{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Policy == nil {
		cfg.Policy = func(context.Context) policy.Thresholds { return policy.Defaults() }
	}
	if cfg.SubscribeRetry <= 0 {
		cfg.SubscribeRetry = 30 * time.Second
	}
	p := &Projection{cfg: cfg, locks: map[Dataset]*sync.Mutex{}, kick: map[Dataset]chan struct{}{},
		st: map[Dataset]*state{}, hints: map[Dataset]*Hint{}, installs: map[Dataset][]chan struct{}{}}
	for _, d := range Datasets {
		p.locks[d] = &sync.Mutex{}
		p.kick[d] = make(chan struct{}, 1)
		p.st[d] = &state{}
	}
	return p
}

// Counters are the projection's counters.
func (p *Projection) Counters() *core.Counters { return p.cfg.Counters }

// reconcileEvery is cis_reconcile_s as a duration, at least a second.
func (p *Projection) reconcileEvery(ctx context.Context) time.Duration {
	s := p.cfg.Policy(ctx).CISReconcileS
	if !(s >= 1) || math.IsInf(s, 0) {
		s = policy.Defaults().CISReconcileS
	}
	return time.Duration(s * float64(time.Second))
}

// Run warms the projection from cis_cache, subscribes, and pulls every
// dataset on a notification and every cis_reconcile_s until ctx ends.
func (p *Projection) Run(ctx context.Context) {
	p.Warm(ctx)
	if p.cfg.Client == nil {
		// Nothing to pull: the stored projection is served with its
		// age, and the status says why it does not move.
		return
	}
	var wg sync.WaitGroup
	for _, d := range Datasets {
		wg.Go(func() { p.worker(ctx, d) })
	}
	wg.Go(func() { p.subscriptionLoop(ctx) })
	wg.Wait()
}

// Warm installs the stored version of every dataset with the age it has
// on the database clock and projects it, so a restart serves the last
// known projection (stale when it is old) instead of none.
func (p *Projection) Warm(ctx context.Context) {
	if p.cfg.Store == nil {
		return
	}
	rows, err := p.cfg.Store.Load(ctx)
	if err != nil {
		p.mu.Lock()
		p.warmErr = err.Error()
		p.mu.Unlock()
		p.cfg.Logger.Warn("the CIS projection could not be read from cis_cache", slog.String("error", err.Error()))
		return
	}
	for _, r := range rows {
		v, rf := ParseVersion(r.Dataset, r.Body, r.ETag, r.Version)
		if rf != nil {
			p.cfg.Logger.Error("a stored CIS version no longer parses; it is not served", slog.String("dataset", string(r.Dataset)),
				slog.Int64("version", r.Version), slog.String("problem", rf.First))
			continue
		}
		v.FetchedAt = r.FetchedAt
		p.mu.Lock()
		p.st[r.Dataset].cur = v
		p.mu.Unlock()
		p.cfg.Logger.Info("CIS version loaded from cis_cache", slog.String("dataset", string(r.Dataset)),
			slog.Int64("version", v.Number), slog.Time("fetched_at", v.FetchedAt))
		p.project(ctx, v)
	}
}

// Trigger asks for a pull of d after a notification; it never blocks.
func (p *Projection) Trigger(d Dataset, h Hint) {
	if _, ok := p.kick[d]; !ok {
		return
	}
	p.mu.Lock()
	if old := p.hints[d]; old == nil || h.Version >= old.Version {
		p.hints[d] = &h
	}
	p.mu.Unlock()
	select {
	case p.kick[d] <- struct{}{}:
	default:
	}
}

// Installed returns a channel closed the next time a version of d is
// installed (tests and the measured notification path).
func (p *Projection) Installed(d Dataset) <-chan struct{} {
	ch := make(chan struct{})
	p.mu.Lock()
	p.installs[d] = append(p.installs[d], ch)
	p.mu.Unlock()
	return ch
}

func (p *Projection) worker(ctx context.Context, d Dataset) {
	_ = p.Pull(ctx, d, false)
	t := time.NewTimer(p.reconcileEvery(ctx))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kick[d]:
			p.mu.Lock()
			delete(p.hints, d)
			p.mu.Unlock()
			_ = p.Pull(ctx, d, false)
		case <-t.C:
			_ = p.Pull(ctx, d, true)
			p.retryProjection(ctx, d)
			t.Reset(p.reconcileEvery(ctx))
		}
	}
}

// Pull reads d from the CISP whole (If-None-Match the version held) and
// installs a newer version. reconcile marks a pull of the periodic
// reconciliation, which counts a newer version found as a catch-up.
func (p *Projection) Pull(ctx context.Context, d Dataset, reconcile bool) error {
	if p.cfg.Client == nil {
		return ErrNoCISP
	}
	lock := p.locks[d]
	lock.Lock()
	defer lock.Unlock()
	cur := p.current(d)
	etag := ""
	if cur != nil {
		etag = cur.ETag
	}
	p.cfg.Counters.Inc(CounterPulls)
	f, err := p.cfg.Client.GetDataset(ctx, d, etag)
	if err != nil {
		var tl *TooLargeError
		if errors.As(err, &tl) {
			p.cfg.Counters.Inc(CounterTooLarge)
			return p.refuse(d, refuse(d, 0, "body: "+err.Error()))
		}
		return p.fail(d, err)
	}
	p.mu.Lock()
	p.st[d].upstream = f.Stale
	p.mu.Unlock()
	if f.Stale {
		p.cfg.Counters.Inc(CounterUpstreamStale)
	}
	switch f.Status {
	case http.StatusNotModified:
		p.cfg.Counters.Inc(CounterNotModified)
		if cur == nil {
			return p.fail(d, errors.New("the CISP answered 304 to a read without If-None-Match"))
		}
		return p.touch(ctx, cur)
	case http.StatusNotFound:
		p.cfg.Counters.Inc(CounterNoVersion)
		p.mu.Lock()
		s := p.st[d]
		s.empty, s.emptyAt = true, p.cfg.Now()
		p.clearFail(s)
		p.mu.Unlock()
		return nil
	}
	v, rf := ParseVersion(d, f.Body, f.ETag, f.Version)
	if rf != nil {
		return p.refuse(d, rf)
	}
	if cur != nil && v.Number <= cur.Number {
		if v.Number < cur.Number {
			p.cfg.Counters.Inc(CounterVersionReplays)
		}
		return p.touch(ctx, cur)
	}
	if err := provenance(ctx, p.cfg.Client, p.cfg.Publishers, v); err != nil {
		var ue *UntrustedError
		if errors.As(err, &ue) {
			return p.hold(ue)
		}
		return p.fail(d, err)
	}
	return p.install(ctx, v, reconcile)
}

func (p *Projection) current(d Dataset) *Version {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st[d].cur
}

// install stores v (committed first), then makes it current, puts it to
// KV and pushes it.
func (p *Projection) install(ctx context.Context, v *Version, reconcile bool) error {
	v.FetchedAt = p.cfg.Now().UTC()
	if p.cfg.Store != nil {
		at, newer, err := p.cfg.Store.Save(ctx, v)
		if err != nil {
			p.cfg.Counters.Inc(CounterStoreFailed)
			return p.fail(v.Dataset, fmt.Errorf("storing %s version %d in cis_cache: %w", v.Dataset, v.Number, err))
		}
		if newer {
			// Another api instance stored a higher version: take it on
			// the next warm-up or pull, never roll back.
			p.cfg.Counters.Inc(CounterStoreNewer)
			p.cfg.Logger.Info("cis_cache holds a newer version than the one pulled; not installed",
				slog.String("dataset", string(v.Dataset)), slog.Int64("version", v.Number))
			p.mu.Lock()
			p.clearFail(p.st[v.Dataset])
			p.mu.Unlock()
			return nil
		}
		v.FetchedAt = at
	}
	p.mu.Lock()
	s := p.st[v.Dataset]
	s.cur, s.empty = v, false
	if s.refused != nil && (s.refused.Version <= v.Number) {
		s.refused = nil
	}
	if s.held != nil && s.held.Version <= v.Number {
		s.held = nil
	}
	p.clearFail(s)
	waiting := p.installs[v.Dataset]
	delete(p.installs, v.Dataset)
	p.mu.Unlock()
	p.cfg.Counters.Inc(CounterInstalled)
	if reconcile {
		p.cfg.Counters.Inc(CounterReconcileCatchups)
	}
	p.cfg.Logger.Info("CIS version installed", slog.String("dataset", string(v.Dataset)), slog.Int64("version", v.Number),
		slog.Bool("reconcile", reconcile))
	p.project(ctx, v)
	for _, ch := range waiting {
		close(ch)
	}
	return nil
}

// touch records that the CISP confirmed the version held: fetched_at
// moves (on the database clock) and the projection is put again.
func (p *Projection) touch(ctx context.Context, cur *Version) error {
	at := p.cfg.Now().UTC()
	if p.cfg.Store != nil {
		t, ok, err := p.cfg.Store.Touch(ctx, cur.Dataset, cur.Number)
		if err != nil {
			p.cfg.Counters.Inc(CounterStoreFailed)
			return p.fail(cur.Dataset, fmt.Errorf("confirming %s version %d in cis_cache: %w", cur.Dataset, cur.Number, err))
		}
		if ok {
			at = t
		}
	}
	next := *cur
	next.FetchedAt = at
	p.mu.Lock()
	s := p.st[cur.Dataset]
	if s.cur == cur {
		s.cur = &next
	}
	p.clearFail(s)
	p.mu.Unlock()
	p.project(ctx, &next)
	return nil
}

// hold keeps the version in use and says why the new one is not used,
// until a version whose signature verifies replaces it. A hold is
// logged once per version and reason.
func (p *Projection) hold(ue *UntrustedError) error {
	p.cfg.Counters.Inc(CounterUntrusted)
	p.mu.Lock()
	s := p.st[ue.Dataset]
	prev := s.held
	s.held = ue
	p.clearFail(s)
	p.mu.Unlock()
	if prev == nil || prev.Version != ue.Version || prev.Reason != ue.Reason {
		p.cfg.Logger.Error("CIS version held: its publisher's signature is not verified; the version in use is kept",
			slog.String("dataset", string(ue.Dataset)), slog.Int64("version", ue.Version), slog.String("reason", ue.Reason))
	}
	return ue
}

func (p *Projection) refuse(d Dataset, rf *RefusalError) error {
	p.cfg.Counters.Inc(CounterRefused)
	p.mu.Lock()
	s := p.st[d]
	s.refused = rf
	p.clearFail(s)
	p.mu.Unlock()
	p.cfg.Logger.Error("CIS dataset refused; the version in use is kept", slog.String("dataset", string(d)),
		slog.Int64("version", rf.Version), slog.String("problem", rf.First), slog.Int("problems", rf.Problems))
	return rf
}

func (p *Projection) fail(d Dataset, err error) error {
	p.cfg.Counters.Inc(CounterPullFailed)
	p.mu.Lock()
	s := p.st[d]
	if s.failingSince.IsZero() {
		s.failingSince = p.cfg.Now().UTC()
	}
	s.lastErr = short(err.Error())
	p.mu.Unlock()
	p.cfg.Logger.Warn("CIS pull failed", slog.String("dataset", string(d)), slog.String("error", err.Error()))
	return err
}

// clearFail ends a run of failures; p.mu is held.
func (p *Projection) clearFail(s *state) {
	if !s.failingSince.IsZero() {
		p.cfg.Logger.Info("CISP answering again", slog.Time("down_since", s.failingSince))
	}
	s.failingSince, s.lastErr = time.Time{}, ""
}

// Doc is the value of a cis_current key and the body of the
// cis.v1.<dataset> push: the dataset version, when it was fetched (the
// database clock) and, for uspace_airspace and ussp_list, the document
// as the CISP served it (the input of ed318.ToZones and of the USSP
// list). restrictions carries no body: the hot path does not read it.
type Doc struct {
	Dataset   Dataset         `json:"dataset"`
	Version   int64           `json:"version"`
	ETag      string          `json:"etag"`
	FetchedAt time.Time       `json:"fetched_at"`
	Body      json.RawMessage `json:"body,omitempty"`
}

// MaxDocBytes bounds a Doc: NATS's default max_payload. A larger
// projection is not written and the status says so.
const MaxDocBytes = 1 << 20

// docOf is v's Doc.
func docOf(v *Version) ([]byte, error) {
	d := Doc{Dataset: v.Dataset, Version: v.Number, ETag: v.ETag, FetchedAt: v.FetchedAt.UTC()}
	if v.Dataset != Restrictions {
		if !json.Valid(v.Body) {
			return nil, errors.New("the body is not JSON")
		}
		d.Body = v.Body
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxDocBytes {
		return nil, fmt.Errorf("the projection of %s version %d is %d bytes, more than the %d a KV value holds", v.Dataset, v.Number, len(b), MaxDocBytes)
	}
	return b, nil
}

// project puts v to KV cis_current and pushes it; called only after the
// commit (or with no database).
func (p *Projection) project(ctx context.Context, v *Version) {
	if p.cfg.KV == nil && p.cfg.Push == nil {
		return
	}
	doc, err := docOf(v)
	if err == nil && p.cfg.KV != nil {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = p.cfg.KV.Put(pctx, string(v.Dataset), doc)
		cancel()
	}
	p.mu.Lock()
	if err != nil {
		p.st[v.Dataset].projErr = short(err.Error())
	} else {
		p.st[v.Dataset].projErr = ""
	}
	p.mu.Unlock()
	if err != nil {
		p.cfg.Counters.Inc(CounterProjectionFailed)
		p.cfg.Logger.Error("CIS projection not written to KV; retried every reconciliation", slog.String("dataset", string(v.Dataset)),
			slog.Int64("version", v.Number), slog.String("error", err.Error()))
		return
	}
	if p.cfg.Push != nil {
		if err := p.cfg.Push.Publish(bus.SubjectCISPrefix+string(v.Dataset), doc); err != nil {
			p.cfg.Counters.Inc(CounterPushFailed)
		}
	}
}

// retryProjection puts the current version again when the last put
// failed (KV was unreachable).
func (p *Projection) retryProjection(ctx context.Context, d Dataset) {
	p.mu.Lock()
	s := p.st[d]
	failed, cur := s.projErr != "", s.cur
	p.mu.Unlock()
	if failed && cur != nil {
		p.project(ctx, cur)
	}
}

// Datasets the subscription names.
var subscribed = []Dataset{USpaceAirspace, USSPList, Restrictions}

func (p *Projection) subscriptionLoop(ctx context.Context) {
	if p.cfg.Client == nil || p.cfg.CallbackURL == "" {
		return
	}
	for ctx.Err() == nil {
		wait := p.reconcileEvery(ctx)
		if err := p.EnsureSubscription(ctx); err != nil {
			wait = min(wait, p.cfg.SubscribeRetry)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// EnsureSubscription registers the subscription when there is none, and
// otherwise checks it: the CISP saying it does not know it registers it
// again, a suspended one is re-activated.
func (p *Projection) EnsureSubscription(ctx context.Context) error {
	if p.cfg.Client == nil || p.cfg.CallbackURL == "" {
		return nil
	}
	p.mu.Lock()
	id := p.subID
	p.mu.Unlock()
	var (
		s   cispclient.Subscription
		err error
	)
	switch id {
	case "":
		s, err = p.cfg.Client.Subscribe(ctx, p.cfg.CallbackURL, subscribed)
		if err == nil {
			p.cfg.Counters.Inc(CounterSubscribed)
		}
	default:
		s, err = p.cfg.Client.GetSubscription(ctx, id)
		switch {
		case errors.Is(err, ErrSubscriptionUnknown):
			p.cfg.Counters.Inc(CounterResubscribed)
			p.cfg.Logger.Warn("the CISP does not know the subscription; registering it again", slog.String("subscription", id))
			s, err = p.cfg.Client.Subscribe(ctx, p.cfg.CallbackURL, subscribed)
		case err == nil && s.Status == cispclient.SubscriptionStatusSuspended:
			p.cfg.Logger.Warn("the subscription is suspended; re-activating it", slog.String("subscription", id))
			s, err = p.cfg.Client.Reactivate(ctx, id, subscribed)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		p.cfg.Counters.Inc(CounterSubscribeFailed)
		p.mu.Lock()
		p.subErr = short(err.Error())
		p.mu.Unlock()
		p.cfg.Logger.Warn("CISP subscription not confirmed; the reconciliation alone keeps the projection", slog.String("error", err.Error()))
		return err
	}
	p.mu.Lock()
	changed := p.subID != s.Id
	p.subID, p.subErr = s.Id, ""
	p.mu.Unlock()
	if changed {
		p.cfg.Logger.Info("subscribed to the CISP's change notifications", slog.String("subscription", s.Id), slog.String("status", string(s.Status)))
	}
	return nil
}

// SubscriptionID is the subscription this system registered ("" while
// none is): the sub every notification must carry.
func (p *Projection) SubscriptionID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.subID
}

// USpaceAirspace is the current uspace_airspace version: its number,
// when it was fetched and its features (for the restriction service's
// placement, M9); ErrNoProjection while there is none.
func (p *Projection) USpaceAirspace() (version string, fetchedAt time.Time, features []ed318.Feature, err error) {
	v := p.current(USpaceAirspace)
	if v == nil {
		return "", time.Time{}, nil, ErrNoProjection
	}
	return strconv.FormatInt(v.Number, 10), v.FetchedAt, v.Collection.Features, nil
}

// USpaceVolumes are the current U-space volumes (never nil).
func (p *Projection) USpaceVolumes() []*zones.Zone {
	if v := p.current(USpaceAirspace); v != nil {
		return v.Volumes
	}
	return []*zones.Zone{}
}

// USSPs is the current USSP list (never nil).
func (p *Projection) USSPs() []cispclient.Ussp {
	if v := p.current(USSPList); v != nil && v.USSPList != nil {
		return v.USSPList.Ussps
	}
	return []cispclient.Ussp{}
}

// Version is the version of d in use, or 0.
func (p *Projection) Version(d Dataset) int64 {
	if v := p.current(d); v != nil {
		return v.Number
	}
	return 0
}

// The readiness states of the projection, the head of Status.
const (
	StateOK    = "ok"
	StateStale = "stale"
	StateDown  = "down"
	StateNone  = "none"
)

// Report is the projection's status: the state, the age of the oldest
// dataset in use, since when the CISP fails, and every problem.
type Report struct {
	State    string
	AgeS     float64
	Since    time.Time
	Problems []string
}

// Line is "ok (age 12 s)", "stale (age 400 s)", "down since T (...)" or
// "no CIS projection", then the problems.
func (r Report) Line() string {
	var head string
	switch r.State {
	case StateOK:
		head = fmt.Sprintf("ok (age %.0f s)", r.AgeS)
	case StateStale:
		head = fmt.Sprintf("stale (age %.0f s)", r.AgeS)
	case StateDown:
		head = "down since " + r.Since.UTC().Format(time.RFC3339)
		if r.AgeS >= 0 {
			head += fmt.Sprintf(" (serving age %.0f s)", r.AgeS)
		}
	default:
		head = StatusNoProjection
	}
	if len(r.Problems) == 0 {
		return head
	}
	return head + "; " + strings.Join(r.Problems, "; ")
}

// Status is the readiness of the projection at now against
// cis_stale_bound_s (the contribution "cisp: ok (age 12 s) | stale (age
// 400 s) | down since T"). Down wins over stale: a CISP that does not
// answer is named as such while the held versions are still served
// with their age.
func (p *Projection) Status(ctx context.Context, now time.Time) Report {
	bound := p.cfg.Policy(ctx).CISStaleBoundS
	p.mu.Lock()
	defer p.mu.Unlock()
	r := Report{AgeS: -1}
	loaded, missing := 0, []string{}
	var since time.Time
	for _, d := range Datasets {
		s := p.st[d]
		switch {
		case s.cur != nil:
			loaded++
			r.AgeS = math.Max(r.AgeS, math.Max(0, now.Sub(s.cur.FetchedAt).Seconds()))
		case s.empty:
			loaded++
			r.AgeS = math.Max(r.AgeS, math.Max(0, now.Sub(s.emptyAt).Seconds()))
			r.Problems = append(r.Problems, string(d)+": no version published yet")
		default:
			missing = append(missing, string(d))
		}
		if !s.failingSince.IsZero() {
			if since.IsZero() || s.failingSince.Before(since) {
				since = s.failingSince
			}
			r.Problems = append(r.Problems, fmt.Sprintf("%s: %s", d, s.lastErr))
		}
		if s.refused != nil {
			r.Problems = append(r.Problems, "last read refused: "+s.refused.Error())
		}
		if s.held != nil {
			r.Problems = append(r.Problems, s.held.Error())
		}
		if s.projErr != "" {
			r.Problems = append(r.Problems, fmt.Sprintf("%s: KV cis_current not written: %s", d, s.projErr))
		}
		if s.upstream {
			r.Problems = append(r.Problems, fmt.Sprintf("%s: the CISP serves its held snapshot (X-CIS-Stale)", d))
		}
	}
	if len(missing) > 0 {
		r.Problems = append(r.Problems, "no version of "+strings.Join(missing, ", "))
	}
	if p.cfg.Client == nil {
		r.Problems = append(r.Problems, "no CISP configured (ANSP_CISP_URL)")
	} else if p.cfg.Publishers == nil {
		r.Problems = append(r.Problems, reasonNoPublisherKeys+": every new version is held")
	}
	switch {
	case p.cfg.CallbackURL == "":
		r.Problems = append(r.Problems, "no change notifications (ANSP_PUBLIC_BASE_URL or ANSP_CIS_NOTIFY_ISSUERS not set): the reconciliation alone")
	case p.subID == "" && p.subErr != "":
		r.Problems = append(r.Problems, "not subscribed: "+p.subErr)
	}
	if p.warmErr != "" && loaded == 0 {
		r.Problems = append(r.Problems, "cis_cache not read: "+short(p.warmErr))
	}
	switch {
	case !since.IsZero():
		r.State, r.Since = StateDown, since
	case loaded == 0:
		r.State = StateNone
	case len(missing) > 0 || !(r.AgeS <= bound):
		r.State = StateStale
	default:
		r.State = StateOK
	}
	return r
}
