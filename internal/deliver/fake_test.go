package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
)

// fakeClock is the database clock of the fake store.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fakeRow struct {
	Delivery
	leaseToken   string
	leaseUntil   time.Time
	busPublished *time.Time
}

type fakeAttempt struct {
	Attempt
	At time.Time
}

type fakeRestriction struct {
	versions  []VersionInfo // index version-1
	state     string
	published *int64
	// The DSS standing (WP-9) and each version's constraint document.
	dss         fakeDSS
	constraints []json.RawMessage
}

// fakeDSS is a restriction's DSS columns.
type fakeDSS struct {
	constraintID string
	ovn          *string
	dssVersion   *int64
	state        string
	since        *time.Time
	reference    json.RawMessage
	putVersion   *int64
	writes       []DSSWrite
}

// fakeRepo is an in-memory Repo with the store's rules (leases, order
// per target, the unique job and alarm keys), on a fake clock.
type fakeRepo struct {
	mu           sync.Mutex
	clock        *fakeClock
	rows         map[string]*fakeRow
	order        []string
	attempts     map[string][]fakeAttempt
	alarms       []*Alarm
	restrictions map[string]*fakeRestriction
	audits       []audit.Event
	// notifications are the dss_notifications rows, with their status.
	notifications []fakeNotification
	// failNext makes the next call of the named method fail.
	failNext map[string]error
	txCount  int
	// loseLease makes the next Finish find the lease taken by another
	// attempt (the row is left as it is).
	loseLease bool
}

func newFakeRepo(clock *fakeClock) *fakeRepo {
	return &fakeRepo{clock: clock, rows: map[string]*fakeRow{}, attempts: map[string][]fakeAttempt{},
		restrictions: map[string]*fakeRestriction{}, failNext: map[string]error{}}
}

func (f *fakeRepo) fail(name string) error {
	if err, ok := f.failNext[name]; ok {
		delete(f.failNext, name)
		return err
	}
	return nil
}

// addVersion records a restriction version (state, window, feature).
func (f *fakeRepo) addVersion(v VersionInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.restrictions[v.RestrictionID]
	if r == nil {
		r = &fakeRestriction{}
		f.restrictions[v.RestrictionID] = r
	}
	if len(r.versions) > 0 {
		v.PrevState = r.versions[len(r.versions)-1].State
	}
	if v.ChangedAt.IsZero() {
		v.ChangedAt = f.clock.Now()
	}
	r.versions = append(r.versions, v)
	r.state = v.State
}

func (f *fakeRepo) row(id string) *fakeRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows[id]
}

func (f *fakeRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	f.mu.Lock()
	if err := f.fail("Tx"); err != nil {
		f.mu.Unlock()
		return err
	}
	f.txCount++
	// A snapshot to roll back to.
	saved := f.snapshot()
	f.mu.Unlock()
	t := &fakeTx{f: f}
	if err := fn(ctx, t); err != nil {
		f.mu.Lock()
		f.restore(saved)
		f.mu.Unlock()
		return err
	}
	return nil
}

type fakeSnapshot struct {
	rows          map[string]fakeRow
	order         []string
	attempts      map[string][]fakeAttempt
	alarms        []Alarm
	published     map[string]*int64
	dss           map[string]fakeDSS
	notifications []fakeNotification
	auditsLength  int
}

func (f *fakeRepo) snapshot() fakeSnapshot {
	s := fakeSnapshot{rows: map[string]fakeRow{}, order: slices.Clone(f.order), attempts: map[string][]fakeAttempt{},
		published: map[string]*int64{}, dss: map[string]fakeDSS{}, notifications: slices.Clone(f.notifications), auditsLength: len(f.audits)}
	for k, v := range f.rows {
		s.rows[k] = *v
	}
	for k, v := range f.attempts {
		s.attempts[k] = slices.Clone(v)
	}
	for _, a := range f.alarms {
		s.alarms = append(s.alarms, *a)
	}
	for k, r := range f.restrictions {
		s.published[k] = r.published
		d := r.dss
		d.writes = slices.Clone(d.writes)
		s.dss[k] = d
	}
	return s
}

func (f *fakeRepo) restore(s fakeSnapshot) {
	f.rows = map[string]*fakeRow{}
	for k := range s.rows {
		r := s.rows[k]
		f.rows[k] = &r
	}
	f.order, f.attempts = s.order, s.attempts
	f.alarms = nil
	for i := range s.alarms {
		a := s.alarms[i]
		f.alarms = append(f.alarms, &a)
	}
	for k, p := range s.published {
		f.restrictions[k].published = p
		f.restrictions[k].dss = s.dss[k]
	}
	f.notifications = s.notifications
	f.audits = f.audits[:s.auditsLength]
}

func (f *fakeRepo) blockedUntil(r *fakeRow) (time.Time, bool) {
	var until time.Time
	found := false
	for _, id := range f.order {
		p := f.rows[id]
		sameChannel := p.Kind == r.Kind || (IsDSSKind(p.Kind) && IsDSSKind(r.Kind))
		if sameChannel && p.RestrictionID == r.RestrictionID && p.Target == r.Target && p.AnspVersion < r.AnspVersion && p.State == StateQueued {
			t := p.NextRetryAt
			if p.leaseToken != "" && p.leaseUntil.After(t) {
				t = p.leaseUntil
			}
			if !found || t.Before(until) {
				until, found = t, true
			}
		}
	}
	return until, found
}

func (f *fakeRepo) Claim(_ context.Context, id, token string, lease time.Duration) (Claim, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Claim"); err != nil {
		return Claim{}, err
	}
	now := f.clock.Now()
	r, ok := f.rows[id]
	if !ok {
		return Claim{Outcome: Gone, Now: now}, nil
	}
	if r.State != StateQueued {
		return Claim{Outcome: Settled, Now: now, Delivery: r.Delivery}, nil
	}
	if r.leaseToken != "" && r.leaseUntil.After(now) {
		return Claim{Outcome: Leased, Now: now, Until: r.leaseUntil}, nil
	}
	if until, blocked := f.blockedUntil(r); blocked {
		if !until.After(now) {
			until = now.Add(time.Second)
		}
		if until.After(r.NextRetryAt) {
			r.NextRetryAt = until
		}
		return Claim{Outcome: Blocked, Now: now, Until: until}, nil
	}
	if r.NextRetryAt.After(now) {
		return Claim{Outcome: NotDue, Now: now, Until: r.NextRetryAt}, nil
	}
	r.leaseToken, r.leaseUntil = token, now.Add(lease)
	r.Attempt++
	at := now
	r.LastAttemptAt = &at
	return Claim{Outcome: Claimed, Now: now, Delivery: r.copy()}, nil
}

func (r *fakeRow) copy() Delivery {
	d := r.Delivery
	d.Body = slices.Clone(r.Body)
	return d
}

func (f *fakeRepo) Prepare(_ context.Context, id, token, method, url string, body []byte) (Delivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Prepare"); err != nil {
		return Delivery{}, err
	}
	r, ok := f.rows[id]
	if !ok || r.leaseToken != token {
		return Delivery{}, ErrNotFound
	}
	if r.Method == "" {
		r.Method, r.URL = method, url
		if r.Body == nil {
			r.Body = slices.Clone(body)
		}
	}
	return r.copy(), nil
}

func (f *fakeRepo) Pending(_ context.Context, publishGrace, stuckGrace time.Duration, limit int) ([]Pending, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Pending"); err != nil {
		return nil, err
	}
	now := f.clock.Now()
	var out []Pending
	for _, id := range f.order {
		r := f.rows[id]
		if r.State != StateQueued || (r.leaseToken != "" && r.leaseUntil.After(now)) {
			continue
		}
		switch {
		case r.busPublished == nil && r.QueuedAt.Before(now.Add(-publishGrace)):
			out = append(out, Pending{ID: id, Kind: r.Kind, BusSeq: r.BusSeq})
		case r.busPublished != nil && r.NextRetryAt.Before(now.Add(-stuckGrace)):
			last := *r.busPublished
			if r.LastAttemptAt != nil && r.LastAttemptAt.After(last) {
				last = *r.LastAttemptAt
			}
			if last.Before(now.Add(-stuckGrace)) {
				out = append(out, Pending{ID: id, Kind: r.Kind, BusSeq: r.BusSeq, Stuck: true})
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) QueuedOf(_ context.Context, rid string, version int64) ([]Pending, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("QueuedOf"); err != nil {
		return nil, err
	}
	var out []Pending
	for _, id := range f.order {
		r := f.rows[id]
		if r.RestrictionID == rid && r.AnspVersion == version && r.State == StateQueued && r.busPublished == nil {
			out = append(out, Pending{ID: id, Kind: r.Kind, BusSeq: r.BusSeq})
		}
	}
	return out, nil
}

func (f *fakeRepo) MarkBusPublished(_ context.Context, id string, seq int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("MarkBusPublished"); err != nil {
		return false, err
	}
	r, ok := f.rows[id]
	if !ok || r.BusSeq != seq-1 {
		return false, nil
	}
	now := f.clock.Now()
	r.BusSeq, r.busPublished = seq, &now
	return true, nil
}

func (f *fakeRepo) Version(_ context.Context, rid string, version int64) (VersionInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Version"); err != nil {
		return VersionInfo{}, err
	}
	r, ok := f.restrictions[rid]
	if !ok {
		return VersionInfo{}, ErrNotFound
	}
	if version == 0 {
		version = int64(len(r.versions))
	}
	if version < 1 || int(version) > len(r.versions) {
		return VersionInfo{}, ErrNotFound
	}
	v := r.versions[version-1]
	v.CurrentState, v.CurrentVersion, v.PublishedVersion = r.state, int64(len(r.versions)), r.published
	v.DSS = r.dss.status()
	return v, nil
}

func (f *fakeRepo) Overdue(_ context.Context, after time.Duration, limit int) ([]Overdue, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Overdue"); err != nil {
		return nil, err
	}
	now := f.clock.Now()
	ids := make([]string, 0, len(f.restrictions))
	for id := range f.restrictions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Overdue
	for _, id := range ids {
		r := f.restrictions[id]
		cur := r.versions[len(r.versions)-1]
		pub := int64(0)
		if r.published != nil {
			pub = *r.published
		}
		open := f.openCISP(id)
		terminal := r.state == "ended" || r.state == "cancelled"
		switch {
		case pub >= cur.Version:
			continue
		case r.state == "active" && cur.ChangedAt.After(now.Add(-after)):
			continue
		case r.state != "active" && (!terminal || open == nil || open.AnspVersion >= cur.Version):
			continue
		}
		if open != nil && open.AnspVersion >= cur.Version {
			continue
		}
		o := Overdue{RestrictionID: id, AnspVersion: cur.Version, ChangedAt: cur.ChangedAt}
		if open != nil {
			o.AlarmID = open.ID
		}
		out = append(out, o)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) openCISP(rid string) *Alarm {
	for _, a := range f.alarms {
		if a.Kind == AlarmCISPNotPublished && a.RestrictionID == rid && a.ClearedAt == nil {
			return a
		}
	}
	return nil
}

func (f *fakeRepo) Clearable(_ context.Context, limit int) ([]Clearable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Clearable"); err != nil {
		return nil, err
	}
	var out []Clearable
	for _, a := range f.alarms {
		if a.Kind != AlarmCISPNotPublished || a.ClearedAt != nil {
			continue
		}
		r := f.restrictions[a.RestrictionID]
		pub := int64(0)
		if r.published != nil {
			pub = *r.published
		}
		cur := int64(len(r.versions))
		queued := false
		for _, d := range f.rows {
			if d.Kind == KindDirect && d.RestrictionID == a.RestrictionID && d.AnspVersion == cur && d.State == StateQueued {
				queued = true
			}
		}
		if pub >= cur || (r.state != "active" && a.AnspVersion >= cur && !queued) {
			out = append(out, Clearable{AlarmID: a.ID, RestrictionID: a.RestrictionID, State: r.state, AnspVersion: cur, PublishedVersion: pub})
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) ActiveRefs(_ context.Context, limit int) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("ActiveRefs"); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range f.restrictions {
		if r.state == "active" {
			out = append(out, r.versions[0].AnspRef)
		}
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeRepo) Unpublished(_ context.Context, limit int) ([]Unpublished, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Unpublished"); err != nil {
		return nil, err
	}
	var out []Unpublished
	for id, r := range f.restrictions {
		cur := int64(len(r.versions))
		pub := int64(0)
		if r.published != nil {
			pub = *r.published
		}
		if r.state == "active" && pub < cur {
			out = append(out, Unpublished{RestrictionID: id, AnspRef: r.versions[0].AnspRef, AnspVersion: cur})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RestrictionID < out[j].RestrictionID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeRepo) Alarms(_ context.Context, all bool, limit int) ([]Alarm, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Alarms"); err != nil {
		return nil, err
	}
	var out []Alarm
	for i := len(f.alarms) - 1; i >= 0; i-- {
		if all || f.alarms[i].ClearedAt == nil {
			out = append(out, *f.alarms[i])
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) Alarm(_ context.Context, id string) (Alarm, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.alarms {
		if a.ID == id {
			return *a, nil
		}
	}
	return Alarm{}, ErrNotFound
}

func (f *fakeRepo) Channels(_ context.Context, rid string, version int64) ([]ChannelRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Channels"); err != nil {
		return nil, err
	}
	var out []ChannelRow
	for _, id := range f.order {
		r := f.rows[id]
		if r.RestrictionID == rid && r.AnspVersion == version {
			out = append(out, ChannelRow{Kind: r.Kind, State: r.State, Attempt: r.Attempt, LastAttemptAt: r.LastAttemptAt,
				StatusCode: r.StatusCode, NextRetryAt: r.NextRetryAt})
		}
	}
	return out, nil
}

func (f *fakeRepo) Attempts(_ context.Context, id string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.attempts[id]), nil
}

// fakeTx runs against the repo under its lock, call by call.
type fakeTx struct{ f *fakeRepo }

func (t *fakeTx) Now(context.Context) (time.Time, error) { return t.f.clock.Now(), nil }

func (t *fakeTx) Insert(_ context.Context, j Job, maxAttempts int, window time.Duration) (bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Insert"); err != nil {
		return false, err
	}
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind == j.Kind && r.IdempotencyKey == j.IdempotencyKey() && r.Target == j.Target {
			return false, nil
		}
	}
	now := f.clock.Now()
	f.rows[j.ID] = &fakeRow{Delivery: Delivery{ID: j.ID, Kind: j.Kind, SubjectRef: j.SubjectRef(), RestrictionID: j.RestrictionID,
		AnspVersion: j.AnspVersion, Op: j.Op, Target: j.Target, IdempotencyKey: j.IdempotencyKey(), State: StateQueued,
		MaxAttempts: maxAttempts, QueuedAt: now, WindowEndsAt: now.Add(window), NextRetryAt: now, Body: slices.Clone(j.Body)}}
	f.order = append(f.order, j.ID)
	return true, nil
}

func (t *fakeTx) Finish(_ context.Context, a Attempt) (bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Finish"); err != nil {
		return false, err
	}
	f.attempts[a.ID] = append(f.attempts[a.ID], fakeAttempt{Attempt: a, At: f.clock.Now()})
	if f.loseLease {
		f.loseLease = false
		return false, nil
	}
	r, ok := f.rows[a.ID]
	if !ok || r.leaseToken != a.Token || r.State != StateQueued {
		return false, nil
	}
	r.State, r.leaseToken, r.StatusCode, r.Excerpt, r.LastError = a.State, "", a.StatusCode, a.Excerpt, a.Error
	switch a.State {
	case StateSent:
		now := f.clock.Now()
		r.SentAt = &now
	case StateQueued:
		r.NextRetryAt = a.RetryAt
	case StateCancelled:
		r.CancelReason = a.CancelReason
	case StateFailed, StateAbandoned:
	}
	return true, nil
}

func (t *fakeTx) MarkPublishedVersion(_ context.Context, rid string, version int64) (PublishedState, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.restrictions[rid]
	if !ok {
		return PublishedState{}, ErrNotFound
	}
	if r.published == nil || *r.published < version {
		v := version
		r.published = &v
	}
	return PublishedState{State: r.state, AnspVersion: int64(len(r.versions)), PublishedVersion: *r.published}, nil
}

func (t *fakeTx) CancelQueued(_ context.Context, kind Kind, rid string, upTo int64, reason string) ([]Cancelled, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Cancelled
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind == kind && r.RestrictionID == rid && r.AnspVersion <= upTo && r.State == StateQueued {
			r.State, r.CancelReason, r.leaseToken = StateCancelled, reason, ""
			out = append(out, Cancelled{ID: id, Target: r.Target, AnspVersion: r.AnspVersion})
		}
	}
	return out, nil
}

func (t *fakeTx) RaiseAlarm(_ context.Context, a Alarm) (Alarm, bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("RaiseAlarm"); err != nil {
		return Alarm{}, false, err
	}
	for _, x := range f.alarms {
		if a.Kind == AlarmCISPNotPublished && x.Kind == a.Kind && x.RestrictionID == a.RestrictionID && x.ClearedAt == nil {
			return *x, false, nil
		}
		if a.Kind != AlarmCISPNotPublished && x.Kind == a.Kind && x.DeliveryID == a.DeliveryID {
			return *x, false, nil
		}
	}
	a.RaisedAt = f.clock.Now()
	f.alarms = append(f.alarms, &a)
	return a, true, nil
}

func (t *fakeTx) AdvanceAlarm(_ context.Context, id string, version int64, detail string) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.alarms {
		if a.ID == id && a.ClearedAt == nil && a.AnspVersion < version {
			a.AnspVersion, a.Detail = version, detail
		}
	}
	return nil
}

func (t *fakeTx) ClearCISPAlarm(_ context.Context, rid, reason string) (Alarm, bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.openCISP(rid)
	if a == nil {
		return Alarm{}, false, nil
	}
	now := f.clock.Now()
	a.ClearedAt, a.ClearReason = &now, reason
	return *a, true, nil
}

func (t *fakeTx) AcknowledgeAlarm(_ context.Context, id, by, reason string) (Alarm, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.alarms {
		if a.ID != id {
			continue
		}
		if a.AcknowledgedAt != nil || a.ClearedAt != nil {
			return Alarm{}, ErrAcknowledged
		}
		now := f.clock.Now()
		a.AcknowledgedAt, a.AcknowledgedBy, a.AckReason = &now, by, reason
		if a.Kind != AlarmCISPNotPublished && a.Kind != AlarmNotifyLate {
			a.ClearedAt, a.ClearReason = &now, "acknowledged"
		}
		return *a, nil
	}
	return Alarm{}, ErrNotFound
}

func (t *fakeTx) Expedite(_ context.Context, kind Kind, rid string) ([]Pending, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Expedite"); err != nil {
		return nil, err
	}
	var out []Pending
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind == kind && r.RestrictionID == rid && r.State == StateQueued {
			r.NextRetryAt = f.clock.Now()
			out = append(out, Pending{ID: id, Kind: r.Kind, BusSeq: r.BusSeq})
		}
	}
	return out, nil
}

func (t *fakeTx) Requeue(_ context.Context, kind Kind, rid string, version int64, extra int, window time.Duration) (Pending, bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind == kind && r.RestrictionID == rid && r.AnspVersion == version && r.State == StateAbandoned {
			now := f.clock.Now()
			r.State, r.MaxAttempts, r.WindowEndsAt, r.NextRetryAt = StateQueued, r.Attempt+extra, now.Add(window), now
			return Pending{ID: id, Kind: r.Kind, BusSeq: r.BusSeq}, true, nil
		}
	}
	return Pending{}, false, nil
}

func (t *fakeTx) Audit(_ context.Context, ev audit.Event) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Audit"); err != nil {
		return err
	}
	f.audits = append(f.audits, ev)
	return nil
}

// fakeBus records publishes and may fail them.
type fakeBus struct {
	mu   sync.Mutex
	msgs []busMsg
	err  error
}

type busMsg struct {
	subject, id string
	data        []byte
}

func (b *fakeBus) Publish(_ context.Context, subject, msgID string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	for _, m := range b.msgs {
		if m.id == msgID {
			return nil // the stream's duplicate window
		}
	}
	b.msgs = append(b.msgs, busMsg{subject: subject, id: msgID, data: slices.Clone(data)})
	return nil
}

func (b *fakeBus) all() []busMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.msgs)
}

// bodies is the restr.v1 bodies published.
func (b *fakeBus) bodies(prefix string) []map[string]any {
	var out []map[string]any
	for _, m := range b.all() {
		if len(m.subject) < len(prefix) || m.subject[:len(prefix)] != prefix {
			continue
		}
		var env struct {
			Body map[string]any `json:"body"`
		}
		_ = json.Unmarshal(m.data, &env)
		out = append(out, env.Body)
	}
	return out
}

// fakeMsg is a work-queue message.
type fakeMsg struct {
	data   []byte
	mu     sync.Mutex
	acked  bool
	naked  []time.Duration
	termed bool
}

func (m *fakeMsg) Data() []byte { return m.data }
func (m *fakeMsg) Ack() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked = true
	return nil
}

func (m *fakeMsg) NakWithDelay(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.naked = append(m.naked, d)
	return nil
}

func (m *fakeMsg) Term() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.termed = true
	return nil
}

var errBoom = errors.New("boom")
