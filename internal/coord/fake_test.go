package coord

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
)

// fakeRepo is Repo in memory with the store's semantics: a transaction
// that fails leaves nothing behind, the escalation query's rule, the
// unique (sender, notice_ref).
type fakeRepo struct {
	mu  sync.Mutex
	now time.Time

	notices map[string]Notice
	audits  []audit.Event
	occ     map[string]Occurrence // by delivery id
	jobs    []deliver.Job
	alarms  map[string]deliver.Alarm
	refSeq  int

	// restrictions answered by Intersecting; boxes what it was asked.
	restrictions []string
	boxes        [][]Box

	undelivered []Undelivered
	delivered   []AlarmRef

	failAudit, failNow, failNotices, failMark, failInsert, failBehind, failOcc error
	failRaise, failClear, failIntersect, failEscalate                          error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), notices: map[string]Notice{},
		occ: map[string]Occurrence{}, alarms: map[string]deliver.Alarm{}}
}

func (r *fakeRepo) Now(context.Context) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNow != nil {
		return time.Time{}, r.failNow
	}
	return r.now, nil
}

func (r *fakeRepo) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *fakeRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	r.mu.Lock()
	saved := struct {
		notices map[string]Notice
		audits  []audit.Event
		occ     map[string]Occurrence
		jobs    []deliver.Job
		alarms  map[string]deliver.Alarm
	}{maps.Clone(r.notices), slices.Clone(r.audits), maps.Clone(r.occ), slices.Clone(r.jobs), maps.Clone(r.alarms)}
	r.mu.Unlock()
	err := fn(ctx, fakeTx{r: r})
	if err != nil {
		r.mu.Lock()
		r.notices, r.audits, r.occ, r.jobs, r.alarms = saved.notices, saved.audits, saved.occ, saved.jobs, saved.alarms
		r.mu.Unlock()
	}
	return err
}

func (r *fakeRepo) Notice(_ context.Context, id string) (Notice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.notices[id]
	if !ok {
		return Notice{}, ErrNotFound
	}
	return n, nil
}

func (r *fakeRepo) sorted() []Notice {
	out := slices.Collect(maps.Values(r.notices))
	sort.Slice(out, func(i, j int) bool { return out[i].AckID > out[j].AckID })
	return out
}

func (r *fakeRepo) Notices(_ context.Context, f Filter) ([]Notice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNotices != nil {
		return nil, r.failNotices
	}
	var out []Notice
	for _, n := range r.sorted() { //nolint:gocritic // a test fake copies freely
		switch f.State {
		case "", string(n.State()):
		case FilterOpen:
			if n.Acknowledged {
				continue
			}
		default:
			continue
		}
		if f.Since != nil && n.ReceivedAt.Before(*f.Since) {
			continue
		}
		out = append(out, n)
		if len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

func (r *fakeRepo) BehindBus(_ context.Context, limit int) ([]Notice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failBehind != nil {
		return nil, r.failBehind
	}
	var out []Notice
	for _, n := range r.sorted() { //nolint:gocritic // a test fake copies freely
		if n.BusSeq < n.EventSeq && len(out) < limit {
			out = append(out, n)
		}
	}
	return out, nil
}

func (r *fakeRepo) CountBehindBus(ctx context.Context) (int, error) {
	l, err := r.BehindBus(ctx, 1<<20)
	return len(l), err
}

func (r *fakeRepo) MarkBus(_ context.Context, id string, seq int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failMark != nil {
		return r.failMark
	}
	n := r.notices[id]
	if seq <= n.EventSeq && seq > n.BusSeq {
		n.BusSeq = seq
		r.notices[id] = n
	}
	return nil
}

func (r *fakeRepo) OccurrenceByDelivery(_ context.Context, id string) (Occurrence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failOcc != nil {
		return Occurrence{}, r.failOcc
	}
	o, ok := r.occ[id]
	if !ok {
		return Occurrence{}, ErrNotFound
	}
	return o, nil
}

func (r *fakeRepo) Undelivered(context.Context, time.Time, time.Duration, int) ([]Undelivered, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.undelivered
	r.undelivered = nil
	return out, nil
}

func (r *fakeRepo) DeliveredAlarms(context.Context, int) ([]AlarmRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.delivered
	r.delivered = nil
	return out, nil
}

func (r *fakeRepo) audited(eventType string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.audits {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

type fakeTx struct {
	r *fakeRepo
	deliver.Tx
}

func (t fakeTx) InsertNotice(_ context.Context, n NewNotice) (Notice, bool, error) {
	r := t.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failInsert != nil {
		return Notice{}, false, r.failInsert
	}
	for _, x := range r.notices { //nolint:gocritic // a test fake copies freely
		if x.SenderClientID == n.SenderClientID && x.NoticeRef == n.NoticeRef {
			return Notice{}, false, nil
		}
	}
	out := Notice{AckID: n.AckID, Kind: n.Kind, SenderClientID: n.SenderClientID, USSPID: n.USSPID, NoticeRef: n.NoticeRef,
		Payload: bytes.Clone(n.Payload), PayloadSHA256: n.PayloadSHA256, IntentRefs: n.IntentRefs, AuthorisationNumbers: n.AuthorisationNumbers,
		ReceivedAt: n.ReceivedAt, AckRequired: n.AckRequired, SenderUnverified: n.SenderUnverified, RestrictionIDs: n.RestrictionIDs,
		CISVersion: n.CISVersion, EventSeq: 1}
	r.notices[n.AckID] = out
	return out, true, nil
}

func (t fakeTx) NoticeBySenderRef(_ context.Context, sender, ref string) (Notice, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	for _, x := range t.r.notices { //nolint:gocritic // a test fake copies freely
		if x.SenderClientID == sender && x.NoticeRef == ref {
			return x, nil
		}
	}
	return Notice{}, ErrNotFound
}

func (t fakeTx) CountSenderNotices(_ context.Context, sender string, since time.Time) (int64, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	var n int64
	for _, x := range t.r.notices { //nolint:gocritic // a test fake copies freely
		if x.SenderClientID == sender && (!x.ReceivedAt.Before(since) || (x.AckRequired && !x.Acknowledged)) {
			n++
		}
	}
	return n, nil
}

func (t fakeTx) Intersecting(_ context.Context, boxes []Box, limit int) ([]string, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.r.failIntersect != nil {
		return nil, t.r.failIntersect
	}
	t.r.boxes = append(t.r.boxes, boxes)
	out := slices.Clone(t.r.restrictions)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t fakeTx) Acknowledge(_ context.Context, id, role, user, note string) (Notice, bool, error) {
	r := t.r
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.notices[id]
	if !ok || n.Acknowledged {
		return Notice{}, false, nil
	}
	at := r.now
	n.Acknowledged, n.AcknowledgedBy, n.AcknowledgedUser, n.AcknowledgedAt, n.AckNote = true, role, user, &at, note
	n.EventSeq++
	r.notices[id] = n
	return n, true, nil
}

// EscalateDue is the store's rule (coord.sql EscalateDue).
func (t fakeTx) EscalateDue(_ context.Context, now time.Time, esc, repeat time.Duration, limit int) ([]Notice, error) {
	r := t.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failEscalate != nil {
		return nil, r.failEscalate
	}
	var out []Notice
	for _, n := range r.sorted() { //nolint:gocritic // a test fake copies freely
		if n.Acknowledged || !n.AckRequired || n.ReceivedAt.After(now.Add(-esc)) {
			continue
		}
		if n.LastEscalatedAt != nil && n.LastEscalatedAt.After(now.Add(-repeat)) {
			continue
		}
		if len(out) == limit {
			break
		}
		at := now
		if n.EscalatedAt == nil {
			n.EscalatedAt = &at
		}
		n.LastEscalatedAt = &at
		n.Escalations++
		n.EventSeq++
		r.notices[n.AckID] = n
		out = append(out, n)
	}
	return out, nil
}

func (t fakeTx) NextOccurrenceRef(context.Context) (string, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	t.r.refSeq++
	return "ANSP-OCC-2026-" + leftPad(t.r.refSeq), nil
}

func leftPad(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

func (t fakeTx) InsertOccurrence(_ context.Context, o NewOccurrence) (Occurrence, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	out := Occurrence{NewOccurrence: o, CreatedAt: t.r.now, DeadlineAt: o.BecameAwareAt.Add(OccurrenceDeadline)}
	t.r.occ[o.DeliveryID] = out
	return out, nil
}

func (t fakeTx) Outbox() deliver.Tx { return t }

func (t fakeTx) Audit(_ context.Context, ev audit.Event) error {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.r.failAudit != nil {
		return t.r.failAudit
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	t.r.audits = append(t.r.audits, ev)
	return nil
}

// The outbox's side of the transaction (deliver.Tx), as far as the
// occurrence outbox uses it.

func (t fakeTx) Now(ctx context.Context) (time.Time, error) { return t.r.Now(ctx) }

func (t fakeTx) Insert(_ context.Context, j deliver.Job, _ int, _ time.Duration) (bool, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	t.r.jobs = append(t.r.jobs, j)
	return true, nil
}

func (t fakeTx) RaiseAlarm(_ context.Context, a deliver.Alarm) (deliver.Alarm, bool, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.r.failRaise != nil {
		return deliver.Alarm{}, false, t.r.failRaise
	}
	for _, x := range t.r.alarms { //nolint:gocritic // a test fake copies freely
		if x.DeliveryID == a.DeliveryID && x.Kind == a.Kind {
			return x, false, nil
		}
	}
	a.RaisedAt = t.r.now
	t.r.alarms[a.ID] = a
	return a, true, nil
}

func (t fakeTx) ClearAlarm(_ context.Context, id, reason string) (deliver.Alarm, bool, error) {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.r.failClear != nil {
		return deliver.Alarm{}, false, t.r.failClear
	}
	a, ok := t.r.alarms[id]
	if !ok || a.ClearedAt != nil {
		return deliver.Alarm{}, false, nil
	}
	at := t.r.now
	a.ClearedAt, a.ClearReason = &at, reason
	t.r.alarms[id] = a
	return a, true, nil
}

// fakeBus records publishes; err fails them.
type fakeBus struct {
	mu   sync.Mutex
	msgs []busMsg
	err  error
}

type busMsg struct {
	subject, id string
	data        []byte
}

func (b *fakeBus) Publish(_ context.Context, subject, id string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.msgs = append(b.msgs, busMsg{subject, id, data})
	return nil
}

func (b *fakeBus) published() []busMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.msgs)
}

func (b *fakeBus) fail(err error) {
	b.mu.Lock()
	b.err = err
	b.mu.Unlock()
}

var errBoom = errors.New("boom")
