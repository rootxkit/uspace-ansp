package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// The DSS half of the fake store (WP-9), with the store's rules: the
// standing of a restriction follows what is queued and written, a put of
// an older version never replaces a newer, notification rows settle with
// their job.

type fakeNotification struct {
	Notification
	status State
	sentAt *time.Time
}

func (d fakeDSS) status() DSSStatus {
	out := DSSStatus{State: d.state, AnspVersion: d.putVersion, DSSVersion: d.dssVersion}
	if out.State == "" {
		out.State = DSSNone
	}
	if d.since != nil {
		s := restriction.Stamp(*d.since)
		out.Since = &s
	}
	return out
}

// setConstraint records version n's constraint document (the details
// WP-5 derived) and the restriction's constraint id.
func (f *fakeRepo) setConstraint(rid, constraintID string, n int64, doc json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.restrictions[rid]
	for int64(len(r.constraints)) < n {
		r.constraints = append(r.constraints, nil)
	}
	r.constraints[n-1] = doc
	r.dss.constraintID = constraintID
}

func (f *fakeRepo) dssOf(rid string) fakeDSS {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restrictions[rid].dss
}

func (f *fakeRepo) notificationRows() []fakeNotification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeNotification(nil), f.notifications...)
}

func (f *fakeRepo) DSSInfo(_ context.Context, rid string, version int64) (DSSInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("DSSInfo"); err != nil {
		return DSSInfo{}, err
	}
	r, ok := f.restrictions[rid]
	if !ok || version < 1 || int(version) > len(r.versions) {
		return DSSInfo{}, ErrNotFound
	}
	var doc json.RawMessage
	if int(version) <= len(r.constraints) {
		doc = r.constraints[version-1]
	}
	return DSSInfo{RestrictionID: rid, AnspRef: r.versions[0].AnspRef, ConstraintID: r.dss.constraintID, OVN: r.dss.ovn,
		CurrentState: r.state, Version: version, Constraint: doc}, nil
}

func (f *fakeRepo) Notification(_ context.Context, id string) (NotificationJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("Notification"); err != nil {
		return NotificationJob{}, err
	}
	var out NotificationJob
	found := false
	for i := range f.notifications {
		n := &f.notifications[i]
		if n.DeliveryID != id {
			continue
		}
		if !found {
			found = true
			out.ConstraintID, out.Op = n.ConstraintID, n.Op
			r := f.restrictions[n.RestrictionID]
			for _, w := range r.dss.writes {
				if w.AnspVersion == n.AnspVersion && w.Op == n.Op && w.Reference != nil {
					out.Reference, _ = json.Marshal(w.Reference)
				}
			}
			if int(n.AnspVersion) <= len(r.constraints) && r.constraints[n.AnspVersion-1] != nil {
				var sc struct {
					Details json.RawMessage `json:"details"`
				}
				_ = json.Unmarshal(r.constraints[n.AnspVersion-1], &sc)
				out.Details = sc.Details
			}
		}
		out.Subscriptions = append(out.Subscriptions, f3548.SubscriptionState{SubscriptionId: n.SubscriptionID, NotificationIndex: n.NotificationIndex})
	}
	if !found {
		return NotificationJob{}, ErrNotFound
	}
	sort.Slice(out.Subscriptions, func(i, j int) bool { return out.Subscriptions[i].SubscriptionId < out.Subscriptions[j].SubscriptionId })
	return out, nil
}

func (f *fakeRepo) LateNotifications(_ context.Context, latency time.Duration, limit int) ([]Late, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("LateNotifications"); err != nil {
		return nil, err
	}
	now := f.clock.Now()
	var out []Late
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind != KindUSSNotify || r.State != StateQueued || r.QueuedAt.After(now.Add(-latency)) {
			continue
		}
		alarmed := false
		for _, a := range f.alarms {
			if a.DeliveryID == id && a.Kind == AlarmNotifyLate {
				alarmed = true
			}
		}
		if !alarmed {
			out = append(out, Late{DeliveryID: id, RestrictionID: r.RestrictionID, AnspVersion: r.AnspVersion, Target: r.Target, QueuedAt: r.QueuedAt})
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) ClearableLate(_ context.Context, limit int) ([]LateClearable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("ClearableLate"); err != nil {
		return nil, err
	}
	var out []LateClearable
	for _, a := range f.alarms {
		if a.Kind != AlarmNotifyLate || a.ClearedAt != nil {
			continue
		}
		if r := f.rows[a.DeliveryID]; r != nil && r.State != StateQueued {
			out = append(out, LateClearable{AlarmID: a.ID, DeliveryID: a.DeliveryID, State: r.State})
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeRepo) DSSBacklog(context.Context) (int, *time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("DSSBacklog"); err != nil {
		return 0, nil, err
	}
	n := 0
	var oldest *time.Time
	for _, id := range f.order {
		r := f.rows[id]
		if IsDSSKind(r.Kind) && r.State == StateQueued {
			n++
			if oldest == nil || r.QueuedAt.Before(*oldest) {
				t := r.QueuedAt
				oldest = &t
			}
		}
	}
	return n, oldest, nil
}

// settle is SettleDSS under the lock.
func (f *fakeRepo) settle(rid string, failed bool) error {
	r, ok := f.restrictions[rid]
	if !ok {
		return ErrNotFound
	}
	pending := false
	for _, id := range f.order {
		x := f.rows[id]
		if x.RestrictionID == rid && IsDSSKind(x.Kind) && x.State == StateQueued {
			pending = true
		}
	}
	d := &r.dss
	switch {
	case pending:
		d.state = DSSPending
	case failed:
		d.state = DSSFailed
	case d.ovn != nil:
		d.state = DSSWritten
	case d.reference != nil:
		d.state = DSSDeleted
	default:
		d.state = DSSNone
	}
	if pending || failed {
		if d.since == nil {
			now := f.clock.Now()
			d.since = &now
		}
	} else {
		d.since = nil
	}
	return nil
}

func (t *fakeTx) SettleDSS(_ context.Context, rid string, failed bool) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("SettleDSS"); err != nil {
		return err
	}
	return f.settle(rid, failed)
}

func (t *fakeTx) RecordDSSWrite(_ context.Context, w DSSWrite) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("RecordDSSWrite"); err != nil {
		return err
	}
	r, ok := f.restrictions[w.RestrictionID]
	if !ok {
		return ErrNotFound
	}
	for _, x := range r.dss.writes {
		if x.AnspVersion == w.AnspVersion && x.Op == w.Op {
			return f.settle(w.RestrictionID, false)
		}
	}
	r.dss.writes = append(r.dss.writes, w)
	switch w.Op {
	case OpDSSPut:
		if w.Reference == nil || w.Reference.Ovn == nil {
			return errors.New("a put without a reference and its ovn")
		}
		if r.dss.putVersion == nil || *r.dss.putVersion <= w.AnspVersion {
			ref, _ := json.Marshal(w.Reference)
			v, dv := w.AnspVersion, int64(w.Reference.Version)
			r.dss.ovn, r.dss.reference, r.dss.putVersion, r.dss.dssVersion = w.Reference.Ovn, ref, &v, &dv
		}
	case OpDSSDelete:
		r.dss.ovn = nil
	}
	return f.settle(w.RestrictionID, false)
}

func (t *fakeTx) InsertNotification(_ context.Context, n Notification) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("InsertNotification"); err != nil {
		return err
	}
	for i := range f.notifications {
		if x := &f.notifications[i]; x.DeliveryID == n.DeliveryID && strings.EqualFold(x.SubscriptionID, n.SubscriptionID) {
			return nil
		}
	}
	f.notifications = append(f.notifications, fakeNotification{Notification: n, status: StateQueued})
	return nil
}

func (t *fakeTx) SettleNotifications(_ context.Context, id string, state State) error {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("SettleNotifications"); err != nil {
		return err
	}
	for i := range f.notifications {
		n := &f.notifications[i]
		if n.DeliveryID == id && n.status == StateQueued {
			n.status = state
			if state == StateSent {
				now := f.clock.Now()
				n.sentAt = &now
			}
		}
	}
	return nil
}

func (t *fakeTx) CancelQueuedTo(_ context.Context, kind Kind, rid, target string, below int64, reason string) ([]Cancelled, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Cancelled
	for _, id := range f.order {
		r := f.rows[id]
		if r.Kind == kind && r.RestrictionID == rid && r.Target == target && r.AnspVersion < below && r.State == StateQueued {
			r.State, r.CancelReason, r.leaseToken = StateCancelled, reason, ""
			out = append(out, Cancelled{ID: id, Target: r.Target, AnspVersion: r.AnspVersion})
		}
	}
	return out, nil
}

func (t *fakeTx) ClearAlarm(_ context.Context, id, reason string) (Alarm, bool, error) {
	f := t.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail("ClearAlarm"); err != nil {
		return Alarm{}, false, err
	}
	for _, a := range f.alarms {
		if a.ID == id && a.ClearedAt == nil {
			now := f.clock.Now()
			a.ClearedAt, a.ClearReason = &now, reason
			return *a, true, nil
		}
	}
	return Alarm{}, false, nil
}
