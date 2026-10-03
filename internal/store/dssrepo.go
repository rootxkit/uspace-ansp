package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// The DSS channel's rows (WP-9): deliver.Repo and deliver.Tx methods of
// the F3548 constraint manager.

// DSSInfo is what a DSS job of a version reads at its attempt.
func (r DeliverRepo) DSSInfo(ctx context.Context, restrictionID string, version int64) (deliver.DSSInfo, error) {
	var out deliver.DSSInfo
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.DSSInfo(ctx, relational.DSSInfoParams{Version: version, ID: restrictionID})
		if err != nil {
			return restrictionNotFound(err)
		}
		if row.DssConstraintID == nil {
			return fmt.Errorf("restriction %s has no dss_constraint_id", restrictionID)
		}
		out = deliver.DSSInfo{RestrictionID: row.ID, AnspRef: row.AnspRef, ConstraintID: row.DssConstraintID.String(), OVN: row.DssOvn,
			CurrentState: string(row.CurrentState), Version: row.Version, Constraint: row.Constraint}
		return nil
	})
	return out, err
}

// Notification is the write a uss_notify job reports and its
// subscriptions.
func (r DeliverRepo) Notification(ctx context.Context, deliveryID string) (deliver.NotificationJob, error) {
	var out deliver.NotificationJob
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.DSSNotificationJob(ctx, deliveryID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return deliver.ErrNotFound
		}
		out = deliver.NotificationJob{ConstraintID: rows[0].ConstraintID.String(), Op: rows[0].Op, Reference: rows[0].Reference, Details: rows[0].Details}
		for _, x := range rows {
			out.Subscriptions = append(out.Subscriptions, f3548.SubscriptionState{SubscriptionId: x.SubscriptionID.String(), NotificationIndex: x.NotificationIndex})
		}
		return nil
	})
	return out, err
}

// LateNotifications is the uss_notify jobs queued past latency without
// an alarm.
func (r DeliverRepo) LateNotifications(ctx context.Context, latency time.Duration, limit int) ([]deliver.Late, error) {
	var out []deliver.Late
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.LateNotifications(ctx, relational.LateNotificationsParams{LatencyS: secs(latency), PageSize: i32(min(max(limit, 1), 1000))})
		for _, x := range rows {
			out = append(out, deliver.Late{DeliveryID: x.ID, RestrictionID: deref(x.RestrictionID), AnspVersion: deref(x.AnspVersion),
				Target: x.Target, QueuedAt: x.QueuedAt})
		}
		return err
	})
	return out, err
}

// ClearableLate is the open uss_notify_late alarms whose job is settled.
func (r DeliverRepo) ClearableLate(ctx context.Context, limit int) ([]deliver.LateClearable, error) {
	var out []deliver.LateClearable
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.ClearableLateAlarms(ctx, i32(min(max(limit, 1), 1000)))
		for _, x := range rows {
			out = append(out, deliver.LateClearable{AlarmID: x.ID, DeliveryID: deref(x.DeliveryID), State: deliver.State(x.State)})
		}
		return err
	})
	return out, err
}

// DSSBacklog is the DSS writes queued and the oldest's queued_at.
func (r DeliverRepo) DSSBacklog(ctx context.Context) (int, *time.Time, error) {
	var n int
	var oldest *time.Time
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.DSSBacklog(ctx)
		if err != nil {
			return err
		}
		n = int(row.N)
		if n > 0 {
			t := row.Oldest.UTC()
			oldest = &t
		}
		return nil
	})
	return n, oldest, err
}

// SettleDSS sets the restriction's dss_state.
func (t deliverTx) SettleDSS(ctx context.Context, restrictionID string, failed bool) error {
	return t.tx.Q.SettleDSS(ctx, relational.SettleDSSParams{Failed: failed, ID: restrictionID})
}

// RecordDSSWrite records what the DSS accepted, then settles the
// restriction's standing.
func (t deliverTx) RecordDSSWrite(ctx context.Context, w deliver.DSSWrite) error {
	cid, err := uuid.Parse(w.ConstraintID)
	if err != nil {
		return fmt.Errorf("constraint id: %w", err)
	}
	var ref json.RawMessage
	var ovn *string
	var ver *int64
	if w.Reference != nil {
		if ref, err = json.Marshal(w.Reference); err != nil {
			return err
		}
		ovn = w.Reference.Ovn
		v := int64(w.Reference.Version)
		ver = &v
	}
	n := 0
	for _, s := range w.Subscribers {
		n += len(s.Subscriptions)
	}
	if err := t.tx.Q.InsertDSSWrite(ctx, relational.InsertDSSWriteParams{RestrictionID: w.RestrictionID, AnspVersion: w.AnspVersion,
		Op: w.Op, DeliveryID: w.DeliveryID, ConstraintID: cid, Ovn: ovn, DssVersion: ver, Reference: ref, Subscribers: i32(n)}); err != nil {
		return err
	}
	switch w.Op {
	case deliver.OpDSSPut:
		if w.Reference == nil || ovn == nil {
			return errors.New("a put the DSS accepted without a reference and its ovn")
		}
		if err := t.tx.Q.RecordDSSPut(ctx, relational.RecordDSSPutParams{Ovn: ovn, DssVersion: ver, Reference: ref,
			Version: w.AnspVersion, ID: w.RestrictionID}); err != nil {
			return err
		}
	case deliver.OpDSSDelete:
		if err := t.tx.Q.RecordDSSDelete(ctx, w.RestrictionID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("a DSS write of op %q", w.Op)
	}
	return t.SettleDSS(ctx, w.RestrictionID, false)
}

// InsertNotification writes one dss_notifications row.
func (t deliverTx) InsertNotification(ctx context.Context, n deliver.Notification) error {
	sid, err := uuid.Parse(n.SubscriptionID)
	if err != nil {
		return fmt.Errorf("subscription id: %w", err)
	}
	cid, err := uuid.Parse(n.ConstraintID)
	if err != nil {
		return fmt.Errorf("constraint id: %w", err)
	}
	return t.tx.Q.InsertDSSNotification(ctx, relational.InsertDSSNotificationParams{DeliveryID: n.DeliveryID, SubscriptionID: sid,
		NotificationIndex: n.NotificationIndex, RestrictionID: n.RestrictionID, AnspVersion: n.AnspVersion, ConstraintID: cid,
		Subscriber: n.Subscriber, Op: n.Op})
}

// SettleNotifications sets the rows of a uss_notify job to its state.
func (t deliverTx) SettleNotifications(ctx context.Context, deliveryID string, state deliver.State) error {
	return t.tx.Q.SettleDSSNotifications(ctx, relational.SettleDSSNotificationsParams{Status: string(state), DeliveryID: deliveryID})
}

// CancelQueuedTo cancels the queued jobs of kind to target older than below.
func (t deliverTx) CancelQueuedTo(ctx context.Context, kind deliver.Kind, restrictionID, target string, below int64, reason string) ([]deliver.Cancelled, error) {
	rows, err := t.tx.Q.CancelQueuedTo(ctx, relational.CancelQueuedToParams{Reason: &reason, Kind: relational.DeliveryKind(kind),
		RestrictionID: &restrictionID, Target: target, Below: &below})
	out := make([]deliver.Cancelled, 0, len(rows))
	for _, x := range rows {
		out = append(out, deliver.Cancelled{ID: x.ID, Target: x.Target, AnspVersion: deref(x.AnspVersion)})
	}
	return out, err
}

// ClearAlarm clears an open alarm by id.
func (t deliverTx) ClearAlarm(ctx context.Context, id, reason string) (deliver.Alarm, bool, error) {
	row, err := t.tx.Q.ClearAlarm(ctx, relational.ClearAlarmParams{Reason: &reason, ID: id})
	if IsNoRows(err) {
		return deliver.Alarm{}, false, nil
	}
	if err != nil {
		return deliver.Alarm{}, false, err
	}
	return alarmFrom(row), true, nil
}
