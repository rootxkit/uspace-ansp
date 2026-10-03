package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// DeliverRepo is deliver.Repo on the relational database (WP-8). The
// outbox's rules are internal/deliver's; this is its rows.
type DeliverRepo struct{ DB *Relational }

var _ deliver.Repo = DeliverRepo{}

// epoch is DeliveryClaimState's "nothing earlier is queued".
var epoch = time.Unix(0, 0)

func secs(d time.Duration) float64 { return d.Seconds() }

func ptr[T any](v T) *T { return &v }

func deref[T any](p *T) T {
	var z T
	if p == nil {
		return z
	}
	return *p
}

func i32(n int) int32 { return int32(min(max(n, -1<<31), 1<<31-1)) }

func i32ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := i32(*p)
	return &v
}

func intptr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

func textPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deliveryNotFound(err error) error {
	if IsNoRows(err) {
		return deliver.ErrNotFound
	}
	return err
}

// Tx runs fn in one transaction.
func (r DeliverRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx deliver.Tx) error) error {
	return r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error {
		return fn(ctx, deliverTx{tx})
	})
}

func (r DeliverRepo) do(ctx context.Context, fn func(ctx context.Context, q *relational.Queries) error) error {
	return r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error { return fn(ctx, q) })
}

func fromClaim(row relational.ClaimDeliveryRow) deliver.Delivery {
	return deliver.Delivery{
		ID: row.ID, Kind: deliver.Kind(row.Kind), SubjectRef: row.SubjectRef, RestrictionID: deref(row.RestrictionID),
		AnspVersion: deref(row.AnspVersion), Op: row.Op, Target: row.Target, IdempotencyKey: row.IdempotencyKey,
		State: deliver.State(row.State), Attempt: int(row.Attempt), MaxAttempts: int(row.MaxAttempts), QueuedAt: row.QueuedAt,
		WindowEndsAt: row.WindowEndsAt, NextRetryAt: row.NextRetryAt, BusSeq: int(row.BusSeq), LastAttemptAt: row.LastAttemptAt,
		SentAt: row.SentAt, StatusCode: intptr(row.StatusCode), Excerpt: deref(row.ResponseExcerpt), LastError: deref(row.LastError),
		Method: deref(row.Method), URL: deref(row.Url), Body: row.Body, CancelReason: deref(row.CancelReason),
	}
}

// Claim leases id to token for one attempt; when it cannot, it says why.
func (r DeliverRepo) Claim(ctx context.Context, id, token string, lease time.Duration) (deliver.Claim, error) {
	var out deliver.Claim
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.ClaimDelivery(ctx, relational.ClaimDeliveryParams{Token: &token, LeaseS: secs(lease), ID: id})
		if err == nil {
			out = deliver.Claim{Outcome: deliver.Claimed, Delivery: fromClaim(row), Now: row.Now}
			return nil
		}
		if !IsNoRows(err) {
			return err
		}
		st, err := q.DeliveryClaimState(ctx, id)
		if IsNoRows(err) {
			out = deliver.Claim{Outcome: deliver.Gone}
			return nil
		}
		if err != nil {
			return err
		}
		out = deliver.Claim{Now: st.Now, Delivery: deliver.Delivery{ID: id, State: deliver.State(st.State)}}
		switch {
		case st.State != relational.DeliveryStateQueued:
			out.Outcome = deliver.Settled
		case st.LeaseUntil != nil && st.LeaseUntil.After(st.Now):
			out.Outcome, out.Until = deliver.Leased, *st.LeaseUntil
		case st.BlockedUntil.After(epoch):
			out.Outcome, out.Until = deliver.Blocked, st.BlockedUntil
			if !st.BlockedUntil.After(st.Now) {
				// The earlier version is due or in flight: look again soon.
				out.Until = st.Now.Add(time.Second)
			}
			return q.DeferDelivery(ctx, relational.DeferDeliveryParams{Until: out.Until, ID: id})
		case st.NextRetryAt.After(st.Now):
			out.Outcome, out.Until = deliver.NotDue, st.NextRetryAt
		default:
			// Due, unleased, unblocked, and yet not claimed: a race with
			// another claim that settled it in between; look again.
			out.Outcome, out.Until = deliver.NotDue, st.Now.Add(100*time.Millisecond)
		}
		return nil
	})
	return out, err
}

// Prepare fixes the request of a claimed row.
func (r DeliverRepo) Prepare(ctx context.Context, id, token, method, url string, body []byte) (deliver.Delivery, error) {
	var out deliver.Delivery
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.PrepareDelivery(ctx, relational.PrepareDeliveryParams{Method: &method, Url: &url, Body: body, ID: id, Token: &token})
		if err != nil {
			return deliveryNotFound(err)
		}
		out = fromClaim(relational.ClaimDeliveryRow{
			ID: row.ID, Kind: row.Kind, SubjectRef: row.SubjectRef, RestrictionID: row.RestrictionID, AnspVersion: row.AnspVersion,
			Op: row.Op, Target: row.Target, IdempotencyKey: row.IdempotencyKey, State: row.State, Attempt: row.Attempt,
			MaxAttempts: row.MaxAttempts, QueuedAt: row.QueuedAt, WindowEndsAt: row.WindowEndsAt, NextRetryAt: row.NextRetryAt,
			BusSeq: row.BusSeq, LastAttemptAt: row.LastAttemptAt, SentAt: row.SentAt, StatusCode: row.StatusCode,
			ResponseExcerpt: row.ResponseExcerpt, LastError: row.LastError, Method: row.Method, Url: row.Url, Body: row.Body,
			CancelReason: row.CancelReason,
		})
		return nil
	})
	return out, err
}

// Pending is the rows the outbox scan publishes.
func (r DeliverRepo) Pending(ctx context.Context, publishGrace, stuckGrace time.Duration, limit int) ([]deliver.Pending, error) {
	var out []deliver.Pending
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.PendingDeliveries(ctx, relational.PendingDeliveriesParams{
			PublishGraceS: secs(publishGrace), StuckGraceS: secs(stuckGrace), PageSize: i32(min(max(limit, 1), 1000))})
		for _, x := range rows {
			out = append(out, deliver.Pending{ID: x.ID, Kind: deliver.Kind(x.Kind), BusSeq: int(x.BusSeq), Stuck: x.Stuck})
		}
		return err
	})
	return out, err
}

// QueuedOf is the queued, unpublished rows of a version.
func (r DeliverRepo) QueuedOf(ctx context.Context, restrictionID string, version int64) ([]deliver.Pending, error) {
	var out []deliver.Pending
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.QueuedOfVersion(ctx, relational.QueuedOfVersionParams{RestrictionID: &restrictionID, AnspVersion: &version})
		for _, x := range rows {
			out = append(out, deliver.Pending{ID: x.ID, Kind: deliver.Kind(x.Kind), BusSeq: int(x.BusSeq)})
		}
		return err
	})
	return out, err
}

// MarkBusPublished records publish seq of id.
func (r DeliverRepo) MarkBusPublished(ctx context.Context, id string, seq int) (bool, error) {
	won := false
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		_, err := q.MarkDeliveryBusPublished(ctx, relational.MarkDeliveryBusPublishedParams{Seq: i32(seq), ID: id})
		if IsNoRows(err) {
			return nil
		}
		won = err == nil
		return err
	})
	return won, err
}

// Version is a version of a restriction (0: the current one).
func (r DeliverRepo) Version(ctx context.Context, restrictionID string, version int64) (deliver.VersionInfo, error) {
	var out deliver.VersionInfo
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.DeliveryVersion(ctx, relational.DeliveryVersionParams{Version: version, ID: restrictionID})
		if err != nil {
			return restrictionNotFound(err)
		}
		out = deliver.VersionInfo{
			RestrictionID: row.ID, AnspRef: row.AnspRef, Identifier: row.Identifier, UspaceAirspaceID: row.UspaceAirspaceID,
			CurrentState: string(row.CurrentState), CurrentVersion: row.CurrentVersion, PublishedVersion: row.PublishedVersion,
			Version: row.Version, State: string(row.State), StartsAt: row.StartsAt, EndsAt: row.EndsAt,
			Feature: json.RawMessage(row.Feature), ChangedAt: row.ChangedAt, PrevState: row.PrevState,
			DSS: dssStatus(row.DssState, row.DssPendingSince, row.DssPutVersion, row.DssVersion),
		}
		return nil
	})
	return out, err
}

// dssStatus is a restriction's standing in the DSS on the wire.
func dssStatus(state string, since *time.Time, putVersion, dssVersion *int64) deliver.DSSStatus {
	out := deliver.DSSStatus{State: state, AnspVersion: putVersion, DSSVersion: dssVersion}
	if out.State == "" {
		out.State = deliver.DSSNone
	}
	if since != nil {
		s := restriction.Stamp(*since)
		out.Since = &s
	}
	return out
}

// DSSStatusOf is a restriction's standing in the DSS on the wire.
func DSSStatusOf(r restriction.Restriction) deliver.DSSStatus {
	return dssStatus(r.DSSState, r.DSSPendingSince, r.DSSPutVersion, r.DSSVersion)
}

// Overdue is the active restrictions unpublished for longer than after.
func (r DeliverRepo) Overdue(ctx context.Context, after time.Duration, limit int) ([]deliver.Overdue, error) {
	var out []deliver.Overdue
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.OverdueRestrictions(ctx, relational.OverdueRestrictionsParams{AfterS: secs(after), PageSize: i32(min(max(limit, 1), 1000))})
		for _, x := range rows {
			out = append(out, deliver.Overdue{RestrictionID: x.ID, AnspVersion: x.AnspVersion, ChangedAt: x.ChangedAt, AlarmID: x.AlarmID})
		}
		return err
	})
	return out, err
}

// Clearable is the open cisp_not_published alarms that can clear.
func (r DeliverRepo) Clearable(ctx context.Context, limit int) ([]deliver.Clearable, error) {
	var out []deliver.Clearable
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.ClearableAlarms(ctx, i32(min(max(limit, 1), 1000)))
		for _, x := range rows {
			out = append(out, deliver.Clearable{AlarmID: x.ID, RestrictionID: deref(x.RestrictionID), State: string(x.State),
				AnspVersion: x.AnspVersion, PublishedVersion: x.PublishedVersion})
		}
		return err
	})
	return out, err
}

// ActiveRefs is the ansp_ref of every active restriction, at most limit.
func (r DeliverRepo) ActiveRefs(ctx context.Context, limit int) ([]string, error) {
	var out []string
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		var err error
		out, err = q.ActiveAnspRefs(ctx, i32(min(max(limit, 1), 10000)))
		return err
	})
	return out, err
}

// Unpublished is the active restrictions the CISP does not hold at
// their current version.
func (r DeliverRepo) Unpublished(ctx context.Context, limit int) ([]deliver.Unpublished, error) {
	var out []deliver.Unpublished
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.UnpublishedActive(ctx, i32(min(max(limit, 1), 1000)))
		for _, x := range rows {
			out = append(out, deliver.Unpublished{RestrictionID: x.ID, AnspRef: x.AnspRef, AnspVersion: x.AnspVersion})
		}
		return err
	})
	return out, err
}

func alarmFrom(a relational.DeliveryAlarm) deliver.Alarm {
	return deliver.Alarm{
		ID: a.ID, Kind: deliver.AlarmKind(a.Kind), RestrictionID: deref(a.RestrictionID), AnspVersion: deref(a.AnspVersion),
		DeliveryID: deref(a.DeliveryID), RaisedAt: a.RaisedAt, Since: a.Since, Detail: a.Detail, ClearedAt: a.ClearedAt,
		ClearReason: deref(a.ClearReason), AcknowledgedBy: deref(a.AcknowledgedBy), AcknowledgedAt: a.AcknowledgedAt,
		AckReason: deref(a.AckReason),
	}
}

// Alarms is the open alarms (every alarm with all), newest first.
func (r DeliverRepo) Alarms(ctx context.Context, all bool, limit int) ([]deliver.Alarm, error) {
	var out []deliver.Alarm
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.ListAlarms(ctx, relational.ListAlarmsParams{AllAlarms: all, PageSize: i32(min(max(limit, 1), 1001))})
		for i := range rows {
			out = append(out, alarmFrom(rows[i]))
		}
		return err
	})
	return out, err
}

// Alarm is one alarm.
func (r DeliverRepo) Alarm(ctx context.Context, id string) (deliver.Alarm, error) {
	var out deliver.Alarm
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.AlarmByID(ctx, id)
		if err != nil {
			return deliveryNotFound(err)
		}
		out = alarmFrom(row)
		return nil
	})
	return out, err
}

// Channels is the deliveries of a version.
func (r DeliverRepo) Channels(ctx context.Context, restrictionID string, version int64) ([]deliver.ChannelRow, error) {
	var out []deliver.ChannelRow
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.DeliveryChannels(ctx, relational.DeliveryChannelsParams{RestrictionID: &restrictionID, AnspVersion: &version})
		for _, x := range rows {
			out = append(out, deliver.ChannelRow{Kind: deliver.Kind(x.Kind), State: deliver.State(x.State), Attempt: int(x.Attempt),
				LastAttemptAt: x.LastAttemptAt, StatusCode: intptr(x.StatusCode), NextRetryAt: x.NextRetryAt})
		}
		return err
	})
	return out, err
}

// Attempts is the number of attempt rows of id.
func (r DeliverRepo) Attempts(ctx context.Context, id string) (int, error) {
	var n int64
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		var err error
		n, err = q.CountDeliveryAttempts(ctx, id)
		return err
	})
	return int(n), err
}

// deliverTx is deliver.Tx on one transaction.
type deliverTx struct{ tx Tx }

var _ deliver.Tx = deliverTx{}

// DeliverTxOf is the outbox's view of a restriction transaction, so a
// version and its jobs commit together (B-05); false when tx is not this
// store's.
func DeliverTxOf(tx restriction.Tx) (deliver.Tx, bool) {
	rt, ok := tx.(restrictionTx)
	if !ok {
		return nil, false
	}
	return deliverTx(rt), true
}

// Now is the database clock.
func (t deliverTx) Now(ctx context.Context) (time.Time, error) { return t.tx.Q.DBNow(ctx) }

// Insert writes a queued job.
func (t deliverTx) Insert(ctx context.Context, j deliver.Job, maxAttempts int, window time.Duration) (bool, error) {
	var pv *int64
	if j.PolicyVersion > 0 {
		pv = &j.PolicyVersion
	}
	_, err := t.tx.Q.InsertDelivery(ctx, relational.InsertDeliveryParams{
		ID: j.ID, Kind: relational.DeliveryKind(j.Kind), SubjectRef: j.SubjectRef(), RestrictionID: ptr(j.RestrictionID),
		AnspVersion: ptr(j.AnspVersion), Op: j.Op, Target: j.Target, IdempotencyKey: j.IdempotencyKey(),
		MaxAttempts: i32(maxAttempts), WindowS: secs(window), Body: j.Body, PolicyVersion: pv,
	})
	if IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}

// Finish writes the attempt row and, under the lease, the outcome.
func (t deliverTx) Finish(ctx context.Context, a deliver.Attempt) (bool, error) {
	if err := t.tx.Q.InsertDeliveryAttempt(ctx, relational.InsertDeliveryAttemptParams{
		DeliveryID: a.ID, Attempt: i32(a.Attempt), DurationMs: i32(int(a.Duration.Milliseconds())), StatusCode: i32ptr(a.StatusCode),
		Outcome: a.Outcome, Error: textPtr(a.Error), ResponseExcerpt: textPtr(a.Excerpt),
	}); err != nil {
		return false, err
	}
	_, err := t.tx.Q.FinishDelivery(ctx, relational.FinishDeliveryParams{
		State: relational.DeliveryState(a.State), StatusCode: i32ptr(a.StatusCode), ResponseExcerpt: textPtr(a.Excerpt),
		LastError: textPtr(a.Error), RetryAt: a.RetryAt, CancelReason: textPtr(a.CancelReason), ID: a.ID, Token: &a.Token,
	})
	if IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}

// MarkPublishedVersion records the CISP's confirmation of version.
func (t deliverTx) MarkPublishedVersion(ctx context.Context, restrictionID string, version int64) (deliver.PublishedState, error) {
	row, err := t.tx.Q.MarkPublishedVersion(ctx, relational.MarkPublishedVersionParams{Version: version, ID: restrictionID})
	if err != nil {
		return deliver.PublishedState{}, restrictionNotFound(err)
	}
	return deliver.PublishedState{State: string(row.State), AnspVersion: row.AnspVersion, PublishedVersion: deref(row.PublishedVersion)}, nil
}

// CancelQueued cancels the queued jobs of kind up to a version.
func (t deliverTx) CancelQueued(ctx context.Context, kind deliver.Kind, restrictionID string, upTo int64, reason string) ([]deliver.Cancelled, error) {
	rows, err := t.tx.Q.CancelQueuedDeliveries(ctx, relational.CancelQueuedDeliveriesParams{
		Reason: &reason, Kind: relational.DeliveryKind(kind), RestrictionID: &restrictionID, UpTo: &upTo})
	out := make([]deliver.Cancelled, 0, len(rows))
	for _, x := range rows {
		out = append(out, deliver.Cancelled{ID: x.ID, Target: x.Target, AnspVersion: deref(x.AnspVersion)})
	}
	return out, err
}

// RaiseAlarm inserts a, or returns the equal open one.
func (t deliverTx) RaiseAlarm(ctx context.Context, a deliver.Alarm) (deliver.Alarm, bool, error) {
	row, err := t.tx.Q.InsertAlarm(ctx, relational.InsertAlarmParams{
		ID: a.ID, Kind: string(a.Kind), RestrictionID: textPtr(a.RestrictionID), AnspVersion: nonZero(a.AnspVersion),
		DeliveryID: textPtr(a.DeliveryID), Since: a.Since, Detail: a.Detail,
	})
	if err == nil {
		return alarmFrom(row), true, nil
	}
	if !IsNoRows(err) {
		return deliver.Alarm{}, false, err
	}
	if a.Kind == deliver.AlarmCISPNotPublished {
		row, err = t.tx.Q.OpenCISPAlarm(ctx, &a.RestrictionID)
	} else {
		row, err = t.tx.Q.AlarmOfDelivery(ctx, relational.AlarmOfDeliveryParams{DeliveryID: &a.DeliveryID, Kind: string(a.Kind)})
	}
	if err != nil {
		return deliver.Alarm{}, false, err
	}
	return alarmFrom(row), false, nil
}

func nonZero(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// AdvanceAlarm moves an open alarm to a newer version.
func (t deliverTx) AdvanceAlarm(ctx context.Context, id string, version int64, detail string) error {
	return t.tx.Q.AdvanceAlarm(ctx, relational.AdvanceAlarmParams{AnspVersion: &version, Detail: detail, ID: id})
}

// ClearCISPAlarm clears the open cisp_not_published of a restriction.
func (t deliverTx) ClearCISPAlarm(ctx context.Context, restrictionID, reason string) (deliver.Alarm, bool, error) {
	row, err := t.tx.Q.ClearCISPAlarm(ctx, relational.ClearCISPAlarmParams{Reason: &reason, RestrictionID: &restrictionID})
	if IsNoRows(err) {
		return deliver.Alarm{}, false, nil
	}
	if err != nil {
		return deliver.Alarm{}, false, err
	}
	return alarmFrom(row), true, nil
}

// AcknowledgeAlarm records a person's acknowledgement.
func (t deliverTx) AcknowledgeAlarm(ctx context.Context, id, by, reason string) (deliver.Alarm, error) {
	row, err := t.tx.Q.AcknowledgeAlarm(ctx, relational.AcknowledgeAlarmParams{By: &by, Reason: &reason, ID: id})
	if err == nil {
		return alarmFrom(row), nil
	}
	if !IsNoRows(err) {
		return deliver.Alarm{}, err
	}
	if _, err := t.tx.Q.AlarmByID(ctx, id); err != nil {
		return deliver.Alarm{}, deliveryNotFound(err)
	}
	return deliver.Alarm{}, deliver.ErrAcknowledged
}

// Expedite makes the queued rows of kind for a restriction due now.
func (t deliverTx) Expedite(ctx context.Context, kind deliver.Kind, restrictionID string) ([]deliver.Pending, error) {
	rows, err := t.tx.Q.ExpediteQueued(ctx, relational.ExpediteQueuedParams{Kind: relational.DeliveryKind(kind), RestrictionID: &restrictionID})
	out := make([]deliver.Pending, 0, len(rows))
	for _, x := range rows {
		out = append(out, deliver.Pending{ID: x.ID, Kind: deliver.Kind(x.Kind), BusSeq: int(x.BusSeq)})
	}
	return out, err
}

// Requeue reopens the abandoned row of a version.
func (t deliverTx) Requeue(ctx context.Context, kind deliver.Kind, restrictionID string, version int64, extra int, window time.Duration) (deliver.Pending, bool, error) {
	row, err := t.tx.Q.RequeueAbandoned(ctx, relational.RequeueAbandonedParams{Extra: i32(extra), WindowS: secs(window),
		Kind: relational.DeliveryKind(kind), RestrictionID: &restrictionID, AnspVersion: &version})
	if IsNoRows(err) {
		return deliver.Pending{}, false, nil
	}
	if err != nil {
		return deliver.Pending{}, false, err
	}
	return deliver.Pending{ID: row.ID, Kind: deliver.Kind(row.Kind), BusSeq: int(row.BusSeq)}, true, nil
}

// Audit records one event in the hash-chained log.
func (t deliverTx) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}
