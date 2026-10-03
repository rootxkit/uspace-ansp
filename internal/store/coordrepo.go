package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/coord"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// CoordRepo is coord.Repo on the relational database (WP-10). The
// inbox's rules are internal/coord's; this is its rows.
type CoordRepo struct{ DB *Relational }

var _ coord.Repo = CoordRepo{}

func (r CoordRepo) do(ctx context.Context, fn func(ctx context.Context, q *relational.Queries) error) error {
	return r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error { return fn(ctx, q) })
}

func coordNotFound(err error) error {
	if IsNoRows(err) {
		return coord.ErrNotFound
	}
	return err
}

// Now is the database clock.
func (r CoordRepo) Now(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		var err error
		now, err = q.DBNow(ctx)
		return err
	})
	return now, err
}

// Tx runs fn in one transaction.
func (r CoordRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx coord.Tx) error) error {
	return r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error { return fn(ctx, coordTx{tx}) })
}

// Notice is one notice.
func (r CoordRepo) Notice(ctx context.Context, ackID string) (coord.Notice, error) {
	var out coord.Notice
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.NoticeByID(ctx, ackID)
		if err != nil {
			return coordNotFound(err)
		}
		out = noticeFrom(row)
		return nil
	})
	return out, err
}

// Notices is the inbox page f.
func (r CoordRepo) Notices(ctx context.Context, f coord.Filter) ([]coord.Notice, error) {
	var out []coord.Notice
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.ListNotices(ctx, relational.ListNoticesParams{State: textPtr(f.State), Since: f.Since, PageSize: i32(max(f.Limit, 1))})
		out = noticesFrom(rows)
		return err
	})
	return out, err
}

// BehindBus is the notices whose latest change is not on coord.v1.
func (r CoordRepo) BehindBus(ctx context.Context, limit int) ([]coord.Notice, error) {
	var out []coord.Notice
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.NoticesBehindBus(ctx, i32(max(limit, 1)))
		out = noticesFrom(rows)
		return err
	})
	return out, err
}

// CountBehindBus counts them.
func (r CoordRepo) CountBehindBus(ctx context.Context) (int, error) {
	var n int64
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		var err error
		n, err = q.CountNoticesBehindBus(ctx)
		return err
	})
	return int(n), err
}

// MarkBus records change seq of the notice as on coord.v1.
func (r CoordRepo) MarkBus(ctx context.Context, ackID string, seq int) error {
	return r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		return q.MarkNoticeBus(ctx, relational.MarkNoticeBusParams{Seq: i32(seq), ID: ackID})
	})
}

// OccurrenceByDelivery is the report a delivery carries.
func (r CoordRepo) OccurrenceByDelivery(ctx context.Context, deliveryID string) (coord.Occurrence, error) {
	var out coord.Occurrence
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		row, err := q.OccurrenceByDelivery(ctx, deliveryID)
		if err != nil {
			return coordNotFound(err)
		}
		out = occurrenceFrom(row)
		return nil
	})
	return out, err
}

// Undelivered is the reports to alarm at now.
func (r CoordRepo) Undelivered(ctx context.Context, now time.Time, after time.Duration, limit int) ([]coord.Undelivered, error) {
	var out []coord.Undelivered
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.UndeliveredOccurrences(ctx, relational.UndeliveredOccurrencesParams{Now: now, AlarmAfterS: secs(after), PageSize: i32(max(limit, 1))})
		for _, row := range rows {
			out = append(out, coord.Undelivered{ID: row.ID, ReportRef: row.ReportRef, DeliveryID: row.DeliveryID,
				BecameAwareAt: row.BecameAwareAt, DeadlineAt: row.DeadlineAt, DeliveryState: string(row.DeliveryState)})
		}
		return err
	})
	return out, err
}

// DeliveredAlarms is the open occurrence_undelivered alarms whose report
// is now delivered.
func (r CoordRepo) DeliveredAlarms(ctx context.Context, limit int) ([]coord.AlarmRef, error) {
	var out []coord.AlarmRef
	err := r.do(ctx, func(ctx context.Context, q *relational.Queries) error {
		rows, err := q.DeliveredOccurrenceAlarms(ctx, i32(max(limit, 1)))
		for _, row := range rows {
			out = append(out, coord.AlarmRef{AlarmID: row.ID, DeliveryID: deref(row.DeliveryID)})
		}
		return err
	})
	return out, err
}

type coordTx struct{ tx Tx }

var _ coord.Tx = coordTx{}

// InsertNotice stores a notice; false for a repeat of its notice_ref.
func (t coordTx) InsertNotice(ctx context.Context, n coord.NewNotice) (coord.Notice, bool, error) {
	refs, err := uuids(n.IntentRefs)
	if err != nil {
		return coord.Notice{}, false, err
	}
	row, err := t.tx.Q.InsertNotice(ctx, relational.InsertNoticeParams{
		ID: n.AckID, Kind: string(n.Kind), SenderClientID: n.SenderClientID, UsspID: n.USSPID, NoticeRef: n.NoticeRef,
		Payload: n.Payload, PayloadSha256: n.PayloadSHA256, IntentRefs: refs, AuthorisationNumbers: nonNilStrings(n.AuthorisationNumbers),
		AckRequired: n.AckRequired, SenderUnverified: n.SenderUnverified, RestrictionIds: nonNilStrings(n.RestrictionIDs),
		CisVersion: textPtr(n.CISVersion), ReceivedAt: n.ReceivedAt,
	})
	if IsNoRows(err) {
		return coord.Notice{}, false, nil
	}
	if err != nil {
		return coord.Notice{}, false, err
	}
	return noticeFrom(row), true, nil
}

// NoticeBySenderRef is the sender's notice of that notice_ref.
func (t coordTx) NoticeBySenderRef(ctx context.Context, sender, noticeRef string) (coord.Notice, error) {
	row, err := t.tx.Q.NoticeBySenderRef(ctx, relational.NoticeBySenderRefParams{SenderClientID: sender, NoticeRef: noticeRef})
	if err != nil {
		return coord.Notice{}, coordNotFound(err)
	}
	return noticeFrom(row), nil
}

// Intersecting is the restrictions the boxes intersect.
func (t coordTx) Intersecting(ctx context.Context, boxes []coord.Box, limit int) ([]string, error) {
	if len(boxes) == 0 {
		return []string{}, nil
	}
	raw, err := json.Marshal(boxes)
	if err != nil {
		return nil, err
	}
	return t.tx.Q.IntersectingRestrictions(ctx, relational.IntersectingRestrictionsParams{Boxes: raw, PageSize: i32(max(limit, 1))})
}

// Acknowledge records a person's acknowledgement.
func (t coordTx) Acknowledge(ctx context.Context, ackID, role, userID, note string) (coord.Notice, bool, error) {
	row, err := t.tx.Q.AcknowledgeNotice(ctx, relational.AcknowledgeNoticeParams{Role: &role, UserID: &userID, Note: textPtr(note), ID: ackID})
	if IsNoRows(err) {
		return coord.Notice{}, false, nil
	}
	if err != nil {
		return coord.Notice{}, false, err
	}
	return noticeFrom(row), true, nil
}

// EscalateDue escalates the notices due at now.
func (t coordTx) EscalateDue(ctx context.Context, now time.Time, escalation, repeat time.Duration, limit int) ([]coord.Notice, error) {
	rows, err := t.tx.Q.EscalateDue(ctx, relational.EscalateDueParams{Now: now, EscalationS: secs(escalation), RepeatS: secs(repeat), PageSize: i32(max(limit, 1))})
	return noticesFrom(rows), err
}

// NextOccurrenceRef is the next report_ref.
func (t coordTx) NextOccurrenceRef(ctx context.Context) (string, error) {
	return t.tx.Q.NextOccurrenceRef(ctx)
}

// InsertOccurrence stores a report.
func (t coordTx) InsertOccurrence(ctx context.Context, o coord.NewOccurrence) (coord.Occurrence, error) {
	refs, err := uuids(o.IntentRefs)
	if err != nil {
		return coord.Occurrence{}, err
	}
	row, err := t.tx.Q.InsertOccurrence(ctx, relational.InsertOccurrenceParams{
		ID: o.ID, ReportRef: o.ReportRef, Channel: o.Channel, OccurredAt: o.OccurredAt, BecameAwareAt: o.BecameAwareAt,
		Category: o.Category, Aircraft: o.Aircraft, Manned: o.Manned, IntentRefs: refs, MinSeparation: o.MinSeparation,
		Narrative: o.Narrative, ReporterPersonRefSealed: o.PersonRefSealed, ReporterKeyID: textPtr(o.KeyID),
		CreatedBy: o.CreatedBy, DeliveryID: o.DeliveryID,
	})
	if err != nil {
		return coord.Occurrence{}, err
	}
	return occurrenceFrom(row), nil
}

// Outbox is the outbox's view of this transaction.
func (t coordTx) Outbox() deliver.Tx { return deliverTx(t) }

// Audit records ev in this transaction.
func (t coordTx) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}

func uuids(in []string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(in))
	for _, s := range in {
		u, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func uuidStrings(in []uuid.UUID) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		out = append(out, u.String())
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func noticesFrom(rows []relational.CoordinationNotice) []coord.Notice {
	out := make([]coord.Notice, 0, len(rows))
	for i := range rows {
		out = append(out, noticeFrom(rows[i]))
	}
	return out
}

func noticeFrom(r relational.CoordinationNotice) coord.Notice {
	return coord.Notice{
		AckID: r.ID, Kind: coord.Kind(r.Kind), SenderClientID: r.SenderClientID, USSPID: r.UsspID, NoticeRef: r.NoticeRef,
		Payload: r.Payload, PayloadSHA256: r.PayloadSha256, IntentRefs: uuidStrings(r.IntentRefs),
		AuthorisationNumbers: nonNilStrings(r.AuthorisationNumbers), ReceivedAt: r.ReceivedAt, Acknowledged: r.State == "acknowledged",
		AckRequired: r.AckRequired, SenderUnverified: r.SenderUnverified, AcknowledgedBy: deref(r.AcknowledgedBy),
		AcknowledgedUser: deref(r.AcknowledgedUser), AcknowledgedAt: r.AcknowledgedAt, AckNote: deref(r.AckNote),
		EscalatedAt: r.EscalatedAt, LastEscalatedAt: r.LastEscalatedAt, Escalations: int(r.Escalations),
		RestrictionIDs: nonNilStrings(r.RestrictionIds), CISVersion: deref(r.CisVersion), EventSeq: int(r.EventSeq), BusSeq: int(r.BusSeq),
	}
}

func occurrenceFrom(r relational.OccurrenceReport) coord.Occurrence {
	return coord.Occurrence{NewOccurrence: coord.NewOccurrence{
		ID: r.ID, ReportRef: r.ReportRef, Channel: r.Channel, OccurredAt: r.OccurredAt, BecameAwareAt: r.BecameAwareAt,
		Category: r.Category, Aircraft: r.Aircraft, Manned: r.Manned, IntentRefs: uuidStrings(r.IntentRefs),
		MinSeparation: r.MinSeparation, Narrative: r.Narrative, PersonRefSealed: r.ReporterPersonRefSealed,
		KeyID: deref(r.ReporterKeyID), CreatedBy: r.CreatedBy, DeliveryID: r.DeliveryID,
	}, CreatedAt: r.CreatedAt, DeadlineAt: r.DeadlineAt}
}
