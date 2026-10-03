package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/policy"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// StateSequenceLimit is PostgreSQL's sequence_generator_limit_exceeded:
// the DAR identifier space is spent.
const StateSequenceLimit = "2200H"

// RestrictionRepo is restriction.Repo on the relational database
// (WP-5). The state machine is internal/restriction's; this is its rows.
type RestrictionRepo struct{ DB *Relational }

var _ restriction.Repo = RestrictionRepo{}

// Tx runs fn in one transaction.
func (r RestrictionRepo) Tx(ctx context.Context, fn func(ctx context.Context, tx restriction.Tx) error) error {
	return r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error {
		return fn(ctx, restrictionTx{tx})
	})
}

// Get is one restriction with its current feature.
func (r RestrictionRepo) Get(ctx context.Context, id string) (restriction.Restriction, error) {
	var out restriction.Restriction
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		row, err := q.RestrictionFull(ctx, id)
		if err != nil {
			return restrictionNotFound(err)
		}
		out, err = restrictionFromRow(row)
		return err
	})
	return out, err
}

// List is the restrictions matching f, newest first, and whether more
// existed than f.Limit.
func (r RestrictionRepo) List(ctx context.Context, f restriction.ListFilter) ([]restriction.Restriction, bool, error) {
	p := relational.ListRestrictionsParams{At: f.At, PageSize: int32(min(max(f.Limit, 1), 1000)) + 1}
	if f.State != nil {
		s := relational.RestrictionState(*f.State)
		p.State = &s
	}
	if f.BBox != nil {
		b := *f.BBox
		p.West, p.South, p.East, p.North = &b[0], &b[1], &b[2], &b[3]
	}
	var out []restriction.Restriction
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.ListRestrictions(ctx, p)
		if err != nil {
			return err
		}
		out = make([]restriction.Restriction, 0, len(rows))
		for i := range rows {
			x, err := restrictionFromRow(relational.RestrictionFullRow(rows[i]))
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > int(p.PageSize)-1
	if more {
		out = out[:len(out)-1]
	}
	return out, more, nil
}

// Versions is every version of id, oldest first, at most limit.
func (r RestrictionRepo) Versions(ctx context.Context, id string, limit int) ([]restriction.Version, error) {
	var out []restriction.Version
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.RestrictionVersions(ctx, relational.RestrictionVersionsParams{RestrictionID: id, PageSize: int32(min(max(limit, 1), 1000))})
		if err != nil {
			return err
		}
		out = make([]restriction.Version, 0, len(rows))
		for i := range rows {
			out = append(out, versionFromRow(relational.RestrictionVersionRow(rows[i])))
		}
		return nil
	})
	return out, err
}

// Version is one version.
func (r RestrictionRepo) Version(ctx context.Context, id string, version int64) (restriction.Version, error) {
	var out restriction.Version
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		row, err := q.RestrictionVersion(ctx, relational.RestrictionVersionParams{RestrictionID: id, Version: version})
		if err != nil {
			return restrictionNotFound(err)
		}
		out = versionFromRow(row)
		return nil
	})
	return out, err
}

// Request is one restriction request.
func (r RestrictionRepo) Request(ctx context.Context, id string) (restriction.Request, error) {
	var out restriction.Request
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		row, err := q.RestrictionRequestByID(ctx, id)
		if err != nil {
			return restrictionNotFound(err)
		}
		out = requestFromRow(row)
		return nil
	})
	return out, err
}

// DueActivations is the planned restrictions whose activate_at has come
// on the database's clock.
func (r RestrictionRepo) DueActivations(ctx context.Context, limit int) ([]string, error) {
	var out []string
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		out, err = q.DueActivations(ctx, int32(min(max(limit, 1), 1000)))
		return err
	})
	return out, err
}

// DueExpiries is the active restrictions whose ends_at has passed on the
// database's clock.
func (r RestrictionRepo) DueExpiries(ctx context.Context, limit int) ([]string, error) {
	var out []string
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		out, err = q.DueExpiries(ctx, int32(min(max(limit, 1), 1000)))
		return err
	})
	return out, err
}

// Unpublished is the versions above each restriction's bus_version.
func (r RestrictionRepo) Unpublished(ctx context.Context, limit int) ([]restriction.Version, error) {
	var out []restriction.Version
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.UnpublishedVersions(ctx, int32(min(max(limit, 1), 1000)))
		if err != nil {
			return err
		}
		for i := range rows {
			out = append(out, versionFromRow(relational.RestrictionVersionRow(rows[i])))
		}
		return nil
	})
	return out, err
}

// MarkPublished records that version of id is on the bus.
func (r RestrictionRepo) MarkPublished(ctx context.Context, id string, version int64) error {
	return r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		return q.MarkBusPublished(ctx, relational.MarkBusPublishedParams{ID: id, Version: version})
	})
}

// restrictionTx is restriction.Tx on one transaction.
type restrictionTx struct{ tx Tx }

var _ restriction.Tx = restrictionTx{}

// Now is the database clock.
func (t restrictionTx) Now(ctx context.Context) (time.Time, error) { return t.tx.Q.DBNow(ctx) }

// Policy is the newest ansp_policy row.
func (t restrictionTx) Policy(ctx context.Context) (policy.Policy, error) {
	row, err := t.tx.Q.LatestPolicy(ctx)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("read ansp_policy: %w", err)
	}
	return policyFromRow(&row), nil
}

// MintIdentifier draws the next DAR identifier from the sequence.
func (t restrictionTx) MintIdentifier(ctx context.Context) (string, error) {
	row, err := t.tx.Q.NextRestrictionIdentifier(ctx)
	if SQLState(err) == StateSequenceLimit {
		return "", &restriction.Refusal{Status: 503, Slug: restriction.SlugIdentifiersSpent,
			Detail: "every DAR identifier (DAR plus 4 base-36 characters, D4) has been used; an identifier names one restriction for ever"}
	}
	if err != nil {
		return "", err
	}
	return restriction.Identifier(row.Seq, row.OffsetN)
}

// ByIdempotency finds the restriction an Idempotency-Key made.
func (t restrictionTx) ByIdempotency(ctx context.Context, actorID, key string) (string, string, bool, error) {
	row, err := t.tx.Q.RestrictionByIdempotency(ctx, relational.RestrictionByIdempotencyParams{Actor: &actorID, IdempotencyKey: &key})
	if IsNoRows(err) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return row.ID, row.Sha256, true, nil
}

// Insert stores a planned restriction.
func (t restrictionTx) Insert(ctx context.Context, r restriction.Restriction, idem *restriction.Idempotency) error {
	dss, err := uuid.Parse(r.DSSConstraintID)
	if err != nil {
		return fmt.Errorf("dss_constraint_id: %w", err)
	}
	p := relational.PlanRestrictionParams{
		ID: r.ID, AnspRef: r.AnspRef, Identifier: r.Identifier, UspaceAirspaceID: r.UspaceAirspaceID, ZoneType: string(r.ZoneType),
		GeomGeojson: r.Shape.GeoJSON(), RadiusM: r.Shape.Radius(), LowerM: r.LowerM, LowerRef: string(r.LowerRef),
		UpperM: r.UpperM, UpperRef: string(r.UpperRef), StartsAt: r.StartsAt, EndsAt: r.EndsAt, ReasonText: r.ReasonText,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, RequestID: r.RequestID, DssConstraintID: &dss, SupersedesID: r.SupersedesID,
		CisVersion: r.CISVersion,
	}
	if idem != nil {
		p.IdempotencyActor, p.IdempotencyKey, p.IdempotencySha256 = &idem.ActorID, &idem.Key, &idem.SHA256
	}
	err = t.tx.Q.PlanRestriction(ctx, p)
	if SQLState(err) == StateUniqueViolation {
		return restriction.ErrConflict
	}
	return err
}

// Lock reads a restriction FOR UPDATE.
func (t restrictionTx) Lock(ctx context.Context, id string) (restriction.Restriction, error) {
	row, err := t.tx.Q.LockRestriction(ctx, id)
	if err != nil {
		return restriction.Restriction{}, restrictionNotFound(err)
	}
	return restrictionFromRow(relational.RestrictionFullRow(row))
}

// Update writes a transition if the version is still prev.
func (t restrictionTx) Update(ctx context.Context, prev int64, r restriction.Restriction) error {
	n, err := t.tx.Q.UpdateRestrictionState(ctx, relational.UpdateRestrictionStateParams{
		ID: r.ID, PrevVersion: prev, State: relational.RestrictionState(r.State), AnspVersion: r.AnspVersion, EndsAt: r.EndsAt,
		ActivateAt: r.ActivateAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		EndedBy: r.EndedBy, EndedAtActual: r.EndedAtActual, CancelledBy: r.CancelledBy,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return restriction.ErrConflict
	}
	return nil
}

// InsertVersion stores one version.
func (t restrictionTx) InsertVersion(ctx context.Context, v restriction.Version) error {
	return t.tx.Q.InsertRestrictionVersion(ctx, relational.InsertRestrictionVersionParams{
		RestrictionID: v.RestrictionID, Version: v.Version, Feature: v.Feature, F3548Constraint: v.Constraint,
		ChangedBy: v.ChangedBy, ChangedAt: v.ChangedAt, ChangeReason: v.ChangeReason,
		State: relational.RestrictionState(v.State), StartsAt: v.StartsAt, EndsAt: v.EndsAt, MsgID: v.MsgID,
	})
}

// Audit records one event in the hash-chained log.
func (t restrictionTx) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}

// Successor is the planned re-issue continuing id.
func (t restrictionTx) Successor(ctx context.Context, id string) (string, bool, error) {
	ids, err := t.tx.Q.RestrictionSuccessor(ctx, &id)
	if err != nil || len(ids) == 0 {
		return "", false, err
	}
	return ids[0], true, nil
}

// AreaM2 is ST_Area of the shape on geography.
func (t restrictionTx) AreaM2(ctx context.Context, s restriction.Shape) (float64, error) {
	return t.tx.Q.RestrictionAreaM2(ctx, relational.RestrictionAreaM2Params{GeomGeojson: s.GeoJSON(), RadiusM: s.Radius()})
}

// Relate measures the shape against an airspace part.
func (t restrictionTx) Relate(ctx context.Context, s restriction.Shape, p restriction.Part) (restriction.Relation, error) {
	row, err := t.tx.Q.RelateShapes(ctx, relational.RelateShapesParams{AGeojson: s.GeoJSON(), ARadiusM: s.Radius(), BGeojson: p.GeoJSON, BRadiusM: p.RadiusM})
	if err != nil {
		return restriction.Relation{}, err
	}
	return restriction.Relation{Intersects: row.Intersects, Covers: row.Covers}, nil
}

// RequestByClientRef finds a request by its requester and client_ref.
func (t restrictionTx) RequestByClientRef(ctx context.Context, requester, ref string) (restriction.Request, bool, error) {
	row, err := t.tx.Q.RestrictionRequestByClientRef(ctx, relational.RestrictionRequestByClientRefParams{Requester: requester, ClientRef: ref})
	if IsNoRows(err) {
		return restriction.Request{}, false, nil
	}
	if err != nil {
		return restriction.Request{}, false, err
	}
	return requestFromRow(row), true, nil
}

// CountOpenRequests counts a requester's undecided requests.
func (t restrictionTx) CountOpenRequests(ctx context.Context, requester string) (int64, error) {
	return t.tx.Q.CountOpenRestrictionRequests(ctx, requester)
}

// InsertRequest stores a received request.
func (t restrictionTx) InsertRequest(ctx context.Context, q restriction.Request) error {
	_, err := t.tx.Q.InsertRestrictionRequest(ctx, relational.InsertRestrictionRequestParams{
		ID: q.ID, Requester: q.Requester, Source: q.Source, Payload: q.Payload, ReceivedAt: q.ReceivedAt,
		ClientRef: q.ClientRef, PayloadSha256: q.PayloadSHA256,
	})
	if SQLState(err) == StateUniqueViolation {
		return restriction.ErrConflict
	}
	return err
}

// LockRequest reads a request FOR UPDATE.
func (t restrictionTx) LockRequest(ctx context.Context, id string) (restriction.Request, error) {
	row, err := t.tx.Q.LockRestrictionRequest(ctx, id)
	if err != nil {
		return restriction.Request{}, restrictionNotFound(err)
	}
	return requestFromRow(row), nil
}

// DecideRequest records a decision on a received request.
func (t restrictionTx) DecideRequest(ctx context.Context, q restriction.Request) error {
	if q.DecidedBy == nil || q.DecidedAt == nil {
		return errors.New("a decision without decided_by and decided_at")
	}
	n, err := t.tx.Q.DecideRestrictionRequest(ctx, relational.DecideRestrictionRequestParams{
		ID: q.ID, State: q.State, DecidedBy: q.DecidedBy, DecidedAt: q.DecidedAt,
		DecisionReason: q.DecisionReason, RestrictionID: q.RestrictionID,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return restriction.ErrConflict
	}
	return nil
}

func restrictionNotFound(err error) error {
	if IsNoRows(err) {
		return restriction.ErrNotFound
	}
	return err
}

func restrictionFromRow(row relational.RestrictionFullRow) (restriction.Restriction, error) {
	g, err := ParseGeometry(row.GeomGeojson)
	if err != nil {
		return restriction.Restriction{}, fmt.Errorf("restriction %s geometry: %w", row.ID, err)
	}
	var shape restriction.Shape
	switch {
	case g.Point != nil && row.RadiusM != nil:
		shape = restriction.Shape{Center: g.Point, RadiusM: *row.RadiusM}
	case g.Polygon != nil && len(g.Polygon.Rings) == 1:
		shape = restriction.Shape{Ring: []core.LatLon(g.Polygon.Rings[0])}
	default:
		return restriction.Restriction{}, fmt.Errorf("restriction %s: a stored shape that is neither one ring nor a circle", row.ID)
	}
	out := restriction.Restriction{
		ID: row.ID, AnspRef: row.AnspRef, Identifier: row.Identifier, UspaceAirspaceID: row.UspaceAirspaceID,
		ZoneType: core.ZoneType(row.ZoneType), Shape: shape, LowerM: row.LowerM, LowerRef: core.VerticalRef(row.LowerRef),
		UpperM: row.UpperM, UpperRef: core.VerticalRef(row.UpperRef), StartsAt: row.StartsAt.UTC(), EndsAt: row.EndsAt.UTC(),
		ReasonText: row.ReasonText, State: restriction.State(row.State), AnspVersion: row.AnspVersion,
		ActivateAt: utc(row.ActivateAt), CreatedBy: row.CreatedBy, ActivatedBy: row.ActivatedBy, EndedBy: row.EndedBy,
		CancelledBy: row.CancelledBy, CreatedAt: row.CreatedAt.UTC(), ActivatedAt: utc(row.ActivatedAt),
		EndedAtActual: utc(row.EndedAtActual), RequestID: row.RequestID, SupersedesID: row.SupersedesID,
		PublishedVersion: row.PublishedVersion, DSSVersion: row.DssVersion, CISVersion: row.CisVersion,
		Feature: row.Feature, Constraint: row.Constraint,
		DSSState: row.DssState, DSSPendingSince: utc(row.DssPendingSince), DSSReference: row.DssReference, DSSPutVersion: row.DssPutVersion,
	}
	if row.DssConstraintID != nil {
		out.DSSConstraintID = row.DssConstraintID.String()
	}
	return out, nil
}

func versionFromRow(row relational.RestrictionVersionRow) restriction.Version {
	return restriction.Version{
		RestrictionID: row.RestrictionID, Version: row.Version, State: restriction.State(row.State),
		StartsAt: row.StartsAt.UTC(), EndsAt: row.EndsAt.UTC(), MsgID: row.MsgID, Feature: row.Feature, Constraint: row.Constraint,
		ChangedBy: row.ChangedBy, ChangedAt: row.ChangedAt.UTC(), ChangeReason: row.ChangeReason, AnspRef: row.AnspRef,
	}
}

func requestFromRow(row relational.RestrictionRequest) restriction.Request {
	return restriction.Request{
		ID: row.ID, Requester: row.Requester, Source: row.Source, ClientRef: row.ClientRef, Payload: row.Payload,
		PayloadSHA256: row.PayloadSha256, ReceivedAt: row.ReceivedAt.UTC(), State: row.State, DecidedBy: row.DecidedBy,
		DecidedAt: utc(row.DecidedAt), DecisionReason: row.DecisionReason, RestrictionID: row.RestrictionID,
	}
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
