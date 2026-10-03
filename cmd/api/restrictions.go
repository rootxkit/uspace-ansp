package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/deliver"
	"github.com/rootxkit/uspace-ansp/internal/dss"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// MaxRestrictionBodyBytes bounds a restriction or request body (E-10):
// 1000 vertices of [lng, lat] are about 50 KiB.
const MaxRestrictionBodyBytes = 256 << 10

// MaxVersionsListed bounds GET /v1/restrictions/{id}/versions.
const MaxVersionsListed = 1000

// DefaultListLimit is GET /v1/restrictions without limit.
const DefaultListLimit = 100

// restrictionsUnavailableRetry is the Retry-After while restrictions
// are not served (no relational database).
const restrictionsUnavailableRetry = 60 * time.Second

// restrictionAPI serves the restriction and restriction-request
// operations (WP-5), the console stream, and the outbox's view (WP-8):
// the deliveries summary and the delivery alarms.
type restrictionAPI struct {
	svc    *restriction.Service
	stream *restrictionStream
	// dl is the outbox; nil while there is none (every channel "none",
	// the alarm operations 503).
	dl *deliveryAPI
	// details serves the F3548 constraint details (WP-9); nil while
	// there is no outbox (the operation answers 503).
	details *dss.Details
}

// actorOf is the caller as the state machine records it: a console
// session (its account id and role) or a machine client (its client id).
func actorOf(r *http.Request) (restriction.Actor, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.Claims.Subject == "" {
		return restriction.Actor{}, false
	}
	if p.Session {
		return restriction.Actor{Type: string(audit.ActorUser), ID: p.Claims.Subject, Role: p.Role}, true
	}
	return restriction.Actor{Type: string(audit.ActorClient), ID: p.Claims.Subject, Role: p.Claims.Subject}, true
}

func (s apiServer) restrictions(w http.ResponseWriter, r *http.Request) (*restrictionAPI, restriction.Actor, bool) {
	if s.rs == nil {
		apierr.WriteError(w, r, apierr.Unavailable(restrictionsUnavailableRetry, "restrictions need the relational database (ANSP_RELATIONAL_DSN)"))
		return nil, restriction.Actor{}, false
	}
	a, ok := actorOf(r)
	if !ok {
		apierr.WriteError(w, r, apierr.Unauthenticated("no authenticated caller"))
		return nil, restriction.Actor{}, false
	}
	return s.rs, a, true
}

// readBody reads a JSON body of at most MaxRestrictionBodyBytes. A body
// that is absent and not required is nil.
func readBody(w http.ResponseWriter, r *http.Request, required bool) ([]byte, bool) {
	if r.Body == nil || r.ContentLength == 0 && !required {
		if required {
			apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "is required")))
			return nil, false
		}
		return nil, true
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			apierr.WriteError(w, r, apierr.UnsupportedMediaType("application/json"))
			return nil, false
		}
	} else if required {
		apierr.WriteError(w, r, apierr.UnsupportedMediaType("application/json"))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRestrictionBodyBytes+1))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		apierr.WriteError(w, r, apierr.TooLarge(mbe.Limit))
		return nil, false
	case err != nil:
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "could not be read")))
		return nil, false
	case len(body) > MaxRestrictionBodyBytes:
		apierr.WriteError(w, r, apierr.TooLarge(MaxRestrictionBodyBytes))
		return nil, false
	case required && len(strings.TrimSpace(string(body))) == 0:
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "is required")))
		return nil, false
	}
	return body, true
}

// refusal writes err: a *restriction.Refusal with its slug and status,
// ErrNotFound as 404, ErrConflict as 409, anything else as 500 (its
// text is not written).
func refusal(w http.ResponseWriter, r *http.Request, err error) {
	var rf *restriction.Refusal
	switch {
	case errors.As(err, &rf):
		fields := make([]apierr.FieldProblem, 0, len(rf.Fields))
		for _, f := range rf.Fields {
			fields = append(fields, apierr.FieldProblem{Field: f.Field, Reason: f.Reason})
		}
		p := apierr.New(rf.Status, rf.Slug, rf.Detail, fields...)
		p.RetryAfter = rf.RetryAfter
		apierr.WriteError(w, r, p)
	case errors.Is(err, restriction.ErrNotFound):
		apierr.WriteError(w, r, apierr.NotFound("no such restriction or request"))
	case errors.Is(err, restriction.ErrConflict):
		apierr.WriteError(w, r, apierr.Conflict("the restriction changed while this request was being made; read it again and retry"))
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		apierr.WriteError(w, r, apierr.Unavailable(5*time.Second, "the request did not complete in time"))
	default:
		apierr.WriteError(w, r, apierr.Internal())
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// CreateRestriction serves POST /v1/restrictions.
func (s apiServer) CreateRestriction(w http.ResponseWriter, r *http.Request, params gen.CreateRestrictionParams) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, true)
	if !ok {
		return
	}
	b, in, errs := restriction.DecodeArea(body, restriction.BodyCreate)
	if len(errs) > 0 {
		refusal(w, r, &restriction.Refusal{Status: http.StatusBadRequest, Slug: restriction.SlugInvalid, Detail: "the restriction is refused; nothing was stored", Fields: errs})
		return
	}
	opt := restriction.PlanOptions{Idempotency: &restriction.Idempotency{ActorID: actor.ID, Key: params.IdempotencyKey, SHA256: restriction.Hash(body)}}
	opt.ConfirmChain = b.ConfirmChain != nil && *b.ConfirmChain
	res, replay, err := rs.svc.Plan(r.Context(), actor, in, opt)
	if err != nil {
		refusal(w, r, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, rs.restrictionJSON(r.Context(), res))
}

// ListRestrictions serves GET /v1/restrictions.
func (s apiServer) ListRestrictions(w http.ResponseWriter, r *http.Request, params gen.ListRestrictionsParams) {
	rs, _, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	f := restriction.ListFilter{Limit: DefaultListLimit, At: params.At}
	if params.Limit != nil {
		f.Limit = *params.Limit
	}
	if params.State != nil {
		st := restriction.State(*params.State)
		if !st.Valid() {
			apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("state", "is not planned, active, ended or cancelled")))
			return
		}
		f.State = &st
	}
	if params.Bbox != nil {
		b, err := parseBBox(*params.Bbox)
		if err != nil {
			apierr.WriteError(w, r, apierr.Invalid(err))
			return
		}
		f.BBox = &b
	}
	list, more, err := rs.svc.List(r.Context(), f)
	if err != nil {
		refusal(w, r, err)
		return
	}
	out := listJSON{Restrictions: make([]restrictionJSON, 0, len(list))}
	for i := range list {
		out.Restrictions = append(out.Restrictions, rs.restrictionJSON(r.Context(), list[i]))
	}
	if more {
		out.Truncated = &more
	}
	out.CISVersion, out.CISAgeS = rs.cisStatus(r.Context())
	writeJSON(w, http.StatusOK, out)
}

// parseBBox reads west,south,east,north in WGS84 degrees.
func parseBBox(s string) ([4]float64, *core.FieldError) {
	var b [4]float64
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return b, core.Fieldf("bbox", "is not west,south,east,north")
	}
	for i, p := range parts {
		v, err := strconv.ParseFloat(p, 64)
		if err != nil || !core.IsFinite(v) {
			return b, core.Fieldf("bbox", "is not four numbers")
		}
		b[i] = v
	}
	switch {
	case b[0] < -180 || b[0] > 180 || b[2] < -180 || b[2] > 180:
		return b, core.Fieldf("bbox", "a longitude is outside [-180, 180]")
	case b[1] < -90 || b[1] > 90 || b[3] < -90 || b[3] > 90 || b[1] > b[3]:
		return b, core.Fieldf("bbox", "the latitudes are outside [-90, 90] or south is above north")
	}
	return b, nil
}

// GetRestriction serves GET /v1/restrictions/{id}.
func (s apiServer) GetRestriction(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	rs, _, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	res, err := rs.svc.Get(r.Context(), id)
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rs.restrictionJSON(r.Context(), res))
}

// ListRestrictionVersions serves GET /v1/restrictions/{id}/versions.
func (s apiServer) ListRestrictionVersions(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	rs, _, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	vs, err := rs.svc.Versions(r.Context(), id, MaxVersionsListed)
	if err != nil {
		refusal(w, r, err)
		return
	}
	out := versionListJSON{Versions: make([]versionJSON, 0, len(vs))}
	for i := range vs {
		out.Versions = append(out.Versions, toVersionJSON(vs[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GetRestrictionVersion serves GET /v1/restrictions/{id}/versions/{version}.
func (s apiServer) GetRestrictionVersion(w http.ResponseWriter, r *http.Request, id gen.RestrictionID, version gen.Version) {
	rs, _, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	v, err := rs.svc.Version(r.Context(), id, version)
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toVersionJSON(v))
}

// transition serves the four transition operations.
func (s apiServer) transition(w http.ResponseWriter, r *http.Request, id string, op restriction.Op) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	required := op != restriction.OpActivate
	body, ok := readBody(w, r, required)
	if !ok {
		return
	}
	b, errs := restriction.DecodeReason(body, required, op == restriction.OpExtend, false)
	var newEnd *time.Time
	if op == restriction.OpExtend && len(errs) == 0 {
		end, eerrs := b.EndOf()
		errs = append(errs, eerrs...)
		newEnd = &end
	}
	if len(errs) > 0 {
		refusal(w, r, &restriction.Refusal{Status: http.StatusBadRequest, Slug: restriction.SlugInvalid, Detail: "the request is refused; nothing changed", Fields: errs})
		return
	}
	res, err := rs.svc.Apply(r.Context(), actor, id, op, b.ReasonOr(string(op)+" by "+actor.Role), newEnd)
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rs.restrictionJSON(r.Context(), res))
}

// ActivateRestriction serves POST /v1/restrictions/{id}/activate.
func (s apiServer) ActivateRestriction(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	s.transition(w, r, id, restriction.OpActivate)
}

// ExtendRestriction serves POST /v1/restrictions/{id}/extend.
func (s apiServer) ExtendRestriction(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	s.transition(w, r, id, restriction.OpExtend)
}

// EndRestriction serves POST /v1/restrictions/{id}/end.
func (s apiServer) EndRestriction(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	s.transition(w, r, id, restriction.OpEnd)
}

// CancelRestriction serves POST /v1/restrictions/{id}/cancel.
func (s apiServer) CancelRestriction(w http.ResponseWriter, r *http.Request, id gen.RestrictionID) {
	s.transition(w, r, id, restriction.OpCancel)
}

// CreateRestrictionRequest serves POST /v1/restriction-requests.
func (s apiServer) CreateRestrictionRequest(w http.ResponseWriter, r *http.Request) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, true)
	if !ok {
		return
	}
	b, _, errs := restriction.DecodeArea(body, restriction.BodyRequest)
	if len(errs) > 0 {
		refusal(w, r, &restriction.Refusal{Status: http.StatusBadRequest, Slug: restriction.SlugInvalid, Detail: "the request is refused; nothing was stored", Fields: errs})
		return
	}
	source, requester := restriction.SourceAuthority, actor.ID
	if actor.Type == string(audit.ActorUser) {
		source, requester = restriction.SourceConsole, actor.Role
	}
	q, replay, err := rs.svc.CreateRequest(r.Context(), actor, requester, source, *b.ClientRef, body)
	if err != nil {
		refusal(w, r, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, toRequestJSON(q))
}

// GetRestrictionRequest serves GET /v1/restriction-requests/{id}.
func (s apiServer) GetRestrictionRequest(w http.ResponseWriter, r *http.Request, id gen.RequestID) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	q, err := rs.svc.Request(r.Context(), id)
	if err == nil && actor.Type == string(audit.ActorClient) && q.Requester != actor.ID {
		// A machine requester reads its own requests only.
		err = restriction.ErrNotFound
	}
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestJSON(q))
}

// AcceptRestrictionRequest serves POST /v1/restriction-requests/{id}/accept.
func (s apiServer) AcceptRestrictionRequest(w http.ResponseWriter, r *http.Request, id gen.RequestID) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, false)
	if !ok {
		return
	}
	b, errs := restriction.DecodeReason(body, false, false, true)
	if len(errs) > 0 {
		refusal(w, r, &restriction.Refusal{Status: http.StatusBadRequest, Slug: restriction.SlugInvalid, Detail: "the request is refused; nothing changed", Fields: errs})
		return
	}
	var zt core.ZoneType
	if b.ZoneType != nil {
		zt = core.ZoneType(*b.ZoneType)
	}
	q, err := rs.svc.Accept(r.Context(), actor, id, zt, b.ReasonOr("accepted by "+actor.Role))
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestJSON(q))
}

// DeclineRestrictionRequest serves POST /v1/restriction-requests/{id}/decline.
func (s apiServer) DeclineRestrictionRequest(w http.ResponseWriter, r *http.Request, id gen.RequestID) {
	rs, actor, ok := s.restrictions(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, true)
	if !ok {
		return
	}
	b, errs := restriction.DecodeReason(body, true, false, false)
	if len(errs) > 0 {
		refusal(w, r, &restriction.Refusal{Status: http.StatusBadRequest, Slug: restriction.SlugInvalid, Detail: "the request is refused; nothing changed", Fields: errs})
		return
	}
	q, err := rs.svc.Decline(r.Context(), actor, id, b.ReasonOr(""))
	if err != nil {
		refusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestJSON(q))
}

// cisStatus is the current CIS projection's version and age, nil
// without one.
func (rs *restrictionAPI) cisStatus(ctx context.Context) (*string, *float64) {
	snap, err := rs.svc.Airspaces.Current(ctx)
	if err != nil {
		return nil, nil
	}
	v := snap.Version
	age := max(0, time.Since(snap.FetchedAt).Seconds())
	return &v, &age
}

// --- wire shapes (api/openapi.yaml Restriction, RestrictionVersion,
// RestrictionRequest); numbers are float64, unlike the generated types.

type restrictionJSON struct {
	ID                  string            `json:"id"`
	AnspRef             string            `json:"ansp_ref"`
	Identifier          string            `json:"identifier"`
	UspaceAirspaceID    string            `json:"uspace_airspace_id"`
	ZoneType            string            `json:"zone_type"`
	Geometry            json.RawMessage   `json:"geometry"`
	RadiusM             *float64          `json:"radius_m"`
	LowerM              float64           `json:"lower_m"`
	LowerRef            string            `json:"lower_ref"`
	UpperM              float64           `json:"upper_m"`
	UpperRef            string            `json:"upper_ref"`
	StartsAt            string            `json:"starts_at"`
	EndsAt              string            `json:"ends_at"`
	ReasonText          string            `json:"reason_text"`
	State               string            `json:"state"`
	AnspVersion         int64             `json:"ansp_version"`
	CreatedBy           string            `json:"created_by"`
	ActivatedBy         *string           `json:"activated_by,omitempty"`
	EndedBy             *string           `json:"ended_by,omitempty"`
	CancelledBy         *string           `json:"cancelled_by,omitempty"`
	CreatedAt           string            `json:"created_at"`
	ActivatedAt         *string           `json:"activated_at"`
	ActivateAt          *string           `json:"activate_at"`
	EndedAtActual       *string           `json:"ended_at_actual"`
	RequestID           *string           `json:"request_id"`
	PublishedVersion    *int64            `json:"published_version"`
	SupersedesID        *string           `json:"supersedes_id"`
	DSSConstraintID     string            `json:"dss_constraint_id"`
	DSSVersion          *int64            `json:"dss_version"`
	Feature             json.RawMessage   `json:"feature"`
	ConstraintReference json.RawMessage   `json:"constraint_reference"`
	DSS                 deliver.DSSStatus `json:"dss"`
	Deliveries          deliver.Summary   `json:"deliveries"`
	CISVersion          *string           `json:"cis_version"`
	CISAgeS             *float64          `json:"cis_age_s"`
}

type listJSON struct {
	Restrictions []restrictionJSON `json:"restrictions"`
	Truncated    *bool             `json:"truncated,omitempty"`
	CISVersion   *string           `json:"cis_version"`
	CISAgeS      *float64          `json:"cis_age_s"`
}

func stampPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := restriction.Stamp(*t)
	return &s
}

// restrictionJSON is x on the wire; cis_version is the projection x was
// placed against, cis_age_s the age of the current projection.
func (rs *restrictionAPI) restrictionJSON(ctx context.Context, x restriction.Restriction) restrictionJSON {
	_, age := rs.cisStatus(ctx)
	return restrictionJSON{
		ID: x.ID, AnspRef: x.AnspRef, Identifier: x.Identifier, UspaceAirspaceID: x.UspaceAirspaceID, ZoneType: string(x.ZoneType),
		Geometry: json.RawMessage(x.Shape.GeoJSON()), RadiusM: x.Shape.Radius(), LowerM: x.LowerM, LowerRef: string(x.LowerRef),
		UpperM: x.UpperM, UpperRef: string(x.UpperRef), StartsAt: restriction.Stamp(x.StartsAt), EndsAt: restriction.Stamp(x.EndsAt),
		ReasonText: x.ReasonText, State: string(x.State), AnspVersion: x.AnspVersion, CreatedBy: x.CreatedBy,
		ActivatedBy: x.ActivatedBy, EndedBy: x.EndedBy, CancelledBy: x.CancelledBy, CreatedAt: restriction.Stamp(x.CreatedAt),
		ActivatedAt: stampPtr(x.ActivatedAt), ActivateAt: stampPtr(x.ActivateAt), EndedAtActual: stampPtr(x.EndedAtActual),
		RequestID: x.RequestID, PublishedVersion: x.PublishedVersion, SupersedesID: x.SupersedesID,
		DSSConstraintID: x.DSSConstraintID, DSSVersion: x.DSSVersion, Feature: x.Feature,
		ConstraintReference: constraintReference(x), DSS: store.DSSStatusOf(x), Deliveries: rs.deliveries(ctx, x),
		CISVersion: x.CISVersion, CISAgeS: age,
	}
}

// constraintReference is the F3548 reference as the DSS last accepted
// it (WP-9), null before the first write.
func constraintReference(x restriction.Restriction) json.RawMessage {
	if len(x.DSSReference) == 0 {
		return json.RawMessage("null")
	}
	return x.DSSReference
}

type versionJSON struct {
	RestrictionID string          `json:"restriction_id"`
	Version       int64           `json:"version"`
	State         string          `json:"state"`
	Feature       json.RawMessage `json:"feature"`
	Constraint    json.RawMessage `json:"constraint"`
	ChangedBy     string          `json:"changed_by"`
	ChangedAt     string          `json:"changed_at"`
	ChangeReason  string          `json:"change_reason"`
}

type versionListJSON struct {
	Versions []versionJSON `json:"versions"`
}

// toVersionJSON is v on the wire. constraint is the F3548 Constraint as
// written to the DSS (the reference the DSS accepted for this version
// and its details, WP-9); null for a version the DSS never accepted (the
// derived details stay in the store with their derivation).
func toVersionJSON(v restriction.Version) versionJSON {
	cons := json.RawMessage("null")
	var stored struct {
		Reference json.RawMessage `json:"reference"`
		Details   json.RawMessage `json:"details"`
	}
	if len(v.Constraint) > 0 && json.Unmarshal(v.Constraint, &stored) == nil && len(stored.Reference) > 0 && string(stored.Reference) != "null" {
		if b, err := json.Marshal(map[string]json.RawMessage{"reference": stored.Reference, "details": stored.Details}); err == nil {
			cons = b
		}
	}
	return versionJSON{
		RestrictionID: v.RestrictionID, Version: v.Version, State: string(v.State), Feature: v.Feature, Constraint: cons,
		ChangedBy: v.ChangedBy, ChangedAt: restriction.Stamp(v.ChangedAt), ChangeReason: v.ChangeReason,
	}
}

type requestJSON struct {
	ID             string          `json:"id"`
	Requester      string          `json:"requester"`
	Source         string          `json:"source"`
	Payload        json.RawMessage `json:"payload"`
	ReceivedAt     string          `json:"received_at"`
	State          string          `json:"state"`
	DecidedBy      *string         `json:"decided_by,omitempty"`
	DecidedAt      *string         `json:"decided_at,omitempty"`
	DecisionReason *string         `json:"decision_reason,omitempty"`
	RestrictionID  *string         `json:"restriction_id,omitempty"`
}

func toRequestJSON(q restriction.Request) requestJSON {
	return requestJSON{
		ID: q.ID, Requester: q.Requester, Source: q.Source, Payload: q.Payload, ReceivedAt: restriction.Stamp(q.ReceivedAt),
		State: q.State, DecidedBy: q.DecidedBy, DecidedAt: stampPtr(q.DecidedAt), DecisionReason: q.DecisionReason, RestrictionID: q.RestrictionID,
	}
}
