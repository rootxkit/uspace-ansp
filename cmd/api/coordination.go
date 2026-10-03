package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/coord"
)

// coordUnavailableRetry is the Retry-After while the inbox is not
// served (no relational database).
const coordUnavailableRetry = 60 * time.Second

// coordAPI serves the coordination and occurrence operations (WP-10).
type coordAPI struct {
	svc    *coord.Service
	occ    *coord.Occurrences
	stream *coordStream
}

func coordUnavailable(w http.ResponseWriter, r *http.Request) {
	apierr.WriteError(w, r, apierr.Unavailable(coordUnavailableRetry, "the coordination inbox needs the relational database (ANSP_RELATIONAL_DSN)"))
}

// readJSON reads a JSON body of at most limit bytes: 415 for another
// media type, 413 past the bound, 400 for a body that is not JSON.
func readJSON(w http.ResponseWriter, r *http.Request, limit int, required bool) ([]byte, bool) {
	if r.Body == nil || (r.ContentLength == 0 && !required) {
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
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		apierr.WriteError(w, r, apierr.TooLarge(mbe.Limit))
		return nil, false
	case err != nil:
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "could not be read")))
		return nil, false
	case len(body) > limit:
		apierr.WriteError(w, r, apierr.TooLarge(int64(limit)))
		return nil, false
	}
	empty := len(strings.TrimSpace(string(body))) == 0
	switch {
	case empty && required:
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "is required")))
		return nil, false
	case !empty && !json.Valid(body):
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "is not the JSON document this operation takes")))
		return nil, false
	}
	return body, true
}

// coordRefusal writes err: a *coord.Refusal with its status and slug,
// ErrNotFound 404, ErrAcknowledged 409, a timeout 503, anything else
// 500 without its text.
func coordRefusal(w http.ResponseWriter, r *http.Request, err error) {
	var rf *coord.Refusal
	switch {
	case errors.As(err, &rf):
		fields := make([]apierr.FieldProblem, 0, len(rf.Fields))
		for _, f := range rf.Fields {
			fields = append(fields, apierr.FieldProblem{Field: f.Field, Reason: f.Reason})
		}
		p := apierr.New(rf.Status, rf.Slug, rf.Detail, fields...)
		p.RetryAfter = rf.RetryAfter
		apierr.WriteError(w, r, p)
	case errors.Is(err, coord.ErrNotFound):
		apierr.WriteError(w, r, apierr.NotFound("no such notice"))
	case errors.Is(err, coord.ErrAcknowledged):
		apierr.WriteError(w, r, apierr.New(http.StatusConflict, apierr.SlugConflict, "the notice is acknowledged already",
			apierr.FieldProblem{Field: "state", Reason: "is acknowledged"}))
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		apierr.WriteError(w, r, apierr.Unavailable(5*time.Second, "the request did not complete in time"))
	default:
		apierr.WriteError(w, r, apierr.Internal())
	}
}

// SubmitCoordinationNotice serves POST /v1/coordination/notices (M2):
// 202 with the receipt after the commit, 200 with the first receipt for
// a repeat.
func (s apiServer) SubmitCoordinationNotice(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(w, r, coord.MaxNoticeBytes, true)
	if !ok {
		return
	}
	if s.co == nil {
		coordUnavailable(w, r)
		return
	}
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.Session || p.Claims.Subject == "" {
		apierr.WriteError(w, r, apierr.Unauthenticated("no machine caller"))
		return
	}
	rec, replay, err := s.co.svc.Submit(r.Context(), p.Claims.Subject, body)
	if err != nil {
		coordRefusal(w, r, err)
		return
	}
	status := http.StatusAccepted
	if replay {
		status = http.StatusOK
	}
	writeJSON(w, status, rec)
}

// GetCoordinationNotice serves GET /v1/coordination/notices/{ack_id}: a
// machine caller reads the notices it sent, without the payload; a
// console session any notice with it.
func (s apiServer) GetCoordinationNotice(w http.ResponseWriter, r *http.Request, ackID gen.AckID) {
	if s.co == nil {
		coordUnavailable(w, r)
		return
	}
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.Claims.Subject == "" {
		apierr.WriteError(w, r, apierr.Unauthenticated("no authenticated caller"))
		return
	}
	sender := ""
	if !p.Session {
		sender = p.Claims.Subject
	}
	n, err := s.co.svc.Get(r.Context(), ackID, sender)
	if err != nil {
		coordRefusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, coord.BodyOf(n, p.Session))
}

type inboxJSON struct {
	Notices   []coord.NoticeBody `json:"notices"`
	Truncated *bool              `json:"truncated,omitempty"`
}

// sessionActor is the console user of the request.
func sessionActor(w http.ResponseWriter, r *http.Request) (coord.Actor, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || !p.Session || p.Claims.Subject == "" {
		apierr.WriteError(w, r, apierr.Unauthenticated("no console session"))
		return coord.Actor{}, false
	}
	return coord.Actor{ID: p.Claims.Subject, Role: p.Role}, true
}

// ListCoordinationInbox serves GET /v1/coordination/inbox (audited).
func (s apiServer) ListCoordinationInbox(w http.ResponseWriter, r *http.Request, params gen.ListCoordinationInboxParams) {
	if s.co == nil {
		coordUnavailable(w, r)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	f := coord.Filter{Limit: DefaultListLimit, Since: params.Since}
	if params.Limit != nil {
		f.Limit = *params.Limit
	}
	if params.State != nil {
		st := coord.State(*params.State)
		if !st.Valid() {
			apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("state", "is not received, escalated or acknowledged")))
			return
		}
		f.State = string(st)
	}
	list, more, err := s.co.svc.Inbox(r.Context(), actor, f)
	if err != nil {
		coordRefusal(w, r, err)
		return
	}
	out := inboxJSON{Notices: make([]coord.NoticeBody, 0, len(list))}
	for i := range list {
		out.Notices = append(out.Notices, coord.BodyOf(list[i], true))
	}
	if more {
		out.Truncated = &more
	}
	writeJSON(w, http.StatusOK, out)
}

// AcknowledgeCoordinationNotice serves POST
// /v1/coordination/inbox/{id}/acknowledge (watch_supervisor, audited).
func (s apiServer) AcknowledgeCoordinationNotice(w http.ResponseWriter, r *http.Request, id gen.NoticeID) {
	if s.co == nil {
		coordUnavailable(w, r)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	body, ok := readJSON(w, r, 4<<10, false)
	if !ok {
		return
	}
	note, fe := coord.DecodeAcknowledge(body)
	if fe != nil {
		apierr.WriteError(w, r, apierr.Invalid(fe))
		return
	}
	n, err := s.co.svc.Acknowledge(r.Context(), actor, id, note)
	if err != nil {
		coordRefusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, coord.BodyOf(n, true))
}

// StreamCoordination serves GET /v1/coordination/stream (WebSocket).
// The guard has judged the session and the Origin before this runs
// (M22).
func (s apiServer) StreamCoordination(w http.ResponseWriter, r *http.Request) {
	if s.co == nil || s.co.stream == nil {
		coordUnavailable(w, r)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		apierr.WriteError(w, r, apierr.UpgradeRequired())
		return
	}
	s.co.stream.serve(w, r)
}

// CreateOccurrence serves POST /v1/occurrences (watch_supervisor): the
// report is stored with its reporter reference sealed and queued to the
// authority in one transaction; 202 with the deadline.
func (s apiServer) CreateOccurrence(w http.ResponseWriter, r *http.Request) {
	body, ok := readJSON(w, r, coord.MaxOccurrenceBytes, true)
	if !ok {
		return
	}
	if s.co == nil || s.co.occ == nil {
		apierr.WriteError(w, r, apierr.Unavailable(coordUnavailableRetry, "occurrence reports need the relational database and the outbox (ANSP_RELATIONAL_DSN)"))
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	in, errs := coord.DecodeOccurrence(body)
	if len(errs) > 0 {
		s.co.occ.Counters().Inc(coord.CounterOccurrencesRefused)
		apierr.WriteError(w, r, apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, "the report is refused; nothing was stored", fieldProblems(errs)...))
		return
	}
	q, err := s.co.occ.Create(r.Context(), actor, in)
	if err != nil {
		coordRefusal(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, q)
}

func fieldProblems(errs []*core.FieldError) []apierr.FieldProblem {
	out := make([]apierr.FieldProblem, 0, len(errs))
	for _, e := range errs {
		out = append(out, apierr.FieldProblem{Field: e.Field, Reason: e.Reason})
	}
	return out
}
