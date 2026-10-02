package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/bus"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/sources"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// sourcesRetry is the Retry-After of a switch refused because KV or the
// database cannot take it.
const sourcesRetry = 10 * time.Second

// sourcesAPI serves the source switches (04 section 3.6, U-15) through
// the sources writer: GET /v1/sources from the database of record, PUT
// /v1/sources/{type}/{instance} row first, KV after the commit.
type sourcesAPI struct {
	repo   sources.Repo
	writer *sources.Writer
	logger *slog.Logger
}

// sourcesWiring is the source-switch side of api and its republish.
type sourcesWiring struct {
	api *sourcesAPI
	run []func(ctx context.Context)
}

// natsPush pushes on a core subject while the bus is connected.
type natsPush struct{ b *bus.Bus }

func (p natsPush) Publish(subject string, data []byte) error {
	nc := p.b.Conn()
	if nc == nil {
		return bus.ErrNoBus
	}
	if s, _ := p.b.Status(); s != obs.StateOK {
		return errors.New("the bus is not connected")
	}
	return nc.Publish(subject, data)
}

// wireSources builds the writer on the relational database and the
// source_control bucket, and republishes the database's state every
// sources.RepublishPeriod (B-09). Without the database the operations
// answer 503.
func wireSources(db *store.Relational, b *bus.Bus, reg prometheus.Registerer, logger *slog.Logger) (*sourcesWiring, error) {
	if db == nil {
		logger.Warn("source switches are not served: ANSP_RELATIONAL_DSN is not set; the source operations answer 503")
		return &sourcesWiring{}, nil
	}
	repo := store.SourcesRepo{DB: db}
	w := &sources.Writer{Repo: repo, KV: b.KeyValue(bus.BucketSourceControl), Push: natsPush{b: b}}
	if err := obs.Counters(reg, "", w.Counters()); err != nil {
		return nil, err
	}
	run := func(ctx context.Context) {
		logged := false
		w.Run(ctx, sources.RepublishPeriod, func(err error) {
			// Logged once per outage, not every period.
			if !logged {
				logger.Error("source switches: the KV bucket does not hold the database's state; republishing every period",
					slog.String("error", err.Error()))
				logged = true
			}
		})
	}
	return &sourcesWiring{api: &sourcesAPI{repo: repo, writer: w, logger: logger}, run: []func(ctx context.Context){run}}, nil
}

// sourceControlJSON is a row as api/openapi.yaml SourceControl gives it:
// the whole type is instance "*".
type sourceControlJSON struct {
	SourceType string `json:"source_type"`
	InstanceID string `json:"instance_id"`
	Enabled    bool   `json:"enabled"`
	Reason     string `json:"reason"`
	Actor      string `json:"actor"`
	ChangedAt  string `json:"changed_at"`
	Version    uint64 `json:"version"`
	Epoch      string `json:"epoch"`
}

func toSourceJSON(r *sources.Row, epoch string) sourceControlJSON {
	inst := "*"
	if r.InstanceID != nil {
		inst = *r.InstanceID
	}
	return sourceControlJSON{SourceType: r.SourceType, InstanceID: inst, Enabled: r.Enabled, Reason: r.Reason, Actor: r.Actor,
		ChangedAt: r.ChangedAt.UTC().Format("2006-01-02T15:04:05.000Z"), Version: r.Version, Epoch: epoch}
}

func (s apiServer) sourcesOr503(w http.ResponseWriter, r *http.Request) *sourcesAPI {
	if s.src == nil {
		apierr.WriteError(w, r, apierr.Unavailable(sourcesRetry, "source switches need the relational database (ANSP_RELATIONAL_DSN)"))
	}
	return s.src
}

// ListSources serves GET /v1/sources: every switch with who set it, when
// and why, from the database of record.
func (s apiServer) ListSources(w http.ResponseWriter, r *http.Request) {
	src := s.sourcesOr503(w, r)
	if src == nil {
		return
	}
	doc, err := src.repo.Load(r.Context())
	if err != nil {
		apierr.WriteError(w, r, apierr.Unavailable(sourcesRetry, "the source switches cannot be read now"))
		return
	}
	out := struct {
		Sources []sourceControlJSON `json:"sources"`
	}{Sources: make([]sourceControlJSON, 0, len(doc.Controls))}
	for i := range doc.Controls {
		out.Sources = append(out.Sources, toSourceJSON(&doc.Controls[i], doc.Epoch))
	}
	writeJSON(w, http.StatusOK, out)
}

// SetSourceControl serves PUT /v1/sources/{type}/{instance}: the switch
// with its reason, set by the admin calling. 503 and nothing changed
// when the source_control bucket cannot be reached; a KV put that fails
// after the commit leaves the switch set (the database is the record),
// is logged at error level and is repaired by the republish.
func (s apiServer) SetSourceControl(w http.ResponseWriter, r *http.Request, pType gen.SetSourceControlParamsType, instance gen.SourceInstance) {
	src := s.sourcesOr503(w, r)
	if src == nil {
		return
	}
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || !p.Session || p.Claims.Subject == "" {
		apierr.WriteError(w, r, apierr.Unauthenticated("a console session is required"))
		return
	}
	body, ok := readBody(w, r, true)
	if !ok {
		return
	}
	var in struct {
		Enabled *bool   `json:"enabled"`
		Reason  *string `json:"reason"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Enabled == nil || in.Reason == nil {
		apierr.WriteError(w, r, apierr.Invalid(core.Fieldf("body", "{enabled, reason} is required")))
		return
	}
	c := sources.Change{SourceType: string(pType), Enabled: *in.Enabled, Reason: *in.Reason, Actor: p.Claims.Subject}
	if inst := instance; inst != "*" {
		c.InstanceID = &inst
	}
	row, doc, putErr, err := src.writer.Set(r.Context(), c)
	var fe *core.FieldError
	switch {
	case errors.Is(err, sources.ErrKVUnavailable):
		apierr.WriteError(w, r, apierr.Unavailable(sourcesRetry, "the source_control bucket cannot be reached; nothing was changed"))
		return
	case errors.As(err, &fe):
		apierr.WriteError(w, r, apierr.FromError(err))
		return
	case err != nil:
		apierr.WriteError(w, r, apierr.Unavailable(sourcesRetry, "the switch could not be recorded; nothing was changed"))
		return
	}
	if putErr != nil {
		src.logger.Error("source switch set, but KV did not take it; the republish repairs it within a period",
			slog.String("source_type", c.SourceType), slog.String("instance", instance), slog.String("error", putErr.Error()))
	}
	writeJSON(w, http.StatusOK, toSourceJSON(&row, doc.Epoch))
}
