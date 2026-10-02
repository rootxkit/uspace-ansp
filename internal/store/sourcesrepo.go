package store

import (
	"context"
	"fmt"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/sources"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// The audit names of a source switch (WP-6).
const (
	EventSourceControlSet = "source_control_set"
	EntitySourceControl   = "source_control"
	purposeSourceControl  = "source switch (04 3.6, U-15)"
	lockSourceControl     = "source_controls"
)

// SourcesRepo is sources.Repo on the relational database
// (source_controls, migration 0004).
type SourcesRepo struct{ DB *Relational }

var _ sources.Repo = SourcesRepo{}

// Set upserts one switch under the writers' advisory lock, so the
// version is taken from the sequence after the lock (the order of the
// versions is the order of the commits), records source_control_set and
// returns the row and the whole state as committed.
func (r SourcesRepo) Set(ctx context.Context, c sources.Change) (sources.Row, sources.Doc, error) {
	var row sources.Row
	var doc sources.Doc
	err := r.DB.Tx(ctx, func(ctx context.Context, tx Tx) error {
		if err := tx.Q.AdvisoryXactLock(ctx, LockKey(lockSourceControl)); err != nil {
			return fmt.Errorf("source_controls lock: %w", err)
		}
		got, err := tx.Q.UpsertSourceControl(ctx, relational.UpsertSourceControlParams{
			SourceType: c.SourceType, InstanceID: c.InstanceID, Enabled: c.Enabled, Reason: c.Reason, Actor: c.Actor,
		})
		if err != nil {
			return fmt.Errorf("upsert source_controls: %w", err)
		}
		row = rowFrom(&got)
		entity := c.SourceType + "/*"
		if c.InstanceID != nil {
			entity = c.SourceType + "/" + *c.InstanceID
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			ActorType: audit.ActorUser, ActorID: c.Actor, Purpose: purposeSourceControl,
			EntityType: EntitySourceControl, EntityID: entity, EventType: EventSourceControlSet,
			Payload: map[string]any{"enabled": c.Enabled, "reason": c.Reason, "version": got.Version, "epoch": got.Epoch.String()},
		}); err != nil {
			return err
		}
		doc, err = load(ctx, tx.Q)
		return err
	})
	if err != nil {
		return sources.Row{}, sources.Doc{}, err
	}
	return row, doc, nil
}

// Load reads the whole state.
func (r SourcesRepo) Load(ctx context.Context) (sources.Doc, error) {
	var doc sources.Doc
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		doc, err = load(ctx, q)
		return err
	})
	return doc, err
}

// load reads the epoch and every row (bounded by sources.MaxRows: a
// state past it is refused, never cut).
func load(ctx context.Context, q *relational.Queries) (sources.Doc, error) {
	epoch, err := q.SourceControlEpoch(ctx)
	if err != nil {
		return sources.Doc{}, fmt.Errorf("read source_control_epoch: %w", err)
	}
	rows, err := q.ListSourceControls(ctx, sources.MaxRows+1)
	if err != nil {
		return sources.Doc{}, fmt.Errorf("read source_controls: %w", err)
	}
	if len(rows) > sources.MaxRows {
		return sources.Doc{}, fmt.Errorf("source_controls holds more than %d rows", sources.MaxRows)
	}
	doc := sources.Doc{Epoch: epoch.String(), Controls: make([]sources.Row, 0, len(rows))}
	for i := range rows {
		if v := uint64(max(rows[i].Version, 0)); v > doc.Version {
			doc.Version = v
		}
		doc.Controls = append(doc.Controls, rowFrom(&rows[i]))
	}
	return doc, nil
}

func rowFrom(r *relational.SourceControl) sources.Row {
	return sources.Row{SourceType: r.SourceType, InstanceID: r.InstanceID, Enabled: r.Enabled, Reason: r.Reason,
		Actor: r.Actor, ChangedAt: r.ChangedAt.UTC(), Version: uint64(max(r.Version, 0))}
}
