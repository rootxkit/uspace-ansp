package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// CISRepo is cis.Store on the relational database: cis_cache (WP-7). It lives here,
// not in internal/cis, so the hot path that follows the projection has
// no database import path (docs/PLAN.md section 3). Every instant is
// the database clock.
type CISRepo struct{ DB *Relational }

var _ cis.Store = CISRepo{}

// Save stores v unless cis_cache holds a higher version of its dataset.
func (r CISRepo) Save(ctx context.Context, v *cis.Version) (time.Time, bool, error) {
	var at time.Time
	newer := false
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		t, err := q.SaveCISVersion(ctx, relational.SaveCISVersionParams{
			Dataset: string(v.Dataset), Version: v.Number, Etag: v.ETag, CisUpdatedAt: v.UpdatedAt, Body: v.Body,
		})
		if IsNoRows(err) {
			newer = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("save cis_cache: %w", err)
		}
		at = t
		return nil
	})
	return at, newer, err
}

// Touch moves fetched_at of the dataset's row at version.
func (r CISRepo) Touch(ctx context.Context, d cis.Dataset, version int64) (time.Time, bool, error) {
	var at time.Time
	ok := true
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		t, err := q.TouchCISVersion(ctx, relational.TouchCISVersionParams{Dataset: string(d), Version: version})
		if IsNoRows(err) {
			ok = false
			return nil
		}
		if err != nil {
			return fmt.Errorf("touch cis_cache: %w", err)
		}
		at = t
		return nil
	})
	return at, ok, err
}

// Load reads every cis_cache row; a row of a dataset this build does not
// project is skipped.
func (r CISRepo) Load(ctx context.Context) ([]cis.Stored, error) {
	var out []cis.Stored
	err := r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		rows, err := q.ListCISVersions(ctx)
		if err != nil {
			return fmt.Errorf("read cis_cache: %w", err)
		}
		for _, row := range rows {
			d, ok := cis.ParseDataset(row.Dataset)
			if !ok {
				continue
			}
			out = append(out, cis.Stored{Dataset: d, Version: row.Version, ETag: row.Etag, Body: row.Body, FetchedAt: row.FetchedAt})
		}
		return nil
	})
	return out, err
}
