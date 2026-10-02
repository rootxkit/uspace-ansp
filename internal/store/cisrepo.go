package store

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/cis"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// sweepBatch bounds the expired delivery ids one notification deletes.
const sweepBatch = 100

// CISRepo is cis.Store and cis.ReceiverStore on the relational
// database: cis_cache and cis_notifications_seen (WP-7). It lives here,
// not in internal/cis, so the hot path that follows the projection has
// no database import path (docs/PLAN.md section 3). Every instant is
// the database clock.
type CISRepo struct{ DB *Relational }

var (
	_ cis.Store         = CISRepo{}
	_ cis.ReceiverStore = CISRepo{}
)

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

// RememberJTI records a delivery id for ttl unless it is live or
// maxLive ids are; a bounded batch of expired ids is deleted first.
func (r CISRepo) RememberJTI(ctx context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (fresh, full bool, err error) {
	err = r.DB.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		if _, err := q.SweepCISNotifications(ctx, sweepBatch); err != nil {
			return fmt.Errorf("sweep cis_notifications_seen: %w", err)
		}
		live, err := q.CISNotificationLive(ctx, relational.CISNotificationLiveParams{Issuer: issuer, Jti: jti})
		if err != nil {
			return fmt.Errorf("read cis_notifications_seen: %w", err)
		}
		if live.Seen {
			return nil
		}
		if live.Live >= maxLive {
			full = true
			return nil
		}
		_, err = q.RememberCISNotification(ctx, relational.RememberCISNotificationParams{Issuer: issuer, Jti: jti, TtlS: ttl.Seconds()})
		if IsNoRows(err) {
			return nil // a concurrent delivery of the same id won
		}
		if err != nil {
			return fmt.Errorf("write cis_notifications_seen: %w", err)
		}
		fresh = true
		return nil
	})
	return fresh, full, err
}
