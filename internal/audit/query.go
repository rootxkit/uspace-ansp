package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/store/relational"
)

// Page sizes of Query (GET /v1/audit).
const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

// Filter selects the events of one page, newest first.
type Filter struct {
	// Since is the earliest ts returned; zero is the beginning.
	Since time.Time
	// EntityType and EntityID narrow to one entity (type alone, or both).
	EntityType string
	EntityID   string
	// Before is the cursor: only ids below it (0 starts at the newest).
	Before int64
	// Limit is the page size; 0 is DefaultPageSize, above MaxPageSize is
	// refused.
	Limit int
}

// Page is one page of events and the cursor of the next, 0 when there
// is none.
type Page struct {
	Events []Row
	Next   int64
}

// Query reads one page of the audit log for /v1/audit.
func Query(ctx context.Context, db relational.DBTX, f Filter) (Page, error) {
	limit := f.Limit
	switch {
	case limit == 0:
		limit = DefaultPageSize
	case limit < 0 || limit > MaxPageSize:
		return Page{}, core.Fieldf("limit", "must be 1 to %d", MaxPageSize)
	}
	if f.EntityID != "" && f.EntityType == "" {
		return Page{}, core.Fieldf("entity_id", "needs entity_type")
	}
	if f.Before < 0 {
		return Page{}, core.Fieldf("before", "must not be negative")
	}
	before := f.Before
	if before == 0 {
		before = maxID
	}
	since := f.Since
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	params := relational.QueryEventsParams{Since: since, BeforeID: before, PageSize: int32(limit)}
	if f.EntityType != "" {
		params.EntityType = &f.EntityType
	}
	if f.EntityID != "" {
		params.EntityID = &f.EntityID
	}
	rows, err := relational.New(db).QueryEvents(ctx, params)
	if err != nil {
		return Page{}, fmt.Errorf("audit query: %w", err)
	}
	out := Page{Events: make([]Row, 0, len(rows))}
	for i := range rows {
		out.Events = append(out.Events, rowFrom(&rows[i]))
	}
	if len(rows) == limit {
		out.Next = rows[len(rows)-1].ID
	}
	return out, nil
}
