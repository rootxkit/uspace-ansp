package dss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// ErrUnknown is a constraint this system does not serve: never written
// to the DSS, ended longer than the retention ago, or not ours.
var ErrUnknown = errors.New("no such constraint")

// Written is a constraint as the DSS last accepted it: the reference the
// DSS answered with (its ovn included: this system is the manager) and
// the details of the version that write carried.
type Written struct {
	Reference json.RawMessage
	Details   json.RawMessage
	// Expired is true once the restriction ended (or was cancelled) more
	// than the retention before the database's now.
	Expired bool
}

// Store reads the written constraint of entity id (internal/store
// implements it with one indexed query on the database clock); ErrUnknown
// when there is none.
type Store interface {
	Written(ctx context.Context, id string, retention time.Duration) (Written, error)
}

// Counters of the details handler (E-09).
const (
	CounterDetailsServed   = "dss_details_served"
	CounterDetailsUnknown  = "dss_details_unknown"
	CounterDetailsExpired  = "dss_details_expired"
	CounterDetailsUnusable = "dss_details_unusable"
)

// DefaultRetention is ExternalDataMaxRetentionTimeHours: how long the
// details of an ended constraint stay served.
const DefaultRetention = f3548.ExternalDataMaxRetentionTimeHours * time.Hour

// Details serves GET /uss/v1/constraints/{entityid}: the
// GetConstraintDetailsResponse of the version the DSS last accepted (the
// standard: "the most recent version the USS knows was accepted by the
// DSS"; before the first write the constraint is unknown, 404), its
// details exactly the restriction's F3548 volumes as WP-5 derived them
// (type DAR, the geozone where core maps it), for the retention after
// the restriction ended.
type Details struct {
	Store     Store
	Retention time.Duration
	Counters  *core.Counters
}

func (d *Details) count(name string) {
	if d.Counters != nil {
		d.Counters.Inc(name)
	}
}

// Get is the response body for constraint id.
func (d *Details) Get(ctx context.Context, id string) ([]byte, error) {
	ret := d.Retention
	if ret <= 0 {
		ret = DefaultRetention
	}
	w, err := d.Store.Written(ctx, id, ret)
	if errors.Is(err, ErrUnknown) {
		d.count(CounterDetailsUnknown)
		return nil, ErrUnknown
	}
	if err != nil {
		return nil, err
	}
	if w.Expired {
		d.count(CounterDetailsExpired)
		return nil, ErrUnknown
	}
	body, err := DetailsBody(w)
	if err != nil {
		d.count(CounterDetailsUnusable)
		return nil, err
	}
	d.count(CounterDetailsServed)
	return body, nil
}

// DetailsBody is the GetConstraintDetailsResponse of w, through
// uspace-core's types (one struct, D7): the stored documents are read
// back into them, so what is served is what the standard describes.
func DetailsBody(w Written) ([]byte, error) {
	var resp f3548.GetConstraintDetailsResponse
	if err := json.Unmarshal(w.Reference, &resp.Constraint.Reference); err != nil {
		return nil, fmt.Errorf("the stored reference: %w", err)
	}
	if err := json.Unmarshal(w.Details, &resp.Constraint.Details); err != nil {
		return nil, fmt.Errorf("the stored details: %w", err)
	}
	if len(resp.Constraint.Details.Volumes) == 0 {
		return nil, errors.New("the stored details have no volume")
	}
	return json.Marshal(resp)
}
