//go:build integration

package store_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-ansp/internal/audit"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
	"github.com/rootxkit/uspace-ansp/internal/store/relational"
	"github.com/rootxkit/uspace-ansp/internal/store/storetest"
)

type airspaces struct{ snap restriction.Snapshot }

func (a airspaces) Current(context.Context) (restriction.Snapshot, error) { return a.snap, nil }

type recordingBus struct {
	mu       sync.Mutex
	subjects []string
}

func (b *recordingBus) Publish(_ context.Context, subject, _ string, _ []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subjects = append(b.subjects, subject[:strings.LastIndexByte(subject, '.')])
	return nil
}

// uspace is a fixture U-space airspace: 44.6..45.0 E, 41.6..41.9 N, up
// to 1500 m WGS84.
func uspace() ed318.Feature {
	upper, lower := 1500.0, 0.0
	return ed318.Feature{Type: "Feature",
		Geometry: ed318.Geometry{Type: ed318.GeometryPolygon, Rings: [][]core.LatLon{{
			{LatDeg: 41.6, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 45.0}, {LatDeg: 41.9, LonDeg: 44.6}, {LatDeg: 41.6, LonDeg: 44.6},
		}}, Layer: &ed318.Layer{Upper: &upper, UpperReference: core.RefWGS84, Lower: &lower, LowerReference: core.RefWGS84}},
		Properties: ed318.UASZone{Identifier: "GEOTU01", Country: "GEO", Type: core.ZoneUSpace},
	}
}

func restrictionService(t *testing.T) (*restriction.Service, *store.Relational, *recordingBus, string) {
	t.Helper()
	dsn := storetest.Scratch(t, store.TreeRelational, true)
	db := storetest.Relational(t, dsn, store.RoleRelational)
	b := &recordingBus{}
	svc := &restriction.Service{
		Repo: store.RestrictionRepo{DB: db}, Bus: b, ClientID: "ansp-01", Producer: "ansp/api",
		Airspaces: airspaces{restriction.Snapshot{Version: "42", FetchedAt: time.Now(), Airspaces: []ed318.Feature{uspace()}}},
		Feature:   restriction.FeatureConfig{AuthorityName: "Test ANSP"},
	}
	return svc, db, b, dsn
}

var supervisor = restriction.Actor{Type: "user", ID: "01K6NZ8Q2W3E4R5T6Y7V8W9X0Z", Role: "watch_supervisor"}

func box(lon0, lat0, lon1, lat1 float64) restriction.Shape {
	return restriction.Shape{Ring: []core.LatLon{{LatDeg: lat0, LonDeg: lon0}, {LatDeg: lat0, LonDeg: lon1}, {LatDeg: lat1, LonDeg: lon1}, {LatDeg: lat1, LonDeg: lon0}, {LatDeg: lat0, LonDeg: lon0}}}
}

func planInput(start time.Time, d time.Duration) restriction.Input {
	return restriction.Input{UspaceAirspaceID: "GEOTU01", ZoneType: core.ZoneProhibited, Shape: box(44.78, 41.70, 44.82, 41.73),
		LowerM: 0, LowerRef: core.RefWGS84, UpperM: 120, UpperRef: core.RefWGS84,
		StartsAt: start.UTC().Truncate(time.Millisecond), EndsAt: start.Add(d).UTC().Truncate(time.Millisecond), ReasonText: "Search and rescue (synthetic)"}
}

// The lifecycle on the real database: four versions with the stored
// feature and constraint, four hash-chained events, four restr.v1
// publishes; versions and events are insert-only.
func TestIntegrationRestrictionLifecycle(t *testing.T) {
	ctx := ctxT(t)
	svc, db, b, _ := restrictionService(t)
	r, _, err := svc.Plan(ctx, supervisor, planInput(time.Now(), 2*time.Hour), restriction.PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !restriction.ValidIdentifier(r.Identifier) || r.CISVersion == nil || *r.CISVersion != "42" || len(r.Feature) == 0 || len(r.Constraint) == 0 || r.DSSConstraintID == "" {
		t.Fatalf("planned: %+v", r)
	}
	if _, err := svc.Apply(ctx, supervisor, r.ID, restriction.OpActivate, "on scene", nil); err != nil {
		t.Fatal(err)
	}
	end := r.EndsAt.Add(time.Hour)
	if _, err := svc.Apply(ctx, supervisor, r.ID, restriction.OpExtend, "longer", &end); err != nil {
		t.Fatal(err)
	}
	ended, err := svc.Apply(ctx, supervisor, r.ID, restriction.OpEnd, "done", nil)
	if err != nil || ended.State != restriction.StateEnded || ended.AnspVersion != 4 || ended.EndedAtActual == nil {
		t.Fatalf("ended: %+v %v", ended, err)
	}
	vs, err := svc.Versions(ctx, r.ID, 100)
	if err != nil || len(vs) != 4 {
		t.Fatalf("versions: %d %v", len(vs), err)
	}
	var page audit.Page
	err = db.Do(ctx, func(ctx context.Context, q relational.DBTX, _ *relational.Queries) error {
		var err error
		page, err = audit.Query(ctx, q, audit.Filter{EntityType: "restriction", EntityID: r.ID})
		return err
	})
	if err != nil || len(page.Events) != 4 {
		t.Fatalf("events: %d %v", len(page.Events), err)
	}
	var types []string
	for _, e := range page.Events {
		types = append(types, e.EventType)
	}
	slices.Sort(types)
	if !slices.Equal(types, []string{"restriction_activate", "restriction_end", "restriction_extend", "restriction_plan"}) {
		t.Fatalf("events %v", types)
	}
	if !slices.Equal(b.subjects, []string{"restr.v1.planned", "restr.v1.active", "restr.v1.active", "restr.v1.ended"}) {
		t.Fatalf("bus %v", b.subjects)
	}
	if left, _ := (store.RestrictionRepo{DB: db}).Unpublished(ctx, 10); len(left) != 0 {
		t.Fatalf("unpublished %d", len(left))
	}
	if v, err := svc.Version(ctx, r.ID, 3); err != nil || v.State != restriction.StateActive || !v.EndsAt.Equal(end) {
		t.Fatalf("version 3: %+v %v", v, err)
	}
	if _, err := svc.Version(ctx, r.ID, 9); !errors.Is(err, restriction.ErrNotFound) {
		t.Fatal(err)
	}
	err = db.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE restriction_versions SET change_reason = 'x'`)
		return err
	})
	if store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("versions updatable: %v", err)
	}
}

// PostGIS measures: the area on geography, and placement: inside
// accepted, partly outside and away refused; a circle by its buffer.
func TestIntegrationRestrictionPlacement(t *testing.T) {
	ctx := ctxT(t)
	svc, db, _, _ := restrictionService(t)
	repo := store.RestrictionRepo{DB: db}
	err := repo.Tx(ctx, func(ctx context.Context, tx restriction.Tx) error {
		a, err := tx.AreaM2(ctx, box(44.78, 41.70, 44.82, 41.73))
		if err != nil {
			return err
		}
		// 0.04 deg lon x 0.03 deg lat at 41.7 N: about 3.33 km x 3.33 km.
		if a < 10.5e6 || a > 11.6e6 {
			t.Errorf("polygon area %.0f m2", a)
		}
		c := core.LatLon{LatDeg: 41.7, LonDeg: 44.8}
		a, err = tx.AreaM2(ctx, restriction.Shape{Center: &c, RadiusM: 1000})
		if err != nil {
			return err
		}
		if a < 3.10e6 || a > 3.15e6 {
			t.Errorf("circle area %.0f m2", a)
		}
		part := restriction.Part{GeoJSON: restriction.Shape{Ring: uspace().Geometry.Rings[0]}.GeoJSON()}
		for name, tc := range map[string]struct {
			s          restriction.Shape
			intersects bool
			covers     bool
		}{
			"inside":  {box(44.78, 41.70, 44.82, 41.73), true, true},
			"partly":  {box(44.95, 41.85, 45.05, 41.88), true, false},
			"away":    {box(43.0, 42.5, 43.1, 42.6), false, false},
			"circle":  {restriction.Shape{Center: &c, RadiusM: 1000}, true, true},
			"overlap": {restriction.Shape{Center: &core.LatLon{LatDeg: 41.6, LonDeg: 44.8}, RadiusM: 1000}, true, false},
		} {
			rel, err := tx.Relate(ctx, tc.s, part)
			if err != nil {
				return err
			}
			if rel.Intersects != tc.intersects || rel.Covers != tc.covers {
				t.Errorf("%s: %+v", name, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	partly := planInput(time.Now(), time.Hour)
	partly.Shape = box(44.95, 41.85, 45.05, 41.88)
	_, _, err = svc.Plan(ctx, supervisor, partly, restriction.PlanOptions{})
	var rf *restriction.Refusal
	if !errors.As(err, &rf) || rf.Slug != restriction.SlugOutsideUSpace {
		t.Fatalf("partly outside: %v", err)
	}
}

// The scheduled activation fires on the database's clock; the expiry at
// ends_at; identifiers are distinct; idempotency keys and client refs
// hold under the database's unique constraints.
func TestIntegrationRestrictionTickAndKeys(t *testing.T) {
	ctx := ctxT(t)
	svc, db, b, _ := restrictionService(t)
	var now time.Time
	_ = db.Do(ctx, func(ctx context.Context, _ relational.DBTX, q *relational.Queries) error {
		var err error
		now, err = q.DBNow(ctx)
		return err
	})
	r, _, err := svc.Plan(ctx, supervisor, planInput(now.Add(2*time.Second), 2*time.Second), restriction.PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := svc.Apply(ctx, supervisor, r.ID, restriction.OpActivate, "at the start", nil); err != nil || s.ActivateAt == nil || s.State != restriction.StatePlanned {
		t.Fatalf("scheduled: %+v %v", s, err)
	}
	if rep, err := svc.Tick(ctx, time.Second); err != nil || rep.Activated != 0 {
		t.Fatalf("early: %+v %v", rep, err)
	}
	time.Sleep(2200 * time.Millisecond)
	if rep, err := svc.Tick(ctx, 5*time.Second); err != nil || rep.Activated != 1 {
		t.Fatalf("at starts_at: %+v %v", rep, err)
	}
	time.Sleep(2 * time.Second)
	if rep, err := svc.Tick(ctx, 5*time.Second); err != nil || rep.Expired != 1 {
		t.Fatalf("at ends_at: %+v %v", rep, err)
	}
	if got, _ := svc.Get(ctx, r.ID); got.State != restriction.StateEnded || got.AnspVersion != 3 {
		t.Fatalf("%+v", got)
	}
	if !slices.Equal(b.subjects, []string{"restr.v1.planned", "restr.v1.active", "restr.v1.ended"}) {
		t.Fatalf("bus %v", b.subjects)
	}

	seen := map[string]bool{}
	for i := range 20 {
		x, _, err := svc.Plan(ctx, supervisor, planInput(time.Now(), time.Hour), restriction.PlanOptions{})
		if err != nil || seen[x.Identifier] {
			t.Fatalf("%d: %s %v", i, x.Identifier, err)
		}
		seen[x.Identifier] = true
	}
	key := &restriction.Idempotency{ActorID: supervisor.ID, Key: "console-1", SHA256: restriction.Hash([]byte("a"))}
	first, _, err := svc.Plan(ctx, supervisor, planInput(time.Now(), time.Hour), restriction.PlanOptions{Idempotency: key})
	if err != nil {
		t.Fatal(err)
	}
	again, replay, err := svc.Plan(ctx, supervisor, planInput(time.Now(), time.Hour), restriction.PlanOptions{Idempotency: key})
	if err != nil || !replay || again.ID != first.ID {
		t.Fatalf("replay %v %v", replay, err)
	}
	other := *key
	other.SHA256 = restriction.Hash([]byte("b"))
	if _, _, err := svc.Plan(ctx, supervisor, planInput(time.Now(), time.Hour), restriction.PlanOptions{Idempotency: &other}); err == nil {
		t.Fatal("another body under the key")
	}

	authority := restriction.Actor{Type: "client", ID: "authority-01", Role: "authority-01"}
	payload := []byte(`{"client_ref":"GCAA-1","uspace_airspace_id":"GEOTU01","geometry":{"type":"Polygon","coordinates":[[[44.78,41.70],[44.82,41.70],[44.82,41.73],[44.78,41.73],[44.78,41.70]]]},"lower_m":0,"lower_ref":"WGS84","upper_m":120,"upper_ref":"WGS84","starts_at":"` +
		restriction.Stamp(time.Now().Add(time.Hour)) + `","ends_at":"` + restriction.Stamp(time.Now().Add(2*time.Hour)) + `","reason_text":"Public event (synthetic)"}`)
	q, _, err := svc.CreateRequest(ctx, authority, "authority-01", restriction.SourceAuthority, "GCAA-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, replay, err := svc.CreateRequest(ctx, authority, "authority-01", restriction.SourceAuthority, "GCAA-1", payload); err != nil || !replay {
		t.Fatalf("request replay: %v %v", replay, err)
	}
	acc, err := svc.Accept(ctx, supervisor, q.ID, "", "for the event")
	if err != nil || acc.State != restriction.RequestAccepted || acc.RestrictionID == nil {
		t.Fatalf("accept: %+v %v", acc, err)
	}
	if got, err := svc.Request(ctx, q.ID); err != nil || got.State != restriction.RequestAccepted || got.DecidedAt == nil {
		t.Fatalf("read back: %+v %v", got, err)
	}
	list, more, err := svc.List(ctx, restriction.ListFilter{Limit: 5})
	if err != nil || len(list) != 5 || !more {
		t.Fatalf("list: %d %v %v", len(list), more, err)
	}
	active := restriction.StateEnded
	bbox := [4]float64{44.7, 41.6, 44.9, 41.8}
	if list, _, err := svc.List(ctx, restriction.ListFilter{State: &active, BBox: &bbox, Limit: 10}); err != nil || len(list) != 1 || list[0].ID != r.ID {
		t.Fatalf("filtered: %d %v", len(list), err)
	}
	away := [4]float64{10, 10, 11, 11}
	if list, _, err := svc.List(ctx, restriction.ListFilter{BBox: &away, Limit: 10}); err != nil || len(list) != 0 {
		t.Fatalf("away: %d %v", len(list), err)
	}
	across := [4]float64{170, 41, 45, 42}
	if list, _, err := svc.List(ctx, restriction.ListFilter{BBox: &across, Limit: 100}); err != nil || len(list) == 0 {
		t.Fatalf("across the antimeridian: %d %v", len(list), err)
	}
}
