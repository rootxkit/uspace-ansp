//go:build integration

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/dss"
	"github.com/rootxkit/uspace-ansp/internal/dss/dsstest"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// dssRestriction is what the DSS path reads of GET /v1/restrictions/{id}.
type dssRestriction struct {
	DSSConstraintID     string                     `json:"dss_constraint_id"`
	ConstraintReference *f3548.ConstraintReference `json:"constraint_reference"`
	DSS                 struct {
		State       string  `json:"state"`
		Since       *string `json:"since"`
		AnspVersion *int64  `json:"ansp_version"`
	} `json:"dss"`
}

func (s *deliverStack) dssOf(id string) dssRestriction {
	s.t.Helper()
	code, out := s.c.do(http.MethodGet, "/v1/restrictions/"+id, s.watch, nil, nil)
	var r dssRestriction
	if code != http.StatusOK || json.Unmarshal(out, &r) != nil {
		s.t.Fatalf("restriction %d %s", code, out)
	}
	validateResponse(s.t, http.MethodGet, "/v1/restrictions/{id}", code, out)
	return r
}

// dssRequests is the DSS requests of the constraint path: every one but
// the readiness reads of dss.PingID.
func (s *deliverStack) dssRequests() []dsstest.Request {
	var out []dsstest.Request
	for _, r := range s.dss.Requests() {
		if !strings.Contains(r.Path, dss.PingID) {
			out = append(out, r)
		}
	}
	return out
}

// awaitDSS waits for the n-th DSS request of the constraint path.
func (s *deliverStack) awaitDSS(n int, within time.Duration) dsstest.Request {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if rs := s.dssRequests(); len(rs) >= n {
			return rs[n-1]
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("%d DSS requests within %v, want %d", len(s.dssRequests()), within, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// awaitUSS waits for the n-th notification of subscriber u.
func (s *deliverStack) awaitUSS(u *dsstest.USS, n int, within time.Duration) dsstest.Request {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if rs := u.Requests(); len(rs) >= n {
			return rs[n-1]
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: %d notifications within %v, want %d", u.URL(), len(u.Requests()), within, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// expectedVolumes is the F3548 volume of the plan of deliverStack.plan
// at the restriction's current window: its polygon without the closing
// vertex, 0 to 120 m WGS84 (W84).
func expectedVolumes(t *testing.T, s *deliverStack, id string) []f3548.Volume4D {
	t.Helper()
	code, out := s.c.do(http.MethodGet, "/v1/restrictions/"+id, s.watch, nil, nil)
	var w struct {
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
	}
	if code != http.StatusOK || json.Unmarshal(out, &w) != nil {
		t.Fatalf("restriction %d %s", code, out)
	}
	return []f3548.Volume4D{{
		Volume: f3548.Volume3D{
			OutlinePolygon: &f3548.Polygon{Vertices: []f3548.LatLngPoint{{Lat: 41.70, Lng: 44.78}, {Lat: 41.70, Lng: 44.82}, {Lat: 41.73, Lng: 44.82}, {Lat: 41.73, Lng: 44.78}}},
			AltitudeLower:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 120},
		},
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: w.StartsAt.UTC()},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: w.EndsAt.UTC()},
	}}
}

// checkNotification is a subscriber's view of a notification: the token
// for its own host with the operation's scope (utm.constraint_management,
// the pinned utm.yaml), the constraint id, its subscription and index,
// and the full constraint (or none for a deletion).
func checkNotification(t *testing.T, u *dsstest.USS, r dsstest.Request, cid, sub string, index int32, withConstraint bool) f3548.PutConstraintDetailsParameters {
	t.Helper()
	if want := "Bearer tok-" + u.Host() + "-utm.constraint_management"; r.Header.Get("Authorization") != want {
		t.Fatalf("%s: bearer %q, want %q", u.URL(), r.Header.Get("Authorization"), want)
	}
	var p f3548.PutConstraintDetailsParameters
	if err := json.Unmarshal(r.Body, &p); err != nil {
		t.Fatal(err)
	}
	if r.Path != "/uss/v1/constraints" || p.ConstraintId != cid || len(p.Subscriptions) != 1 || p.Subscriptions[0].SubscriptionId != sub ||
		p.Subscriptions[0].NotificationIndex != index || (p.Constraint != nil) != withConstraint {
		t.Fatalf("%s: %s", u.URL(), r.Body)
	}
	return p
}

// The DSS path end to end against real PostgreSQL + PostGIS and NATS,
// an in-test DSS with ovn semantics and two in-test subscribers:
// activate → PUT with extents equal to the restriction's volume, the ovn
// stored, both subscribers notified within 5 s of the DSS answer
// (measured) with the full Constraint; the details served are that
// volume; extend with an ovn another writer moved → one re-read and the
// update; end → DELETE at the ovn, the deletion notified; the details
// stay served for the retention and not after it.
func TestIntegrationDSSConstraintPath(t *testing.T) {
	s := newDeliverStack(t)
	subA, subB := "78ea3fe8-71c2-4f5c-9b44-9c02f5563c6f", "88ea3fe8-71c2-4f5c-9b44-9c02f5563c6f"
	r := s.plan("wp9-1")
	if d := s.dssOf(r.ID); d.DSS.State != "none" || d.ConstraintReference != nil {
		t.Fatalf("a planned restriction in the DSS: %+v", d)
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(s.dssRequests()); n != 0 {
		t.Fatalf("a planned restriction was written to the DSS: %d requests", n)
	}
	if pings := len(s.dss.Requests()); pings == 0 {
		t.Fatal("the readiness read of the DSS did not run")
	}
	s.op(r.ID, "activate", map[string]string{"reason": "rescue helicopter on scene"})
	put := s.awaitDSS(1, 5*time.Second)
	cid := s.dssOf(r.ID).DSSConstraintID
	if put.Method != http.MethodPut || put.Path != "/dss/v1/constraint_references/"+cid {
		t.Fatalf("%s %s", put.Method, put.Path)
	}
	if want := "Bearer tok-" + s.dss.Host() + "-utm.constraint_management"; put.Header.Get("Authorization") != want {
		t.Fatalf("bearer %q", put.Header.Get("Authorization"))
	}
	var p f3548.PutConstraintReferenceParameters
	if err := json.Unmarshal(put.Body, &p); err != nil {
		t.Fatal(err)
	}
	if want := expectedVolumes(t, s, r.ID); !reflect.DeepEqual(p.Extents, want) || p.UssBaseUrl != "https://ansp.test" {
		t.Fatalf("extents %s\nwant %+v", put.Body, want)
	}
	a := s.awaitUSS(s.subs[0], 1, 5*time.Second)
	b := s.awaitUSS(s.subs[1], 1, 5*time.Second)
	last := a.At
	if b.At.After(last) {
		last = b.At
	}
	lat := last.Sub(put.At)
	t.Logf("DSS answer to the last subscriber notification (DSS stub receipt to subscriber stub receipt, one clock): %v (budget CstrPublishedNotificationLatencySeconds = 5 s)", lat)
	if lat > 5*time.Second {
		t.Fatalf("the last subscriber was notified %v after the DSS write", lat)
	}
	na := checkNotification(t, s.subs[0], a, cid, subA, 1, true)
	checkNotification(t, s.subs[1], b, cid, subB, 1, true)
	d := s.dssOf(r.ID)
	if d.DSS.State != "written" || d.ConstraintReference == nil || d.ConstraintReference.Ovn == nil || *d.ConstraintReference.Ovn != s.dss.OVN(cid) ||
		*d.DSS.AnspVersion != 2 {
		t.Fatalf("stored %+v", d)
	}
	if *na.Constraint.Reference.Ovn != s.dss.OVN(cid) || !reflect.DeepEqual(na.Constraint.Details.Volumes, p.Extents) || *na.Constraint.Details.Type != "DAR" {
		t.Fatalf("the notified constraint %s", a.Body)
	}
	body, err := s.dw.details.Get(s.ctx, cid)
	if err != nil {
		t.Fatal(err)
	}
	validateResponse(t, http.MethodGet, "/uss/v1/constraints/{entityid}", http.StatusOK, body)
	var got f3548.GetConstraintDetailsResponse
	if err := json.Unmarshal(body, &got); err != nil || !reflect.DeepEqual(got.Constraint.Details.Volumes, p.Extents) ||
		*got.Constraint.Reference.Ovn != s.dss.OVN(cid) {
		t.Fatalf("details %s", body)
	}
	if n := s.deliveries(`SELECT count(*) FROM dss_notifications WHERE constraint_id = $1 AND status = 'sent' AND sent_at IS NOT NULL AND ansp_version = 2`, cid); n != 2 {
		t.Fatalf("%d notification rows sent", n)
	}
	code, out := s.c.do(http.MethodGet, "/v1/restrictions/"+r.ID+"/versions/2", s.watch, nil, nil)
	validateResponse(t, http.MethodGet, "/v1/restrictions/{id}/versions/{version}", code, out)
	if !strings.Contains(string(out), `"ovn":"`+s.dss.OVN(cid)+`"`) {
		t.Fatalf("the version does not carry the reference written: %s", out)
	}

	// Extend after another writer moved the ovn: 409, one re-read, the
	// update at the current ovn.
	stale := s.dss.OVN(cid)
	if !s.dss.Bump(cid) {
		t.Fatal("no reference")
	}
	end := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	s.op(r.ID, "extend", map[string]string{"reason": "search area widened", "ends_at": restriction.Stamp(end)})
	upd := s.awaitDSS(4, 5*time.Second)
	reqs := s.dssRequests()
	if reqs[1].Path != "/dss/v1/constraint_references/"+cid+"/"+stale || reqs[2].Method != http.MethodGet || upd.Method != http.MethodPut ||
		upd.Path == reqs[1].Path {
		t.Fatalf("%s %s, %s %s, %s %s", reqs[1].Method, reqs[1].Path, reqs[2].Method, reqs[2].Path, upd.Method, upd.Path)
	}
	checkNotification(t, s.subs[0], s.awaitUSS(s.subs[0], 2, 5*time.Second), cid, subA, 2, true)
	checkNotification(t, s.subs[1], s.awaitUSS(s.subs[1], 2, 5*time.Second), cid, subB, 2, true)
	if d := s.dssOf(r.ID); d.DSS.State != "written" || *d.DSS.AnspVersion != 3 {
		t.Fatalf("%+v", d)
	}

	// End: the delete at the ovn; the deletion notified (no constraint).
	ovn := s.dss.OVN(cid)
	s.op(r.ID, "end", map[string]string{"reason": "rescue complete"})
	del := s.awaitDSS(5, 5*time.Second)
	if del.Method != http.MethodDelete || del.Path != "/dss/v1/constraint_references/"+cid+"/"+ovn {
		t.Fatalf("%s %s", del.Method, del.Path)
	}
	checkNotification(t, s.subs[0], s.awaitUSS(s.subs[0], 3, 5*time.Second), cid, subA, 3, false)
	checkNotification(t, s.subs[1], s.awaitUSS(s.subs[1], 3, 5*time.Second), cid, subB, 3, false)
	deadline := time.Now().Add(5 * time.Second)
	for s.dssOf(r.ID).DSS.State != "deleted" {
		if time.Now().After(deadline) {
			t.Fatalf("%+v", s.dssOf(r.ID))
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The details of the last write stay served within the retention,
	// and are unknown after it (the database's clock).
	st := store.DSSStore{DB: s.db}
	if w, err := st.Written(s.ctx, cid, dss.DefaultRetention); err != nil || w.Expired {
		t.Fatalf("within the retention: %+v %v", w, err)
	}
	time.Sleep(20 * time.Millisecond)
	if w, err := st.Written(s.ctx, cid, 10*time.Millisecond); err != nil || !w.Expired {
		t.Fatalf("past the retention: %+v %v", w, err)
	}
	if _, err := (&dss.Details{Store: st, Retention: 10 * time.Millisecond}).Get(s.ctx, cid); !errors.Is(err, dss.ErrUnknown) {
		t.Fatalf("served past the retention: %v", err)
	}
	if st, why := probe(s.dw, depDSS); st != obs.StateOK || !strings.HasPrefix(why, "ok (last answer at ") {
		t.Fatalf("readiness %s %s", st, why)
	}
}

// The DSS down: the CISP publication of the activation still goes (D6,
// the twin of WP-8's stub), the DSS write is retried, restr.v1 and the
// restriction say pending since T and the readiness line unreachable
// since T (never lost); the DSS back, it is written. A subscriber that
// answers 5xx is retried while the other is notified once; past 5 s the
// miss is the alarm uss_notify_late on restr.v1, cleared when it is
// delivered.
func TestIntegrationDSSDownAndSubscriberRetry(t *testing.T) {
	s := newDeliverStack(t)
	r := s.plan("wp9-d1")
	s.cisp.await(t, "/v1/restrictions", 1, 5*time.Second)
	s.dss.Down.Store(true)
	s.subs[1].Answer(func(int, dsstest.Request) int { return http.StatusServiceUnavailable })
	s.op(r.ID, "activate", map[string]string{"reason": "rescue helicopter on scene"})
	s.cisp.await(t, "/v1/restrictions", 2, 5*time.Second)
	pending := s.awaitBody(10*time.Second, func(b map[string]any) bool {
		d, ok := b["dss"].(map[string]any)
		return ok && d["state"] == "pending" && d["since"] != nil && b["restriction_id"] == r.ID
	})
	t.Logf("restr.v1 while the DSS is down: dss %v", pending["dss"])
	if d := s.dssOf(r.ID); d.DSS.State != "pending" || d.DSS.Since == nil {
		t.Fatalf("%+v", d)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, why := probe(s.dw, depDSS)
		if st == obs.StateDown && strings.HasPrefix(why, "unreachable since ") && strings.Contains(why, "DSS writes waiting, pending since") {
			t.Logf("readiness while the DSS is down: dss: %s", why)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness %s %s", st, why)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(strings.ToLower(s.logs.String()), "lost") {
		t.Fatal("said lost")
	}
	s.dss.Down.Store(false)
	s.awaitUSS(s.subs[0], 1, 30*time.Second)
	if n := s.deliveries(`SELECT count(*) FROM delivery_attempts a JOIN deliveries d ON d.id = a.delivery_id
		WHERE d.restriction_id = $1 AND d.kind = 'dss_put'`, r.ID); n < 2 {
		t.Fatalf("%d attempts of the DSS write", n)
	}
	late := s.awaitBody(15*time.Second, func(b map[string]any) bool {
		a, ok := b["alarm"].(map[string]any)
		return ok && a["kind"] == "uss_notify_late" && a["state"] == "open"
	})["alarm"].(map[string]any)
	if !strings.Contains(late["detail"].(string), s.subs[1].URL()) || strings.Contains(late["detail"].(string), "lost") {
		t.Fatalf("%v", late["detail"])
	}
	if n := len(s.subs[0].Requests()); n != 1 {
		t.Fatalf("the healthy subscriber was notified %d times", n)
	}
	s.subs[1].Answer(nil)
	cleared := s.awaitBody(90*time.Second, func(b map[string]any) bool {
		a, ok := b["alarm"].(map[string]any)
		return ok && a["kind"] == "uss_notify_late" && a["state"] == "cleared"
	})["alarm"].(map[string]any)
	if cleared["clear_reason"] != "delivered" {
		t.Fatalf("%v", cleared)
	}
	if n := len(s.subs[1].Requests()); n < 2 {
		t.Fatalf("the failing subscriber was tried %d times", n)
	}
	if d := s.dssOf(r.ID); d.DSS.State != "written" || d.DSS.Since != nil {
		t.Fatalf("%+v", d)
	}
}
