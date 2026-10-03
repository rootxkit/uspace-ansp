package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/dss"
)

// writtenStore is a dss.Store holding one written constraint.
type writtenStore struct {
	id  string
	w   dss.Written
	err error
}

func (s *writtenStore) Written(_ context.Context, id string, _ time.Duration) (dss.Written, error) {
	if s.err != nil {
		return dss.Written{}, s.err
	}
	if id != s.id {
		return dss.Written{}, dss.ErrUnknown
	}
	return s.w, nil
}

func detailsServer(t *testing.T, st dss.Store) http.Handler {
	t.Helper()
	mtls, err := auth.NewMTLS(config.MTLSOff, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	rs := &restrictionAPI{details: &dss.Details{Store: st}}
	if _, err := mountAPI(mux, &auth.Guard{Machine: scopeVerifier{}, MTLS: mtls}, nil, rs, nil, nil); err != nil {
		t.Fatal(err)
	}
	return mux
}

// A USSP with utm.constraint_processing reads exactly the volume that
// was written, type DAR, the reference with its ovn, in the contract's
// shape; an unknown constraint and one past the retention are 404 in the
// problem body; without the scope 403; a store that fails is 500 and
// says nothing of why.
func TestConstraintDetailsHandler(t *testing.T) {
	const id = "2f8343be-6482-4d1b-a474-16847e01af1e"
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	vol := f3548.Volume4D{
		Volume: f3548.Volume3D{
			OutlinePolygon: &f3548.Polygon{Vertices: []f3548.LatLngPoint{{Lat: 41.7, Lng: 44.78}, {Lat: 41.7, Lng: 44.82}, {Lat: 41.73, Lng: 44.82}}},
			AltitudeLower:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper:  &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 120},
		},
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: start},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: start.Add(time.Hour)},
	}
	ovn, typ := "ovn-3", "DAR"
	ref, _ := json.Marshal(f3548.ConstraintReference{Id: id, Manager: "ansp-01", Ovn: &ovn, Version: 1, UssAvailability: "Unknown",
		UssBaseUrl: "https://ansp.test", TimeStart: *vol.TimeStart, TimeEnd: *vol.TimeEnd})
	det, _ := json.Marshal(f3548.ConstraintDetails{Volumes: []f3548.Volume4D{vol}, Type: &typ})
	st := &writtenStore{id: id, w: dss.Written{Reference: ref, Details: det}}
	h := detailsServer(t, st)
	get := func(path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	rec := get("/uss/v1/constraints/"+id, "scopes:utm.constraint_processing")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	validateResponse(t, http.MethodGet, "/uss/v1/constraints/{entityid}", rec.Code, rec.Body.Bytes())
	var resp f3548.GetConstraintDetailsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resp.Constraint.Details.Volumes, []f3548.Volume4D{vol}) || *resp.Constraint.Details.Type != "DAR" ||
		*resp.Constraint.Reference.Ovn != ovn || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s", rec.Body)
	}
	for name, tc := range map[string]struct {
		path, token string
		code        int
		slug        string
		setup       func()
	}{
		"unknown":       {"/uss/v1/constraints/00000000-0000-4000-8000-000000000000", "scopes:utm.constraint_processing", 404, apierr.SlugNotFound, nil},
		"without scope": {"/uss/v1/constraints/" + id, "scopes:utm.constraint_management", 403, apierr.SlugForbidden, nil},
		"expired":       {"/uss/v1/constraints/" + id, "scopes:utm.constraint_processing", 404, apierr.SlugNotFound, func() { st.w.Expired = true }},
		"store failure": {"/uss/v1/constraints/" + id, "scopes:utm.constraint_processing", 500, "", func() { st.err = errors.New("pool exhausted (synthetic)") }},
	} {
		t.Run(name, func(t *testing.T) {
			saved := *st
			t.Cleanup(func() { *st = saved })
			if tc.setup != nil {
				tc.setup()
			}
			rec := get(tc.path, tc.token)
			var p apierr.Problem
			_ = json.Unmarshal(rec.Body.Bytes(), &p)
			if rec.Code != tc.code || (tc.slug != "" && p.Type != apierr.TypeBase+tc.slug) {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if tc.code == 500 && strings.Contains(rec.Body.String(), "pool exhausted") {
				t.Fatal("the cause leaked")
			}
			validateResponse(t, http.MethodGet, "/uss/v1/constraints/{entityid}", rec.Code, rec.Body.Bytes())
		})
	}
}
