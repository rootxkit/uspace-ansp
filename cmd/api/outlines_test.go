package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/outline"
)

func viewerReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	return r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Session: true, Role: auth.RoleViewer,
		Claims: coreauth.Claims{Subject: "viewer-1"}}))
}

// Presence: any session gets the circle drawn, closed, as float64
// positions (the generated float32 LngLat would move a vertex).
func TestCircleOutlineDrawsTheCircle(t *testing.T) {
	rec := httptest.NewRecorder()
	apiServer{}.GetCircleOutline(rec, viewerReq("/v1/outlines/circle"), gen.GetCircleOutlineParams{Lat: 41.715, Lng: 44.8, RadiusM: 1500})
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var got circleOutlineJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	ring := got.Outline.Coordinates
	if got.Outline.Type != "Polygon" || got.Vertices != outline.Vertices || len(ring) != 1 || len(ring[0]) != outline.Vertices+1 {
		t.Fatalf("outline %+v", got)
	}
	if ring[0][0] != ring[0][outline.Vertices] {
		t.Fatalf("not closed: %v", ring[0])
	}
	// The first vertex is due north, written to 1e-8 degree (the
	// example of api/openapi.yaml is this answer).
	if ring[0][0] != [2]float64{44.8, 41.72850525} {
		t.Fatalf("first vertex %v", ring[0][0])
	}
}

// Absence, each bound named, nothing computed past it.
func TestCircleOutlineRefusesOutOfBounds(t *testing.T) {
	for name, c := range map[string]struct {
		p     gen.GetCircleOutlineParams
		field string
	}{
		"zero radius":        {gen.GetCircleOutlineParams{Lat: 41.7, Lng: 44.8, RadiusM: 0}, "radius_m"},
		"radius past bound":  {gen.GetCircleOutlineParams{Lat: 41.7, Lng: 44.8, RadiusM: outline.MaxRadiusM + 1}, "radius_m"},
		"latitude past 89":   {gen.GetCircleOutlineParams{Lat: 89.5, Lng: 44.8, RadiusM: 1500}, "lat"},
		"longitude past 180": {gen.GetCircleOutlineParams{Lat: 41.7, Lng: 181, RadiusM: 1500}, "lng"},
	} {
		rec := httptest.NewRecorder()
		apiServer{}.GetCircleOutline(rec, viewerReq("/v1/outlines/circle"), c.p)
		var p apierr.Problem
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if rec.Code != http.StatusBadRequest || p.Slug() != apierr.SlugInvalidRequest || len(p.Errors) != 1 || p.Errors[0].Field != c.field {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// The route is behind a session: no credential 401, a machine token 403.
func TestCircleOutlineNeedsASession(t *testing.T) {
	_, h := testServer(t, nil)
	path := "/v1/outlines/circle?lat=41.7&lng=44.8&radius_m=1500"
	if a := call(t, h, http.MethodGet, path, "", "", ""); a.code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d %+v", a.code, a.problem)
	}
	if a := call(t, h, http.MethodGet, path, "scopes:ansp.coordination", "", ""); a.code != http.StatusForbidden {
		t.Fatalf("machine token: %d %+v", a.code, a.problem)
	}
}
