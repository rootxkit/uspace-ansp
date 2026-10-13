package main

import (
	"errors"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/gen"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/outline"
)

// circleOutlineJSON is api/openapi.yaml CircleOutline, written with
// float64 positions (the generated LngLat is float32, which would move
// a vertex by a decimetre).
type circleOutlineJSON struct {
	Outline  polygonJSON `json:"outline"`
	Vertices int         `json:"vertices"`
}

type polygonJSON struct {
	Type        string         `json:"type"`
	Coordinates [][][2]float64 `json:"coordinates"`
}

// GetCircleOutline serves GET /v1/outlines/circle: the circle drawn for
// the restriction editor's map (internal/outline; docs/PLAN.md section
// 15 row 53). Pure: it reads no store, writes nothing and audits nothing;
// the bounds are checked before anything is computed.
func (s apiServer) GetCircleOutline(w http.ResponseWriter, r *http.Request, params gen.GetCircleOutlineParams) {
	ring, err := outline.Circle(core.LatLon{LatDeg: params.Lat, LonDeg: params.Lng}, params.RadiusM)
	var fe *core.FieldError
	switch {
	case errors.As(err, &fe):
		apierr.WriteError(w, r, apierr.Invalid(fe))
		return
	case err != nil:
		apierr.WriteInternal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, circleOutlineJSON{
		Outline:  polygonJSON{Type: "Polygon", Coordinates: [][][2]float64{ring}},
		Vertices: outline.Vertices,
	})
}
