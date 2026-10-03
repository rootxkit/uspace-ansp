package main

import (
	"errors"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rootxkit/uspace-ansp/internal/apierr"
	"github.com/rootxkit/uspace-ansp/internal/dss"
)

// constraintsUnavailableRetry is the Retry-After while the details are
// not served (no relational database).
const constraintsUnavailableRetry = 60 * time.Second

// GetConstraintDetails serves GET /uss/v1/constraints/{entityid} (WP-9,
// F3548 USS API; the router admits only a token with
// utm.constraint_processing): the constraint as the DSS last accepted
// it, 404 before its first write and after the retention that follows
// the restriction's end. The route fails closed: without the store it
// answers 503, never an empty 200.
func (s apiServer) GetConstraintDetails(w http.ResponseWriter, r *http.Request, entityid openapi_types.UUID) {
	if s.rs == nil || s.rs.details == nil {
		apierr.WriteError(w, r, apierr.Unavailable(constraintsUnavailableRetry,
			"constraint details are not served on this instance (ANSP_RELATIONAL_DSN)"))
		return
	}
	body, err := s.rs.details.Get(r.Context(), entityid.String())
	switch {
	case errors.Is(err, dss.ErrUnknown):
		apierr.WriteError(w, r, apierr.NotFound("no constraint of this system with this id is in the DSS, or it ended longer than the retention ago"))
		return
	case err != nil:
		refusal(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
