package auth

import (
	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// Problem slugs of this package. The generic ones are apierr's; the
// others are this package's refusal names, beside core's token counters,
// which are the slug of a refused token (rejected_audience,
// rejected_expired, ...). Every refusal is an *apierr.Problem.
const (
	SlugUnauthenticated    = apierr.SlugUnauthenticated
	SlugForbidden          = apierr.SlugForbidden
	SlugRateLimited        = apierr.SlugRateLimited
	SlugInvalidRequest     = apierr.SlugInvalidRequest
	SlugNotFound           = apierr.SlugNotFound
	SlugConflict           = apierr.SlugConflict
	SlugUnavailable        = apierr.SlugUnavailable
	SlugInternal           = apierr.SlugInternal
	SlugMTLSRequired       = "mtls_required"
	SlugMTLSMismatch       = "mtls_mismatch"
	SlugInvalidCredentials = "invalid_credentials" //nolint:gosec // a problem slug, not a credential
	SlugMFARefused         = "mfa_refused"
	SlugAccountLocked      = "account_locked"
	SlugSessionRefused     = "session_refused"
)

// refusal is a problem with status, slug, detail and the fields at
// fault. It never carries a credential: details and reasons are this
// package's own text.
func refusal(status int, slug, detail string, fields ...apierr.FieldProblem) *apierr.Problem {
	return apierr.New(status, slug, detail, fields...)
}
