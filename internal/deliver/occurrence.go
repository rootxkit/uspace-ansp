package deliver

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-ansp/internal/auth"
)

// PathOccurrences is the authority's occurrence intake (02 F7; the
// authority owns occurrence/v1, docs/PLAN.md section 15 row 23).
const PathOccurrences = "/v1/occurrences"

// ScopeOccurrences is the scope of an occurrence delivery.
const ScopeOccurrences = "occurrences.write"

// TargetAuthority is the target of an occurrence job: the configured
// authority (ANSP_AUTHORITY_URL), read by the sender at each attempt.
const TargetAuthority = "authority"

// OccurrenceSender sends one attempt of an occurrence job (WP-10,
// internal/coord): it builds the body from the report at each attempt
// and never returns the reporter's reference in the response's excerpt
// or error.
type OccurrenceSender interface {
	SendOccurrence(ctx context.Context, d Delivery) Response
}

// Authority posts JSON to the authority with a token of scope
// occurrences.write whose aud is the authority's host (M18).
type Authority struct {
	BaseURL string
	Client  *http.Client
	Tokens  Tokens
	Policy  Policy
}

// Post sends body to path on the authority.
func (a *Authority) Post(ctx context.Context, path string, body []byte) Response {
	if a == nil || a.BaseURL == "" {
		return Response{Err: "no authority configured (ANSP_AUTHORITY_URL)"}
	}
	if a.Tokens == nil {
		return Response{Err: "no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE)"}
	}
	aud, err := auth.AudienceOf(a.BaseURL)
	if err != nil {
		return Response{Err: "target: " + err.Error()}
	}
	tok, err := a.Tokens.TokenFor(ctx, aud, []string{ScopeOccurrences})
	if err != nil {
		return Response{Err: "token: " + transportReason(err)}
	}
	req, err := newRequest(http.MethodPost, strings.TrimRight(a.BaseURL, "/")+path, body)
	if err != nil {
		return Response{Err: "request: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	timeout := a.Policy.HTTPTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return do(ctx, a.Client, req, a.Policy.MaxResponseBytes, a.Policy.ExcerptBytes, a.Policy.BackoffMax)
}
