package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// The CISP's contract (api/clients/cisp.yaml).
const (
	// ScopePublish is the scope of the publication and the heartbeat.
	ScopePublish = "cis.publish:restrictions"
	// HeaderSignature carries the detached JWS over the body (M26, the
	// CISP's Q8).
	HeaderSignature = "X-JWS-Signature"
	// PathRestrictions is POST /v1/restrictions; PATCH appends the
	// ansp_ref and ?by=ansp_ref.
	PathRestrictions = "/v1/restrictions"
	// PathHeartbeat is POST /v1/publishers/heartbeat (M3); there is no
	// configurable path.
	PathHeartbeat = "/v1/publishers/heartbeat"
)

// Tokens fetches client-credentials tokens (internal/auth.TokenSource).
type Tokens interface {
	TokenFor(ctx context.Context, audience string, scopes []string) (string, error)
}

// Signer signs what this system delivers with its delivery key
// (uspace-core auth.KeyRing: SignDetached, SignCompact; M27).
type Signer interface {
	SignDetached(payload []byte, now time.Time) (string, error)
	SignCompact(cl coreauth.CompactClaims, body json.RawMessage, now time.Time) (string, error)
}

// Publication is the request of a cisp_publish job, fixed at its first
// attempt.
type Publication struct {
	Method string
	// Path is relative to the CISP's base URL.
	Path string
	Body []byte
	// Cancel, when set, says the job is not sent and why.
	Cancel string
}

// BuildPublication is the CISP request of op for version v, from the
// generated types of the CISP's pinned contract (cispclient: the member
// is ansp_version, never version, M4). published says whether the CISP
// holds any version of the restriction: a planned create is POSTed; an
// activation or extension of a restriction the CISP never confirmed is
// POSTed as active (its first publication); an end or a cancel of one it
// never held is not sent (never_published).
func BuildPublication(v VersionInfo, op string) (Publication, error) {
	published := v.PublishedVersion != nil
	create := func(state cispclient.RestrictionCreateState) (Publication, error) {
		body, err := json.Marshal(cispclient.RestrictionCreate{
			AnspRef: v.AnspRef, AnspVersion: v.Version, UspaceAirspaceId: v.UspaceAirspaceID, State: state,
			StartsAt: v.StartsAt.UTC(), EndsAt: v.EndsAt.UTC(), Feature: v.Feature,
		})
		return Publication{Method: http.MethodPost, Path: PathRestrictions, Body: body}, err
	}
	patch := func(p cispclient.RestrictionPatch) (Publication, error) {
		p.AnspVersion = v.Version
		body, err := json.Marshal(p)
		return Publication{Method: http.MethodPatch, Path: PatchPath(v.AnspRef), Body: body}, err
	}
	if len(v.Feature) == 0 || v.AnspRef == "" {
		return Publication{}, errors.New("the version has no feature or ansp_ref")
	}
	switch op {
	case OpCreate:
		if v.State != string(restriction.StatePlanned) {
			return Publication{}, fmt.Errorf("a create of a %s version", v.State)
		}
		return create(cispclient.RestrictionCreateStatePlanned)
	case OpActivate:
		if !published {
			return create(cispclient.RestrictionCreateStateActive)
		}
		return patch(cispclient.RestrictionPatch{Op: cispclient.RestrictionPatchOpActivate})
	case OpExtend:
		if !published {
			return create(cispclient.RestrictionCreateStateActive)
		}
		end := v.EndsAt.UTC()
		f := v.Feature
		return patch(cispclient.RestrictionPatch{Op: cispclient.RestrictionPatchOpExtend, EndsAt: &end, Feature: &f})
	case OpEnd, OpCancel:
		if !published {
			return Publication{Cancel: CancelNeverPublished}, nil
		}
		o := cispclient.RestrictionPatchOpEnd
		if op == OpCancel {
			o = cispclient.RestrictionPatchOpCancel
		}
		return patch(cispclient.RestrictionPatch{Op: o})
	}
	return Publication{}, fmt.Errorf("op %q is not a CISP publication", op)
}

// PatchPath is PATCH /v1/restrictions/{id} naming the restriction by its
// ansp_ref (by=ansp_ref): this system never needs the CISP's own id.
func PatchPath(anspRef string) string {
	return PathRestrictions + "/" + url.PathEscape(anspRef) + "?by=ansp_ref"
}

// CISP sends publications and heartbeats to the CISP of record: a token
// with ScopePublish whose aud is the CISP's host (M18), the client
// certificate (in Client, M24), and on a publication the detached JWS.
type CISP struct {
	BaseURL string
	Client  *http.Client
	Tokens  Tokens
	Signer  Signer
	Policy  Policy
	Now     func() time.Time
}

func (c *CISP) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *CISP) url(path string) string { return strings.TrimRight(c.BaseURL, "/") + path }

// token is the bearer for the CISP.
func (c *CISP) token(ctx context.Context) (string, error) {
	if c.Tokens == nil {
		return "", errors.New("no token client (ANSP_TOKEN_URL, ANSP_CLIENT_SECRET_FILE)")
	}
	aud, err := auth.AudienceOf(c.BaseURL)
	if err != nil {
		return "", err
	}
	return c.Tokens.TokenFor(ctx, aud, []string{ScopePublish})
}

// Publish sends one prepared publication: the body as stored, signed
// now (the CISP refuses an iat older than five minutes, so each attempt
// signs again over the same bytes). idem is the pair, sent as the
// optional Idempotency-Key header that nothing depends on.
func (c *CISP) Publish(ctx context.Context, method, path string, body []byte, idem string) Response {
	tok, err := c.token(ctx)
	if err != nil {
		return Response{Err: "token: " + transportReason(err)}
	}
	if c.Signer == nil {
		return Response{Err: "no delivery key (ANSP_DELIVERY_KEY_FILE)"}
	}
	sig, err := c.Signer.SignDetached(body, c.now())
	if err != nil {
		return Response{Err: "signature: " + err.Error()}
	}
	req, err := newRequest(method, c.url(path), body)
	if err != nil {
		return Response{Err: "request: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(HeaderSignature, sig)
	req.Header.Set("Idempotency-Key", idem)
	ctx, cancel := context.WithTimeout(ctx, c.Policy.HTTPTimeout)
	defer cancel()
	return do(ctx, c.Client, req, c.Policy.MaxResponseBytes, c.Policy.ExcerptBytes, c.Policy.BackoffMax)
}

// Heartbeat sends POST /v1/publishers/heartbeat {sent_at, active_refs}.
func (c *CISP) Heartbeat(ctx context.Context, sentAt time.Time, refs []string) Response {
	tok, err := c.token(ctx)
	if err != nil {
		return Response{Err: "token: " + transportReason(err)}
	}
	if refs == nil {
		refs = []string{}
	}
	body, err := json.Marshal(cispclient.PublisherHeartbeat{SentAt: sentAt.UTC().Truncate(time.Millisecond), ActiveRefs: &refs})
	if err != nil {
		return Response{Err: "body: " + err.Error()}
	}
	req, err := newRequest(http.MethodPost, c.url(PathHeartbeat), body)
	if err != nil {
		return Response{Err: "request: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(ctx, c.Policy.HTTPTimeout)
	defer cancel()
	return do(ctx, c.Client, req, c.Policy.MaxResponseBytes, c.Policy.ExcerptBytes, c.Policy.BackoffMax)
}
