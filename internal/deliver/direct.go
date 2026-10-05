package deliver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/restriction"
)

// PathNotifications is the one receiver path of a CIS change
// notification on every USSP and the authority (M1, M5): no per-target
// path is configured.
const PathNotifications = "/v1/cis/notifications"

// ContentTypeJOSE is the media type of a compact JWS delivery.
const ContentTypeJOSE = "application/jose"

// Producer is the producer member of a direct change record: this
// process (04 section 2), not the CISP's deliver instance.
const Producer = "ansp/api"

// ReasonOf is the cis/change/v1 reason of a restriction op.
func ReasonOf(op string) (cispclient.ChangeReason, error) {
	switch op {
	case OpCreate:
		return cispclient.ChangeReasonRestrictionCreated, nil
	case OpActivate:
		return cispclient.ChangeReasonRestrictionActivated, nil
	case OpExtend:
		return cispclient.ChangeReasonRestrictionExtended, nil
	case OpEnd:
		return cispclient.ChangeReasonRestrictionEnded, nil
	case OpCancel:
		return cispclient.ChangeReasonRestrictionCancelled, nil
	}
	return "", fmt.Errorf("op %q has no change reason", op)
}

// PullURL is this system's GET /v1/restrictions/{id}/direct on
// ANSP_PUBLIC_BASE_URL exactly: the signed restriction/direct/v1 of the
// restriction's current version (the receivers pull it only when its
// host is the ANSP's configured base host, M5).
func PullURL(publicBase, restrictionID string) string {
	return strings.TrimRight(publicBase, "/") + "/v1/restrictions/" + restrictionID + "/direct"
}

// DirectSchema names the body of GET /v1/restrictions/{id}/direct.
const DirectSchema = "restriction/direct/v1"

// DirectRestriction is restriction/direct/v1 (api/openapi.yaml
// DirectRestriction): a restriction's version as a receiver of the
// degraded direct path applies it. The version member is ansp_version
// (M4).
type DirectRestriction struct {
	Schema           string          `json:"schema"`
	ID               string          `json:"id"`
	AnspRef          string          `json:"ansp_ref"`
	AnspVersion      int64           `json:"ansp_version"`
	Identifier       string          `json:"identifier"`
	UspaceAirspaceID string          `json:"uspace_airspace_id"`
	State            string          `json:"state"`
	StartsAt         string          `json:"starts_at"`
	EndsAt           string          `json:"ends_at"`
	ChangedAt        string          `json:"changed_at"`
	Feature          json.RawMessage `json:"feature"`
}

// BuildDirect is the restriction/direct/v1 body of version v: the bytes
// GET /v1/restrictions/{id}/direct signs and serves.
func BuildDirect(v VersionInfo) ([]byte, error) {
	if v.RestrictionID == "" || v.AnspRef == "" || v.Identifier == "" || v.Version < 1 || len(v.Feature) == 0 {
		return nil, errors.New("the version has no id, ansp_ref, identifier, version or feature")
	}
	if !json.Valid(v.Feature) {
		return nil, errors.New("the version's feature is not JSON")
	}
	return json.Marshal(DirectRestriction{
		Schema: DirectSchema, ID: v.RestrictionID, AnspRef: v.AnspRef, AnspVersion: v.Version, Identifier: v.Identifier,
		UspaceAirspaceID: v.UspaceAirspaceID, State: v.State, StartsAt: restriction.Stamp(v.StartsAt),
		EndsAt: restriction.Stamp(v.EndsAt), ChangedAt: restriction.Stamp(v.ChangedAt), Feature: v.Feature,
	})
}

// BuildChange is the cis/change/v1 record of a degraded direct delivery
// of op for v (the CISP's Change schema, api/clients/cisp.yaml): msg_id
// is the delivery id, dataset restrictions, version the ansp_version,
// etag "<ansp_ref>:<ansp_version>", feature_ids the identifier (in
// removed_ids too once the restriction is ended or cancelled), at the
// version's change, pull_url this system's signed restriction/direct/v1
// of the restriction (PullURL). The record is the CISP's closed
// cis/change/v1, so the version member carries the ansp_version; a
// receiver tells it from a CIS dataset version by its issuer.
func BuildChange(v VersionInfo, op, deliveryID, publicBase string) ([]byte, error) {
	reason, err := ReasonOf(op)
	if err != nil {
		return nil, err
	}
	if publicBase == "" {
		return nil, errors.New("no ANSP_PUBLIC_BASE_URL for the pull_url")
	}
	removed := []string{}
	if v.State == string(restriction.StateEnded) || v.State == string(restriction.StateCancelled) {
		removed = []string{v.Identifier}
	}
	return json.Marshal(cispclient.Change{
		Schema: cispclient.ChangeSchemaCischangev1, MsgId: deliveryID, Producer: Producer,
		Dataset: cispclient.ChangeDatasetRestrictions, Version: v.Version,
		Etag:       strconv.Quote(v.AnspRef + ":" + strconv.FormatInt(v.Version, 10)),
		FeatureIds: []string{v.Identifier}, RemovedIds: removed, Reason: reason,
		At: v.ChangedAt.UTC(), PullUrl: PullURL(publicBase, v.RestrictionID),
	})
}

// Direct sends degraded direct deliveries: POST {base_url}/v1/cis/
// notifications with the change record as a compact JWS signed by the
// delivery key (core's SignCompact): iss this system's issuer URL, aud
// the host of the target's base URL (M19), sub the restriction id, jti
// the delivery id, iat now. No bearer: the signature authenticates.
type Direct struct {
	Issuer string
	Client *http.Client
	Signer Signer
	Policy Policy
	Now    func() time.Time
}

// Send delivers body (a change record) for delivery id of restriction
// rid to the receiver at base.
func (d *Direct) Send(ctx context.Context, base, rid, id string, body []byte) Response {
	if d.Signer == nil {
		return Response{Err: "no delivery key (ANSP_DELIVERY_KEY_FILE)"}
	}
	aud, err := auth.AudienceOf(base)
	if err != nil {
		return Response{Err: "target: " + err.Error()}
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	jws, err := d.Signer.SignCompact(coreauth.CompactClaims{Issuer: d.Issuer, Audience: aud, Subject: rid, JTI: id}, body, now)
	if err != nil {
		return Response{Err: "signature: " + err.Error()}
	}
	req, err := newRequest(http.MethodPost, strings.TrimRight(base, "/")+PathNotifications, []byte(jws))
	if err != nil {
		return Response{Err: "request: " + err.Error()}
	}
	req.Header.Set("Content-Type", ContentTypeJOSE)
	ctx, cancel := context.WithTimeout(ctx, d.Policy.HTTPTimeout)
	defer cancel()
	return do(ctx, d.Client, req, d.Policy.MaxResponseBytes, d.Policy.ExcerptBytes, d.Policy.BackoffMax)
}
