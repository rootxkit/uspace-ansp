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

// PullURL is this system's GET /v1/restrictions/{id} on
// ANSP_PUBLIC_BASE_URL exactly (the receivers pull it only when its host
// is the ANSP's configured base host, M5).
func PullURL(publicBase, restrictionID string) string {
	return strings.TrimRight(publicBase, "/") + "/v1/restrictions/" + restrictionID
}

// BuildChange is the cis/change/v1 record of a degraded direct delivery
// of op for v (the CISP's Change schema, api/clients/cisp.yaml): msg_id
// is the delivery id, dataset restrictions, version the ansp_version,
// etag "<ansp_ref>:<ansp_version>", feature_ids the identifier (in
// removed_ids too once the restriction is ended or cancelled), at the
// version's change, pull_url this system's read of the restriction.
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
