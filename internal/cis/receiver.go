package cis

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/api/clients/cispclient"
	"github.com/rootxkit/uspace-ansp/internal/apierr"
)

// ContentTypeJOSE is the media type of a compact JWS delivery.
const ContentTypeJOSE = "application/jose"

// ChangeSchema is the schema of a change record.
const ChangeSchema = "cis/change/v1"

// Receiver bounds (E-10).
const (
	// MaxNotificationBytes bounds the body: the contract's maxLength of
	// the compact JWS (api/openapi.yaml).
	MaxNotificationBytes = 256 << 10
	// JTITTL is how long a delivery id is remembered: longer than the
	// 5 min in which core accepts its iat, plus the skew, so a replay in
	// that time is always caught.
	JTITTL = 10 * time.Minute
	// MaxLiveJTIs bounds the remembered delivery ids; past it the
	// receiver answers 503 (the CISP retries) and counts it.
	MaxLiveJTIs = 100_000
)

// Counter names of the receiver.
const (
	CounterNotifyAccepted       = "cis_notify_accepted"
	CounterNotifyNoop           = "cis_notify_noop"
	CounterNotifyUnknownReason  = "cis_notify_unknown_reason"
	CounterNotifyBadSignature   = "cis_notify_bad_signature"
	CounterNotifyWrongSub       = "cis_notify_wrong_subscription"
	CounterNotifyNoSubscription = "cis_notify_no_subscription"
	CounterNotifyMalformed      = "cis_notify_malformed"
	CounterNotifyReplayed       = "cis_notify_replayed"
	CounterNotifyJTIFull        = "cis_notify_jti_full"
	CounterNotifyStoreFailed    = "cis_notify_store_failed"
	CounterPullURLMismatch      = "cis_pull_url_mismatch"
)

// Problem slugs of the receiver.
const (
	SlugSignature = "signature"
)

// pullReasons trigger a pull (M16): a publication and every restriction
// reason. subscription_test, republished and any reason this build does
// not know are acknowledged 204 without a pull (spec 04 section 4: the
// enumeration is additive within v1).
var pullReasons = map[string]bool{
	"publication": true, "restriction_created": true, "restriction_activated": true,
	"restriction_extended": true, "restriction_ended": true, "restriction_cancelled": true,
	"restriction_expired": true,
}

// knownNoopReasons are acknowledged without a pull and are not unknown.
var knownNoopReasons = map[string]bool{"subscription_test": true, "republished": true}

// ReceiverStore remembers delivery ids across restarts and replicas (the
// replay guard: core's CompactVerifier keeps no nonce memory).
type ReceiverStore interface {
	// RememberJTI records (issuer, jti) for ttl on the database clock.
	// fresh is false for a delivery id already live; full is true when
	// maxLive ids are live and nothing was recorded.
	RememberJTI(ctx context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (fresh, full bool, err error)
}

// PullURLGuard says whether a pull_url is on the configured CISP
// (Client.CheckPullURL).
type PullURLGuard interface {
	CheckPullURL(raw string) error
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	Verifier CompactVerifier
	// Subscription is the id this system registered ("" while none is).
	Subscription func() string
	Store        ReceiverStore
	// Guard checks pull_url; nil refuses every pull_url.
	Guard   PullURLGuard
	Trigger func(Dataset, Hint)
	// Timeout bounds the store call (the CISP wants an answer in 2 s).
	Timeout  time.Duration
	Counters *core.Counters
	Logger   *slog.Logger
	Now      func() time.Time
}

// Receiver is POST /v1/cis/notifications (M1, M19). The notification is
// a hint, never data: an accepted one triggers a pull of the named
// dataset from the configured CISP (02 F3), and its content is never
// installed.
type Receiver struct{ cfg ReceiverConfig }

// NewReceiver builds a Receiver.
func NewReceiver(cfg ReceiverConfig) *Receiver {
	if cfg.Counters == nil {
		cfg.Counters = &core.Counters{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 1500 * time.Millisecond
	}
	return &Receiver{cfg: cfg}
}

// ServeHTTP verifies the delivery and answers: 202 with a pull
// triggered, 204 for a reason that asks for none or a replayed delivery
// id, 400, 401, 413, 415 or 503 with the problem body.
func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != ContentTypeJOSE {
		rc.cfg.Counters.Inc(CounterNotifyMalformed)
		apierr.WriteError(w, r, apierr.UnsupportedMediaType(ContentTypeJOSE))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxNotificationBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			rc.cfg.Counters.Inc(CounterNotifyMalformed)
			apierr.WriteError(w, r, apierr.TooLarge(MaxNotificationBytes))
			return
		}
		rc.cfg.Counters.Inc(CounterNotifyMalformed)
		apierr.WriteError(w, r, apierr.New(http.StatusBadRequest, apierr.SlugInvalidRequest, "the body could not be read"))
		return
	}
	if len(raw) > MaxNotificationBytes {
		rc.cfg.Counters.Inc(CounterNotifyMalformed)
		apierr.WriteError(w, r, apierr.TooLarge(MaxNotificationBytes))
		return
	}
	claims, body, err := rc.cfg.Verifier.Verify(ctx, strings.TrimSpace(string(raw)))
	if err != nil {
		rc.cfg.Counters.Inc(CounterNotifyBadSignature)
		claim := "token"
		var te *coreauth.TokenError
		if errors.As(err, &te) {
			claim = te.Claim
		}
		rc.cfg.Logger.Warn("CIS notification refused", slog.String("claim", claim), slog.String("error", err.Error()))
		apierr.WriteError(w, r, apierr.New(http.StatusUnauthorized, SlugSignature,
			"the notification is not signed by an allowed issuer for this host", apierr.FieldProblem{Field: claim, Reason: "refused"}))
		return
	}
	log := rc.cfg.Logger.With(slog.String("issuer", claims.Issuer), slog.String("jti", short(claims.JTI)))
	sub := rc.cfg.Subscription()
	switch {
	case sub == "":
		rc.cfg.Counters.Inc(CounterNotifyNoSubscription)
		apierr.WriteError(w, r, apierr.Unavailable(30*time.Second, "this system has not registered its subscription yet; retry"))
		return
	case claims.Subject != sub:
		rc.cfg.Counters.Inc(CounterNotifyWrongSub)
		log.Warn("CIS notification for another subscription refused", slog.String("sub", short(claims.Subject)))
		apierr.WriteError(w, r, apierr.New(http.StatusUnauthorized, SlugSignature,
			"the notification is not for the subscription this system registered", apierr.FieldProblem{Field: "sub", Reason: "not this system's subscription"}))
		return
	}
	ch, ds, known, ferr := decodeChange(body)
	if ferr != nil {
		rc.cfg.Counters.Inc(CounterNotifyMalformed)
		apierr.WriteError(w, r, apierr.Invalid(ferr))
		return
	}
	sctx, cancel := context.WithTimeout(ctx, rc.cfg.Timeout)
	fresh, full, err := rc.cfg.Store.RememberJTI(sctx, claims.Issuer, claims.JTI, JTITTL, MaxLiveJTIs)
	cancel()
	switch {
	case err != nil:
		rc.cfg.Counters.Inc(CounterNotifyStoreFailed)
		log.Error("CIS notification not recorded", slog.String("error", err.Error()))
		apierr.WriteError(w, r, apierr.Unavailable(5*time.Second, "the delivery id cannot be recorded; retry"))
		return
	case full:
		rc.cfg.Counters.Inc(CounterNotifyJTIFull)
		apierr.WriteError(w, r, apierr.Unavailable(30*time.Second, "too many recent deliveries; retry"))
		return
	case !fresh:
		rc.cfg.Counters.Inc(CounterNotifyReplayed)
		log.Info("CIS notification replayed; acknowledged without a pull")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	log = log.With(slog.String("dataset", string(ch.Dataset)), slog.Int64("version", ch.Version), slog.String("reason", short(string(ch.Reason))))
	if !known || !pullReasons[string(ch.Reason)] {
		rc.cfg.Counters.Inc(CounterNotifyNoop)
		if !knownNoopReasons[string(ch.Reason)] {
			rc.cfg.Counters.Inc(CounterNotifyUnknownReason)
		}
		log.Info("CIS notification acknowledged without a pull")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if rc.cfg.Guard == nil {
		rc.cfg.Counters.Inc(CounterPullURLMismatch)
	} else if err := rc.cfg.Guard.CheckPullURL(ch.PullUrl); err != nil {
		// M5: the configured dataset URL is pulled instead.
		rc.cfg.Counters.Inc(CounterPullURLMismatch)
		log.Warn("pull_url is not on the configured CISP; the configured dataset URL is pulled", slog.String("reason", err.Error()))
	}
	rc.cfg.Counters.Inc(CounterNotifyAccepted)
	rc.cfg.Trigger(ds, Hint{Version: ch.Version, Issuer: claims.Issuer, At: rc.cfg.Now()})
	log.Info("CIS notification accepted; pull triggered")
	w.WriteHeader(http.StatusAccepted)
}

// decodeChange reads a cis/change/v1 record into the generated type.
// Members it does not know are ignored (records are additive within
// v1); known is false for a dataset this system does not project (it is
// acknowledged without a pull).
func decodeChange(body json.RawMessage) (cispclient.Change, Dataset, bool, *core.FieldError) {
	var c cispclient.Change
	if err := json.Unmarshal(body, &c); err != nil {
		return c, "", false, core.Fieldf("body", "not a %s record", ChangeSchema)
	}
	switch {
	case string(c.Schema) != ChangeSchema:
		return c, "", false, core.Fieldf("schema", "must be %s", ChangeSchema)
	case c.Dataset == "":
		return c, "", false, core.Fieldf("dataset", "empty")
	case c.Version < 0:
		return c, "", false, core.Fieldf("version", "negative")
	case c.Reason == "":
		return c, "", false, core.Fieldf("reason", "empty")
	}
	ds, ok := ParseDataset(string(c.Dataset))
	return c, ds, ok, nil
}
