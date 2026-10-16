package cis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// The publishers of the datasets (the names of ANSP_CIS_PUBLISHER_KEYS):
// the authority publishes the U-space designation and the USSP list
// (F1), this system the restrictions (F2).
const (
	PublisherAuthority = "authority"
	PublisherANSP      = "ansp"
)

// PublisherOf is the publisher whose key must have signed a version of d.
func PublisherOf(d Dataset) string {
	if d == Restrictions {
		return PublisherANSP
	}
	return PublisherAuthority
}

// PublisherVerifier verifies a publisher's detached JWS over a version's
// bytes; core's auth.DetachedVerifier and LazyPublisherVerifier
// implement it.
type PublisherVerifier interface {
	Verify(ctx context.Context, publisher, header string, payload []byte) (coreauth.Signature, error)
}

// UntrustedError is a version whose provenance could not be shown: its
// publisher's signature is missing or does not verify, or there are no
// keys to verify it with. The version is held, never used; the one in
// use before stays in use and ages.
type UntrustedError struct {
	Dataset Dataset
	Version int64
	Reason  string
	// Expiry is a restrictions version without a publisher signature
	// that was judged as a CISP expiry and not shown to be one
	// (counted cis_expiry_held).
	Expiry bool
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("%s version %d held, not used: %s", e.Dataset, e.Version, e.Reason)
}

// reasonNoPublisherKeys is the reason of every hold while no publisher
// keys are configured.
const reasonNoPublisherKeys = "no publisher keys are configured (ANSP_CIS_PUBLISHER_KEYS)"

// The provenance kinds of an installed version (Version.Provenance).
const (
	// ProvenancePublisher: its publisher's X-Publisher-Signature verified
	// and the content served is what it signed.
	ProvenancePublisher = "publisher"
	// ProvenanceCISPExpiry: a restrictions version the CISP made itself
	// when restrictions expired, installed by the content rule of spec
	// 02 F3 (erratum 2026-10-16; expiryProvenance).
	ProvenanceCISPExpiry = "cisp_expiry"
)

// expiryRule is what the content rule of a CISP expiry version is
// judged against: the version in use and this system's clock.
type expiryRule struct {
	// prev is the version of restrictions in use (nil while none is).
	prev *Version
	now  time.Time
	// skew is cis_expiry_skew_s: how far past now the record's at may be.
	skew time.Duration
}

// provenance reads version v as its publisher sent it (GET
// /v1/{dataset}/versions/{v}) and verifies X-Publisher-Signature over
// those bytes with the key of the dataset's publisher (spec 06 T4). The
// bytes installed are v.Body, read from the current path, which the
// CISP serves as its own snapshot (top-level cis_* members, its own
// metadata), so they must carry exactly the content the signature
// covers (signedMatches): a CISP or a proxy that serves a signed
// document on one path and other features on the other is held (B-1 of
// the 2026-10 audit). A restrictions version with no publisher
// signature is judged by expiryProvenance instead: the CISP's own
// version at an expiry. It returns the provenance kind, an
// *UntrustedError when the provenance could not be shown, and another
// error when the version could not be read (a pull failure: nothing is
// held, the next pull tries again).
func provenance(ctx context.Context, c *Client, pubs PublisherVerifier, v *Version, rule expiryRule) (string, error) {
	untrusted := func(format string, a ...any) error {
		return &UntrustedError{Dataset: v.Dataset, Version: v.Number, Reason: fmt.Sprintf(format, a...)}
	}
	if pubs == nil {
		return "", untrusted(reasonNoPublisherKeys)
	}
	f, err := c.GetVersion(ctx, v.Dataset, v.Number)
	if err != nil {
		return "", fmt.Errorf("reading %s version %d as published: %w", v.Dataset, v.Number, err)
	}
	if f.Status != http.StatusOK {
		return "", fmt.Errorf("reading %s version %d as published: the CISP answered %d", v.Dataset, v.Number, f.Status)
	}
	if f.Version != 0 && f.Version != v.Number {
		return "", untrusted("the CISP served version %d for version %d", f.Version, v.Number)
	}
	if f.PublisherSignature == "" {
		if v.Dataset == Restrictions {
			if err := expiryProvenance(ctx, pubs, v, f, rule); err != nil {
				return "", err
			}
			return ProvenanceCISPExpiry, nil
		}
		return "", untrusted("no %s", HeaderPublisherSignature)
	}
	pub := PublisherOf(v.Dataset)
	sig, err := pubs.Verify(ctx, pub, f.PublisherSignature, f.Body)
	if err != nil {
		return "", untrusted("%s does not verify with the %s's keys: %s", HeaderPublisherSignature, pub, short(err.Error()))
	}
	if f.PublisherKID != "" && f.PublisherKID != sig.KID {
		return "", untrusted("%s names %q, the signature's kid is %q", HeaderPublisherKID, short(f.PublisherKID), sig.KID)
	}
	if reason := signedMatches(v, f.Body); reason != "" {
		return "", untrusted("%s (at /v1/%s and /v1/%s/versions/%d)", reason, v.Dataset, v.Dataset, v.Number)
	}
	return ProvenancePublisher, nil
}

// PublisherCISP is the name of the CISP's keys in
// ANSP_CIS_PUBLISHER_KEYS: they verify X-CIS-Signature over an expiry
// version, the one version the CISP makes itself.
const PublisherCISP = "cisp"

// OpExpire is the op of the CISP's expiry record; no publisher can send
// it (a publisher's PATCH ops are activate, extend, end and cancel).
const OpExpire = "expire"

// expiryRecord is the CISP's expiry record, the bytes of a restrictions
// version it made when a restriction passed its ends_at (spec 02 F3,
// erratum 2026-10-16): {op: "expire", restriction_id, feature_id,
// ends_at, at}. A CISP before the erratum writes no feature_id and no
// ends_at.
type expiryRecord struct {
	Op            string `json:"op"`
	RestrictionID string `json:"restriction_id"`
	FeatureID     string `json:"feature_id"`
	EndsAt        string `json:"ends_at"`
	At            string `json:"at"`
}

// reasonNotExpiry starts the reason of every hold of a restrictions
// version that has no publisher signature and is not shown to be a CISP
// expiry: the status line keeps naming the missing signature.
const reasonNotExpiry = "no " + HeaderPublisherSignature + ", and not a CISP expiry: "

// expiryProvenance shows that v, a restrictions version served without
// X-Publisher-Signature, is the CISP's own version at an expiry and only
// that (spec 02 F3, erratum 2026-10-16): f.Body, the bytes at
// /versions/{v}, is the CISP's expiry record and X-CIS-Signature over
// them verifies with the CISP's keys (PublisherCISP, under the same
// signature age as a publisher's); the record's at is not later than
// this system's clock plus cis_expiry_skew_s; and, feature by feature
// against the version in use (canonicalFeatures, extendedProperties
// cis_* left out), v removes one or more features and adds or changes
// none, every removed feature has one limitedApplicability period whose
// endDateTime is at or before at, and feature_id is one of them. Any
// other case returns an *UntrustedError with Expiry set and the version
// is held as before; the projection never stops a restriction on it (no
// restriction applies here from the projection: this system's own
// restrictions end at their ends_at by internal/restriction's ticker).
func expiryProvenance(ctx context.Context, pubs PublisherVerifier, v *Version, f Fetched, rule expiryRule) error {
	untrusted := func(format string, a ...any) error {
		return &UntrustedError{Dataset: v.Dataset, Version: v.Number, Expiry: true, Reason: reasonNotExpiry + fmt.Sprintf(format, a...)}
	}
	if f.CISSignature == "" {
		return untrusted("no %s", HeaderCISSignature)
	}
	if _, err := pubs.Verify(ctx, PublisherCISP, f.CISSignature, f.Body); err != nil {
		return untrusted("%s does not verify with the %s's keys: %s", HeaderCISSignature, PublisherCISP, short(err.Error()))
	}
	var rec expiryRecord
	if err := json.Unmarshal(f.Body, &rec); err != nil {
		return untrusted("the version's bytes are not the CISP's expiry record")
	}
	switch {
	case rec.Op != OpExpire:
		return untrusted("the CISP's record is op %q, not %s", short(rec.Op), OpExpire)
	case rec.RestrictionID == "":
		return untrusted("the expiry record names no restriction_id")
	case rec.FeatureID == "":
		return untrusted("the expiry record names no feature_id (a CISP before the F3 erratum of 2026-10-16)")
	case rec.EndsAt == "":
		return untrusted("the expiry record has no ends_at")
	}
	if _, err := time.Parse(time.RFC3339, rec.EndsAt); err != nil {
		return untrusted("the expiry record's ends_at is not an RFC 3339 time")
	}
	at, err := time.Parse(time.RFC3339, rec.At)
	if err != nil {
		return untrusted("the expiry record's at is not an RFC 3339 time")
	}
	if latest := rule.now.Add(rule.skew); at.After(latest) {
		return untrusted("the expiry record's at %s is later than this system's clock plus cis_expiry_skew_s (%s)",
			at.UTC().Format(time.RFC3339Nano), latest.UTC().Format(time.RFC3339Nano))
	}
	if rule.prev == nil || rule.prev.Collection == nil {
		return untrusted("no restrictions version in use to compare it with")
	}
	if v.Collection == nil {
		return untrusted("the version holds no collection to compare")
	}
	held, err := canonicalFeatures(rule.prev.Collection.Features)
	if err != nil {
		return untrusted("the version in use does not export: %s", short(err.Error()))
	}
	served, err := canonicalFeatures(v.Collection.Features)
	if err != nil {
		return untrusted("the version's features do not export: %s", short(err.Error()))
	}
	for id, s := range served {
		h, ok := held[id]
		switch {
		case !ok:
			return untrusted("it adds %q", short(id))
		case !bytes.Equal(h, s):
			return untrusted("it changes %q", short(id))
		}
	}
	removed := map[string]bool{}
	for i := range rule.prev.Collection.Features {
		feat := &rule.prev.Collection.Features[i]
		id := feat.Properties.Identifier
		if _, ok := served[id]; ok {
			continue
		}
		removed[id] = true
		periods := feat.Properties.LimitedApplicability
		if len(periods) != 1 || periods[0].EndDateTime == nil {
			return untrusted("it removes %q, which has no single signed end", short(id))
		}
		if end := periods[0].EndDateTime.Time; end.After(at) {
			return untrusted("it removes %q before its signed end %s (at %s)", short(id),
				end.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano))
		}
	}
	if len(removed) == 0 {
		return untrusted("it removes nothing")
	}
	if !removed[rec.FeatureID] {
		return untrusted("feature_id %q is not among the features it removes", short(rec.FeatureID))
	}
	return nil
}

// DefaultKeysRetry is how often a lazy verifier tries to fetch its keys
// again while it has none.
const DefaultKeysRetry = 30 * time.Second

// lazy builds a core verifier once its JWKS can be fetched: a process
// that starts while the publisher or the CISP is unreachable (B-08)
// refuses until the keys are fetched, and says so.
type lazy[V any] struct {
	build func(context.Context) (*V, error)
	retry time.Duration
	v     atomic.Pointer[V]

	mu      sync.Mutex
	lastErr string
}

// Build tries once to build the verifier (core fetches the JWKS).
func (l *lazy[V]) Build(ctx context.Context) error {
	if l.v.Load() != nil {
		return nil
	}
	v, err := l.build(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.lastErr = err.Error()
		return err
	}
	l.lastErr = ""
	l.v.Store(v)
	return nil
}

// Run builds the verifier, trying again every retry period until it
// succeeds or ctx ends.
func (l *lazy[V]) Run(ctx context.Context) {
	t := time.NewTicker(l.retry)
	defer t.Stop()
	for l.Build(ctx) != nil {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Ready is whether the keys were fetched, and why not.
func (l *lazy[V]) Ready() (bool, string) {
	if l.v.Load() != nil {
		return true, ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastErr == "" {
		return false, "the keys are being fetched"
	}
	return false, "the keys are not fetched: " + short(l.lastErr)
}

func retryOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultKeysRetry
	}
	return d
}

// LazyPublisherVerifier is the projection's PublisherVerifier on core's
// auth.DetachedVerifier: until the publishers' JWKS are fetched every
// new version is held, and the reason says so.
type LazyPublisherVerifier struct {
	lazy[coreauth.DetachedVerifier]
}

// NewLazyPublisherVerifier returns a verifier that Run builds.
func NewLazyPublisherVerifier(cfg coreauth.DetachedConfig, retry time.Duration) *LazyPublisherVerifier {
	l := &LazyPublisherVerifier{}
	l.build = func(ctx context.Context) (*coreauth.DetachedVerifier, error) {
		return coreauth.NewDetachedVerifier(ctx, cfg)
	}
	l.retry = retryOrDefault(retry)
	return l
}

// errKeysUnavailable refuses a verification before the keys were fetched.
var errKeysUnavailable = errors.New("the keys have not been fetched since this process started")

// Verify verifies with the built verifier, or refuses.
func (l *LazyPublisherVerifier) Verify(ctx context.Context, publisher, header string, payload []byte) (coreauth.Signature, error) {
	if v := l.v.Load(); v != nil {
		return v.Verify(ctx, publisher, header, payload)
	}
	return coreauth.Signature{}, errKeysUnavailable
}

// Counters are core's verifier counters once built, nil before.
func (l *LazyPublisherVerifier) Counters() *core.Counters {
	if v := l.v.Load(); v != nil {
		return v.Counters()
	}
	return nil
}

// CounterNotifyKeysUnavailable counts notifications refused because the
// issuers' keys were not fetched since the process started.
const CounterNotifyKeysUnavailable = "cis_notify_keys_unavailable"

// CompactVerifier verifies a compact delivery JWS (core's
// auth.CompactVerifier, LazyNotifyVerifier).
type CompactVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.CompactClaims, json.RawMessage, error)
}

// LazyNotifyVerifier is the receiver's CompactVerifier on core's
// auth.CompactVerifier: until the notification issuers' JWKS are
// fetched every notification is refused 401 and counted (the CISP
// retries for 24 h, and the reconciliation keeps the projection).
type LazyNotifyVerifier struct {
	lazy[coreauth.CompactVerifier]
	counters *core.Counters
}

// NewLazyNotifyVerifier returns a verifier that Run builds; counters
// receives CounterNotifyKeysUnavailable.
func NewLazyNotifyVerifier(cfg coreauth.CompactConfig, retry time.Duration, counters *core.Counters) *LazyNotifyVerifier {
	if counters == nil {
		counters = &core.Counters{}
	}
	l := &LazyNotifyVerifier{counters: counters}
	l.build = func(ctx context.Context) (*coreauth.CompactVerifier, error) {
		return coreauth.NewCompactVerifier(ctx, cfg)
	}
	l.retry = retryOrDefault(retry)
	return l
}

// Verify verifies with the built verifier, or refuses.
func (l *LazyNotifyVerifier) Verify(ctx context.Context, token string) (coreauth.CompactClaims, json.RawMessage, error) {
	if v := l.v.Load(); v != nil {
		return v.Verify(ctx, token)
	}
	l.counters.Inc(CounterNotifyKeysUnavailable)
	return coreauth.CompactClaims{}, nil, &coreauth.TokenError{Counter: CounterNotifyKeysUnavailable, Claim: "kid",
		Reason: "the notification issuers' keys have not been fetched since this process started"}
}

// Counters are core's verifier counters once built, nil before.
func (l *LazyNotifyVerifier) Counters() *core.Counters {
	if v := l.v.Load(); v != nil {
		return v.Counters()
	}
	return nil
}
