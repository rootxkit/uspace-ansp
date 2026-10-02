package cis

import (
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
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("%s version %d held, not used: %s", e.Dataset, e.Version, e.Reason)
}

// reasonNoPublisherKeys is the reason of every hold while no publisher
// keys are configured.
const reasonNoPublisherKeys = "no publisher keys are configured (ANSP_CIS_PUBLISHER_KEYS)"

// provenance reads version v as its publisher sent it (GET
// /v1/{dataset}/versions/{v}) and verifies X-Publisher-Signature over
// those bytes with the key of the dataset's publisher (spec 06 T4). It
// returns an *UntrustedError when the signature is missing or does not
// verify, and another error when the version could not be read (a pull
// failure: nothing is held, the next pull tries again).
func provenance(ctx context.Context, c *Client, pubs PublisherVerifier, v *Version) error {
	untrusted := func(format string, a ...any) error {
		return &UntrustedError{Dataset: v.Dataset, Version: v.Number, Reason: fmt.Sprintf(format, a...)}
	}
	if pubs == nil {
		return untrusted(reasonNoPublisherKeys)
	}
	f, err := c.GetVersion(ctx, v.Dataset, v.Number)
	if err != nil {
		return fmt.Errorf("reading %s version %d as published: %w", v.Dataset, v.Number, err)
	}
	if f.Status != http.StatusOK {
		return fmt.Errorf("reading %s version %d as published: the CISP answered %d", v.Dataset, v.Number, f.Status)
	}
	if f.Version != 0 && f.Version != v.Number {
		return untrusted("the CISP served version %d for version %d", f.Version, v.Number)
	}
	if f.PublisherSignature == "" {
		return untrusted("no %s", HeaderPublisherSignature)
	}
	pub := PublisherOf(v.Dataset)
	sig, err := pubs.Verify(ctx, pub, f.PublisherSignature, f.Body)
	if err != nil {
		return untrusted("%s does not verify with the %s's keys: %s", HeaderPublisherSignature, pub, short(err.Error()))
	}
	if f.PublisherKID != "" && f.PublisherKID != sig.KID {
		return untrusted("%s names %q, the signature's kid is %q", HeaderPublisherKID, short(f.PublisherKID), sig.KID)
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
