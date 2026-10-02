package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
)

// maxProbeBytes bounds a JWKS read by the readiness probe.
const maxProbeBytes = 1 << 20

// MachineVerifier verifies the ecosystem tokens of machine clients with
// one uspace-core auth.Verifier: RS256, kid, iss on ANSP_TOKEN_ISSUERS,
// aud one of ANSP_AUDIENCES (hosts, M18; ANSP_SYSTEM_ID never), exp with
// 30 s skew, sub and jti, StrictSessionClaims. Core fetches every
// issuer's JWKS when it is built and refuses to build without them, so
// start-up fails while a JWKS cannot be fetched; afterwards core keeps
// verifying from its cache through an issuer outage (06 section 2 T5),
// and Check reports the issuer stale with the age of its last good
// fetch.
type MachineVerifier struct {
	v       *coreauth.Verifier
	jwks    map[string]string // iss -> JWKS URL
	probe   *http.Client
	now     func() time.Time
	mu      sync.Mutex
	fetched map[string]time.Time
	lastErr map[string]string
}

// NewMachineVerifier builds the verifier of cfg (config.VerifierConfig).
func NewMachineVerifier(ctx context.Context, cfg config.Config) (*MachineVerifier, error) {
	cc, err := cfg.VerifierConfig()
	if err != nil {
		return nil, err
	}
	return NewMachineVerifierWith(ctx, cc, nil)
}

// NewMachineVerifierWith builds the verifier of a core configuration;
// probe fetches the JWKS for readiness (nil: a 2 s client that follows
// no redirect).
func NewMachineVerifierWith(ctx context.Context, cc coreauth.Config, probe *http.Client) (*MachineVerifier, error) {
	v, err := coreauth.NewVerifier(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("ANSP_TOKEN_ISSUERS: %w", err)
	}
	if probe == nil {
		probe = &http.Client{
			Timeout:       2 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	now := cc.Now
	if now == nil {
		now = time.Now
	}
	m := &MachineVerifier{v: v, jwks: map[string]string{}, probe: probe, now: now,
		fetched: map[string]time.Time{}, lastErr: map[string]string{}}
	at := now()
	for iss, ic := range cc.Issuers {
		if ic.JWKSURL != "" {
			m.jwks[iss] = ic.JWKSURL
			m.fetched[iss] = at // core fetched it to build
		}
	}
	return m, nil
}

// Verify verifies token; a refusal is core's *coreauth.TokenError.
func (m *MachineVerifier) Verify(ctx context.Context, token string) (coreauth.Claims, error) {
	return m.v.Verify(ctx, token)
}

// Counters are core's verifier counters (accepted, rejected_*,
// jwks_refresh*), exported as they are.
func (m *MachineVerifier) Counters() *core.Counters { return m.v.Counters() }

// Check is the readiness check "jwks": ok while every issuer's JWKS
// answers; degraded, "<iss>: stale (age N s: why)", when one does not
// (tokens are still verified from core's cache); never down, because
// the verifier was built with every set and core keeps them.
func (m *MachineVerifier) Check() obs.Check {
	return obs.Check{Name: obs.DepJWKS, Required: true, Probe: m.probeAll}
}

func (m *MachineVerifier) probeAll(ctx context.Context) (obs.State, string) {
	state := obs.StateOK
	var details []string
	for _, iss := range slices.Sorted(maps.Keys(m.jwks)) {
		err := m.fetchJWKS(ctx, m.jwks[iss])
		now := m.now()
		m.mu.Lock()
		if err == nil {
			m.fetched[iss] = now
			delete(m.lastErr, iss)
			m.mu.Unlock()
			continue
		}
		m.lastErr[iss] = err.Error()
		age := now.Sub(m.fetched[iss])
		m.mu.Unlock()
		state = obs.StateDegraded
		details = append(details, fmt.Sprintf("%s: stale (age %d s: %v)", iss, int64(age/time.Second), err))
	}
	return state, strings.Join(details, "; ")
}

// fetchJWKS checks that url answers 200 with a JSON object holding a
// keys array.
func (m *MachineVerifier) fetchJWKS(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := m.probe.Do(req)
	if err != nil {
		return errors.New("unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProbeBytes)).Decode(&set); err != nil || set.Keys == nil {
		return errors.New("not a JWKS")
	}
	return nil
}

// unverifiedIssuer reads the iss of a compact JWT without verifying
// anything: it only chooses which verifier judges the token, and each
// verifier refuses an issuer it does not allow-list. A token that does
// not parse has no issuer.
func unverifiedIssuer(token string) string {
	if len(token) > coreauth.DefaultMaxTokenBytes {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.Iss
}
