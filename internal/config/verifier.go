package config

import (
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// VerifierConfig is the uspace-core auth.Config of every token verifier
// in this system: the allow-listed ANSP_TOKEN_ISSUERS with their JWKS
// URLs, the accepted audiences ANSP_AUDIENCES (hosts, M18;
// ANSP_SYSTEM_ID is never an audience, so Audience stays empty) and
// StrictSessionClaims on, so a session token whose roles is not an
// array of strings or whose realm is not a string is refused as
// rejected_claims instead of being read as having no role (M20,
// uspace-core v1.1.0).
//
// It is the one place an auth.Config is built in this repository;
// internal/auth (WP-2) passes it to auth.NewVerifier unchanged.
func (c Config) VerifierConfig() (auth.Config, error) {
	if len(c.TokenIssuers) == 0 {
		return auth.Config{}, core.Fieldf("ANSP_TOKEN_ISSUERS", "required to verify tokens")
	}
	if len(c.Audiences) == 0 {
		return auth.Config{}, core.Fieldf("ANSP_AUDIENCES", "required to verify tokens")
	}
	allow := make(map[string]auth.IssuerConfig, len(c.TokenIssuers))
	for _, iss := range c.TokenIssuers {
		allow[iss.Issuer] = auth.IssuerConfig{JWKSURL: iss.JWKSURL}
	}
	return auth.Config{
		Issuers:             allow,
		Audiences:           append([]string(nil), c.Audiences...),
		StrictSessionClaims: true,
	}, nil
}

// The publishers ANSP_CIS_PUBLISHER_KEYS may name (internal/cis
// PublisherAuthority, PublisherANSP).
var cisPublishers = []string{"authority", "ansp"}

// PublisherConfig is the uspace-core auth.DetachedConfig that verifies
// the publishers' signatures of CIS dataset versions:
// ANSP_CIS_PUBLISHER_KEYS (publisher=jwks_url, the publisher one of
// authority and ansp) and MaxAge ANSP_CIS_PUBLISHER_SIG_MAX_AGE_S.
func (c Config) PublisherConfig() (auth.DetachedConfig, error) {
	if len(c.CISPublisherKeys) == 0 {
		return auth.DetachedConfig{}, core.Fieldf("ANSP_CIS_PUBLISHER_KEYS", "required to verify CIS dataset versions")
	}
	pubs := make(map[string]auth.IssuerConfig, len(c.CISPublisherKeys))
	for _, e := range c.CISPublisherKeys {
		name, jwks, ok := strings.Cut(e, "=")
		name, jwks = strings.TrimSpace(name), strings.TrimSpace(jwks)
		switch {
		case !ok || name == "" || jwks == "":
			return auth.DetachedConfig{}, core.Fieldf("ANSP_CIS_PUBLISHER_KEYS", "each entry must be publisher=jwks_url")
		case !slices.Contains(cisPublishers, name):
			return auth.DetachedConfig{}, core.Fieldf("ANSP_CIS_PUBLISHER_KEYS", "%q is not a publisher (%s)", name, strings.Join(cisPublishers, ", "))
		case checkURL(jwks) != nil:
			return auth.DetachedConfig{}, core.Fieldf("ANSP_CIS_PUBLISHER_KEYS", "the JWKS URL of %s is not an absolute URL", name)
		}
		if _, dup := pubs[name]; dup {
			return auth.DetachedConfig{}, core.Fieldf("ANSP_CIS_PUBLISHER_KEYS", "%s is listed twice", name)
		}
		pubs[name] = auth.IssuerConfig{JWKSURL: jwks}
	}
	return auth.DetachedConfig{Publishers: pubs, MaxAge: time.Duration(c.CISPublisherSigMaxAgeS) * time.Second}, nil
}
