package config

import (
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
