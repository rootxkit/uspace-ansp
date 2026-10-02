package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/vectors"
)

type jwtFixtures struct {
	Issuer   string          `json:"issuer"`
	Audience string          `json:"audience"`
	MaxSkewS float64         `json:"max_skew_s"`
	JWKS     json.RawMessage `json:"jwks"`
}

type jwtInput struct {
	Token        string `json:"token"`
	NowS         int64  `json:"now_s"`
	RequireScope string `json:"require_scope"`
}

type jwtExpected struct {
	Accepted       bool     `json:"accepted"`
	Reason         string   `json:"reason"`
	Claim          string   `json:"claim"`
	Subject        string   `json:"subject"`
	Scopes         []string `json:"scopes"`
	RequireScopeOK *bool    `json:"require_scope_ok"`
}

// jwt_verify.json, the cases owned by ansp, through this repository's
// middleware (brief WP-2): the vector's issuer is an allow-listed
// ecosystem issuer whose JWKS a local server publishes, its audience is
// the accepted audience, its skew the verifier's and its now the clock.
// Each token is presented as a bearer to a route behind RequireScopes
// with the case's scope (ansp.traffic when the case names none); the
// status, the problem type (core's counter), the claim at fault and the
// counters are asserted, and no refusal echoes the token. The verdicts
// are core's; the plumbing is this package's.
func TestVectorsJWTVerify(t *testing.T) {
	f := vectors.Load(t, "jwt_verify.json")
	var fx jwtFixtures
	vectors.Unmarshal(t, f.Fixtures, &fx)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(fx.JWKS) }))
	defer jwks.Close()

	ran := 0
	f.RunOwned(t, "ansp", func(t *testing.T, c vectors.Case) {
		ran++
		var in jwtInput
		var exp jwtExpected
		c.Decode(t, &in, &exp)
		now := time.Unix(in.NowS, 0).UTC()
		m, err := NewMachineVerifierWith(context.Background(), coreauth.Config{
			Issuers:             map[string]coreauth.IssuerConfig{fx.Issuer: {JWKSURL: jwks.URL}},
			Audiences:           []string{fx.Audience},
			StrictSessionClaims: true,
			MaxSkew:             time.Duration(fx.MaxSkewS * float64(time.Second)),
			Now:                 func() time.Time { return now },
		}, nil)
		must(t, err)
		scope := in.RequireScope
		if scope == "" && len(exp.Scopes) > 0 {
			scope = exp.Scopes[0] // a scope the token grants: the route then admits it
		}
		if scope == "" {
			scope = "ansp.traffic"
		}
		g := &Guard{Machine: m}
		var seen *Principal
		h := g.RequireScopes(scope)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := PrincipalFrom(r.Context())
			seen = &p
			w.WriteHeader(http.StatusOK)
		}))
		r := httptest.NewRequest(http.MethodGet, "/v1/manned-traffic/snapshot", nil)
		r.Header.Set("Authorization", "Bearer "+in.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		if strings.Contains(rec.Body.String(), in.Token) {
			t.Fatal("the answer echoes the token")
		}
		if !exp.Accepted {
			var p ProblemBody
			must(t, json.Unmarshal(rec.Body.Bytes(), &p))
			if rec.Code != http.StatusUnauthorized || p.Slug() != exp.Reason || len(p.Errors) != 1 || p.Errors[0].Field != exp.Claim {
				t.Fatalf("got %d %s, want 401 %s on %s", rec.Code, rec.Body.String(), exp.Reason, exp.Claim)
			}
			if rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatalf("headers %v", rec.Header())
			}
			if m.Counters().Get(exp.Reason) != 1 || g.Counters().Get(CounterTokenRefused) != 1 {
				t.Fatalf("counter %s not counted: %v %v", exp.Reason, m.Counters().Snapshot(), g.Counters().Snapshot())
			}
			return
		}
		if exp.RequireScopeOK != nil && !*exp.RequireScopeOK {
			var p ProblemBody
			must(t, json.Unmarshal(rec.Body.Bytes(), &p))
			if rec.Code != http.StatusForbidden || p.Slug() != SlugForbidden || g.Counters().Get(CounterScopeRefused) != 1 || seen != nil {
				t.Fatalf("got %d %s, want 403 for the missing scope %s", rec.Code, rec.Body.String(), scope)
			}
			return
		}
		// An accepted token whose case names no scope at all is judged
		// against ansp.traffic, which it does not grant: core's verdict
		// (accepted) is read from its counters and the 403 is this
		// middleware's scope check.
		if in.RequireScope == "" && len(exp.Scopes) == 0 {
			if m.Counters().Get(coreauth.CounterAccepted) != 1 || rec.Code != http.StatusForbidden {
				t.Fatalf("got %d, want core's acceptance then 403", rec.Code)
			}
			return
		}
		if rec.Code != http.StatusOK || seen == nil || m.Counters().Get(coreauth.CounterAccepted) != 1 {
			t.Fatalf("got %d %s", rec.Code, rec.Body.String())
		}
		if seen.Claims.Subject != exp.Subject || (exp.Scopes != nil && !slices.Equal(seen.Claims.Scopes, exp.Scopes)) {
			t.Fatalf("claims %+v, want %s %v", seen.Claims, exp.Subject, exp.Scopes)
		}
		if g.Counters().Get(CounterMachineAccepted) != 1 {
			t.Fatalf("guard counters %v", g.Counters().Snapshot())
		}
	})
	t.Logf("jwt_verify.json: %d cases run through RequireScopes", ran)
	if ran != 16 {
		t.Fatalf("ran %d cases, the file holds 16 for ansp", ran)
	}
}
