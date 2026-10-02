package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-ansp/internal/auth"
	"github.com/rootxkit/uspace-ansp/internal/config"
	"github.com/rootxkit/uspace-ansp/internal/obs"
	"github.com/rootxkit/uspace-ansp/internal/store"
)

// sweepEvery is how often expired sessions, challenges and lockouts
// are deleted.
const sweepEvery = 10 * time.Minute

// authWiring is the accounts side of api (WP-2): the routes of
// internal/auth on mux, the readiness checks, and the background work
// (the sweep, the clients-seen recorder).
type authWiring struct {
	checks []obs.Check
	run    []func(ctx context.Context)
}

// wireAuth mounts console sign-in, the user operations and the JWKS
// when ANSP_SESSION_KEY_FILE is set (it needs the relational database,
// ANSP_SECRETS_KEY_FILE, ANSP_PUBLIC_BASE_URL and ANSP_AUDIENCES), and
// builds the machine verifier when ANSP_TOKEN_ISSUERS is set (start-up
// fails while an issuer's JWKS cannot be fetched). Without either it
// mounts nothing and says so. ANSP_MTLS_MODE=required without
// bindings refuses the start in every case (buildMTLS).
func wireAuth(ctx context.Context, cfg config.Config, db *store.Relational, mux *http.ServeMux, reg prometheus.Registerer, logger *slog.Logger) (*authWiring, error) {
	w := &authWiring{}
	proxies, err := auth.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	mtls, err := buildMTLS(cfg, proxies)
	if err != nil {
		return nil, err
	}
	guard := &auth.Guard{Origins: cfg.WSAllowedOrigins, MTLS: mtls}
	if len(cfg.TokenIssuers) > 0 {
		m, err := auth.NewMachineVerifier(ctx, cfg)
		if err != nil {
			return nil, err
		}
		guard.Machine = m
		w.checks = append(w.checks, m.Check())
		if err := obs.Counters(reg, "auth_machine", m.Counters()); err != nil {
			return nil, err
		}
		seen := auth.NewSeenRecorder(0, 0)
		guard.Seen = seen
		if err := obs.Counters(reg, "", seen.Counters()); err != nil {
			return nil, err
		}
		if db != nil {
			repo := store.AuthRepo{DB: db}
			w.run = append(w.run, func(ctx context.Context) { seen.Run(ctx, repo) })
		}
	}
	if cfg.SessionKeyFile == "" {
		logger.Warn("console sign-in is not mounted: ANSP_SESSION_KEY_FILE is not set")
		return w, obs.Counters(reg, "", guard.Counters())
	}
	if db == nil {
		return nil, core.Fieldf("ANSP_RELATIONAL_DSN", "required with ANSP_SESSION_KEY_FILE: accounts and sessions live there")
	}
	var errs []error
	if cfg.SecretsKeyFile == "" {
		errs = append(errs, core.Fieldf("ANSP_SECRETS_KEY_FILE", "required with ANSP_SESSION_KEY_FILE: TOTP secrets are sealed under it"))
	}
	if cfg.PublicBaseURL == "" {
		errs = append(errs, core.Fieldf("ANSP_PUBLIC_BASE_URL", "required with ANSP_SESSION_KEY_FILE: it is the issuer of sessions"))
	}
	if len(cfg.Audiences) == 0 {
		errs = append(errs, core.Fieldf("ANSP_AUDIENCES", "required with ANSP_SESSION_KEY_FILE: its first host is the aud of sessions"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sk, err := auth.LoadKeyFile("ANSP_SESSION_KEY_FILE", cfg.SessionKeyFile)
	if err != nil {
		return nil, err
	}
	ring, err := coreauth.NewKeyRing(sk)
	if err != nil {
		return nil, err
	}
	sealer, err := auth.LoadSealer(cfg.SecretsKeyFile)
	if err != nil {
		return nil, err
	}
	hasher, err := auth.NewHasher()
	if err != nil {
		return nil, err
	}
	issuer := strings.TrimSuffix(cfg.PublicBaseURL, "/")
	limiterCounters := &core.Counters{}
	accounts, err := auth.NewAccounts(auth.AccountsDeps{
		Store: store.AuthRepo{DB: db}, Hasher: hasher, Sealer: sealer, Ring: ring, Issuer: issuer,
		IPLimiter:   auth.NewRateLimiter(cfg.LoginIPPerMin, auth.DefaultLimiterKeys, limiterCounters, nil),
		UserLimiter: auth.NewRateLimiter(cfg.LoginUserPerMin, auth.DefaultLimiterKeys, limiterCounters, nil),
	}, auth.AccountsConfigFrom(cfg))
	if err != nil {
		return nil, err
	}
	sessions, err := auth.NewSessionVerifier(ctx, auth.SessionVerifierConfig{Issuer: issuer, Ring: ring, Audiences: cfg.Audiences, Checker: accounts})
	if err != nil {
		return nil, err
	}
	accounts.SetSessionVerifier(sessions)
	guard.Sessions = sessions
	keys := auth.NewPublicKeys()
	if err := keys.Add("session", ring); err != nil {
		return nil, err
	}

	if cfg.BootstrapAdminUsername != "" {
		pw, err := os.ReadFile(cfg.BootstrapAdminPasswordFile)
		if err != nil {
			return nil, core.Fieldf("ANSP_BOOTSTRAP_ADMIN_PASSWORD_FILE", "cannot be read")
		}
		created, err := accounts.Bootstrap(ctx, cfg.BootstrapAdminUsername, strings.TrimSpace(string(pw)))
		if err != nil {
			return nil, fmt.Errorf("bootstrap admin: %w", err)
		}
		if created {
			logger.Info("bootstrap: the first admin was created; it enrols TOTP at its first sign-in", slog.String("username", auth.NormalizeUsername(cfg.BootstrapAdminUsername)))
		}
	}

	inner := http.NewServeMux()
	rt := auth.NewRoutes(inner, auth.AccessTable(), guard)
	(&auth.Handlers{Accounts: accounts, Keys: keys}).Mount(rt)
	if err := rt.Err(); err != nil {
		return nil, fmt.Errorf("routes: %w", err)
	}
	h := auth.RealIP(proxies)(inner)
	for pattern := range auth.AccessTable() {
		mux.Handle(pattern, h)
	}

	for prefix, c := range map[string]*core.Counters{
		"": guard.Counters(), "auth_accounts": accounts.Counters(), "auth_sessions": sessions.Counters(),
		"auth_sessions_core": sessions.CoreCounters(), "auth_limiter": limiterCounters, "auth_jwks": keys.Counters(),
	} {
		if err := obs.Counters(reg, prefix, c); err != nil {
			return nil, err
		}
	}
	w.run = append(w.run, func(ctx context.Context) {
		accounts.RunSweep(ctx, sweepEvery, func(err error) {
			logger.Warn("session sweep failed; it runs again next interval", slog.String("error", err.Error()))
		})
	})
	logger.Info("console sign-in mounted", slog.String("issuer", issuer), slog.String("kid", ring.ActiveKID()))
	return w, nil
}

// buildMTLS is the certificate binding of the mTLS route groups.
// ANSP_MTLS_MODE=required with no ANSP_MTLS_BINDINGS_FILE (or an empty
// one) is refused: every mTLS route would refuse every client, which is
// a misconfiguration to stop at start, not an outage to find later.
func buildMTLS(cfg config.Config, proxies []netip.Prefix) (*auth.MTLS, error) {
	if cfg.MTLSMode != config.MTLSRequired {
		return auth.NewMTLS(cfg.MTLSMode, nil, nil)
	}
	if cfg.MTLSBindingsFile == "" {
		return nil, core.Fieldf("ANSP_MTLS_BINDINGS_FILE",
			"required when ANSP_MTLS_MODE=required: without bindings no client can pass the mTLS routes (set the file, or ANSP_MTLS_MODE=off outside production)")
	}
	bindings, err := auth.LoadMTLSBindings(cfg.MTLSBindingsFile)
	if err != nil {
		return nil, err
	}
	return auth.NewMTLS(cfg.MTLSMode, bindings, proxies)
}
