# WP-2: `auth-accounts`

Branch `feat/WP-2-auth-accounts`. Milestone N-M0. Owns `internal/auth`
and `migrations/relational/0020–0029` (`users`, `user_sessions`,
`user_mfa`, `oauth_clients_seen`). Depends on WP-0; uses WP-1's
`store.Tx` and `audit.Record` once merged (until then, code against the
interfaces in `docs/PLAN.md §5` and rebase). Consumers: every handler of
`api`, the WS upgrades of `manned-feed`, the console's BFF.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §6` (the Auth column of every endpoint),
   `§8`, `§15` gaps 7, 8, 19.
2. Spec `00 §6.2` (JWT and the BFF), `01 §4` users table, `06 §2` T4,
   T5, T6, `06 §3`.
3. `uspace-core/auth` `doc.go` and `jwt.go` (`Config`, `Verifier`,
   `Claims`, `RequireScope`, `Issuer`); `vectors/testdata/jwt_verify.json`
   (your `RunOwned(t, "ansp", ...)` test runs it through your
   middleware).
4. LESSONS B-14, E-01, E-10, E-14; utm S-15 (login limits) via
   `utm/api/auth.py`, `auth_http.py`, `ratelimit.py` (reference only).

## What to build

### Ecosystem tokens (machine clients)

- `NewMachineVerifier(ctx, cfg)`: one `uspace-core/auth.Verifier` with
  `Issuers` = every entry of `ANSP_TOKEN_ISSUERS` (the authority's token
  service and, in the lab, the lab issuer; nobody waits for authority
  WP-2) and the audience list `ANSP_AUDIENCES` (hosts: this system's
  public host plus a lab alias; `aud` must match one of them, M18).
  `cfg.SystemID` is never an audience. Start-up fails if a JWKS cannot
  be fetched (core semantics); readiness reports `jwks: ok | stale
  (age)` per issuer.
- Middleware `RequireScopes(v, scopes ...string)` for the generated
  strict server: bearer from `Authorization`, `Verify`, every listed
  scope present, else `401` (invalid token) or `403` (missing scope) as
  RFC 9457 problems that never echo the token; the `Claims` are put in
  the request context (`ClaimsFrom(ctx)`). Counters from the verifier are
  exported.
- mTLS binding: when `ANSP_MTLS_MODE=required` (M25; the only other
  value is `off`), the middleware on the mTLS route groups
  (`/v1/manned-traffic/*`, `/v1/coordination/*`) requires the header
  Caddy sets from the client certificate (`X-Client-Cert-Subject`),
  believed only when the request's peer is in `ANSP_TRUSTED_PROXIES`
  (CIDRs or addresses; empty trusts no proxy; from any other peer the
  header is ignored and the call has no client certificate), and
  refuses when the subject does not match the binding for `sub` (trust
  on first use is **not** acceptable: the binding comes from
  configuration `ANSP_MTLS_BINDINGS_FILE` mapping `sub` → subject, and
  an unmapped `sub` is refused). Caddy terminates with `client_auth {
  mode verify_if_given }` and strips the header on every other route
  (the snippet is WP-13's; the deployment repo composes it). With `off`,
  the middleware logs `mtls: off` at error level every status period so
  a staging setting cannot reach production unnoticed.
- `oauth_clients_seen` upsert on every accepted call (first and last
  seen, scopes seen), off the request path through a bounded channel.

### Outbound tokens

`TokenSource(cfg)` for this system's calls to the CISP, DSS, USSPs and
authority: client credentials at `ANSP_TOKEN_URL` as `client_id =
ansp-01` (M24) with the secret from `ANSP_CLIENT_SECRET_FILE`, the
`audience` parameter set to **the host of the target's base URL**
(`ANSP_CISP_URL`'s host, `ANSP_DSS_URL`'s host, a peer's `uss_base_url`
host, the authority's host; M18), one token per (`aud`, scope set),
refreshed at 50 % TTL in the background (`06` T5), bounded retry,
counters `token_fetch_ok`, `token_fetch_failed`; a cached token is used
until `exp` during an issuer outage. `AudienceOf(url) string` is the one
place that derives a host, with a test for ports and trailing paths.

### Local accounts and sessions

- `users` with `argon2id` (parameters as constants, a benchmark proving
  ≥ 100 ms per hash on CI), roles `watch_supervisor`, `viewer`, `admin`;
  `user_mfa` with the TOTP secret encrypted under a key from
  `ANSP_SECRETS_KEY_FILE`; MFA mandatory: a user without MFA enrolled
  can only enrol.
- `POST /v1/auth/login` (password) → a short-lived `mfa_pending` token;
  `POST /v1/auth/mfa` (TOTP) → session JWT issued by a
  `uspace-core/auth.Issuer` with this system's key (`ANSP_SESSION_KEY_FILE`,
  RS256, `kid`) in the ecosystem's one session shape (M20): `iss` = this
  system's issuer URL, `aud` = this system's own host (the first entry
  of `ANSP_AUDIENCES`), `sub` = account id, `scope = "session"`,
  `roles: [<role>]` (one element here), `realm: "console"`, `jti` =
  session id recorded in `user_sessions`, `exp` ≤ 12 h, idle 30 min;
  `POST /v1/auth/logout` revokes the `jti`; `GET /v1/auth/me`. Login
  rate limit per username and per IP (S-15) with `429` and
  `Retry-After`; every login, refusal and logout is an audit event.
- `SessionVerifier`: the same core `Verifier` with this system as issuer
  (keys from the local JWKS, no network) and the same audience list,
  plus a revocation check against `user_sessions` through a short
  cache. `RequireRole(roles ...)` reads `roles[]`, never `scope`.
- WebSocket upgrades (`manned-feed`, `api` streams) accept the session
  cookie **`uspace_session`** on same-origin requests (checked against
  an `Origin` allow-list), or a bearer; no ticket route (M22). Document
  the BFF contract: the Next.js BFF sets the `HttpOnly`, `Secure`,
  `SameSite=Strict` `uspace_session` cookie from the `mfa` response and
  forwards it as a bearer on REST calls; the `uspace_csrf` cookie and
  the `X-CSRF-Token` header carry the double-submit token on
  state-changing calls (M21); a `4401` close on a WebSocket means
  "re-login".
- `GET /.well-known/jwks.json`: the session key and the delivery-signing
  key (WP-8 adds the latter; expose the set from one place).

### Admin

`admin` creates users and resets MFA through `POST /v1/users` and
`POST /v1/users/{id}/reset-mfa` (add to `api/openapi.yaml` under the
auth group in the same PR as WP-3, or in this PR if WP-3 has merged).

## Tests

- `TestVectorsJWTVerify`: `vectors.Load(t, "jwt_verify.json").RunOwned(t,
  "ansp", ...)` through `RequireScopes` with a generated key pair; every
  refusal maps to the right status and counter.
- E-01 pairs: accepted token / each refusal (including `aud` = the lab
  alias accepted, `aud` = `ansp` refused, `aud` = another system's host
  refused); mTLS subject matches / mismatches / header absent, and
  `ANSP_MTLS_MODE=off` accepts without the header while the error-level
  line is logged; MFA right / wrong / replayed code (the same TOTP code
  twice is refused); role allowed / forbidden read from `roles[]`;
  revoked session refused after logout, accepted before; a session
  token with `scope = "watch_supervisor"` (the old shape) refused.
- Outbound: the token request for the CISP carries `audience` = the
  CISP's host, for the DSS the DSS's host (stub asserts the parameter).
- E-02: issuer JWKS unreachable after start → tokens still verified from
  the cache, readiness `jwks: stale`; token service down → outbound
  calls use the cached token and the counter moves.
- E-10: rate limiter past its window; session cache bound.
- No key material in testdata: keys generated per test; gitleaks clean.

## Done when

- [ ] `make lint`, `make race` green; the vector test passes 16/16 (or
  the file's current count; report it).
- [ ] Coverage ≥ 90 % on `internal/auth`.
- [ ] Benchmarks `BenchmarkArgon2id`, `BenchmarkVerifyToken` reported.
- [ ] `doc.go` rewritten (the BFF contract, the mTLS header, the roles);
  CHANGELOG line.

## Commits

`feat(auth): verify ecosystem tokens and scopes with uspace-core/auth [WP-2 N-M0]`,
`feat(auth): fetch client-credentials tokens for outbound calls [WP-2 N-M0]`,
`feat(auth): add local accounts with mandatory TOTP and session tokens [WP-2 N-M0]`,
`feat(auth): bind mTLS subjects to client ids from configuration [WP-2 N-M0]`,
`test(auth): run the jwt_verify vectors through the middleware [WP-2 N-M0]`.
