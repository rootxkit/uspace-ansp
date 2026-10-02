// Package auth is who may call uspace-ansp and how: ecosystem tokens of
// machine clients, the mTLS binding of their certificates, this
// system's own client-credentials tokens for outbound calls, console
// accounts with mandatory TOTP, console sessions and roles, and the
// contract the console's BFF implements (docs/PLAN.md sections 3, 6
// and 8, docs/WORKPACKAGES/WP-2.md). JWT verification and signing are
// calls into uspace-core/auth (CLAUDE.md rule 3); nothing here parses
// a signature. The package never logs: every refusal is a typed error
// and a counter, and the process decides what to log.
//
// # Machine clients
//
// MachineVerifier is one core Verifier over ANSP_TOKEN_ISSUERS (the
// authority's token service and, in the lab, the lab issuer) with aud
// one of ANSP_AUDIENCES, the hosts of this system (its public host and
// a lab alias, M18; ANSP_SYSTEM_ID is never an audience), and
// StrictSessionClaims. Start-up fails while an issuer's JWKS cannot be
// fetched (core's semantics); afterwards core verifies from its cache
// through an issuer outage (06 T5) and Check reports "jwks: degraded"
// with "<iss>: stale (age N s: why)".
//
// Guard is the middleware of every route. Every operation has an Access
// entry (the x-auth of api/openapi.yaml): Public, or Scopes (a machine
// token granting every one; RequireScopes), or Roles / AnyRole (a
// console session; RequireRole reads roles[], never scope), or both.
// Routes registers operations only through their entry and reports a
// route without one, an invalid one and an unused one, so routes fail
// closed. The bearer comes from the one Authorization header; its
// unverified iss only chooses the verifier. Refusals are RFC 9457
// problems in the ecosystem's one body (M28) that never echo the token:
// 401 with core's counter as the problem type (rejected_audience,
// rejected_expired, ...) and the claim at fault, 403 forbidden for a
// missing scope or role, 503 when a session cannot be checked. The
// verified claims are on the request context (ClaimsFrom,
// PrincipalFrom). Accepted machine calls go to oauth_clients_seen off
// the request path (SeenRecorder: a bounded queue, dropped and counted
// when full).
//
// # mTLS
//
// On the mTLS route groups (/v1/manned-traffic/*, /v1/coordination/*;
// Access.MTLS) Caddy terminates TLS with client_auth verify_if_given
// and sets X-Client-Cert-Subject from a verified client certificate,
// stripping the header on every other route (the snippet is WP-13's).
// With ANSP_MTLS_MODE=required the header must be present once and
// equal the subject bound to the token's sub in ANSP_MTLS_BINDINGS_FILE
// (a JSON array of {sub, subject}); an unmapped sub is refused: there
// is no trust on first use. The header is believed only when the
// request's peer (RemoteAddr) is in ANSP_TRUSTED_PROXIES; from any
// other peer it is ignored and the call is refused as having no client
// certificate. With off nothing is checked (counted) and
// obs.Server logs the mode at error level every status period.
//
// # Outbound tokens
//
// TokenSource fetches client-credentials tokens at ANSP_TOKEN_URL as
// ansp-01 (M24, client_secret_post) with audience = the host of the
// target's base URL (AudienceOf, the one place a host is derived: the
// CISP's host, the DSS's host, a USSP's uss_base_url host, the
// authority's host; M18), one per (aud, scope set), refreshed in the
// background from half its lifetime, used until exp while the token
// service is down (counted), with bounded retries.
//
// # Console accounts and sessions
//
// Accounts (users with argon2id passwords, roles watch_supervisor,
// viewer and admin) sign in in two steps. POST /v1/auth/login checks
// the password and returns a short-lived, single-use mfa_token (only
// its SHA-256 is stored, login_challenges); an account without a
// confirmed TOTP also receives its enrolment and can do nothing but
// enrol. POST /v1/auth/mfa takes the mfa_token and a TOTP code (RFC
// 6238, the secret sealed with AES-256-GCM under ANSP_SECRETS_KEY_FILE;
// the challenge, the account and its MFA row are locked FOR UPDATE, and
// a code at or before the last accepted step is refused, so a code is
// spent once) and returns the session token. Unknown user, disabled
// user and wrong password are one answer after one argon2id check;
// every failure, a wrong code included, counts against the username in
// login_lockouts, in the database so that the lockout holds on every
// replica, and per-address and per-username limiters answer 429 with
// Retry-After (S-15). Every sign-in, refusal and logout is an audit
// event. Expiry is judged on the database clock.
//
// The session token is signed by core's Issuer.IssueSession with the
// key of ANSP_SESSION_KEY_FILE (RS256, kid = its RFC 7638 thumbprint)
// in the one session shape (M20): iss = ANSP_PUBLIC_BASE_URL, aud =
// ANSP_AUDIENCES[0], sub = the account id, scope "session", roles
// [role], realm "console", jti = the user_sessions row, exp at most
// 12 h, ended after 30 min idle. SessionVerifier checks it with core's
// Verifier (this system's keys, no network), then the shape, then the
// row through a short bounded cache: logout and admin changes end a
// session at once in this process and within the cache TTL in others.
// The old shape (scope = the role) is refused. PublicKeys serves
// /.well-known/jwks.json from one place: the session key here, the
// delivery-signing key when WP-8 adds its ring.
//
// # The BFF contract (M21, M22)
//
// The Next.js BFF calls login and mfa, and sets from the mfa answer the
// uspace_session cookie (the token; HttpOnly, Secure, SameSite=Strict,
// Path=/, expiring with the session) and the uspace_csrf cookie (a
// random value of at least 128 bits, readable by the page). On REST
// calls it forwards the session as Authorization: Bearer; the api
// never reads the session from a cookie on REST. On every
// state-changing request the page sends X-CSRF-Token equal to the
// uspace_csrf cookie, which the BFF checks (CheckCSRF is the reference)
// before it forwards anything. WebSocket upgrades (manned-feed, the api
// streams) take the uspace_session cookie on a request whose Origin is
// on ANSP_WS_ALLOWED_ORIGINS, or a bearer; there is no ticket
// (RequireUpgrade). A 4401 close (CloseReLogin) means "sign in again".
// On logout, a 401 or exp the BFF clears both cookies.
//
// # Live sessions on manned-feed (docs/PLAN.md section 15 row 21)
//
// manned-feed never opens PostgreSQL, so it checks a console session
// against the KV bucket sessions_live, which holds the live sessions
// (key = jti, value {user_id, role, expires_at}; max age 12 h).
// SessionProjector is api's writer: Accounts tells it after each commit
// (a session started at the MFA step; ended by logout, admin disable or
// reset, or idle), a failed put or delete is counted and never retried
// inline, and Run rewrites the whole bucket from user_sessions (not
// revoked, not expired, used within the idle timeout, on the database
// clock) every LiveSessionResync, deleting every other key; a listing
// cut at MaxLiveSessions deletes nothing. KVSessionChecker is the
// feed's SessionChecker: a full read every LiveSessionResync and the
// watch between reads. Absence refuses (a jti with no key, or past its
// expires_at); while the bucket cannot be read for longer than one
// resync (or the bus is down that long) every check is
// ErrLiveSessionsUnavailable, which the guard answers on a cookie
// upgrade with an accepted-then-closed 4401 (Guard.UpgradeReLogin) and
// an open stream answers by closing with 4401. Machine bearers do not
// depend on it. An open console stream reports its session on
// ctl.sessions.seen at most once a minute, and SessionSeen moves its
// last_seen_at: a supervisor watching the picture is not idle.
package auth
