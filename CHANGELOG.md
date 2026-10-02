# Changelog

All notable changes to `uspace-ansp`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning, and the published API `api/openapi.yaml` changes
additively within `/v1`. One line per work package.

## [Unreleased]

### Added

- WP-0 scaffold: the Go module pinned to `uspace-core` v1.1.0; the
  `api`, `manned-adapter` and `manned-feed` stubs serving `/healthz`,
  `/readyz` (every dependency named with its state and why) and
  `/metrics`, draining on SIGTERM, with a `migrate` subcommand for WP-1;
  the `ANSP_*` configuration (unknown and malformed variables refused by
  name, secrets from files, redacted start-up line) and the one token
  verifier configuration with `StrictSessionClaims`; slog JSON logging,
  Prometheus with `core.Counters` export, OpenTelemetry; the NATS
  connection that reconnects forever and starts degraded, with the
  streams and buckets of `docs/PLAN.md` section 7; the layout test; the
  Makefile, the lean CI workflow, the Dockerfile and the development
  compose.
- WP-1 store and migrations: the two goose trees (relational: PostGIS,
  the hash-chained append-only `events`, `ansp_policy`, `source_controls`
  with version and epoch, `restrictions`, `restriction_versions`,
  `restriction_requests`, `adapters`; timeseries: the `manned_tracks`
  hypertable with compression after 7 days and retention of 90 days,
  `feed_products`), each with its own version table and an application
  role without UPDATE or DELETE on the insert-only tables; the `migrate`
  subcommand and the start-up schema check (M36); bounded pgx pools
  (`ANSP_DB_*`), sqlc queries, the COPY writer of manned tracks;
  `internal/audit` (record, verify a month, query) and `internal/policy`
  (load, update through KV, follower with the compiled defaults);
  `uspace-core` v1.2.0.
- WP-2 auth and accounts: ecosystem tokens verified by one
  `uspace-core/auth` verifier (`ANSP_TOKEN_ISSUERS`, `aud` in
  `ANSP_AUDIENCES`, readiness `jwks: degraded` with the cache's age), a
  guard with an access entry per route that fails closed, RFC 9457
  refusals typed by core's counters, the mTLS subject bound to `sub` from
  `ANSP_MTLS_BINDINGS_FILE`, `oauth_clients_seen` off the request path;
  client-credentials tokens as `ansp-01` with `audience` = the target's
  host, refreshed at half their lifetime; console accounts (argon2id,
  roles `watch_supervisor`, `viewer`, `admin`) with mandatory TOTP sealed
  under `ANSP_SECRETS_KEY_FILE`, two-step sign-in, per-username lockout in
  the database and per-address limits, session tokens through
  `Issuer.IssueSession` checked against `user_sessions` (logout, 30 min
  idle, 12 h), the WebSocket cookie rule with an `Origin` allow-list, the
  JWKS endpoint, admin user operations and a bootstrap admin; migration
  0020.
