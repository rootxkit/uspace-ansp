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
- WP-3 OpenAPI contract: `api/openapi.yaml` (OpenAPI 3.1) with every
  operation of `docs/PLAN.md` section 6, each with `x-process`, `x-spec`
  and `x-auth`, examples for every parameter, request and response, the
  WebSocket frames (envelope plus body) and the one problem body; the
  strict server, models and client generated with oapi-codegen v2.8.0 in
  `api/gen`, with the F3548 types aliased to `uspace-core/f3548`; every
  route mounted through the generated router behind its `x-auth`
  (`auth.ParseAccess`, `auth.Routes`; unserved operations answer 501);
  the WP-2 sign-in, user and key operations moved onto it;
  `internal/apierr` (RFC 9457 with `errors[]`, capped at 100 with
  `truncated`) replacing `auth.WriteProblem`; the JSON Schemas of
  `track/manned/v1`, `restriction/state/v1` and
  `coordination/annex_v/v1` with examples both ways; pinned copies of
  the CISP, authority and USSP OpenAPI files and of the lab's common
  schemas, diffed in CI; the generated CISP client; contract tests (lint,
  examples, request and response validation, every route through the
  generated client, the PLAN table).
- WP-4 manned adapter: `internal/manned` (the `track/manned/v1` model
  with the pressure and WGS84 altitudes kept apart, the unit
  conversions in one file, time placement through
  `timeplace.PlaceBatch` against the feed's own clock, order, dedupe,
  refusals by field, clearing of implausible optional members, the
  bounded aircraft set); the runner (reconnect forever with backoff,
  stall detection with feed-time placement or `backlog`, the source
  switch from KV `source_control` and `ctl.sources`, `source/status/v1`
  every 2 s on `src.v1.manned.<adapter>`); the replay adapter (synthetic
  NDJSON only, never without `ANSP_ADAPTER_REPLAY_ALLOWED=true`), the
  dump1090 SBS and `aircraft.json` readers with field names and columns
  pinned in `internal/manned/dump1090/SOURCE`, and the ASTERIX CAT021
  stub that refuses to start; `cmd/manned-adapter` with `ANSP_ADAPTER_*`;
  three synthetic replay files in `testdata/replay/`.
- WP-5 restrictions: `internal/restriction` (the state machine plan,
  activate at once or scheduled at `starts_at`, extend or a linked
  re-issue past 24 h, end, cancel, expire, each versioned with a
  `restriction_versions` row, a hash-chained event and a `restr.v1`
  message republished from `bus_version` when the bus was down; the
  validation of geometry, limits, window and reason with the F3548
  `Cstr*` bounds, AGL refused with the D3 text; placement inside a
  current USPACE feature of the CIS projection, 503 `cis_stale` without
  one; the ED-318 feature, `DAR` plus 4 base-36, checked with
  `ed318.Export` and `ed318.Parse`, changed by an extend only in its
  period's `endDateTime` as the CISP requires; the F3548 volume in W84
  through the geoid with the conservative envelope); migration `0030`
  (activation schedule, bus version, Idempotency-Key, identifier
  sequence, version state and window, request `client_ref`); the
  restriction and restriction-request operations and the
  `/v1/restrictions/stream` console WebSocket in `cmd/api` with the
  ticker; `ANSP_GEOID_FILE` and `ANSP_AUTHORITY_*`;
  `github.com/coder/websocket` (PLAN section 4).
- WP-6 manned-feed: `internal/sources` (the KV document of WP-4
  confirmed unchanged; the api's writer, row first and a compare-and-set
  put to KV and `ctl.sources` after the commit, 503 when the bucket
  cannot be reached, a republish every 60 s; the follower with three
  reads at start, the push and a re-read every 60 s; the ansp vectors of
  `source_control.json`), `GET /v1/sources` and `PUT
  /v1/sources/{type}/{instance}` in `cmd/api`; `internal/picture` (last
  sample per icao24, out-of-order dropped, backlog never live, stale,
  `source_disabled` within one tick, eviction by age and by
  `max_aircraft`, relevance through uspace-core with no CIS projection
  "not evaluated"); `internal/feed` (the snapshot and the WebSocket
  stream in the console frames with `age_s`, 2 Hz throttle, bounded
  queues, connection caps, `degraded[]`, `feed_products`, and the
  `MAN_MIRROR` recorder that acknowledges after the commit);
  `cmd/manned-feed` wired with readiness for every dependency;
  timeseries migration `0010` (`manned_tracks.msg_id`, a sample lands
  once); the live-session projection `sessions_live` with
  `ctl.sessions.seen` (PLAN section 15 row 21); uspace-core `v1.3.0`.
- WP-7 cis-projection: `internal/cis` (the CISP client on the pinned
  `cisp.yaml` with `getDatasetVersion`, `listSubscriptions` and
  `patchSubscription` generated; unfiltered pulls with `If-None-Match`,
  a 20 MB body bound, `ed318.Parse` and the strict `cis/ussp_list/v1`
  decode refusing a dataset whole; the publisher's detached signature
  verified before a version is used, untrusted versions held; the
  `cis_cache` row committed before the KV `cis_current` put and the
  `cis.v1` push; a reconciliation every `cis_reconcile_s`; the
  idempotent subscription, registered again when the CISP forgets it;
  the `POST /v1/cis/notifications` receiver on core's compact JWS with
  the delivery ids in the database; the hot-path `Follower`; the
  readiness line `cisp: ok | stale | down since T`), relational
  migration `0040` (`cis_cache`, `cis_notifications_seen`),
  `ANSP_CIS_PUBLISHER_KEYS` and `ANSP_CIS_PUBLISHER_SIG_MAX_AGE_S`,
  restriction placement and manned-feed relevance wired to the
  projection, the fixtures under `testdata/fixtures/`, and the layout
  tests for a direct `jwx` import and the hot-path import rule (PLAN
  section 15 rows 30, 34, 38).
