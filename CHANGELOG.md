# Changelog

All notable changes to `uspace-ansp`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning, and the published API `api/openapi.yaml` changes
additively within `/v1`. One line per work package.

## [Unreleased]

Prepared as 1.0.0, the N-M3 release (docs/runbooks/release.md): at the
owner's tag this heading becomes `## [1.0.0] - <date>` and every entry
below is the release's. Not to be tagged before N-M1 and N-M2 are proven
in docs/runbooks/n-m1.md and n-m2.md, the lab's conformance suite has run
green against `make conformance-target`, and `docs/runbooks/` is
complete.

### Fixed

- A WebSocket upgrade with neither a credential nor an `Origin` was
  refused `403 forbidden` as a browser's cookie upgrade; it is now
  `401 unauthenticated` with `WWW-Authenticate: Bearer`, as a request
  without credential is on every other route (uspace-lab conformance
  finding C4: `streamCoordination`, `streamMannedTraffic`,
  `streamRestrictions`). An `Origin` that is present and not on
  `ANSP_WS_ALLOWED_ORIGINS`, or a cookie without an `Origin`, stays
  `403`; the order is stated in the contract's `sessionCookie` scheme
  (description only).
- `POST /v1/auth/login` and `POST /v1/auth/mfa` answered a body their
  schema refuses (a required member missing or empty, a member over its
  `maxLength`, a `code` that is not six digits) `401`; they now answer
  the declared `400 invalid_request` with `errors[]` naming every field,
  before any credential is judged, limited or audited (uspace-lab
  conformance finding C5). A body the schema admits is judged as before.
- `POST /v1/restrictions` answered a bare `500` with no log line to an
  `Idempotency-Key` outside the contract's `^[A-Za-z0-9._:-]{1,128}$`
  (seen in uspace-lab `ussp-wp12-restriction`, whose runner sent
  `${time:0}` unexpanded): the key reached the
  `restrictions.idempotency_key` check and the insert's error became
  internal. The key is now judged before the transaction and refused
  `400 restriction_invalid` naming `Idempotency-Key`, counted as
  `restriction_refused` and `restriction_refused_<slug>`. Every process
  now logs and counts every `500` on every route (`obs.ServerErrors`:
  `http_internal_errors`, the route, the cause the handler noted;
  `http_panics` for a recovered panic, answered `500 internal`).

- WP-12 review: `POST /v1/occurrences` takes an optional `Idempotency-Key`
  (additive; migration `0071`): a repeat with the key and body answers
  `200` with the first receipt, another body `409`. The console sends one
  with every report and keeps it after no answer or any 5xx, so its
  explicit re-send cannot queue a second report; only a 4xx with a
  problem is a refusal.

- The CIS projection held every authority version it pulled from a real
  CISP: since the retro-audit's B-1 it required the bytes at
  `/v1/{dataset}` to equal the signed bytes at `/versions/{n}`, but the
  CISP serves the current version as its own snapshot (top-level `cis_*`
  members, its own `metadata`), so the two never match (found on the
  staging droplet: `uspace_airspace version 1 held, not used`). The
  binding is now of content, as the USSP's: the same features by
  identifier as `ed318.Export` writes them (`cis_*` extended properties
  left out), the request's feature for a restrictions version, the
  `ussp_list` without its `cis_*` members. A served feature the publisher
  did not sign is still held; the tests now serve the CISP's snapshot, not
  a copy of the signed bytes.

### Added

- WP-13 deploy proof: `deploy/compose.prod.yaml` (the production and
  staging shape: one timescaledb-ha container with both databases, the
  one-shot migrate, read-only Go services, limits on every service, the
  replay and real adapter profiles, no published port),
  `deploy/caddy/ansp.caddy` (the reference site for the shared Caddy)
  with `deploy/caddy/proof.sh` (22 checks against the pinned Caddy:
  routes, `/metrics` and `/readyz` unrouted, the certificate subject only
  from a verified certificate on the two mTLS groups),
  `deploy/verify.sh` (cosign signature and SPDX attestation by digest),
  `deploy/backup.sh` (both databases, read back, optional off-host copy),
  `deploy/rollback.md`, `make check-deploy` and the CI job `deploy`,
  `make conformance-target` with `testdata/conformance/`, and the
  runbooks `n-m1.md`, `n-m2.md` and `release.md`. N-M1 and N-M2 are not
  proven yet: the runbooks say which criteria were observed and which
  need a run on staging.

- WP-19: uspace-core v1.4.0. api loads `ANSP_GEOID_FILE` with
  `geoid.LoadMapped`, a read-only memory map on linux and darwin shared
  in the page cache by the processes on one host (read into memory
  elsewhere), and says the result of `Grid.Mapped` on `/readyz` (a new
  non-required check, `geoid: ok (mapped: true)`, present when a grid is
  loaded) and in the start log (`geoid_mapped`). A mapped file must be
  replaced by renaming, never rewritten in place. The ANSP loads no
  terrain.
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
- WP-8 outbox-cisp: `internal/deliver` (the outbox: a `deliveries` row
  written in the transaction of each restriction version, `deliver.v1`
  published after the commit and by a 5 s scan when that publish was
  lost; the DELIVER pull consumer leasing each row on the database
  clock, versions of one restriction in order, at most 8 attempts in
  flight, retries with backoff 1 s to 60 s for 24 h and 1445 attempts,
  a `4xx` failed at once with the excerpt, failed and abandoned jobs
  alarmed until a person acknowledges them; the CISP publication from
  the generated `cis/restriction/v1` types with the pair `(ansp_ref,
  ansp_version)`, core's detached JWS in `X-JWS-Signature` and the
  client certificate; the heartbeat with `active_refs` every
  `cisp_heartbeat_s` and the readiness line `cisp_publisher`;
  `cisp_not_published` after `cisp_alarm_after_s` with the degraded
  direct delivery to the USSPs and the authority as core's compact JWS,
  superseded when the CISP publishes; the reconciliation when the CISP
  returns), relational migration `0050` (`deliveries`,
  `delivery_attempts`, `delivery_alarms`), `ANSP_DELIVERY_KEY_FILE`
  (in `/.well-known/jwks.json`), `ANSP_CISP_CLIENT_CERT_FILE` and
  `ANSP_CISP_CLIENT_KEY_FILE`, `GET /v1/delivery-alarms` and `POST
  /v1/delivery-alarms/{id}/acknowledge`, `published` and `alarm` on
  `restriction/state/v1`, the deliveries summary on every restriction,
  and `api/outbound.md` (PLAN section 15 rows 39, 40).
- WP-10 coordination-inbox: `internal/coord` (the Annex V intake
  `POST /v1/coordination/notices`, M2: the sender judged against the CIS
  USSP list, 403 with an audit row, or accepted as `sender_unverified`
  while no list is projected; the body checked member by member through
  uspace-core's f3548 checks and bounded; the restrictions its volumes
  intersect recorded; 202 with the receipt after the commit, 200 for a
  repeat, 409 for a reused `notice_ref`; the two-state acknowledgement by
  a watch supervisor, read by the sender as a role; the escalation of an
  unacknowledged nonconformance or contingent notice after
  `notice_escalation_s` and every 30 s, kept on the row; coord.v1 and
  `GET /v1/coordination/stream` with `coordination/notice/v1`, owned here
  and settling PLAN row 24; the audited inbox; occurrence reports with
  the reporter reference sealed at rest and sent in clear to the
  authority through the outbox, and `occurrence_undelivered` at 60 h),
  `migrations/relational/0070` (`coordination_notices`,
  `occurrence_reports`), `FuzzAnnexVNotice` and `FuzzOccurrence`.
- WP-9 dss-constraints: `internal/dss` (the F3548 constraint manager:
  the DSS client for `PUT`, `DELETE` and `GET
  /dss/v1/constraint_references/...` with `ovn` handling and typed
  errors, answers bounded and checked, at most 10 000 subscriptions
  each; the subscriber notifier; the paths table held equal to the
  pinned `utm.yaml`; the details of `GET /uss/v1/constraints/{entityid}`
  as the DSS last accepted them, kept for the retention after the end;
  `dsstest`, an in-test DSS with the ovn semantics), the outbox's
  `dss_put` on an activation or extension and `dss_delete` on an end or
  expiry with one re-read of a stale `ovn`, and one `uss_notify` per
  subscriber the DSS names, queued with the write and sent at once
  (`uss_notify_late` past 5 s), the readiness line `dss`, `dss` on
  `restriction/state/v1` and the Restriction, the written reference in
  `constraint_reference` and in each version's `constraint`, relational
  migration `0060` (`dss_constraint_writes`, `dss_notifications`, the
  restriction's DSS standing) (PLAN section 15 row 41).
- WP-11 console-restrictions: `web/`, the supervisor console on
  `@rootxkit/uspace-ui` `0.1.0-rc.1` (pinned release tarball): sign-in
  with mandatory MFA through the three-route BFF (`uspace_session`,
  `uspace_csrf`, the enrolment QR at a first sign-in), the restrictions
  list with the delivery state per channel and the open alarms live on
  `/v1/restrictions/stream`, the map editor (polygon or circle, AMSL or
  WGS84 with AGL shown unavailable, the API's problems on their fields,
  the chain proposal for long windows), plan, activate, extend, end and
  cancel each confirmed with what is sent to whom and a reason, the
  restriction detail (versions, ED-318 feature, F3548 reference, alarms),
  restriction requests by id with accept and decline, and the adapters
  with disabled, silent and running told apart; `ka` and `en`
  catalogues, the lint rules against a geometry import, a hard-coded
  string and server code outside the BFF, vitest, a Playwright smoke run
  against a fixture API, the web image's Dockerfile and the `web` CI job.
- WP-12 console-picture-inbox: the manned picture on
  `/v1/manned-traffic/stream` (every aircraft at its last position with
  its age, live, stale, source disabled by whom or delivered late,
  relevant ones apart; both altitudes as sent with their datum, and a
  vitest guard that fails the build on altitude arithmetic in the
  browser) with the stream's own status bar (adapters, degraded,
  dropped frames, CIS age, policy version and thresholds from the
  frame; "no aircraft reported; adapters: ..." when empty); the
  coordination inbox live on `/v1/coordination/stream` (escalated first
  and loudest on every page, acknowledgement with a note, a 409 said
  and not retried, an opt-in browser notification per escalation);
  source switches (admin; the API's 503 shown as said, no control for
  other roles), the policy row with its history from the audit log, the
  audit view with a JSON export carrying the chain hashes, and the
  occurrence report form (protected reporter reference, 72 h deadline,
  no resend without an answer). Kit stays at `0.1.0-rc.1`: no `0.3.0`
  is released (PLAN section 15 rows 51 and 52).
