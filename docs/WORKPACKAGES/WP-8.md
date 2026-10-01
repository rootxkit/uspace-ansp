# WP-8: `outbox-cisp`

Branch `feat/WP-8-outbox-cisp`. Milestone N-M1. Owns `internal/deliver`,
`migrations/relational/0050–0059` (`deliveries`), the CISP publisher, the
heartbeat, the degraded direct delivery, the delivery-signing key in
`/.well-known/jwks.json`, `api/outbound.md`. Depends on WP-5 (the
`restr.v1` messages and the feature builder), WP-7 (USSP list, CISP
state) and on `uspace-core v1.1.0` for the JWS helpers
(`auth.SignDetached`, `auth.SignCompact`, `auth.KeyRing`; core WP-14,
M27: it is in the cross-repo wave 0, this WP in wave 3, so it is
released before this WP starts; if it is not, this WP stops and asks
rather than importing `jwx` directly). Consumer: WP-9 (DSS jobs ride
the same outbox), WP-10
(occurrence jobs), the console (delivery outcomes on the restriction
stream).

Safety note: this is where "timely and effective" (ATS.TR.237(b)) is
decided. A restriction that is active here and unknown to the USSPs is
the worst state this system can be in; the outbox must make that state
visible within 10 s and keep trying until it is resolved or a person
abandons it with a reason.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` D5, D6, `§5.1` (`deliveries`), `§6`
   (outbound table), `§7` (`deliver.v1`), `§9`, `§15` gaps 9, 10.
2. Spec `02 F2` (API, idempotency, failure rules: retry, alarm after
   10 s, degraded direct delivery on the F3 contract, reconciliation,
   heartbeat), `02 F3` (`cis/change/v1`, JWS), `01` C5 (the CISP's 1 s
   figure), `06` T4, T5; `04 §3.4`; the CISP's OpenAPI copy
   `api/clients/cisp.yaml` (WP-3, M11) for `cis/restriction/v1`, the
   `PATCH` body, `POST /v1/publishers/heartbeat` and the detached-JWS
   rule of its Q8; the authority's and USSP's copies for the
   `/v1/cis/notifications` receiver they implement.
3. nats.go JetStream: work-queue retention, pull consumers, `AckWait`,
   `MaxDeliver`, `Nak` with delay (backoff).
4. LESSONS B-05 (persist before you acknowledge), B-07, B-08, E-02,
   E-09, C-12 (alarm text: "not yet published to the CISP since T", never
   "lost"); utm `CLAUDE.md` "no retry loops around side effects without
   idempotency keys".

## What to build

### The outbox (`internal/deliver`)

- `Enqueue(ctx, tx, Job)` writes the `deliveries` row (`queued`) in the
  caller's transaction and publishes `deliver.v1.<kind>` after commit
  (an outbox table scan every 5 s re-publishes rows still `queued` whose
  publish was lost: B-05).
- `Worker` (in `cmd/api`, N goroutines): pull consumer on `DELIVER`,
  explicit ack after the `deliveries` row is updated; retry with
  exponential backoff (1 s → 60 s cap) for `5xx`, timeouts and network
  errors; no retry for `4xx` other than `409`/`429` (a `4xx` is
  `failed` with the response excerpt and an alarm); `max_deliver` by
  policy (24 h window), then `abandoned` with an alarm that stays on the
  console until a person acknowledges it with a reason (audited).
- Idempotency: the key is the body pair `(ansp_ref, ansp_version)` for
  restriction jobs, which the CISP reads from the body itself (M4); an
  `Idempotency-Key` header with the same pair may be sent but nothing
  on either side depends on it; a replayed job that finds its row
  `sent` does nothing (test).
- `Alarms`: a restriction `active` for more than `cisp_alarm_after_s`
  (10 s) without a `cisp_publish` `sent` for its current version raises
  `cisp_not_published` on `restr.v1` (so the console and the supervisor
  see it) and starts the degraded path; cleared when the publication
  succeeds, with the duration in the clear.

### CISP publisher

- `POST {cisp}/v1/restrictions` on first activation with the CISP's
  `cis/restriction/v1` body exactly as its pinned OpenAPI copy defines
  it: `{ansp_ref, ansp_version, uspace_airspace_id, state, starts_at,
  ends_at, feature}` (the field is **`ansp_version`**, never `version`,
  M4; types generated from `api/clients/cisp.yaml`), `PATCH
  {cisp}/v1/restrictions/{id}` `{op, ansp_version, ends_at?}` for
  extend, end and cancel; scope `cis.publish:restrictions`, `aud` = the
  CISP's host (WP-2's token source); mTLS client certificate from
  `ANSP_CISP_CLIENT_CERT_FILE`/`_KEY_FILE` (presented whenever
  configured; the CISP requires it when its own mode is `required`). A
  `201`/`200` records `published_version` on the restriction and emits
  `restr.v1` with `published: true`.
- Detached JWS over the body in the **`X-JWS-Signature`** header
  (M26, the CISP's Q8): `<protected>..<signature>`, RFC 7515 App. F,
  RFC 7797 `b64: false`, `crit: ["b64"]`, `alg RS256`, `kid`, `iat`
  (the CISP refuses older than 5 min), produced by core's
  `auth.SignDetached` with the key from `ANSP_DELIVERY_KEY_FILE`
  (M27), so the CISP can prove provenance (Annex III A(4)); the key's
  public part served from `/.well-known/jwks.json` (WP-2's set, `use:
  sig`, distinguished by `kid`).
- Heartbeat job every `cisp_heartbeat_s` (**15 s**, M3) to `POST
  {cisp}/v1/publishers/heartbeat` with the body `{sent_at: <RFC 3339>,
  active_refs: [<ansp_ref> of every active restriction]}`, same scope,
  same mTLS; the CISP answers `204` and flags this publisher `source
  stale` after 60 s (three misses). No configurable path (there is no
  `ANSP_CISP_HEARTBEAT_PATH`). A failed heartbeat counts and shows as
  `cisp: unreachable since T` in readiness, never as data loss (C-12).
- Reconciliation when the CISP returns (readiness `down → ok`): every
  `active` restriction whose `published_version < version` is re-queued.

### Degraded direct delivery

When the alarm fires: for every USSP on the CIS USSP list projection and
for the authority, `POST {base_url}/v1/cis/notifications` (M1, M5: the
one receiver path, the same one the CISP posts to; no per-target path
configuration) with a `cis/change/v1` payload (the CISP's schema from
`api/clients/cisp.yaml`: `dataset: restrictions`, `version`,
`feature_ids: [identifier]`, `reason: restriction_activated | ended |
...`, `at`, `pull_url: <ANSP_PUBLIC_BASE_URL>/v1/restrictions/{id}`)
carried as a compact JWS, `Content-Type: application/jose`, signed by
core's `auth.SignCompact` with the ANSP's delivery key: `iss` = this
system's issuer URL, `aud` = **the host of the target's base URL**
(M19), `sub` = the restriction id, `jti` = the delivery id, `iat`. The
receivers allow-list the ANSP issuer beside the CISP's and pull
`pull_url` only because its host is the ANSP's configured base host
(M5), so `pull_url` must be on `ANSP_PUBLIC_BASE_URL` exactly. One job
per target, same retry policy, logged per target. The direct path stops
when the CISP publication succeeds (jobs still queued are cancelled and
logged `superseded_by_cisp`).

### `api/outbound.md`

The list of calls this system makes, each with owner, auth, idempotency
key and failure rule, kept in step with `docs/PLAN.md §6`.

## Tests

- Integration (NATS, PostgreSQL, httptest stubs for the CISP, two USSPs
  and the authority recording every request):
  - activate → the CISP receives one `POST` whose body carries the
    pair `(ansp_ref, ansp_version)` and whose `X-JWS-Signature` the
    stub verifies against the served JWKS with core's
    `auth.VerifyDetached` (`b64: false`, `crit`, `kid`, `iat` fresh),
    the row is `sent 201`, `published_version` set, within 200 ms of
    the commit (measured, printed); extend → one `PATCH` with the
    bumped `ansp_version`; end → one `PATCH`. A body with the field
    named `version` fails the generated-type test.
  - the CISP returns `503` twice then `201` → three attempts logged, one
    publication, backoff respected (fake clock).
  - the CISP down for 15 s → the alarm fires at 10 s (`restr.v1`
    carries `cisp_not_published`), both USSPs and the authority receive
    the signed direct delivery at `/v1/cis/notifications` as
    `application/jose`, and each stub verifies the compact JWS with the
    served JWKS and asserts `aud` = its own host and `sub` = the
    restriction id; the CISP returns → reconciliation publishes, the
    alarm clears with its duration, the direct jobs still queued are
    `superseded_by_cisp`.
  - the twin of every "nothing sent" assertion (a cancelled `planned`
    restriction sends nothing to the DSS but does send the CISP cancel).
  - replayed job after `sent` → no second request (count the stub's
    requests).
  - a `400` from the CISP → `failed`, no retry, alarm on.
  - the outbox scan re-publishes a `queued` row whose NATS publish was
    dropped (simulate by writing the row directly).
- E-02: heartbeat success path asserted (the stub receives
  `POST /v1/publishers/heartbeat` with `sent_at` and the active
  `active_refs` every 15 s ± 1 s over one minute, `204` logged,
  readiness `ok`); heartbeat failure → `unreachable since T`, no
  data-loss wording (grep the status text for "lost": must be absent).
- E-10: the worker's in-flight bound; a 1 MiB + 1 response body
  truncated in the excerpt.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; the measured
  commit-to-wire latency in the PR.
- [ ] Coverage ≥ 90 % on `internal/deliver`.
- [ ] `api/outbound.md` written; `docs/PLAN.md §6` outbound table
  unchanged or updated in the same PR.
- [ ] `go.mod` pins `uspace-core v1.1.0` (if WP-7 has not already);
  no direct `jwx` import; every signature produced by core's helpers.
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(deliver): add the JetStream outbox with idempotent, logged deliveries [WP-8 N-M1]`,
`feat(deliver): publish restrictions to the CISP with signatures and heartbeats [WP-8 N-M1]`,
`feat(deliver): alarm after 10 s and deliver directly to USSPs and the authority [WP-8 N-M1]`,
`feat(deliver): reconcile with the CISP when it returns [WP-8 N-M1]`,
`test(deliver): prove retries, the degraded path and reconciliation end to end [WP-8 N-M1]`.
