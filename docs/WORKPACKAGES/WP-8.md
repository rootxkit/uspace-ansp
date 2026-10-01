# WP-8: `outbox-cisp`

Branch `feat/WP-8-outbox-cisp`. Milestone N-M1. Owns `internal/deliver`,
`migrations/relational/0050–0059` (`deliveries`), the CISP publisher, the
heartbeat, the degraded direct delivery, the delivery-signing key in
`/.well-known/jwks.json`, `api/outbound.md`. Depends on WP-5 (the
`restr.v1` messages and the feature builder), WP-7 (USSP list, CISP
state). Consumer: WP-9 (DSS jobs ride the same outbox), WP-10
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
   figure), `06` T4, T5; `04 §3.4`.
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
- Idempotency: the key is `<ansp_ref>:<version>` for restriction jobs;
  every HTTP call carries `Idempotency-Key`; a replayed job that finds
  its row `sent` does nothing (test).
- `Alarms`: a restriction `active` for more than `cisp_alarm_after_s`
  (10 s) without a `cisp_publish` `sent` for its current version raises
  `cisp_not_published` on `restr.v1` (so the console and the supervisor
  see it) and starts the degraded path; cleared when the publication
  succeeds, with the duration in the clear.

### CISP publisher

- `POST {cisp}/v1/restrictions` on first activation (body: the ED-318
  feature from WP-5, `ansp_ref`, the U-space airspace id, state,
  `starts_at`, `ends_at`, `version`; the exact body follows the CISP
  planner's OpenAPI once published; until then the fields of `02 F2` and
  `03 §2 restrictions`), `PATCH {cisp}/v1/restrictions/{id}` for extend,
  end and cancel; scope `cis.publish:restrictions`; mTLS client
  certificate from `ANSP_CISP_CLIENT_CERT_FILE`/`_KEY_FILE` when
  configured. A `201`/`200` records `published_version` on the
  restriction and emits `restr.v1` with `published: true`.
- Detached JWS over the feature (`ANSP_DELIVERY_KEY_FILE`, RS256, `kid`)
  in a `Signature` header, so the CISP can prove provenance (Annex III
  A(4)); the key's public part served from `/.well-known/jwks.json`
  (WP-2's set).
- Heartbeat job every `cisp_heartbeat_s` (30 s) to the configurable path
  `ANSP_CISP_HEARTBEAT_PATH` (default `/v1/restrictions/heartbeat`, gap
  9) with the active `ansp_ref`s; a failed heartbeat counts and shows as
  `cisp: unreachable since T` in readiness, never as data loss (C-12).
- Reconciliation when the CISP returns (readiness `down → ok`): every
  `active` restriction whose `published_version < version` is re-queued.

### Degraded direct delivery

When the alarm fires: for every USSP on the CIS USSP list projection and
for the authority, `POST {base_url}/v1/cis/changes` (gap 10; path
configurable per target until the planners confirm) with a `cis/change/
v1` body (`dataset: restrictions`, `version: <ansp version>`,
`feature_ids: [identifier]`, `reason: restriction_activated | ended |
...`, `at`, `pull_url: <public base>/v1/restrictions/{id}`), JWS-signed
by the ANSP's delivery key, `iss` this system, `aud` the target; one job
per target, same retry policy, logged per target. The direct path stops
when the CISP publication succeeds (jobs still queued are cancelled and
logged `superseded_by_cisp`).

### `api/outbound.md`

The list of calls this system makes, each with owner, auth, idempotency
key and failure rule, kept in step with `docs/PLAN.md §6`.

## Tests

- Integration (NATS, PostgreSQL, httptest stubs for the CISP, two USSPs
  and the authority recording every request):
  - activate → the CISP receives one `POST` with `Idempotency-Key`,
    the row is `sent 201`, `published_version` set, within 200 ms of the
    commit (measured, printed); extend → one `PATCH`; end → one `PATCH`.
  - the CISP returns `503` twice then `201` → three attempts logged, one
    publication, backoff respected (fake clock).
  - the CISP down for 15 s → the alarm fires at 10 s (`restr.v1`
    carries `cisp_not_published`), both USSPs and the authority receive
    the signed direct delivery and the stub verifies the JWS with the
    served JWKS; the CISP returns → reconciliation publishes, the alarm
    clears with its duration, the direct jobs still queued are
    `superseded_by_cisp`.
  - the twin of every "nothing sent" assertion (a cancelled `planned`
    restriction sends nothing to the DSS but does send the CISP cancel).
  - replayed job after `sent` → no second request (count the stub's
    requests).
  - a `400` from the CISP → `failed`, no retry, alarm on.
  - the outbox scan re-publishes a `queued` row whose NATS publish was
    dropped (simulate by writing the row directly).
- E-02: heartbeat success path asserted (`204` logged, readiness `ok`);
  heartbeat failure → `unreachable since T`, no data-loss wording (grep
  the status text for "lost": must be absent).
- E-10: the worker's in-flight bound; a 1 MiB + 1 response body
  truncated in the excerpt.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; the measured
  commit-to-wire latency in the PR.
- [ ] Coverage ≥ 90 % on `internal/deliver`.
- [ ] `api/outbound.md` written; `docs/PLAN.md §6` outbound table
  unchanged or updated in the same PR.
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(deliver): add the JetStream outbox with idempotent, logged deliveries [WP-8 N-M1]`,
`feat(deliver): publish restrictions to the CISP with signatures and heartbeats [WP-8 N-M1]`,
`feat(deliver): alarm after 10 s and deliver directly to USSPs and the authority [WP-8 N-M1]`,
`feat(deliver): reconcile with the CISP when it returns [WP-8 N-M1]`,
`test(deliver): prove retries, the degraded path and reconciliation end to end [WP-8 N-M1]`.
