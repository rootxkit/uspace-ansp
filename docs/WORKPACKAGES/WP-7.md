# WP-7: `cis-projection`

Branch `feat/WP-7-cis-projection`. Milestone N-M1. Owns `internal/cis`,
`migrations/relational/0040–0049` (`cis_cache`), the `POST /v1/cis/webhook`
handler, `testdata/fixtures/` (a U-space airspace designation, a USSP
list and a restrictions dataset as the CISP publishes them, ED-318).
Depends on WP-1, WP-2 (JWS keys, token source), WP-3. Consumers: WP-5
(containment), WP-6 (relevance), WP-8 (USSP list for degraded delivery),
WP-10 (sender validation).

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §5.1` (`cis_cache`), `§7` (`cis.v1`, KV
   `cis_current`), `§15` gap 10.
2. Spec `02 F3` (pull with `ETag`, `since_version`, subscriptions, signed
   webhook, 60 s reconciliation, failure: cache with `cis_version` and
   `cis_age_s`), `03 §2` (what the CISP holds), `03 §4` projected rows,
   `04 §3.4` (`cis/change/v1`, `zone/applicable/v1`), `05 §6` CISP row,
   `06` T4, T9.
3. `uspace-core/ed318` (`Parse` with `Limits`, `ToZones`), `uspace-core/
   auth` (JWKS fetch pattern; the webhook body is a JWS: use
   `lestrrat-go/jwx/v3/jws` with the CISP's JWKS, RS256 only, `iss` and
   `aud` in the payload), LESSONS B-08, E-02, E-10, Z-12, G-08 (a
   projection is never an authority).
4. The CISP planner's `api/openapi.yaml` when it exists (ask; until
   then, the paths of `02 F3` exactly as written).

## What to build

- `Client`: `GET {cisp}/v1/uspace_airspace`, `/v1/ussp_list`,
  `/v1/restrictions` with `If-None-Match` from the stored `etag`
  (`304` → touch `fetched_at` only), scope `cis.read` through WP-2's
  token source; body size cap 20 MB; every dataset parsed with
  `ed318.Parse` (the USSP list is JSON per the CISP's schema; parse
  strictly into a struct with the fields of `02 F1`: name, contact,
  certificate id, base URL, services, limitations, validity, `terms_url`)
  and refused whole on a problem, keeping the previous version and
  counting `cis_refused` (T9).
- `Projection` rows in `cis_cache` (one per dataset) and KV
  `cis_current` (version, `fetched_at`, and the parsed U-space volumes
  as `zones.Zone` inputs) with a `cis.v1.<dataset>` push; `Follower` for
  the hot path (WP-6) that keeps the last state, exposes `Version()`,
  `Age(now)`, `USpaceVolumes()`, `USSPs()`, and starts empty with the
  status `no CIS projection` (SC-22).
- Reconciliation ticker every `cis_reconcile_s` (60 s) regardless of
  webhooks; `Subscribe` registers `POST /v1/subscriptions {callback_url:
  <public base>/v1/cis/webhook, datasets: [uspace_airspace, ussp_list,
  restrictions]}` at start and re-registers when the CISP says the
  subscription is unknown.
- Webhook handler: verify the JWS with the CISP's JWKS (URL from
  configuration; cached as core does), check `iss` (the CISP's id) and
  `aud` (this system), refuse a notification older than 5 min or seen
  before (`msg_id`), then trigger a pull of the named dataset; `202`.
  Never trust the notification's content as data: the pull is the data
  (`02 F3`).
- Readiness contribution: `cisp: ok (age 12 s) | stale (age 400 s) |
  down since T`; the `cis_stale_bound_s` policy marks `stale` for
  consumers (WP-5 refuses containment-dependent writes on `stale`).

## Tests

- Integration with an in-test CISP stub (httptest): first pull stores
  three datasets; a second pull with `304` only touches `fetched_at`; a
  changed `ETag` replaces the version and pushes `cis.v1`; a malformed
  dataset is refused and the old one kept (counter asserted, the twin:
  the next good one is taken); the webhook with a valid JWS triggers a
  pull within 100 ms, an invalid signature `401`, a replayed `msg_id`
  `409`, a wrong `aud` `403`.
- E-02: kill the stub → the follower keeps serving with age; readiness
  says `down since T`; bring it back → recovered on the next tick and
  `cisp: ok`.
- Follower with empty KV says `no CIS projection` and
  `USpaceVolumes()` is empty, not nil-panicking.
- E-10: a 21 MB body refused; 10 001 features refused by `ed318.Limits`.
- Fixtures: `testdata/fixtures/uspace_airspace.json` (one `USPACE`
  feature over a synthetic area with Art. 3(4) `extendedProperties`),
  `ussp_list.json` (two USSPs with base URLs on `localhost`), parsed by
  the tests and by WP-5/WP-6/WP-8/WP-10.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; coverage ≥
  85 % on `internal/cis`.
- [ ] The subscription registration and the reconciliation are both
  observed in the stub's log in one test (presence), and a change
  reaches the follower both ways (webhook and reconciliation) with the
  webhook path measured.
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(cis): pull the CIS datasets with ETags and parse them strictly [WP-7 N-M1]`,
`feat(cis): project the current CIS into KV with age for the hot path [WP-7 N-M1]`,
`feat(cis): subscribe to the CISP and verify its signed change notifications [WP-7 N-M1]`,
`test(cis): keep serving with age when the CISP is down [WP-7 N-M1]`.
