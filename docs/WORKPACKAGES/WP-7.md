# WP-7: `cis-projection`

Branch `feat/WP-7-cis-projection`. Milestone N-M1. Owns `internal/cis`,
`migrations/relational/0040–0049` (`cis_cache`), the `POST
/v1/cis/notifications` handler (M1), `testdata/fixtures/` (a U-space
airspace designation, a USSP
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
   auth` (JWKS fetch pattern; the notification body is a compact JWS
   verified with core `v1.1.0`'s `auth.VerifyCompact` and a `KeyRing`
   built from the issuer's JWKS, RS256 only, `iss`, `aud`, `jti` in the
   payload; no direct `jwx` import, M27), LESSONS B-08, E-02, E-10,
   Z-12, G-08 (a projection is never an authority).
4. The CISP's `api/openapi.yaml` as pinned under `api/clients/cisp.yaml`
   with its `SOURCE` commit (WP-3, M11): the paths, `cis/change/v1`,
   `cis/ussp_list/v1` and the `cis_dataset` / `cis_version` /
   `cis_updated_at` members and `ETag` come from there, never from
   memory.

## What to build

- `Client`: `GET {cisp}/v1/uspace_airspace`, `/v1/ussp_list`,
  `/v1/restrictions` with `If-None-Match` from the stored `etag`
  (`304` → touch `fetched_at` only), scope `cis.read` through WP-2's
  token source; body size cap 20 MB; every dataset parsed with
  `ed318.Parse` (collection metadata in core's names, `issued` and
  `provider`, M15; the USSP list is `cis/ussp_list/v1` per the CISP's
  pinned schema: `ussp_id` is the authority's short certificate code,
  M8, with name, contact, base URL, services, limitations, validity,
  `terms_url`; parsed strictly into the generated type) and refused
  whole on a problem, keeping the previous version and counting
  `cis_refused` (T9). `GET` may carry `?applies_at=` for annotation
  (M17); the projection stores what the CISP returns unfiltered.
- `Projection` rows in `cis_cache` (one per dataset) and KV
  `cis_current` (version, `fetched_at`, and the parsed U-space volumes
  as `zones.Zone` inputs) with a `cis.v1.<dataset>` push; `Follower` for
  the hot path (WP-6) that keeps the last state, exposes `Version()`,
  `Age(now)`, `USpaceVolumes()`, `USSPs()`, and starts empty with the
  status `no CIS projection` (SC-22).
- Reconciliation ticker every `cis_reconcile_s` (60 s) regardless of
  notifications; `Subscribe` registers `POST /v1/subscriptions
  {callback_url: <ANSP_PUBLIC_BASE_URL>/v1/cis/notifications, datasets:
  [uspace_airspace, ussp_list, restrictions]}` at start and re-registers
  when the CISP says the subscription is unknown.
- Notification handler (`POST /v1/cis/notifications`, M1, M19): the body
  is a compact JWS, `Content-Type: application/jose`; verify it with the
  JWKS of the issuer named by `iss` when that issuer is on
  `ANSP_CIS_NOTIFY_ISSUERS` (the CISP; URL from configuration, cached as
  core does), check `aud` = the host of this system's registered
  `callback_url` (an entry of `ANSP_AUDIENCES`), `sub` = the
  subscription id this system registered, `iat` within 5 min, `jti`
  not seen before (replay store bounded, E-10). Then: reasons
  `subscription_test`, `republished` and any reason this build does not
  know → `204`, no pull, counted `cis_notify_noop` (M16, additive-enum
  rule); otherwise trigger a pull of the named dataset and answer
  `202`. `pull_url` is honoured only when its host equals the issuer's
  configured base host (`ANSP_CISP_URL`), else the configured dataset
  URL is pulled and the mismatch counted (SSRF guard, M5). Never trust
  the notification's content as data: the pull is the data (`02 F3`).
- Readiness contribution: `cisp: ok (age 12 s) | stale (age 400 s) |
  down since T`; the `cis_stale_bound_s` policy marks `stale` for
  consumers (WP-5 refuses containment-dependent writes on `stale`).

## Tests

- Integration with an in-test CISP stub (httptest): first pull stores
  three datasets; a second pull with `304` only touches `fetched_at`; a
  changed `ETag` replaces the version and pushes `cis.v1`; a malformed
  dataset is refused and the old one kept (counter asserted, the twin:
  the next good one is taken); the notification with a valid JWS
  triggers a pull within 100 ms (`202`), an invalid signature `401`, an
  issuer not on the list `401`, a replayed `jti` `409`, a wrong `aud`
  (`ansp`, or another system's host) `403`, the lab alias accepted;
  `subscription_test` and an unknown reason → `204` and no request at
  the stub (and the twin: `updated` → one pull); a `pull_url` on a
  foreign host → the configured URL pulled, the counter moves.
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
  reaches the follower both ways (notification and reconciliation) with
  the notification path measured.
- [ ] `go.mod` pins `uspace-core v1.1.0` (the JWS helpers) in a
  `build:` commit of its own; no direct `jwx` import (a layout test
  greps for it).
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(cis): pull the CIS datasets with ETags and parse them strictly [WP-7 N-M1]`,
`feat(cis): project the current CIS into KV with age for the hot path [WP-7 N-M1]`,
`build(core): bump uspace-core to v1.1.0 for the JWS helpers [WP-7 N-M1]`,
`feat(cis): subscribe to the CISP and verify its signed change notifications [WP-7 N-M1]`,
`test(cis): keep serving with age when the CISP is down [WP-7 N-M1]`.
