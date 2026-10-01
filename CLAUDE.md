# uspace-ansp: rules for every contributor and agent

`uspace-ansp` is the U-space interface of the air navigation service
provider (Sakaeronavigatsia; branding is configuration) in the Georgian
U-space system-of-systems: dynamic airspace reconfiguration towards the
CISP and the USSPs, the manned traffic feed into U-space, and the Annex V
coordination inbox. It is an interface, not an ATM system. Read
`docs/PLAN.md` before changing anything; every change belongs to a work
package brief in `docs/WORKPACKAGES/`.

## Hard rules

1. **Nothing here commands an aircraft.** No type, function, dependency
   or socket has a send path towards a vehicle, manned or unmanned
   (spec `00 §1`, LESSONS INV-01). Surveillance feeds are opened
   read-only. A task that seems to need a send path is out of scope:
   stop and ask.
2. **This is not an ATM system.** No flight-plan processing, no
   clearances, no separation, no radar processing beyond normalising a
   position feed, no alerts to operators or remote pilots (those are the
   USSP's). The ANSP issues time-bounded restrictions under the
   authority's framework; it never authors or edits geo-zones.
3. **Judgement lives once, in `uspace-core`.** ED-318 validation and
   export, F3548 types and bounds, JWT verification, source switches,
   time placement, geodesy, geoid, zone containment are calls into the
   pinned `github.com/rootxkit/uspace-core`. Never re-implement one, in
   Go or in TypeScript; `web/` imports no geometry or geodesy library
   (lint fails it). A vector of `uspace-core/vectors` that names `ansp`
   is run here with `RunOwned(t, "ansp", ...)` against this repo's
   adapters.
4. **Nothing hides an aircraft or a restriction.** A stale, disabled or
   silent source is shown as such with who, when and why; an empty
   stream says why it is empty; a restriction active here and not yet
   published is an alarm within 10 s, visible until resolved. Never
   "lost" for something that is buffered or unreachable (C-12).
5. **Thresholds, margins and limits are data.** The `ansp_policy` row
   with a `policy_version`, projected to the hot path; never a literal
   in a judgement, never relaxed to make a test pass (INV-03). F3548
   limits come from `uspace-core/f3548` constants.
6. **Two migration trees, never merged** (`migrations/relational`,
   `migrations/timeseries`; separate version tables). `api` is the only
   writer to the relational database; `manned-feed` the only writer to
   the hypertable; `manned-adapter` and `manned-feed` never open
   PostgreSQL (they read NATS KV projections).
7. **An endpoint that is not in `api/openapi.yaml` does not exist.**
   Server, client and TypeScript types are generated from it and
   committed; CI fails on a stale generation. Additive changes only
   within `/v1`.
8. **Never write a wire format, field name or path from memory.**
   dump1090 fields come from its pinned documentation
   (`internal/manned/dump1090/SOURCE`), F3548 and ED-318 members from
   `uspace-core`'s generated types and models, DSS paths from the
   `utm.yaml` commit in `uspace-core/f3548/SOURCE`, sibling APIs from
   their published OpenAPI files. Pin each with a test (E-03).
9. **Units and datums in every name** (E-13): `alt_pressure_m`,
   `alt_wgs84_m`, `gs_ms`, `vrate_ms`, `feed_margin_lateral_m`,
   `stale_after_s`; Go `AltPressureM`, `GSMS`, `MarginLateralM`.
   Pressure altitude is never written to an AMSL column; AMSL and AGL
   never meet in one calculation (D-01). A restriction's vertical
   reference is `AMSL` or `WGS84`; `AGL` is refused with a reason.
10. **No panics on untrusted input; everything refused, dropped,
    degraded or stalled is counted** with a stable snake_case name
    exported as a metric and shown in the process status (E-09, E-10).
11. **No secret, key, certificate, hostname or real traffic data in the
    repository.** Test keys are generated at test time; replay data is
    synthetic and says so; `gitleaks` runs in CI; domains live in the
    private infra repo (`06 §4`).
12. **English only** in code, comments, commits, logs and docs.
    User-facing strings go through i18n (`ka`, `en`) from day one.

## Testing rules (LESSONS E-01 to E-04, E-10, E-11, INV-02)

- **E-01 Test presence, not only absence.** Every test that asserts
  something does not happen (no publish, no alert clear, no delivery,
  no refusal) is paired with the test that makes it happen.
- **E-02 Run the branch that says nothing is wrong.** Make the delivery
  succeed and read the log row; make the status line healthy and read
  it; then take the dependency away (CISP, DSS, NATS, KV, the CIS
  projection, the geoid) and assert the exact degraded output and
  counter.
- **E-03** wire formats and field names from pinned references only.
- **E-04 Never report an inference as an observation.** A PR body
  lists the commands run and their last lines; a skipped job is
  reported as skipped; a timing is one that was read from a log.
- **E-10** every bound (picture size, nonce memory, send queue, body
  size, subscriber count) has a test past it.
- **E-11** tests restore global state and pass under `-shuffle=on` and
  `-race`.
- **INV-02** the restriction path (WP-5, 8, 9) and the manned path
  (WP-4, 6) are not done until a SITL aircraft and a replayed manned
  track have driven them end to end (N-M1 runbook); a unit test alone
  does not close them. SC-08 and SC-15 of `uspace-lab/knowledge/
  scenarios.md` apply to this system.
- Integration tests run against real PostgreSQL + PostGIS, TimescaleDB
  and NATS (`make integration`; CI `services:`). Stubs of the CISP, DSS,
  USSPs and the authority record every request so presence is asserted.
- Coverage: ≥ 85 % per package; ≥ 90 % in `restriction`, `manned`,
  `picture`, `deliver`, `dss`, `coord`, `auth`.

## Conventions

- Layout: `cmd/<process>/` (`api`, `manned-adapter`, `manned-feed`),
  `internal/<package>/`, `api/` (OpenAPI first), `schemas/`,
  `migrations/{relational,timeseries}/`, `web/`, `deploy/`, `docs/`.
- Go 1.27, `net/http` routing, pgx v5 + sqlc, goose, nats.go JetStream,
  `log/slog` JSON, Prometheus, OpenTelemetry, configuration through
  `ANSP_*` environment variables (secrets from `*_FILE`). A dependency
  needs a one-line reason in the commit body and a row in
  `docs/PLAN.md §4`. No cgo.
- Logs carry `process`, `instance` and where it applies `adapter_id`,
  `icao24`, `restriction_id`, `ack_id`, `client_id`, `policy_version`.
  A library package never logs; the process decides.
- Errors: `*core.FieldError` inside; RFC 9457 problems with `field` and
  `reason` on the wire; never a token or a secret in an error.
- Branch per work package: `feat/WP-<k>-<slug>`. Commits: Conventional
  Commits with the WP and milestone in brackets:
  `feat(restriction): validate the window against the F3548 limits [WP-5 N-M1]`.
  Types `feat`, `fix`, `test`, `refactor`, `perf`, `docs`, `build`,
  `ci`, `chore`; scopes `api`, `adapter`, `feed`, `restriction`, `dss`,
  `cis`, `deliver`, `coord`, `auth`, `store`, `web`, `deploy`, `ci`,
  `docs`. Imperative subject under 72 characters, one logical change
  per commit.
- **No AI attribution of any kind** in commits, PRs, code or docs.
- Never force-push a shared branch; never commit to `main`. Do not merge
  your own PR unless the owner's process says so.

## Commands

```
make tools            # once per machine: pinned golangci-lint, staticcheck, gitleaks
make lint             # gofmt, vet, staticcheck, golangci-lint (refuses an unpinned version)
make race             # go test -race -shuffle=on ./...
make integration      # against ANSP_RELATIONAL_DSN, ANSP_TIMESERIES_DSN, ANSP_NATS_URL (compose-up provides them)
make vectors          # this repo's RunOwned tests and uspace-core's own vectors from this module
make generate         # oapi-codegen, sqlc, openapi-typescript; make generate-check in CI
make fuzz-smoke bench # decoders fuzzed 10 s; budgets of docs/PLAN.md §9 reported
make web-lint web-build
make compose-up       # api, manned-adapter (replay), manned-feed, web, databases, NATS
make ci               # what CI runs
```

Before you say a work package is done: run `make lint`, `make race`,
`make integration`, `make generate-check`, `make fuzz-smoke
FUZZTIME=10s`, `make bench` in that order, paste the last lines of each
into the PR, then check the brief's done-when list item by item. If a
requirement cannot be met without a contract the plan did not foresee,
write it in the PR as a spec gap and add it to `docs/PLAN.md §15`; do
not invent a contract silently.
