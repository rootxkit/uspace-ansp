# WP-0: scaffold

Branch `feat/WP-0-scaffold`. Milestone N-M0. Owns `go.mod`, `go.sum`,
`cmd/*` (stubs), `internal/config`, `internal/obs`, `internal/bus`,
`Makefile`, `.golangci.yml`, `.github/workflows/`, `deploy/Dockerfile`,
`deploy/compose.yaml` (dev), `deploy/.env.example`, `SECURITY.md`,
`CHANGELOG.md`, `.gitleaks.toml`, `.gitattributes`, `.gitignore`,
`tests/layout_test.go`. Depends on nothing. Every other WP starts when
this merges, so it is small and lands first.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §2`, `§3`, `§4`, `§7`, `§11`, `§14`.
2. `uspace-core` at `main`: `CLAUDE.md`, `Makefile`, `.golangci.yml`,
   `.github/workflows/ci.yml`, `.gitleaks.toml`, `.gitattributes`
   (copy the shape; this repo adds processes, databases and a web app).
3. Spec `00 §6`, `05 §2`, `§6`, `06 §4`; LESSONS E-02, E-09, B-08, B-16.

## What to build

### Module and layout

- `go.mod`: `module github.com/rootxkit/uspace-ansp`, `go 1.27`,
  `require github.com/rootxkit/uspace-core <newest tag>` (record the tag
  in `docs/PLAN.md §4`), `github.com/nats-io/nats.go`,
  `github.com/prometheus/client_golang`, `go.opentelemetry.io/otel` and
  its OTLP HTTP exporter. Nothing else yet (pgx, goose, sqlc, oapi-codegen
  arrive with WP-1 and WP-3). Each `require` line has its reason in the
  commit body.
- Directories of `docs/PLAN.md §3` with a `doc.go` in every `internal`
  package naming the WP that fills it.
- `tests/layout_test.go`: fails if a third tree appears under
  `migrations/`, if a `cmd/` directory is not one of the three, or if a
  Go file under `web/` exists.

### `internal/config`

`type Config struct{...}` loaded from environment variables with the
prefix `ANSP_` (`Load() (Config, error)`): `ANSP_PROCESS`
(`api` / `manned-adapter` / `manned-feed`, set by the entrypoint),
`ANSP_INSTANCE`, `ANSP_SYSTEM_ID` (the JWT audience, e.g. `ansp`),
`ANSP_HTTP_ADDR`, `ANSP_NATS_URL`, `ANSP_NATS_CREDS`,
`ANSP_RELATIONAL_DSN`, `ANSP_TIMESERIES_DSN`, `ANSP_MIGRATE_ON_START`,
`ANSP_TOKEN_ISSUER`, `ANSP_TOKEN_JWKS_URL`, `ANSP_TOKEN_URL`,
`ANSP_CLIENT_ID`, `ANSP_CLIENT_SECRET_FILE`, `ANSP_CISP_URL`,
`ANSP_CISP_JWKS_URL`, `ANSP_DSS_URL`, `ANSP_DSS_AUDIENCE`,
`ANSP_AUTHORITY_URL`, `ANSP_PUBLIC_BASE_URL` (the `uss_base_url` written
to the DSS), `ANSP_MTLS_REQUIRED`, `ANSP_LOG_LEVEL`, `ANSP_OTLP_ENDPOINT`,
`ANSP_COUNTRY` (`GEO`). Unknown `ANSP_*` variables and malformed values
are start-up errors that name the variable. Secrets are read from files
(`*_FILE`), never from the environment directly. `Redacted()` for the
start-up log line.

### `internal/obs`

`Logger(cfg) *slog.Logger` (JSON, level from config, `process` and
`instance` attributes on every line), `Metrics() *prometheus.Registry`
with `Counters(reg, prefix, *core.Counters)` that exports every
`core.Counters` name as a Prometheus counter of the same snake_case name,
`Tracer(ctx, cfg)`, and `Health` with `Liveness()` and
`Readiness(checks ...Check)` where each `Check` names a dependency
(`nats`, `relational`, `timeseries`, `cisp`, `dss`, `jwks`) and reports
`ok`, `degraded` or `down` with a reason; `/readyz` returns `200` with
the JSON list when every required check is `ok` or `degraded`, `503`
otherwise, and never hides a dependency (E-02, SC-22).

### `internal/bus`

`Connect(ctx, cfg, logger) (*Bus, error)`: nats.go with
`MaxReconnects(-1)` (B-08), reconnect and disconnect handlers that log
once per transition, a bounded start-up retry (3 attempts with backoff,
then return a degraded `Bus` that reports `down` in readiness and
reconnects in the background). Subject and bucket names of `PLAN §7` as
constants with a test that lists them; `EnsureStreams(ctx)` creating
`MAN_MIRROR`, `RESTR`, `DELIVER`, `COORD` and the KV buckets
`cis_current`, `source_control`, `policy` idempotently.

### Process stubs

`cmd/api`, `cmd/manned-adapter`, `cmd/manned-feed`: load config, build
logger and metrics, connect the bus, serve `/healthz`, `/readyz`,
`/metrics` on `ANSP_HTTP_ADDR` with `net/http`, handle `SIGTERM` with a
drain. No business handlers. Each `main.go` is the only place `os.Exit`
is allowed.

### Makefile and lint

Targets: `build`, `vet`, `fmt`, `fmt-check`, `lint` (refuses an unpinned
golangci-lint, as core does), `tools`, `test`, `race`, `cover`,
`integration` (needs `ANSP_RELATIONAL_DSN`, `ANSP_TIMESERIES_DSN`,
`ANSP_NATS_URL`; skipped with a printed reason otherwise, E-04),
`generate`, `generate-check`, `fuzz-smoke`, `bench`, `vulncheck`,
`secrets`, `web-install`, `web-lint`, `web-build`, `web-types`,
`compose-up`, `compose-down`, `ci`. Pinned: golangci-lint v2.14.0,
staticcheck v0.8.1, gitleaks 8.24.3, govulncheck v1.8.0 (same as core;
bump both files in one `ci:` commit). `.golangci.yml`: core's, plus
`forbidigo` allowing `os.Exit` only in `cmd/*/main.go`, `exhaustive` on
the state enums, exemptions for `*.gen.go` and `*.sql.go`.

### CI (`.github/workflows/ci.yml`)

Lean, as the owner requires: `concurrency` with `cancel-in-progress`,
`timeout-minutes` on every job, `actions/setup-go` cache, path filters
so a docs-only change runs only `lint-docs`, no scheduled jobs. Jobs:

1. `build-vet-lint` (gofmt, build, vet, `go mod tidy` clean,
   staticcheck, golangci-lint).
2. `test-race` (`-race -count=1 -shuffle=on -coverprofile`).
3. `generate-check` (`scripts/generate-check.sh`: `go generate ./...`
   then `git diff --exit-code`; from WP-3 it covers oapi-codegen and
   sqlc; offline: the generators are `go run` with pinned versions and
   module cache).
4. `integration`: `services:` for `postgis/postgis:16-3.4`,
   `timescale/timescaledb:latest-pg16` and `nats:2-alpine` (JetStream
   on); runs `make integration`. Path-filtered to `internal/**`,
   `cmd/**`, `migrations/**`, `go.*`.
5. `vectors`: `go test -run 'Vectors' ./...` (this repo's `RunOwned`
   tests) and `go test -run Vectors github.com/rootxkit/uspace-core/...`
   from this module (proves the pinned core passes its own vectors in
   this build).
6. `fuzz-smoke` (10 s per target), `bench` (reported, not gated).
7. `web` (path-filtered to `web/**`, `api/openapi.yaml`): `npm ci`,
   `web-types` current, lint, `tsc`, `next build`. Never on the server.
8. `gitleaks`, `govulncheck`.
9. `image` on `main` and tags only: build the Go image and the web image,
   push to GHCR, cosign sign, SBOM (WP-13 finishes this; WP-0 adds the
   job building without pushing on PRs).

Branch protection on `main` requires 1–5 and 8.

### Containers

`deploy/Dockerfile` (multi-stage, `golang:1.27` builder, distroless
runtime, three binaries, `ENTRYPOINT ["/api"]` overridden per service).
`deploy/compose.yaml` for development: `api`, `manned-adapter`
(replay, waits for WP-4), `manned-feed`, `postgres` (PostGIS 3.4),
`timescaledb`, `nats` with JetStream and the three credential files
generated by `scripts/nats-creds.sh` into `local/` (git-ignored).
`deploy/.env.example` lists every `ANSP_*` variable with its default and
no real value.

## Done when

- [ ] `make lint`, `make race`, `make ci` green locally and in CI on the
  skeleton; CI minutes of a docs-only push ≤ 1 min (path filters proven
  by a docs-only commit on the branch).
- [ ] `go test -run Vectors github.com/rootxkit/uspace-core/...` passes
  from this module (paste the summary).
- [ ] The three processes start with `docker compose up`, answer
  `/healthz` and `/readyz` (readiness lists `nats` as `ok`; stop NATS and
  it says `nats: down (reconnecting)` and the process stays up, B-08,
  E-02).
- [ ] `tests/layout_test.go` passes and fails on a planted third
  migration tree (prove with a throwaway commit, revert).
- [ ] `docs/PLAN.md §4` records the pinned `uspace-core` tag.
- [ ] `CHANGELOG.md` created with an Unreleased section and the WP-0
  line.

## Commits

`build: create the module pinned to uspace-core <tag> [WP-0 N-M0]`,
`feat(config): load the ANSP configuration from the environment [WP-0 N-M0]`,
`feat(obs): add logging, metrics, tracing and readiness [WP-0 N-M0]`,
`feat(bus): connect to NATS and declare the streams and buckets [WP-0 N-M0]`,
`feat(api): add the three process stubs with health endpoints [WP-0 N-M0]`,
`ci: add the lean workflow with services and path filters [WP-0 N-M0]`,
`build(deploy): add the image and the development compose [WP-0 N-M0]`.
