# WP-3: `openapi-contract`

Branch `feat/WP-3-openapi-contract`. Milestone N-M0. Owns
`api/openapi.yaml`, `api/oapi-codegen.yaml`, `api/gen/`, `schemas/`,
`scripts/generate.sh`, `scripts/generate-check.sh`, `internal/apierr`
(RFC 9457 problems), the contract tests. Depends on WP-0. This is the
published national API of the ANSP and the contract the USSP, CISP and
authority planners depend on: open the PR early and keep the file the
single source of truth; later WPs fill handlers and may only add fields
additively.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §6` (every endpoint, its spec section and
   auth), `§7` (messages), `§15` gaps 6, 7, 9, 10, 14, 15, 16.
2. Spec `02 §1` (conventions: transport, time, geometry, versioning),
   `02 F2`, `F4`, `F11`, `F13`, `02 §3 ansp`, `04 §1` (schema rules,
   `$id`), `04 §2` (envelope), `04 §3.1` `track/manned/v1`, `04 §3.4`
   `restriction/state/v1`, `04 §3.5` `coordination/annex_v/v1`, `04 §3.6`
   `source/status/v1`, `04 §4`, `00 §7` (publication, compatibility).
3. `uspace-core/f3548`: `types.gen.go` (`Constraint`, `ConstraintDetails`,
   `GetConstraintDetailsResponse`, `Volume4D`), `oapi-codegen.yaml`,
   `SOURCE` (how a generated file is pinned); `uspace-core/ed318`
   `model.go` (the feature a restriction publishes).
4. oapi-codegen v2 docs: strict server, `net/http` (Go 1.22 routing)
   target, `types`, `client`.

## What to build

### `api/openapi.yaml` (OpenAPI 3.1)

Every operation of `PLAN §6`, grouped by tag (`restrictions`,
`restriction-requests`, `coordination`, `manned-traffic`, `adapters`,
`sources`, `policy`, `occurrences`, `audit`, `auth`, `uss` (F3548),
`cis`, `health`), each with:

- `operationId` in `camelCase`, `x-process` (`api` / `manned-feed`),
  `x-spec` (the spec section), `x-auth` (`session:<role>` /
  `token:<scope>` / `jws:cisp` / `public`), `description` naming the
  regulation clause.
- Request and response schemas with `$ref`s into `components`;
  `additionalProperties` left open on inbound bodies (unknown fields
  ignored, `02 §1`); every time `format: date-time` UTC with `Z`; every
  geometry GeoJSON `[lng, lat]` with `SRID 4326` stated; altitudes with
  `_m` and a `_ref` enum (`AMSL`, `WGS84`; `AGL` listed as refused in the
  description, D3).
- Errors: `application/problem+json` (RFC 9457) in the ecosystem's one
  body (M28): `{type, title, status, detail, instance, errors: [{field,
  reason}], truncated?: boolean}`, `errors` capped at 100 with
  `truncated: true`, `type` = `https://schemas.uspace.ge/problems/<slug>`
  (the counter or refusal name); one `Problem` component referenced by
  every error response; `Retry-After` on `503` and `429`. The schema
  mirrors `uspace-lab/schemas/common/problem/v1`.
- `Restriction` schema: the columns of `PLAN §5.1` the client sees,
  `feature` (ED-318 `Feature` object, `$ref` to a schema that mirrors
  `uspace-core/ed318`'s member names, UNVERIFIED note copied from its
  `doc.go`), `constraint_reference` (F3548 `ConstraintReference`
  members), `deliveries` summary.
- `POST /v1/coordination/notices` (M2) request body: **this repo's own**
  `coordination/annex_v/v1` (the API owner owns the request schema,
  M14): the `04 §3.5` fields (`kind`, intents with refs, authorisation
  numbers, times, volumes as F3548 `Volume4D`, non-conformance detail)
  as `schemas/coordination/annex_v/v1.json` with examples, `$ref`'d from
  the OpenAPI file; the USSP consumes it from this repo. No
  `x-pending-schema`. Response `202` `{ack_id, state: received,
  received_at}`.
- `GET /v1/manned-traffic/stream` and the console streams
  (`/v1/restrictions/stream`, `/v1/coordination/stream`): documented as
  WebSocket upgrades (`x-websocket: true`) whose every frame is the
  `04 §2` envelope with `schema` and a `body` (M29): bodies
  `track/manned/v1` (also with `state: stale | source_disabled`),
  `restriction/state/v1`, the coordination notice frames, and the
  common `console/status/v1` (every 2 s and on connect; this system's
  extras `adapters[]`, `cis_version`, `cis_age_s`, `nats`),
  `console/snapshot/v1` (on connect and re-subscribe); the client sends
  `console/subscribe/v1 {bbox, layers[]}`. The common frames are
  `$ref`'d to `uspace-lab/schemas/common/` (until the lab publishes
  them, a pinned copy under `schemas/common/` with a `SOURCE`). There is
  no `feed/status/v1` (M12). The snapshot endpoint returns the
  `console/snapshot/v1` body plus `degraded[]` and `adapters[]`.
- `POST /v1/cis/notifications` (M1): the CISP's `cis/change/v1` as a
  compact JWS (`application/jose`), described by reference to the
  CISP's OpenAPI copy; `204` for `subscription_test`, `republished` and
  unknown reasons, `202` when a pull is triggered.
- `api/clients/`: a pinned copy of each sibling's `api/openapi.yaml`
  (`cisp.yaml`, `authority.yaml`, `ussp.yaml`) with a `SOURCE` file
  naming repo and commit, and a CI job that diffs each copy against its
  repo at that commit (M11; the authority's mechanism). The outbound
  client types (`cis/restriction/v1`, `cis/change/v1`,
  `cis/ussp_list/v1`, `occurrence/v1`) are generated from these copies,
  never hand-written; bumping a copy is a `build:` commit of its own.
- `GET /uss/v1/constraints/{entityid}`: the response is F3548's
  `GetConstraintDetailsResponse`; describe by reference to the standard's
  OpenAPI (`x-standard: ASTM F3548-21 utm.yaml <commit from
  uspace-core/f3548/SOURCE>`), and generate the Go type as an alias of
  `uspace-core/f3548.GetConstraintDetailsResponse` through
  `x-go-type` so there is one struct.
- Degraded direct delivery and the CISP heartbeat are **outbound**: they
  are described in `docs/PLAN.md §6` and in `api/outbound.md` (a short
  list of the calls this system makes with their owners), not in this
  file.
- Examples for every request and response (used by the contract tests
  and by `uspace-lab`'s aggregation).

### Generation

`api/oapi-codegen.yaml`: `package gen`, `generate: {std-http-server:
true, strict-server: true, models: true, client: true}`,
`output-options.skip-prune: false`. `scripts/generate.sh` runs
`go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0`
(the version core pinned; one place) and `sqlc` (from WP-1) and
`openapi-typescript` for `web/` when `web/` exists; `generate-check.sh`
runs it and fails on a diff. Generated files carry the generator version
in their header; `api/gen/SOURCE` records the OpenAPI file's SHA-256 as
core does.

### `schemas/`

JSON Schema 2020-12 for `track/manned/v1`, `restriction/state/v1` and
`coordination/annex_v/v1` (the messages this repo owns, M14), each with
`$id https://schemas.uspace.ge/<family>/<name>/v1.json` and `schema`
constant; `source/status/v1`, `envelope/v1` and the console frames are
consumed from `uspace-lab/schemas/common/` (pinned copy + `SOURCE`
until the aggregate exists), not defined here;
`schemas/examples/<family>/<name>/v1/*.json`; a test validates
every example (use `encoding/json` round trip through the Go struct plus
the required-field list; a JSON Schema validator library is allowed in
`_test.go` only with a reason). Go structs for the messages live in the
owning packages (WP-4 `manned`, WP-5 `restriction`) and are checked
against the schemas by those WPs' tests; this WP ships the structs' field
lists as the schema.

### `internal/apierr`

`Problem` type with `Errors []FieldProblem{Field, Reason}` and
`Truncated bool`, `Write(w, status, problem)`, constructors
`Invalid(errs ...*core.FieldError)` (caps at 100, sets `truncated`),
`NotFound`, `Conflict`, `Unavailable(retryAfter)`, `Forbidden(scope)`,
each setting `type` to `https://schemas.uspace.ge/problems/<slug>`;
never echoes a token or a secret; a test that every status used in the
OpenAPI file has a constructor and that 101 field errors come back as
100 plus `truncated: true` (E-10).

### Contract tests

- The file lints (`vacuum` or `@redocly/cli`, pinned, run through
  `npx` in the web job or a Go-run alternative; choose one and pin it).
- Every example validates against its schema through the generated
  strict server's request validation (`oapi-codegen` + the
  `openapi3filter` middleware), with a stub implementation that returns
  the example response.
- The generated client calls every operation against that stub
  (presence of every route).
- A test asserts every operation has `x-spec`, `x-auth` and
  `x-process`, and that the set of paths equals the table in
  `docs/PLAN.md §6` (parse the Markdown table; a drift fails).

## Done when

- [ ] `make generate-check` clean; `api/gen` committed; CI job green.
- [ ] Every operation of `PLAN §6` present with examples; the table test
  passes.
- [ ] `schemas/` with examples; the example test passes.
- [ ] `docs/PLAN.md §6` updated if an operation was added or renamed
  during the work (say so in the PR title).
- [ ] CHANGELOG line; `api/README.md` explaining how to regenerate and
  the compatibility rule (additive within `/v1`).

## Commits

`feat(api): publish the ANSP national API as OpenAPI 3.1 [WP-3 N-M0]`,
`build(api): generate the strict server, types and client with oapi-codegen [WP-3 N-M0]`,
`feat(api): publish the JSON Schemas of the messages this system owns [WP-3 N-M0]`,
`build(api): pin the sibling OpenAPI copies with SOURCE and a CI diff [WP-3 N-M0]`,
`test(api): validate every example and every route against the stub [WP-3 N-M0]`.
