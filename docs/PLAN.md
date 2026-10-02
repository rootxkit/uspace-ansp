# uspace-ansp implementation plan

Status: plan for implementation by independent agents, one work package
per PR. Branch `plan/initial`. Inputs: the spec at `uspace-lab/docs/spec/`
(`00 §3, §6.1, §7`, `01 §4` N1–N4, `02 F2, F4, F11, F13, §3 ansp`, `03 §4`,
`04 §2, §3.1, §3.4, §3.5, §3.6`, `05 §2–§7`, `06`, `07` Phase 5, `08` Q3,
Q14, `09 §1.1` ATS.OR.127 / ATS.TR.237 rows), the knowledge base at
`uspace-lab/knowledge/` (`LESSONS.md` rules marked `ansp`, `scenarios.md`
SC-08, SC-15, SC-22) and `uspace-core` at `main` (`docs/PLAN.md` is the
template for this file; the packages this system imports are listed in
§4). The predecessor `rootxkit/utm` is read-only reference for U-04, U-07
and P1-16 behaviour, never for structure.

Sections: 1 scope and role boundary; 2 architecture; 3 package layout;
4 dependencies; 5 data model and migrations; 6 the published API; 7 bus
subjects and internal messages; 8 security; 9 performance budgets;
10 testing; 11 deployment; 12 milestones; 13 work packages and waves;
14 engineering standards; 15 open questions.

---

## 1. Scope and role boundary

`uspace-ansp` is the U-space interface of the air navigation service
provider (Sakaeronavigatsia; branding is configuration). It implements the
four obligations of spec `01 §4`:

| # | Obligation | Source | Where in this plan |
|---|---|---|---|
| N1 | Dynamic airspace reconfiguration: plan, activate, extend, end and cancel time-bounded restrictions inside designated U-space airspace; notify the CISP and the USSPs in a timely and effective manner | 2021/664 Art. 4, 5(2); 2021/665 ATS.TR.237(a)–(b) | `internal/restriction`, `internal/deliver`, `internal/dss` (WP-5, WP-8, WP-9) |
| N2 | Manned traffic information for U-space airspace in the controlled airspace it serves, on a non-discriminatory basis; coordination facilities with USSPs and the CISP | 2021/665 ATS.OR.127(a)–(b); Art. 5(2), 11(2), Annex V | `internal/manned`, `cmd/manned-adapter`, `cmd/manned-feed` (WP-4, WP-6) |
| N3 | Receive Annex V data from USSPs (intents touching controlled airspace, non-conformance notices) and acknowledge conformance alerts | Art. 7(3), 13(2), Annex V | `internal/coord` (WP-10) |
| N4 | Audit every reconfiguration (who, why, when, until when); exchange under an SLA with recognised encryption and an open protocol; record-keeping and occurrence reporting of an ATS provider | Annex V(1), (3)–(4); 2017/373 ATM/ANS.OR.B.030 *(unverified)*; 376/2014 Art. 4(8) | `internal/audit`, `internal/coord` occurrence outbox (WP-1, WP-10) |

### 1.1 What this system does NOT do

These are the MUST NOTs of spec `01 §4` plus the boundaries that keep the
repo small. A task that seems to need one of them is out of scope: stop
and ask.

| Not done here | Who does it | Why |
|---|---|---|
| Command, configure or geofence an aircraft; hold any credential, socket or protocol that reaches a flight controller | nobody (`00 §1` invariant, `06 §1`) | permanent |
| Act as an ATM system: flight-plan processing, clearances, radar data processing beyond normalising a position feed, separation of any traffic | the ANSP's real ATM systems, outside this repo | `01 §4` MUST NOT |
| Alert remote pilots or operators, issue traffic information or conformance alerts to them | `uspace-ussp` (Art. 11, 13) | `01 §4` MUST NOT |
| Author, edit or publish geo-zones or U-space airspace designations | `uspace-authority` authors, `uspace-cisp` publishes | the ANSP issues time-bounded restrictions under the authority's framework only |
| Serve a public map, the CIS read API, zone history or the change feed | `uspace-cisp` | the CISP is the regulatory channel (Art. 5(2)); the ANSP's degraded direct delivery exists only while the CISP is down (`02 F2`) |
| Judge zones, CPA, identification, conformance, time placement | `uspace-core` packages, compiled in | safety logic lives once (`00 §6` hard rule, `06` T12) |
| Receive direct Remote ID, operator telemetry, or run an e-conspicuity receiver for airspace outside ATC service | authority (F9), USSP (F5, SERA.6005(c)) | the ANSP forwards ATS surveillance only (`02 F4` scope) |
| Hold operator PII, telemetry of UAS, or flight records | authority, USSP | `06 §1`: the ANSP holds none |
| Assume the CISP or any USSP is ours | — | `00 §7`: the CISP of record and the DSS come from deployment configuration; USSPs come from the CIS USSP list and the DSS |
| Host the DSS or issue ecosystem tokens | CISP (Q7, national choice), authority | the ANSP is a DSS client with `utm.constraint_management` and a token client of the authority |

### 1.2 Decisions taken in this plan

| # | Decision | Why |
|---|---|---|
| D1 | Three Go processes, not two: `api`, `manned-adapter` (one instance per surveillance feed) and `manned-feed` (serves F4 to USSPs and the authority, writes TimescaleDB). Spec `00 §6.1` lists two and gives the F4 stream to `manned-adapter`. | LESSONS B-16: every adapter is its own process with its own switch and imports no other adapter. Several adapter instances cannot each serve one country-wide F4 stream; the stream needs the union. `manned-feed` is that union, and it is the only writer to the hypertable (`03` conventions: one `tsdb-writer` role). Recorded in §15 gap 1. |
| D2 | No H3 in this system. Internal manned subjects are keyed by adapter instance and ICAO address, `man.v1.<adapter>.<icao24>`. | Spec `05 §3` partitions by H3 cell for fleets of thousands; this system carries tens of manned aircraft and no UAS. uspace-core left H3 out at v0.x because the Go binding is cgo (core PLAN §11 gap 3). The partition key never crosses an external interface, so the USSP and the authority are unaffected. §15 gap 2. |
| D3 | Restrictions are authored with vertical limits in AMSL or WGS84 only in this release. AGL limits are refused with a reason (`lower_ref: AGL is not supported for a dynamic restriction in this release`). | An F3548 constraint needs W84 altitudes (`f3548.Altitude.HAEM`), derived from AMSL through `uspace-core/geoid`. AGL would need a DEM lookup over the whole polygon and a conservative envelope; nothing in the spec requires an ATC unit to limit UAS by height over ground rather than by level. §15 gap 3. |
| D4 | The ED-318 feature of a restriction has `type` `PROHIBITED` by default (supervisor may choose `REQ_AUTHORIZATION`), `reason` `["DAR"]`, `variant` `COMMON`, `identifier` `DAR` + 4 base-36 characters (7 characters, the ED-318 limit), `country` from configuration (`GEO`). | Spec `02 F2` fixes reason `DAR`, `03 §6` fixes the `DAR-` prefix and the ED-318 identifier is at most 7 characters (`uspace-core/ed318` doc). `DAR-` with a hyphen leaves three characters; `DAR` plus four base-36 characters gives 1.6 million identifiers. §15 gap 4. |
| D5 | Every outbound side effect (CISP publication, DSS write, USS subscriber notification, degraded direct delivery, occurrence report) goes through one JetStream work-queue outbox with the body pair `(ansp_ref, ansp_version)` as the idempotency key, and a delivery row per attempt. The CISP reads the pair from the body; an `Idempotency-Key` header may be sent but nothing depends on it (reconciliation M4). | `02 F2` failure rules (retry, alarm after 10 s, degraded path, reconciliation) and CLAUDE.md of utm: no retry loops around side effects without idempotency keys. One outbox, one retry policy, one delivery log. |
| D6 | The outbox sends the restriction to the CISP and writes the DSS constraint in parallel; the CISP publication is the regulatory channel, the DSS constraint the F3548 channel; a failure on one does not block the other. | `02 F2`: "the CISP publication remains the regulatory channel"; `09 §1.4`: the ANSP is the constraint manager. |
| D7 | Server and client types are generated from `api/openapi.yaml` with oapi-codegen v2 (strict server, `net/http` router), committed, and CI fails if regeneration changes anything. The F3548 USS endpoint the ANSP serves (`GET /uss/v1/constraints/{entityid}`) uses `uspace-core/f3548` types and is described in the same file by reference to the standard. | Owner's fixed stack. An endpoint not in the OpenAPI file does not exist (`00 §7`). |
| D8 | Migrations with goose (embedded, two trees), not `golang-migrate` as `03` says. | Owner's fixed stack; recorded in §15 gap 5 for the spec. |
| D9 | The console (`web/`) renders only; its API routes are the BFF cookie exchange and nothing else. Live data reaches it over WebSocket from `api` (restriction state, inbox) and `manned-feed` (manned picture) on the same origin, authenticated by the session cookie. | Spec `00 §6.2`. |
| D10 | Thresholds and margins are rows of `ansp_policy` with a `policy_version`, projected to the hot path through NATS KV, never literals: feed relevance margin (5 km lateral, 1500 m vertical above the U-space ceiling), stale after 15 s, source liveness, CISP alarm after 10 s, publisher heartbeat 15 s (three misses = the CISP's 60 s stale bound, M3), unacknowledged-notice escalation 60 s, F3548 constraint limits as published constants. | LESSONS INV-03; `02 F2`, `F4`. |
| D11 | Cross-system contracts follow the reconciliation of 2026-10-02 (`uspace-lab` cross-plan decisions, M1–M38): every machine token's `aud` is the **host** of the target's published base URL and this system verifies against `ANSP_AUDIENCES` (its public host plus a lab alias); the error body is `{type, title, status, detail, instance, errors: [{field, reason}], truncated?}` with `type = https://schemas.uspace.ge/problems/<slug>`; every WebSocket frame, browser- or machine-facing, carries the `04 §2` envelope with `schema` and a `body`, with `console/status/v1`, `console/snapshot/v1` and `console/subscribe/v1` from `uspace-lab/schemas/common/`; sessions are `scope = "session"`, `roles[]`, `realm` in the `uspace_session` cookie; mTLS is `ANSP_MTLS_MODE = required \| off`; sibling APIs are consumed as a pinned copy under `api/clients/<system>.yaml` with a `SOURCE` commit and a CI diff until the lab aggregate exists. | One verifier, one error body, one stream frame and one client-copy mechanism across five repos; each is additive to what this plan already had. |

---

## 2. Architecture

```
                 surveillance feeds (ADS-B receiver, ASTERIX bridge, ATM API)
                         │ one adapter process per feed (B-16)
                         ▼
   ┌──────────────── cmd/manned-adapter (N instances) ─────────────────┐
   │ decode → normalise to track/manned/v1 → time placement (T-01..T-03,│
   │ T-11) → dedupe → NATS core  man.v1.<adapter>.<icao24>              │
   │ status every 2 s  src.v1.manned.<adapter>                          │
   └───────────────────────────────┬────────────────────────────────────┘
                                   │ NATS (one cluster, this system only)
          ┌────────────────────────┼─────────────────────────────┐
          ▼                        ▼                             ▼
 cmd/manned-feed             cmd/api                      web/ (Next.js, renders only)
 live picture by icao24      restrictions lifecycle       dispatcher console: map,
 relevance filter (CIS)      coordination inbox           restriction editor, inbox,
 F4  WS stream + snapshot    restriction requests (F11)   adapters, audit
 TimescaleDB writer          outbox (JetStream work queue)│ BFF cookie only
 source-control follower     DSS constraint manager       │
 console picture WS          CIS projection (F3 client)   │
          │                  accounts, audit, policy      │
          │                  JWKS, F3548 USS endpoint     │
          ▼                        │                      │
  TimescaleDB (manned_tracks)   PostgreSQL + PostGIS      │
                                   │
        ┌──────────────────────────┼──────────────────────────────┐
        ▼                          ▼                              ▼
 uspace-cisp (F2 publish,     InterUSS DSS (F3548          USSPs (F4 consumers; F13
 F3 subscribe, heartbeat)     constraint_references)       Annex V senders; constraint
                                                           details readers; degraded
 uspace-authority (F4 consumer; F11 requests;              direct delivery targets)
 occurrences; token issuer and JWKS)
```

Processes and their failure domains (spec `05 §6`):

| Process | Hot path or control plane | Holds | Opens | If it dies |
|---|---|---|---|---|
| `manned-adapter` (per feed) | hot path | a dedupe window and the last sample per aircraft | its feed, NATS | that feed's tracks age out as `stale` in `manned-feed` within `stale_after_s`; the console shows the adapter `silent since T`; other adapters unaffected |
| `manned-feed` | hot path | the live picture (last sample per `icao24`, age), the CIS projection (U-space volumes + margin), the source-control state, a bounded TimescaleDB write buffer (B-07) | NATS, TimescaleDB (write), never PostgreSQL | F4 consumers lose the stream and mark manned traffic `unavailable since T` (`02 F4` failure rule); adapters keep publishing to NATS; the JetStream mirror replays the gap into TimescaleDB on restart |
| `api` | control plane | nothing between requests (stateless behind Caddy; sessions in cookies; jobs in JetStream) | PostgreSQL, NATS, TimescaleDB (read-only for exports), the CISP, the DSS, USSP base URLs, the authority | no new restrictions, acks or requests; active restrictions stay active until `ends_at` at the CISP and in the DSS; the manned feed is unaffected |

Rules (spec `05 §2`, `03` conventions): `manned-adapter` and `manned-feed`
never open PostgreSQL; what they need (policy, source switches, the CIS
projection) is written to NATS KV by `api` and read as in-memory
projections, refreshed by push plus periodic re-read; a stale projection
is served with its age, never blocks. `api` is the only writer to the
relational database; `manned-feed` the only writer to the hypertable.
Judgements (ED-318 validation, applicability, JWT verification, source
switches, F3548 volume envelopes) are package calls into `uspace-core`
inside the process that needs them; NATS is used only where it decouples
processes.

---

## 3. Package layout and responsibilities

```
github.com/rootxkit/uspace-ansp
├── cmd/
│   ├── api/               control plane: HTTP (generated strict server), outbox worker, DSS client, CIS client, KV projections writer
│   ├── manned-adapter/    one surveillance feed → track/manned/v1 on NATS; flags select the adapter kind and instance id
│   └── manned-feed/       live manned picture, F4 WS and snapshot, TimescaleDB writer, console picture WS
├── api/
│   ├── openapi.yaml       the published national API of the ANSP (OpenAPI 3.1); the only source of handler and client types
│   ├── oapi-codegen.yaml  generator config (strict server, net/http, types, client)
│   ├── gen/               generated (committed): server.gen.go, types.gen.go, client.gen.go
│   └── clients/           pinned copies of sibling OpenAPI files (cisp.yaml, authority.yaml, ussp.yaml) each with a SOURCE
│                          commit; CI diffs each against its repo at that commit (M11); replaced by the uspace-lab aggregate
├── schemas/               JSON Schema 2020-12 of the messages this repo owns (04 §1, ownership rule M14): track/manned/v1,
│                          restriction/state/v1, coordination/annex_v/v1 (this repo's API carries the request body, so this
│                          repo owns it; the USSP consumes it); examples under schemas/examples/ (mirrored read-only into
│                          uspace-lab/schemas/). source/status/v1, the envelope and the console frames (console/status/v1,
│                          console/snapshot/v1, console/subscribe/v1) are consumed from uspace-lab/schemas/common/
├── migrations/
│   ├── relational/        goose, PostgreSQL + PostGIS, version table goose_db_version_relational
│   └── timeseries/        goose, TimescaleDB, version table goose_db_version_timeseries   (never merged: B-15)
├── internal/
│   ├── config/            env var loading with documented defaults; refuses an unknown or malformed value at start
│   ├── obs/               slog JSON logger, Prometheus registry, OpenTelemetry tracer, health and readiness handlers
│   ├── store/             pgx pools, sqlc-generated queries (relational/, timeseries/), goose runner, transaction helpers
│   ├── audit/             append-only events with monthly hash chain (06 T7); every write, switch, view of the inbox, export
│   ├── auth/              ecosystem token middleware on uspace-core/auth (scopes, aud), local accounts (argon2id, TOTP),
│   │                      console session issuer (uspace-core/auth Issuer), roles, mTLS subject binding, BFF cookie contract
│   ├── policy/            ansp_policy row, policy_version, KV projection, follower for the hot path
│   ├── sources/           source-control writer (api) and follower (feed) on uspace-core/sources; U-15 semantics (B-09..B-11)
│   ├── restriction/       the restriction state machine, validation (geometry, limits, F3548 Cstr* bounds, U-space containment),
│   │                      versioning, the ED-318 feature of a restriction (uspace-core/ed318), the F3548 volumes of it
│   ├── cis/               CIS client: pull with ETag, 60 s reconciliation, webhook receiver (JWS verify), KV cis_current, USSP list
│   ├── deliver/           the outbox: JetStream work queue, idempotent delivery to CISP / DSS / USS subscribers / direct /
│   │                      authority, retry policy, alarm, delivery log, reconciliation
│   ├── dss/               F3548 constraint manager: constraint references in the DSS, ovn, subscriber notification, the USS
│   │                      constraint-details handler (uspace-core/f3548 types)
│   ├── coord/             Annex V inbox (coordination/annex_v/v1 intake, receipts, human acknowledgement, escalation),
│   │                      restriction requests (F11), occurrence outbox to the authority
│   ├── manned/            track/manned/v1 model, normalisation, time placement (uspace-core/timeplace), dedupe, stall detection,
│   │   ├── adapter/       the Adapter interface and the registry of kinds
│   │   ├── replay/        recorded-frame adapter (NDJSON of track/manned/v1 with original ts; lab and tests)
│   │   ├── dump1090/      SBS/BaseStation text and aircraft.json readers (field names pinned to dump1090's README-json.md, SOURCE)
│   │   └── asterix/       CAT021 (deferred; stub refusing to start with a reason)
│   ├── picture/           the live manned picture: last sample per icao24, ages, relevance filter, stale and source_disabled
│   │                      ageing, bbox queries, 1 Hz framing with server-side throttle
│   ├── feed/              F4 handlers: WS stream (envelope-wrapped frames), snapshot, degraded markers, per-client limits
│   └── bus/               NATS/JetStream connection (reconnect forever, B-08), subjects and KV bucket names, stream definitions
├── web/                   Next.js App Router console on @rootxkit/uspace-ui (npmjs, exact pin, pnpm); ka/en; types from api/openapi.yaml
├── deploy/
│   ├── Dockerfile         one image, three entrypoints (cmd/*); web built in CI into its own image
│   ├── compose.yaml       api, manned-adapter (replay), manned-feed, web, migrate (one-shot), timescaledb-ha (both databases), nats
│   └── caddy/             the ansp Caddy *snippet*: routes per process, client_auth verify_if_given on the mTLS route groups;
│                          composed into the shared Caddyfile by the deployment repo uspace-deploy (D1), never run alone
├── testdata/
│   ├── replay/            synthetic manned tracks (generated; never real traffic) for the replay adapter and the scenarios
│   └── fixtures/          a U-space airspace designation and a USSP list as the CISP would publish them (ED-318), test keys generated at run time
├── scripts/               generate.sh, generate-check.sh, migrate.sh, scenario runners
└── docs/                  this plan, WORKPACKAGES/, runbooks/ (milestone proofs), DECISIONS.md
```

Package dependency rules: `internal/*` packages import `uspace-core` and
each other in one direction only: `manned`, `picture`, `feed`, `sources`,
`policy`, `bus`, `cis` never import `restriction`, `deliver`, `dss`,
`coord`, `store` (the hot-path side has no database import path at all;
`manned-feed` writes TimescaleDB through `store/timeseries` only). `api/gen`
is imported by `cmd/api` and the handler packages; nothing imports
`cmd/*`. `web/` imports no geometry or geodesy library (lint rule, `06`
T12).

---

## 4. Dependencies

| Module | Used by | Why it is allowed |
|---|---|---|
| `github.com/rootxkit/uspace-core` **`v1.2.0`** (WP-1 bumped WP-0's `v1.1.0` to `v1.2.0`, additive: `auth.Issuer.IssueSession` and `SessionClaims` for WP-2's console sessions. `v1.1.0`, pinned by WP-0, added to `v1.0.0` `auth.KeyRing`, `auth.SignDetached`, `auth.VerifyDetached`, `auth.SignCompact`, `auth.VerifyCompact` (M27), `auth.Config.Audiences` (M18) and `auth.Config.StrictSessionClaims` (M20), which `internal/config.VerifierConfig` always sets; WP-8 therefore needs no bump) | everything | the shared judgement: `auth` (JWT, issuer, and from `v1.1.0` the JWS helpers), `ed318` (restriction feature, validation, `ToZones`), `ed269` (`Problems`), `f3548` (constraint types, `Cstr*` constants, `Altitude.HAEM`, `Volume4DToZonesEnvelope`), `geodesy` (rings, bbox, containment, area), `geoid` (AMSL → HAE for constraints), `zones` (U-space volume containment for the relevance filter and restriction placement), `timeplace` (`PlaceBatch`, `Times`), `sources` (`State`, `Follower`), `core` (types, counters, field errors), `vectors` (`RunOwned(t, "ansp", ...)`) |
| `github.com/jackc/pgx/v5` + `github.com/sqlc-dev/sqlc` (tool, `go run`, pinned) | `store` | owner's fixed stack |
| `github.com/google/uuid` | `store` (sqlc type of `uuid` columns) | already in the build through `uspace-core`; WP-1 maps `dss_constraint_id` and the source-control `epoch` to it instead of `pgtype.UUID` |
| `github.com/pressly/goose/v3` | `store` | owner's fixed stack; embedded migrations, two trees with distinct version tables |
| `github.com/nats-io/nats.go` | `bus` | owner's fixed stack; JetStream, KV |
| `github.com/oapi-codegen/oapi-codegen/v2` (tool, `go run`, same version as uspace-core, `v2.8.0`) + `github.com/oapi-codegen/runtime` | `api/gen` | owner's fixed stack; strict server on `net/http` |
| `github.com/prometheus/client_golang` | `obs` | owner's fixed stack |
| `go.opentelemetry.io/otel` (+ `sdk` and the otlp http exporter) | `obs` | owner's fixed stack; the SDK provides the tracer provider the exporter feeds |
| `github.com/nats-io/nkeys` | `bus` tests | already in the build through `nats.go`; the tests generate a throwaway NKey seed at run time instead of committing one |
| `github.com/lestrrat-go/jwx/v3` | (transitive only) | a transitive dependency through uspace-core/auth. **Not imported directly**: the JWS of publications, change notifications and degraded deliveries is signed and verified through core `v1.1.0`'s `auth.SignDetached` / `VerifyDetached` / `SignCompact` / `VerifyCompact` (M27); WP-7 and WP-8 wait for that release rather than carrying a second JOSE implementation |
| `github.com/coder/websocket` | `feed`, `api` (console streams) | pure Go, context-aware, maintained; `net/http` has no WebSocket |
| `github.com/pquerna/otp` | `auth` | TOTP for mandatory MFA (`01 §4`); small, pure Go |
| `golang.org/x/crypto/argon2` | `auth` | local accounts (`06 §3`) |
| web: `next`, `react`, `typescript`, `tailwindcss`, `shadcn/ui`, `maplibre-gl`, `@rootxkit/uspace-ui` (from npmjs, exact pin: ≥ 0.1 for WP-11, ≥ 0.3 for WP-12; never a `github:` tag install, M32/M33), `openapi-typescript` (dev, through the kit's `uspace-ui-gen-api`) | `web/` | owner's fixed stack; `pnpm` with `packageManager` pinned and `--frozen-lockfile` (M34) |

Rejected: `uber/h3-go` (cgo; D2), any GeoJSON or geometry library (core
`geodesy` and `ed318` carry what is needed; a second geometry
implementation is `06` T12), an ORM, a logging library other than `slog`,
any ADS-B decoding library that would read Mode S frames (the adapter
reads dump1090's decoded outputs; raw 1090 MHz decoding is a receiver
concern, and a wire format nobody here can pin from memory, E-03), any
MAVLink or vehicle-link library (INV-01).

Every added module gets a one-line reason in the commit body and a row
here.

---

## 5. Data model and migrations

Conventions (`03`): units and datums in every column name; `TIMESTAMPTZ`
UTC; geometry `SRID 4326`, distance and area on `geography`; no AGL
column anywhere; `api` writes the relational database, `manned-feed` the
hypertable; two goose trees, two version tables, never merged (B-15).

### 5.1 Relational (PostgreSQL 16 + PostGIS 3.4), `migrations/relational/`

Owned (**O**) entities of `03 §4` plus what the obligations need:

| Table | Key columns | Notes |
|---|---|---|
| `restrictions` O | `id` (ULID), `ansp_ref` (unique; the idempotency key towards the CISP and the DSS), `identifier` (ED-318, `DAR` + 4 base-36, unique), `uspace_airspace_id` (CIS identifier of the designated volume it modifies; **not null**: the CISP refuses a restriction that names no current `USPACE` feature, so a free-standing restriction is unpublishable, M9), `zone_type` (`PROHIBITED` / `REQ_AUTHORIZATION`), `geom` (Polygon or Point+radius: `geom`, `radius_m` nullable), `lower_m`, `lower_ref` (`AMSL` / `WGS84`), `upper_m`, `upper_ref`, `starts_at`, `ends_at`, `reason_text`, `state` (`planned` / `active` / `ended` / `cancelled`), `ansp_version` (monotonic per restriction, bumped on every change; the name the CISP's `cis/restriction/v1` carries, M4), `created_by`, `activated_by`, `ended_by`, `cancelled_by`, `created_at`, `activated_at`, `ended_at_actual`, `request_id` (nullable, F11), `published_version` (CISP-confirmed version, nullable), `dss_constraint_id` (UUID v4, minted here), `dss_ovn`, `dss_version`, `supersedes_id` (re-issue chain for restrictions longer than `CstrMaxDurationHours`) | Master of ATS.TR.237. State machine in `internal/restriction`. Limits: `ends_at - starts_at ≤ CstrMaxDurationHours`, `starts_at ≤ now + CstrMaxPlanningHorizonDays`, area ≤ `CstrMaxAreaKm2`, vertices ≤ `CstrMaxVertices` (constants from `uspace-core/f3548`); a longer restriction is a chain of re-issues. |
| `restriction_versions` O | `restriction_id`, `version`, `feature` (JSONB, the ED-318 feature as published for this version), `constraint` (JSONB, the F3548 `Constraint` as written), `changed_by`, `changed_at`, `change_reason` | Every version retrievable (`02 §3`: history by version); the N4 audit of who, why, when, until when. |
| `restriction_requests` O | `id`, `requester` (client id or user), `source` (`authority` / `console`), `payload` (the request as received: area, limits, window, reason, case ref), `received_at`, `state` (`received` / `accepted` / `declined`), `decided_by`, `decided_at`, `decision_reason`, `restriction_id` (nullable) | F11 inbound; a supervisor turns a request into a restriction or declines it. |
| `coordination_notices` O | `id` (the `ack_id`), `kind` (`intent_notice` / `nonconformance` / `contingent` / `ended`), `sender_client_id`, `ussp_id`, `payload` (JSONB, `coordination/annex_v/v1` as received), `intent_refs[]`, `authorisation_numbers[]`, `received_at`, `state` (`received` / `acknowledged`), `acknowledged_by`, `acknowledged_at`, `escalated_at`, `restriction_ids[]` (restrictions the notice's volumes intersect, computed at receipt) | `03 §4 coordination_inbox`. Receipt is immediate (the `ack_id` in the response); the human acknowledgement is the second state (§15 gap 6). |
| `adapters` O | `id` (instance slug), `kind` (`replay` / `dump1090_sbs` / `dump1090_json` / `asterix_cat021` / `atm_api`), `display_name`, `source_class` (`ads_b` / `mode_s` / `ssr` / `atm_feed` / `ads_l`), `config` (JSONB, non-secret), `status` (`configured` / `running` / `silent` / `disabled`), `last_frame_at`, `last_status_at`, `counters` (JSONB snapshot from `src.v1`) | The registry of feeds; the running state comes from `src.v1.manned.<id>`. |
| `source_controls` O | `(source_type, instance_id)`, `enabled`, `reason`, `actor`, `changed_at`, `version` (DB sequence), `epoch` (random per table creation) | Predecessor U-15 (`04 §3.6`, LESSONS B-09). Written in the same transaction as the KV put; refused with 503 when KV is unreachable. |
| `ansp_policy` O | `policy_version` (PK, monotonic), `feed_margin_lateral_m` (5000), `feed_margin_vertical_m` (1500), `stale_after_s` (15), `source_liveness_s` (15), `cisp_alarm_after_s` (10), `cisp_heartbeat_s` (15), `cis_reconcile_s` (60), `cis_stale_bound_s` (300), `notice_escalation_s` (60), `default_zone_type` (`PROHIBITED`), `country` (`GEO`), `changed_by`, `changed_at` | INV-03. Projected to KV `policy`; `policy_version` travels on every status line and delivery. There is no `require_uspace_airspace` switch: containment in a current `USPACE` feature is always required (M9; the lab publishes a designation for every demo). |
| `deliveries` O | `id`, `kind` (`cisp_publish` / `cisp_heartbeat` / `dss_put` / `dss_delete` / `uss_notify` / `direct_degraded` / `occurrence`), `subject_ref` (restriction id + version, or occurrence id), `target` (URL or client id), `attempt`, `queued_at`, `sent_at`, `status_code`, `response_excerpt`, `next_retry_at`, `state` (`queued` / `sent` / `failed` / `abandoned`), `idempotency_key` | The outbox log (D5). Abandoned after the retry window with an alarm, never silently. |
| `occurrence_reports` O | `id`, `report_ref`, `channel` (`mandatory` / `voluntary`), `occurred_at`, `became_aware_at`, `category`, `aircraft[]`, `manned[]`, `intent_refs[]`, `narrative`, `reporter_person_ref` (an opaque reference; encrypted **at rest** under this system's secrets key, sent to the authority in clear text over TLS where the authority encrypts it under its own key, M13; never logged, streamed or exported), `created_by`, `delivery_id`, `deadline_at` (`became_aware_at + 72 h`) | 376/2014 Art. 4(8); the ANSP's outbox copy of `occurrence/v1` (schema owned by the authority, consumed from its pinned OpenAPI copy); delivered through `deliveries`. |
| `users`, `user_sessions`, `user_mfa` O | `id`, `username`, `password_hash` (argon2id), `role` (`watch_supervisor` / `viewer` / `admin`), `status`, `mfa_secret_ref` (encrypted), `mfa_enrolled_at`, `last_login_at`; sessions: `jti`, `user_id`, `issued_at`, `expires_at`, `revoked_at` | `01 §4`: local accounts, MFA mandatory, OIDC-ready (an `oidc_subject` column reserved). WP-2 (migration 0020) keeps the TOTP secret sealed in `user_mfa` (`key_id`, `secret_enc`, `enrolled_at`, `last_step`: each code accepted once) and adds `login_challenges` (the `mfa_pending` token by its SHA-256, single use, 5 min, 5 codes) and `login_lockouts` (failures per username, known or not, so the lockout holds on every replica); `user_sessions` also carries `role`, `last_seen_at` (idle 30 min), `revoke_reason`. |
| `oauth_clients_seen` O | `client_id`, `system` (`ussp` / `cisp` / `authority` / `lab`), `mtls_subject`, `first_seen_at`, `last_seen_at`, `scopes_seen[]` | What machine clients the ANSP has served (for the console and the SLA record). Truth is the authority's token service; this is an observation log. |
| `events` O | `id`, `ts`, `actor_type` (`user` / `client` / `system`), `actor_id`, `purpose`, `entity_type`, `entity_id`, `event_type`, `payload`, `prev_hash`, `hash` | Append-only, partitioned by month, hash-chained (06 T7); application role has no `UPDATE`/`DELETE`. Includes views of the inbox and exports. |

Projected (**P**, read-only locally, with `source_version` and `fetched_at`):

| Table | From | Notes |
|---|---|---|
| `cis_cache` P | CISP F3 (`uspace_airspace`, `ussp_list`, `restrictions` datasets) | `dataset`, `version`, `fetched_at`, `etag`, `body` (JSONB) per dataset; the current U-space airspace volumes (the ones the ANSP may reconfigure) and the USSP list (base URLs for degraded direct delivery and `coord` sender validation). Also mirrored to KV `cis_current` for `manned-feed`. |

### 5.2 Time series (TimescaleDB), `migrations/timeseries/`

| Hypertable | Columns | Notes |
|---|---|---|
| `manned_tracks` O | `captured_at` (time column), `ts`, `rx_ts`, `time_source`, `backlog`, `adapter_id`, `icao24`, `callsign`, `geom` (Point 4326), `alt_pressure_m`, `alt_wgs84_m` (nullable), `gs_ms`, `track_deg`, `vrate_ms`, `emergency` (nullable bool), `squawk` (nullable), `source_class`, `quality` (JSONB: NIC/NACp or the adapter's quality block as received), `relevant` (bool: inside a U-space volume plus margin at capture), `policy_version` | What was handed to U-space, as handed (ATS.OR.127(a)); every sample kept, relevant or not (B-12: do not filter at the edge; relevance is a flag). 1-day chunks, `compress_segmentby = icao24`, `compress_orderby = captured_at`, compressed after 7 days, kept 90 days online (`05 §4`; national choice Q8 for longer). |
| `feed_products` O | `at`, `client_id`, `tracks_sent`, `tracks_relevant`, `degraded[]`, `policy_version` | Sampled 0.1 Hz: what was served to whom (Annex V record of the exchange). |

### 5.3 Migration rules

- Two goose trees, two databases, two version tables
  (`goose_db_version_relational`, `goose_db_version_timeseries`). A CI
  test fails if a migration in one tree references a table of the other,
  and `tests/layout_test.go` fails if a third tree appears.
- Migration files are numbered `NNNN_<slug>.sql` with ranges reserved per
  work package (WP-1: 0001–0019 relational, 0001–0009 timeseries; WP-2:
  0020–0029; WP-5: 0030–0039; WP-7: 0040–0049; WP-8: 0050–0059; WP-9:
  0060–0069; WP-10: 0070–0079) so parallel PRs do not collide.
- Long-running processes **never migrate** (M36). Each tree is applied
  by the `migrate` subcommand of the system binary (`api migrate
  relational`, `manned-feed migrate timeseries`), run as a one-shot
  `migrate` compose service that the long-running services depend on
  (`condition: service_completed_successfully`), in development,
  staging and production alike. `api` and `manned-feed` read the version
  table at start and refuse to start on a version lower than the one
  they were built for, printing which tree, which version is present and
  which is needed. There is no `ANSP_MIGRATE_ON_START`. A tree run
  against the wrong database fails on its version-table name.
- Every migration has a `-- +goose Down`. The application role cannot
  `UPDATE` or `DELETE` on `events` and `manned_tracks`.

---

## 6. The published API (`api/openapi.yaml`)

One origin, `https://<ansp host>/`; Caddy routes each group to its process
(`02 §3`). Every endpoint below is in `api/openapi.yaml`; an endpoint not
there does not exist. Path version `/v1`. Errors are RFC 9457
`application/problem+json` with the ecosystem's one body (M28):
`{type, title, status, detail, instance, errors: [{field, reason}],
truncated?: bool}`, where `field` is the JSON path as `core.FieldError`
and `ed269.Problems` write it, `errors` is capped at 100 entries with
`truncated: true`, and `type` is `https://schemas.uspace.ge/problems/<slug>`
with `slug` the counter or refusal name (`unauthenticated`, `forbidden`,
`signature`, `cis_stale`, `geoid_unavailable`, `reference_mismatch`,
...). Every response that carries airspace data carries `cis_version`
and `cis_age_s`.

Every WebSocket endpoint below, browser- or machine-facing, sends frames
in the ecosystem's one shape (M29, Appendix C of the reconciliation):
the `04 §2` envelope (`schema`, `msg_id`, `producer`, `ts`, `rx_ts`,
`captured_at`, `time_source`, `backlog`) plus a `body` named by
`schema`. A `console/status/v1` frame goes out on connect and every 2 s
(`connection_id`, `server_ts`, `policy_version`, `stale_after_s`,
`live_max_age_s`, `dropped_frames`, `degraded[]`, `sources[]`, plus this
system's extras `adapters[]`, `cis_version`, `cis_age_s`, `nats`), a
`console/snapshot/v1` on connect and on re-subscribe, and the client
sends `console/subscribe/v1 {bbox, layers[]}`. Consumers dispatch on
`schema`; the former `feed/status/v1` is retired (M12). Browser clients
authenticate with the `uspace_session` cookie on a same-origin upgrade
checked against an `Origin` allow-list; machine clients with a bearer
(M22).

| Method and path | Process | Spec | Auth | Purpose |
|---|---|---|---|---|
| `POST /v1/restrictions` | api | `02 §3 ansp`, `02 F2`, `01` N1 | session, role `watch_supervisor` | plan a restriction (`planned`): geometry, limits, window, reason, U-space airspace id; `Idempotency-Key` header = client reference |
| `GET /v1/restrictions?state=&at=&bbox=` | api | `02 §3` | session (any role) or ecosystem token `ansp.coordination` | list with states and delivery status |
| `GET /v1/restrictions/{id}` | api | `02 §3` | same | the restriction, its current ED-318 feature, F3548 reference, deliveries summary |
| `GET /v1/restrictions/{id}/versions` and `/versions/{v}` | api | `01` N4, `02 §3` history | session | every version as published |
| `POST /v1/restrictions/{id}/activate` | api | ATS.TR.237(b) activation | `watch_supervisor` | `planned → active` (immediately, or at `starts_at` when in the future); starts the outbox |
| `POST /v1/restrictions/{id}/extend` | api | ATS.TR.237(b) temporary limitation | `watch_supervisor` | new `ends_at` (within `CstrMaxDurationHours` of `starts_at`, else a re-issue is created and linked) |
| `POST /v1/restrictions/{id}/end` | api | ATS.TR.237(b) deactivation | `watch_supervisor` | `active → ended` now |
| `POST /v1/restrictions/{id}/cancel` | api | `02 F2` states | `watch_supervisor` | `planned → cancelled` |
| `GET /v1/restrictions/stream` (WS) | api | console | session cookie (same origin) | restriction state changes (`restriction/state/v1` bodies) and delivery outcomes for the console, in the console frame |
| `POST /v1/restriction-requests` | api | `02 F11` | ecosystem token, scope `ansp.requests` (in the catalogue, M23), or session | a request from the authority (or a console user) for a restriction over an area and window |
| `GET /v1/restriction-requests/{id}` | api | `02 F11` | same | state of the request (`received` / `accepted` with `restriction_id` / `declined` with reason) |
| `POST /v1/restriction-requests/{id}/accept`, `/decline` | api | `02 F11` | `watch_supervisor` | decision; `accept` creates the restriction |
| `POST /v1/coordination/notices` | api | `02 F13`, `04 §3.5 coordination/annex_v/v1` (schema owned here, M14), Art. 13(2) | ecosystem token, scope `ansp.coordination` (in the catalogue, M23); the sender's `sub` must be on the CIS USSP list; mTLS per `ANSP_MTLS_MODE` | intake of intent notices, non-conformance, contingent and ended notices; `202 {ack_id, state: received, received_at}` (M2) |
| `GET /v1/coordination/notices/{ack_id}` | api | `02 F13` | the sending client, or session | the notice's state, `acknowledged_by` (role only, never a name) and `acknowledged_at` when a person has acknowledged; the USSP polls this (every 10 s for 5 min on its side), no push in v1 |
| `GET /v1/coordination/inbox?state=&since=` | api | `01` N3 | session | the inbox for the console |
| `POST /v1/coordination/inbox/{id}/acknowledge` | api | Art. 13(2) | `watch_supervisor` | the person's acknowledgement |
| `GET /v1/coordination/stream` (WS) | api | console | session cookie (same origin) | new notices and escalations, in the console frame |
| `GET /v1/manned-traffic/snapshot?bbox=` | manned-feed | `02 F4` | ecosystem token, scope `ansp.traffic`; mTLS per `ANSP_MTLS_MODE` (`required` in production, `off` in staging and the lab, M25); or session (console) | bootstrap: every relevant aircraft's last sample with age, plus `degraded[]`, `adapters[]` state |
| `GET /v1/manned-traffic/stream?bbox=` (WS) | manned-feed | `02 F4`, `04 §3.1 track/manned/v1` | same | envelope-wrapped frames: `console/snapshot/v1` on connect, `track/manned/v1` bodies at 1 Hz per aircraft (also with `state: stale \| source_disabled` when an aircraft ages), `console/status/v1` every 2 s with `adapters[]`, ages, `degraded[]`, `dropped_frames`; the client may send `console/subscribe/v1 {bbox, layers[]}` (M12, M29) |
| `GET /v1/adapters`, `GET /v1/adapters/{id}` | api | `02 §3` | session | the surveillance adapters: configured, running, silent, disabled, last frame, counters |
| `GET /v1/sources`, `PUT /v1/sources/{type}/{instance}` | api | `04 §3.6`, U-15 | `admin` (write), session (read) | enable / disable by type (`manned`) and instance (adapter id), with reason; audited; 503 when KV cannot take it |
| `GET /v1/policy`, `PUT /v1/policy` | api | INV-03 | `admin` | the thresholds row; a new `policy_version` |
| `POST /v1/occurrences` | api | `01` N4, 376 Art. 4(8), `02 F7` | `watch_supervisor` | an ANSP staff occurrence report, queued to the authority's `POST /v1/occurrences` |
| `GET /v1/audit?entity=&since=` | api | `01` N4 | `admin` | the append-only events |
| `POST /v1/auth/login`, `POST /v1/auth/mfa`, `POST /v1/auth/logout`, `GET /v1/auth/me` | api | `06 §3` | — / session | local accounts with mandatory TOTP; the BFF calls these and sets the `uspace_session` / `uspace_csrf` cookies (M21); the session JWT is `scope = "session"`, `roles: [role]`, `realm: "console"`, `aud` = this system's host (M20) |
| `GET /v1/users`, `POST /v1/users`, `POST /v1/users/{id}/reset-mfa`, `POST /v1/users/{id}/disable` | api | `01 §4` users, `06 §3` | `admin` | console accounts and roles; every change audited |
| `GET /.well-known/jwks.json` | api | `06 §2` T4 | public | the ANSP's signing keys (`use: sig`, distinguished by `kid`): console session tokens, the detached JWS of CISP publications and the compact JWS of degraded direct deliveries (M26) |
| `GET /uss/v1/constraints/{entityid}` | api | F3548-21 USS API; `02 F2`, `09 §1.4` | ecosystem token, scope `utm.constraint_processing` | the `ConstraintDetails` of a restriction, for USSPs that discovered the reference in the DSS; answered within `CstrMaxTimeSendDetailsSeconds` |
| `POST /v1/cis/notifications` | api | `02 F3` | compact JWS (`application/jose`) signed by an issuer on `ANSP_CIS_NOTIFY_ISSUERS` (the CISP; JWKS URL from configuration), `aud` = the host of this system's registered `callback_url`, `sub` = the subscription id, `jti` = the delivery id (M1, M19) | the CISP's `cis/change/v1` notification; triggers a pull of the named dataset. Reasons `subscription_test`, `republished` and any unknown reason are acknowledged `204` without a pull (M16); `pull_url` is honoured only when its host equals the issuer's configured base host |
| `GET /healthz`, `GET /readyz`, `GET /metrics` | each process | `05` | network-local | liveness, readiness (dependencies named, never hidden), Prometheus |

Outbound calls this system makes (contracts owned elsewhere, consumed as
published OpenAPI or standard):

| Call | Owner of the contract | Spec |
|---|---|---|
| `POST /v1/restrictions` with a `cis/restriction/v1` body `{ansp_ref, ansp_version, uspace_airspace_id, state, starts_at, ends_at, feature}` and `PATCH /v1/restrictions/{id}` `{op, ansp_version, ends_at?}` on the CISP; the idempotency key is the body pair `(ansp_ref, ansp_version)`, an `Idempotency-Key` header is optional and unread (M4); detached JWS over the body in `X-JWS-Signature` (`<protected>..<signature>`, RFC 7515 App. F, RFC 7797 `b64: false`, `crit: ["b64"]`, `alg RS256`, `kid`, `iat` ≤ 5 min; key from this system's JWKS, M26); scope `cis.publish:restrictions`; `aud` = the CISP's host; mTLS client cert bound to the client id `ansp-01` (M24) | `uspace-cisp` (`api/clients/cisp.yaml`) | `02 F2` |
| `POST /v1/publishers/heartbeat {sent_at, active_refs: [<ansp_ref>...]}` every `cisp_heartbeat_s` (15 s); the CISP flags this publisher `source stale` after 60 s (three misses); `204` (M3) | `uspace-cisp` | `02 F2` failure rule |
| `GET /v1/uspace_airspace`, `GET /v1/ussp_list`, `GET /v1/restrictions` with `ETag` (and `?applies_at=` for annotation, M17); `POST /v1/subscriptions {callback_url: <public base>/v1/cis/notifications, datasets}`; scope `cis.read` | `uspace-cisp` | `02 F3` |
| `PUT /dss/v1/constraint_references/{entityid}`, `DELETE .../{entityid}/{ovn}`, `GET .../{entityid}`; scope `utm.constraint_management`; `aud` = the DSS's host (M18) | InterUSS DSS (F3548-21) | `02 F2`, `02 F6` |
| `POST {uss_base_url}/uss/v1/constraints` to each subscriber the DSS returns, within `CstrPublishedNotificationLatencySeconds`; `aud` = the host of that `uss_base_url` (M18) | each USSP (F3548-21 USS API) | `02 F6` |
| Degraded direct delivery: `POST {base_url}/v1/cis/notifications` on every USSP of the CIS USSP list and on the authority (the same path the CISP posts to; M1, M5) with a `cis/change/v1` payload as a compact JWS (`application/jose`) signed by the ANSP: `iss` = this system, `aud` = the host of the target base URL, `sub` = the restriction id, `jti` = the delivery id, `iat`; `pull_url` = this system's `GET /v1/restrictions/{id}` (the receiver pulls only when the host matches the ANSP's configured base host); the receiver allow-lists the ANSP issuer beside the CISP's | `uspace-ussp`, `uspace-authority` | `02 F2` failure rule |
| `POST /v1/occurrences` on the authority (`occurrence/v1`, schema owned by the authority); scope `occurrences.write`; `aud` = the authority's host | `uspace-authority` (`api/clients/authority.yaml`) | `02 F7`, `F11` |
| `POST /oauth/token` (client credentials, `client_id = ansp-01`, `audience` = the host of the target per call) and `GET /.well-known/jwks.json` on the authority | `uspace-authority` | `06 §3` |

---

## 7. Bus subjects and internal messages

One NATS cluster for this system, on its own network, with per-process
credentials (`00 §6.2`). No cross-system NATS. Subjects (D2: no H3):

| Subject | Stream | Producer → consumer | Message |
|---|---|---|---|
| `man.v1.<adapter>.<icao24>` | core (ephemeral) + JetStream mirror `MAN_MIRROR`, 1 h retention | `manned-adapter` → `manned-feed` | `track/manned/v1` (schema in `schemas/track/manned/v1.json`; `04 §3.1` fields plus the envelope of `04 §2`: `schema`, `msg_id`, `producer`, `ts`, `rx_ts`, `captured_at`, `time_source`, `backlog`, `trust: surveillance`, `source: ansp_feed`, `source_instance: <adapter>`) |
| `src.v1.manned.<adapter>` | core | `manned-adapter` → `api`, `manned-feed`, console | `source/status/v1` every 2 s: instance, enabled, last seen, accepted, refused, dropped, stalled, `policy_version` |
| `restr.v1.<state>.<restriction_id>` | JetStream `RESTR`, 30 d | `api` (restriction) → `api` (outbox), console stream | `restriction/state/v1` (`04 §3.4`): `restriction_id`, `ansp_ref`, `state`, `starts_at`, `ends_at`, `feature`, `ansp_version` |
| `deliver.v1.<kind>` | JetStream work queue `DELIVER`, explicit ack, `max_deliver` by policy, 24 h | `api` (restriction, coord) → `api` outbox worker | a delivery job: kind, subject ref, idempotency key, attempt |
| `cis.v1.<dataset>` + KV `cis_current` | JetStream 30 d + KV | `api` (cis client) → `manned-feed`, `api` | the projected dataset version and body (U-space volumes, USSP list, restrictions as the CISP shows them) |
| `ctl.sources` + KV `source_control` | KV + push | `api` → `manned-feed`, adapters | `sources.State` (`04 §3.6`); followers apply by version within epoch (B-09) |
| `ctl.policy` + KV `policy` | KV + push | `api` → hot path | the `ansp_policy` row and `policy_version` |
| `coord.v1.<kind>.<ack_id>` | JetStream `COORD`, 30 d | `api` (coord) → console stream, escalation timer | a received notice and its state changes |

Rules: adapters publish and never subscribe (except `ctl.sources` for
their own switch); `manned-feed` holds JetStream pull consumers with
explicit ack for the mirror replay only and core subscriptions for the
live path; every consumer reconnects forever (B-08); a process that cannot
reach NATS at start retries three times with backoff then starts degraded
and says so in `/readyz` and its log (E-02, SC-08 step 8).

---

## 8. Security

| Boundary | Mechanism | Scopes / roles |
|---|---|---|
| USSPs and the authority → F4 stream and snapshot | ecosystem RS256 JWT verified by `uspace-core/auth` (issuer allow-list = the authority's token service and, in the lab, the lab issuer, from configuration; `aud` ∈ `ANSP_AUDIENCES`, a list of hosts: this system's public host plus a lab alias such as the compose service name, M18; `exp` with 30 s skew; `jti`); mTLS per `ANSP_MTLS_MODE = required \| off` (M25): Caddy terminates with `client_auth { mode verify_if_given }` and forwards `X-Client-Cert-Subject` (stripped on every other route); the Go middleware believes the header only from a peer in `ANSP_TRUSTED_PROXIES` (from any other peer it is ignored, as no certificate), requires it and binds the subject to the `sub` on the mTLS route groups only (`/v1/manned-traffic/*`, `/v1/coordination/*`); `off` is logged at error level every status period | `ansp.traffic` |
| USSPs → coordination intake | ecosystem JWT; the `sub` must appear on the CIS USSP list projection, else `403` and an audit row; mTLS per `ANSP_MTLS_MODE` | `ansp.coordination` (in the `06 §3` catalogue held by authority WP-2, M23) |
| Authority → restriction requests | ecosystem JWT | `ansp.requests` (in the catalogue, M23) |
| USSPs → constraint details | ecosystem JWT with the F3548 scope | `utm.constraint_processing` |
| CISP → change notifications (`/v1/cis/notifications`) | compact JWS (`application/jose`) verified with core's `auth.VerifyCompact` against the JWKS of an issuer on `ANSP_CIS_NOTIFY_ISSUERS`; `iss`, `aud` (= the host of the registered `callback_url`), `jti` (replay window 5 min) checked; `pull_url` host must equal the issuer's configured base host | — |
| This system → CISP, DSS, authority, USSPs | client-credentials tokens from the authority's token service as client `ansp-01`, one token per (`aud` = the target's host, scope set), fetched at 50 % TTL (`06` T5); mTLS client certificate for the CISP publication and heartbeat (`02 F2`); detached JWS (`X-JWS-Signature`) on CISP publications and compact JWS bodies for degraded direct deliveries, signed with core's `auth.SignDetached` / `SignCompact` (key in `/.well-known/jwks.json`, M26, M27) | `cis.publish:restrictions`, `cis.read`, `utm.constraint_management`, `utm.constraint_processing` (subscriber notifications), `occurrences.write` |
| Surveillance feeds → adapters | network isolation per adapter (dedicated interface or mTLS where the feed supports it); an adapter refuses `trust: simulated` and `source: sitl` outside the lab build (`06` T11); the replay adapter is enabled only by explicit configuration and is shown as `replay` on the console | — |
| Humans → console | local accounts (argon2id), TOTP MFA mandatory for every role (`01 §4`), roles `watch_supervisor`, `viewer`, `admin`; the Next.js BFF exchanges the login for the `uspace_session` cookie (`HttpOnly; Secure; SameSite=Strict`) holding a session JWT issued by this system's `uspace-core/auth` Issuer with `iss` = this system, `aud` = this system's host, `sub` = account id, `scope = "session"`, `roles: [role]`, `realm: "console"`, `jti` = session id, `exp` ≤ 12 h, `kid` (M20), verified by `api` and `manned-feed` with the same `core/auth.Verifier` as machine tokens; `uspace_csrf` cookie and `X-CSRF-Token` header on every state-changing call (M21); WebSocket upgrades take the cookie on a same-origin request checked against an `Origin` allow-list, no ticket (M22); login rate limits (S-15) | roles |
| Internal NATS | per-process credentials, isolated network, no JWT | — |

Threats of `06 §2` that land here: T4 (impersonation: scopes, `aud`,
mTLS, JWS), T5 (token outage: tokens valid to TTL, JWKS cached 24 h;
restrictions already active stay active), T7 (tamper: hash-chained
`events`, no `UPDATE` on `manned_tracks`), T8 (flood on the F4 WS: per
client connection cap and 2 Hz frame cap, Caddy rate limit), T9 (a faulty
peer: body size caps 1 MiB, ED-318 and F3548 validated on receipt by
`uspace-core` and refused, never repaired), T10 (public repo: gitleaks,
pinned modules, SBOM, cosign), T11 (simulator in production), T12
(duplicated judgement: lint fails a geometry import in `web/`; every
geometric check in Go is a `uspace-core` call).

Public-repository constraints (`06 §4`): no secret or test key committed
(test keys are generated at test time); no hostname outside
`deploy/staging/`; fixtures use `GEO-TEST-*` and synthetic ICAO addresses;
`SECURITY.md` with a 90-day policy; branch protection on `main` requiring
CI.

---

## 9. Performance budgets (from spec `05`)

The ANSP is independent of drone count. Budgets are per process on one
core, with the margins that make the `05 §7` load-test criteria pass at
every tier.

| Path | Load (100 / 1000 / 5000 drones) | Budget | Target |
|---|---|---|---|
| Restriction activation → CISP publication request sent | a few per day, bursts of tens | the outbox picks the job up within 100 ms of the commit | CISP-accepted → subscribers within 1 s is the CISP's figure (`01` C5); the ANSP's leg ≤ 200 ms p99 (commit to request on the wire) |
| Restriction activation → DSS `PUT` and subscriber `POST`s | same | `CstrPublishedNotificationLatencySeconds = 5` end to end | DSS write ≤ 1 s p99; every subscriber notified ≤ 3 s p99 after the DSS answer |
| `GET /uss/v1/constraints/{entityid}` | one per USSP per change | `CstrMaxTimeSendDetailsSeconds = 5` | ≤ 200 ms p99 (served from `restriction_versions`) |
| Adapter frame → F4 WS frame out | tens of aircraft × 1 Hz (independent of tier) | ingest-to-picture p99 < 1 s (`05 §7`) | ≤ 250 ms p99 adapter `rx_ts` → WS write; `BenchmarkNormalise` ≤ 20 µs, `BenchmarkPictureUpsert` ≤ 5 µs, `BenchmarkRelevance` (point in ≤ 20 U-space volumes with margin) ≤ 50 µs |
| F4 consumers | 2 USSPs + authority now; ≤ 20 clients | 1 Hz × aircraft × clients; server-side throttle at 2 Hz per track | 20 clients × 100 aircraft = 2000 frames/s on one core with margin 10× |
| Snapshot | on connect | ≤ 100 aircraft | ≤ 50 ms p99 |
| TimescaleDB writer | tens of rows/s | batched `COPY` every 1 s or 500 rows; bounded buffer 50 000 rows (B-07) | writer lag < 10 s; mirror replay after an outage drains at ≥ 5× intake (B-01) |
| Coordination intake | a few per minute | `202` ≤ 100 ms p99; escalation timer ± 1 s | — |
| Memory | — | no monotonic growth over a 2 h soak; picture bounded by `max_aircraft` (policy, default 5000) with eviction counted (E-10) | — |

Targets are design budgets reported by `make bench` and the job summary,
never gated; the lab's L-M2 load test is the proof.

---

## 10. Testing strategy

### 10.1 Levels

| Level | What | Where it runs |
|---|---|---|
| Unit | every package; E-01 presence/absence pairs; E-10 bound tests; `-race -shuffle=on`; ≥ 85 % statement coverage per package, ≥ 90 % in `restriction`, `manned`, `picture`, `deliver`, `dss`, `coord` | every push |
| Vectors | `uspace-core/vectors` `RunOwned(t, "ansp", ...)` for the files that name this system (`ed318_roundtrip.json`, `jwt_verify.json`, `source_control.json`), run against this repo's adapters (the restriction feature builder, the token middleware, the switch follower), never a second judgement | every push |
| Schema examples | every message in `schemas/examples/` validates against its schema and round-trips through the Go struct; the generated TypeScript types compile against them | every push |
| Contract | `api/openapi.yaml` lints (`vacuum` or `redocly`, pinned); generated code is current (`scripts/generate-check.sh` diff); the OpenAPI examples pass the strict server's validation; the client in `api/gen` exercises every operation against the server in a test | every push |
| Integration | real PostgreSQL + PostGIS, TimescaleDB and NATS as GitHub Actions `services:`; migrations up and down; the restriction state machine end to end through HTTP with the outbox delivering to an in-test CISP, DSS and USSP stub (every stub records what it got, so presence is asserted: the publish happened, the `PUT` happened, the subscriber `POST` happened, within budget); degraded path with the CISP stub down; `manned-feed` from replay frames to a WS client with the stall case of SC-15; source switch of SC-08; CIS change notification → pull → KV | every push, job `integration` with path filters |
| Scenario (milestone proof) | N-M1 and N-M2 of `07` Phase 5 against the sibling images and the lab's SITL, DSS and simulated USSP, from `deploy/compose.yaml`; recorded in `docs/runbooks/` with timings (E-04) | WP-13; on demand |
| Conformance hooks | the lab's suite (`uspace-lab/conformance/`, L-M4) runs InterUSS `uss_qualifier` constraint-management checks against the ANSP and the lab DSS, and the national OpenAPI contract tests from the aggregated `api/openapi.yaml`; this repo exposes `make conformance-target` (brings up the stack with lab-issued test keys) and a `testdata/conformance/` directory for the suite's configuration | lab CI, release |
| Fuzz | `FuzzSBSLine`, `FuzzAircraftJSON`, `FuzzReplayFrame` (adapter inputs), `FuzzAnnexVNotice`, `FuzzRestrictionRequest` (inbound JSON), 10 s each | every push |
| Bench | the targets of §9 | reported |
| Web | `eslint` (+ the no-geometry-import rule), `tsc --noEmit`, `next build`, generated types current, Playwright smoke (login with MFA, plan and activate a restriction against the mocked API) | path-filtered |

### 10.2 Rules every work package follows

- **E-01** every test that asserts nothing happened (no publish, no alert
  clear, no refusal, no delivery) has the twin that makes it happen.
- **E-02** the success path is exercised and its output read: the
  delivery log says `sent 201`, the status line says `healthy`, the
  readiness says what is reachable; and the dependency is taken away
  (CISP down, DSS down, NATS down, KV empty, no CIS projection) and the
  exact degraded output and counter are asserted (SC-22).
- **E-03** no wire format from memory: dump1090 field names come from its
  `README-json.md` at a pinned commit recorded in
  `internal/manned/dump1090/SOURCE`, with recorded sample lines in
  testdata; F3548 and ED-318 member names come from `uspace-core`'s
  generated types; `coordination/annex_v/v1` is this repo's own schema
  (`schemas/coordination/annex_v/v1.json`, M14); `cis/change/v1`,
  `cis/restriction/v1` and `cis/ussp_list/v1` fields come from the
  CISP's OpenAPI file pinned under `api/clients/cisp.yaml` with its
  `SOURCE` commit (M11), `occurrence/v1` from the authority's copy; the
  envelope and the console frames from `uspace-lab/schemas/common/`.
- **E-04** a PR reports what was run and what it printed; a skipped
  integration job is reported as skipped.
- **INV-02** the restriction and manned paths are not done until a SITL
  aircraft and a replayed manned track have driven them (N-M1); a unit
  test alone does not close WP-5, WP-6, WP-8 or WP-9.
- **T-11 / SC-15** every adapter has the stall test: input buffered for
  30 s is placed by its own time base or flagged `backlog`, never
  stamped as now.
- **B-11** a disabled adapter's tracks age out as `source_disabled`
  within one tick, visibly, and other adapters are untouched.

---

## 11. Deployment

- One image `ghcr.io/rootxkit/uspace-ansp` built in CI on `main` and
  tags (multi-stage, distroless, cosign-signed, SBOM attached), with the
  three binaries and `ENTRYPOINT` chosen by the compose service; a second
  image `ghcr.io/rootxkit/uspace-ansp-web` for the Next.js build. Next.js
  is never built on the server.
- `deploy/compose.yaml`: `api`, `manned-feed`, `manned-adapter-replay`
  (staging) or `manned-adapter-<feed>` (production), `web`, a one-shot
  `migrate` service (both trees; the long-running services depend on
  its completion, M36), one `timescale/timescaledb-ha:pg16` container
  holding **both** databases (it ships PostGIS; the relational database
  and the timeseries database stay separate databases with separate
  version tables, M37; two hosts only when the system outgrows it), and
  `nats` (JetStream, file store, per-process credentials), on an
  isolated network. Caddy is the only shared component on the droplet
  (`05 §6`), and its Caddyfile is composed by the private deployment
  repo `uspace-deploy` from each system's snippet (D1); it also serves
  `/basemap/*` for every console from one shared read-only volume
  (M38). Resource limits sized for the ANSP stack's share (≤ 600 MB,
  ≤ 0.5 vCPU, measured in WP-13); the droplet's own sizing is an open
  owner question (reconciliation §2.1).
- `deploy/caddy/ansp.caddy`: the `uspace-ansp.<domain>` **snippet**
  (domain from the private infra repo, never in code), consumed by
  `uspace-deploy`: `/v1/manned-traffic/*` → `manned-feed`, `/uss/*`,
  `/v1/*`, `/.well-known/*` → `api`, `/_bff/*` and the rest → `web`;
  `client_auth { mode verify_if_given, trusted_ca_cert_file ... }` on
  the host, `X-Client-Cert-Subject` forwarded on the mTLS route groups
  and stripped everywhere else (M25); `/metrics` never routed.
- `web/` uses `pnpm` (`packageManager` pinned, `--frozen-lockfile`),
  fonts from the kit through `next/font/local`, the kit's CSP
  (`connect-src 'self'`, `font-src 'self'`, `worker-src blob:`), and the
  basemap at `/basemap/` served by the deployment's Caddy; no third-party
  tile or font request, ever (M34, M38).
- Configuration through environment variables only
  (`internal/config`), documented in `deploy/.env.example`; the configured
  addresses are exactly the DSS, the CISP of record, the authority's token
  service and JWKS, and the feed endpoints (`00 §7`). `ANSP_MTLS_MODE` is
  `required` in production and `off` on the staging droplet and in the
  lab (M25).
- Backups: nightly `pg_dump` of the relational database and
  TimescaleDB chunk backups to a second account (S-22 pattern); rollback
  by image tag (S-21).
- Production: separate infrastructure run by the ANSP; the same compose
  shape, with the real surveillance adapters and mTLS required.

---

## 12. Milestones

| Milestone | Done when (spec `07` Phase 5, plus the scaffold) |
|---|---|
| N-M0 Scaffold and contracts | module builds with the pinned `uspace-core`; CI green on the skeleton; `api/openapi.yaml` published with every endpoint of §6 and generated code committed; schemas published; migrations apply to a real database in CI; the three processes start, report `/readyz` with every dependency named, and start degraded without NATS or the database (E-02) |
| **N-M1 Restrictions and manned feed** (first demo) | a supervisor activates a restriction over a SITL aircraft: the CISP publishes within 1 s and the DSS constraint is written and its subscribers notified within 5 s, the USSP raises `restriction_activated` on the affected intent within one tick, the authority shows it; a recorded (synthetic) ADS-B file streams as manned traffic to the USSP and the authority (ATS.OR.127); every delivery is in the log; the console shows it all; timings recorded in `docs/runbooks/n-m1.md` |
| N-M2 Coordination and degraded paths | the Annex V inbox receives intents touching the restricted volume and non-conformance notices, answers with `ack_id` and a supervisor acknowledges them (Art. 13(2)); with the CISP down, the restriction reaches the USSPs and the authority by the direct path, the supervisor alarm fires after 10 s, and the CISP reconciles when back; an adapter stalled for 30 s raises nothing from old positions (SC-15); a disabled adapter ages out as `source_disabled` (SC-08); an occurrence report reaches the authority |
| N-M3 Release | images signed and published; the lab's conformance hooks run green; `docs/runbooks/` complete; the owner tags `v1.0.0` of this repo |

---

## 13. Work packages and waves

Each WP has a brief in `docs/WORKPACKAGES/WP-<k>.md` that is complete on
its own. Branch `feat/WP-<k>-<slug>`. Commit suffix `[WP-<k> N-M<n>]`.
Done-when always includes: gofmt, vet, staticcheck and golangci-lint
clean with the pinned versions; `go test -race -shuffle=on` green; the
integration job green where the WP touches a store or the bus; generated
code current; coverage as §10.1; the package `doc.go` rewritten; a
CHANGELOG line; the PR body lists the commands run and their last lines
(E-04).

| WP | Slug | Owns (exclusively) | Depends on | Milestone |
|---|---|---|---|---|
| WP-0 | `scaffold` | `go.mod`, `cmd/*` stubs, `internal/config`, `internal/obs`, `internal/bus`, `Makefile`, `.golangci.yml`, `.github/workflows/`, `deploy/Dockerfile`, `deploy/compose.yaml` (dev), `CLAUDE.md`, `SECURITY.md`, `CHANGELOG.md`, `.gitleaks.toml`, `.gitattributes` | — | N-M0 |
| WP-1 | `store-migrations` | `migrations/relational/0001–0019`, `migrations/timeseries/0001–0009`, `internal/store`, `internal/audit`, `internal/policy` | WP-0 | N-M0 |
| WP-2 | `auth-accounts` | `internal/auth`, `migrations/relational/0020–0029` (users, sessions, mfa, oauth_clients_seen) | WP-0 (store helpers from WP-1 are used once merged; until then the WP writes against pgx directly behind its own interface) | N-M0 |
| WP-3 | `openapi-contract` | `api/openapi.yaml`, `api/oapi-codegen.yaml`, `api/gen`, `api/clients/` (pinned sibling copies + `SOURCE` + CI diff), `schemas/` (including `coordination/annex_v/v1`, owned here), `scripts/generate*.sh`, the contract tests | WP-0 | N-M0 |
| WP-4 | `manned-adapter` | `internal/manned` (model, adapter, replay, dump1090, asterix stub), `cmd/manned-adapter`, `testdata/replay/` | WP-0 | N-M1 |
| WP-5 | `restrictions` | `internal/restriction`, `migrations/relational/0030–0039`, restriction and restriction-request handlers in `cmd/api` | WP-1, WP-2, WP-3 | N-M1 |
| WP-6 | `manned-feed` | `internal/picture`, `internal/feed`, `internal/sources`, `cmd/manned-feed`, `migrations/timeseries` additions in `0010–0019` | WP-1, WP-2, WP-4 | N-M1 |
| WP-7 | `cis-projection` | `internal/cis`, `migrations/relational/0040–0049` (`cis_cache`), the webhook handler, `testdata/fixtures/` | WP-1, WP-2, WP-3 | N-M1 |
| WP-8 | `outbox-cisp` | `internal/deliver`, `migrations/relational/0050–0059` (`deliveries`), the CISP publisher, heartbeat, degraded direct delivery, JWKS endpoint | WP-5, WP-7; `uspace-core v1.1.0` for the JWS helpers (core WP-14, which runs in the cross-repo wave 0 while this WP is in wave 3, so it does not wait in practice) | N-M1 |
| WP-9 | `dss-constraints` | `internal/dss`, `migrations/relational/0060–0069`, `GET /uss/v1/constraints/{entityid}` | WP-5, WP-8 (the outbox carries DSS jobs) | N-M1 |
| WP-10 | `coordination-inbox` | `internal/coord`, `migrations/relational/0070–0079`, coordination, inbox and occurrence handlers | WP-1, WP-2, WP-3, WP-7 (USSP list) | N-M2 |
| WP-11 | `console-restrictions` | `web/` (app shell, auth/BFF, i18n, restriction map editor and list, adapters page) | WP-3 (types), WP-5, WP-2; `@rootxkit/uspace-ui` ≥ 0.1 from npmjs (`RestrictionLayer` ships in 0.1.0, M33) | N-M1 |
| WP-12 | `console-picture-inbox` | `web/` manned picture layer, coordination inbox, audit view, source switches | WP-11, WP-6, WP-10; `@rootxkit/uspace-ui` ≥ 0.3 (`MannedLayer`, M33) | N-M2 |
| WP-13 | `deploy-proof` | `deploy/` (prod compose, Caddy, GHCR publish, cosign, SBOM), `docs/runbooks/n-m1.md`, `n-m2.md`, `make conformance-target`, `testdata/conformance/` | all | N-M1, N-M2, N-M3 |

Waves (what can run in parallel):

```
wave 0 (1 agent):            WP-0
wave 1 (4 agents):           WP-1  WP-2  WP-3  WP-4
wave 2 (3 agents):           WP-5 (1,2,3)   WP-6 (1,2,4)   WP-7 (1,2,3)
wave 3 (3 agents):           WP-8 (5,7)   WP-9 (5,8)   WP-10 (1,2,3,7)   WP-11 (2,3,5)
wave 4 (2 agents):           WP-12 (6,10,11)   WP-13 (all)
N-M1 is proven when WP-5, 6, 8, 9, 11 and the N-M1 runbook of WP-13 merge
N-M2 is proven when WP-10, 12 and the N-M2 runbook merge
```

Dependency graph (edges point at what is needed first):

```
WP-0 ← WP-1 ← WP-5 ← WP-8 ← WP-9
WP-0 ← WP-2 ← WP-5, WP-6, WP-7, WP-10, WP-11
WP-0 ← WP-3 ← WP-5, WP-7, WP-10, WP-11
WP-0 ← WP-4 ← WP-6 ← WP-12
WP-7 ← WP-8, WP-10
WP-11 ← WP-12
everything ← WP-13
```

Critical path: WP-0 → WP-1 → WP-5 → WP-8 → WP-9 → WP-13 (N-M1 proof).
WP-5 is the largest brief and is on it; it opens its PR as soon as the
state machine and the ED-318 feature pass, and WP-8 starts against its
interfaces the day the PR opens. WP-9 may start its DSS client against
`uspace-core/f3548` types before WP-8 merges and rebases.

Cross-WP conflicts are avoided by exclusive directory ownership and the
migration number ranges. Shared files: `CHANGELOG.md` (one line per WP),
`api/openapi.yaml` after WP-3 (a WP that adds an operation edits the file
and regenerates in the same PR; WP-3 writes every operation of §6 up
front, so later WPs only fill handlers), `cmd/api/main.go` wiring (each
WP adds its own `register<Package>(...)` call; conflicts are one-line).

---

## 14. Engineering standards

Inherited from `uspace-core` `docs/PLAN.md §8` and `CLAUDE.md`, with the
system-level additions below. The repo's `CLAUDE.md` is the authoritative
short form.

- `gofmt`, `go vet` (+ `govet enable-all` minus `fieldalignment`,
  `shadow`), staticcheck v0.8.1, golangci-lint v2.14.0 with the core
  `.golangci.yml` adapted: `forbidigo` forbids `panic`, `fmt.Print*`,
  `log.*` and `os.Exit` outside `cmd/*/main.go` and tests; `exhaustive`
  over every state enum; generated files (`*.gen.go`, `*.sql.go`) exempt
  from style linters, never from `vet`.
- `go test -race -count=1 -shuffle=on ./...` on every push; every
  stateful component (`picture.Picture`, `deliver.Outbox`,
  `sources.Follower` wrapper, `cis.Projection`, adapters) has a
  concurrency test or documents single-goroutine use.
- No panic on untrusted input: feed lines, JSON bodies, tokens, webhook
  bodies and DSS responses are bounded (bytes, depth, counts) and refused
  with `*core.FieldError` or RFC 9457 problems that name the field.
- Everything refused, dropped, degraded or stalled is a `core.Counters`
  name exported as a Prometheus counter with the same snake_case name,
  and appears in the process's status line and `src.v1` message (E-09).
- Units and datums in every name (E-13): `alt_pressure_m`, `alt_wgs84_m`,
  `gs_ms`, `vrate_ms`, `feed_margin_lateral_m`; Go `AltPressureM`,
  `GSMS`, `MarginLateralM`. Pressure altitude is never written to an
  AMSL column (`04 §3.1`).
- Structured logs with `slog` JSON, every line carrying `process`,
  `instance`, and where it applies `adapter_id`, `icao24`,
  `restriction_id`, `ack_id`, `client_id`, `policy_version`.
- Commits: `type(scope): subject [WP-k N-Mn]`; scopes `api`, `adapter`,
  `feed`, `restriction`, `dss`, `cis`, `deliver`, `coord`, `auth`,
  `store`, `web`, `deploy`, `ci`, `docs`. No AI attribution of any kind.

---

## 15. Open questions and proposed answers

Where the spec is silent or ambiguous. The cross-plan reconciliation of
2026-10-02 (`uspace-lab`, "Cross-plan reconciliation", §2) decided every
row the coordinator could decide; those rows are marked **decided** with
the answer this plan now follows and the mismatch id (`Mnn`) that
carries it. Four rows (3, 11, 12, 17) are **owner-only**: they stay open,
the plan builds the demo default stated in the row, and nobody invents
the policy answer.

| # | Gap | Answer | Status |
|---|---|---|---|
| 1 | `00 §6.1` lists two ANSP processes and gives the F4 stream to `manned-adapter`; several adapter instances cannot each serve the union. | A third process `manned-feed` serves F4 and writes TimescaleDB (D1). Spec erratum for `00 §6.1` and `05 §2` (lab WP-L4). | **decided** (§2.2 ansp 1) |
| 2 | `05 §3` partitions internal subjects by H3; core has no H3 (cgo). | No H3 and no cells here: `man.v1.<adapter>.<icao24>` (D2). Core ships a pure-Go grid (`geodesy/cell`) for the authority and the USSP; the ANSP does not partition. | **decided** (M30, M35) |
| 3 | Vertical reference of a dynamic restriction: ED-318 allows AGL; F3548 constraints need W84. | Demo default: AMSL or WGS84 only (D3); AGL refused with a reason; AMSL → HAE through `uspace-core/geoid` with the minimum undulation over the vertices for the lower limit and the maximum for the upper (conservative). | **open, owner-only**: how Sakaeronavigatsia's ATC states levels (reconciliation §2.1) |
| 4 | ED-318 identifier of a restriction: `03 §6` says prefixed `DAR-`; the identifier is at most 7 characters. | `DAR` + 4 base-36 characters, no hyphen (D4); the CISP enforces only `≤ 7` and uniqueness across datasets, never a prefix. Spec erratum for `03 §6`. | **decided** (M10) |
| 5 | `03` says `golang-migrate`; the fixed stack says goose. | goose, two embedded trees, version tables `goose_db_version_relational` / `goose_db_version_timeseries`; a `migrate` subcommand plus a one-shot compose service; long-running processes never migrate (§5.3). Spec erratum for `03`. | **decided** (M36) |
| 6 | Art. 13(2) acknowledgement: `02 F13` returns an `ack_id` synchronously; `03 §4` records `acknowledged_by` (a person). | Two states: `received` (the `ack_id` in the `202`) and `acknowledged` (a `watch_supervisor` on the console, within `notice_escalation_s`, else escalated). No push to the USSP in v1; the USSP polls `GET /v1/coordination/notices/{ack_id}` every 10 s for 5 min. | **decided** (M2; ussp Q10) |
| 7 | `06 §3` lists `ansp.traffic` and nothing for the F11 and F13 inbound calls. | `ansp.coordination` (USSPs → `/v1/coordination/*`) and `ansp.requests` (authority → `/v1/restriction-requests`) are in the scope catalogue held by authority WP-2; a further scope opens a PR there first. | **decided** (M23) |
| 8 | mTLS for F4: `01 §4` says "available", `02 F4` says "mandatory". | `ANSP_MTLS_MODE = required \| off`: `required` in production, `off` on the staging droplet and in the lab (the lab's simulated USSP has no certificate); covers `/v1/manned-traffic/*` and `/v1/coordination/*`; Caddy `client_auth verify_if_given` + `X-Client-Cert-Subject`, bound in Go on those routes only; `off` logged at error level every status period. | **decided** (M25) |
| 9 | `02 F2` failure rule: the CISP flags the ANSP `source stale` after 60 s of missed heartbeat, but the CISP's API lists no heartbeat endpoint. | `POST {cisp}/v1/publishers/heartbeat {sent_at, active_refs: [<ansp_ref>...]}` every `cisp_heartbeat_s` = 15 s (three misses = 60 s stale); `204`. No configurable path. | **decided** (M3) |
| 10 | Degraded direct delivery (`02 F2`): "sends the restriction directly to subscribed USSPs and the authority on the same contract (F3 payload)" names no endpoint on the USSP or authority. | `POST {base_url}/v1/cis/notifications` on every USSP of the CIS list and on the authority, the one receiver path the CISP also posts to; payload `cis/change/v1` as a compact JWS signed by the ANSP (`iss` = ANSP, `aud` = the target's host, `sub` = restriction id, `jti` = delivery id); receivers allow-list the ANSP issuer beside the CISP's and honour `pull_url` only on the ANSP's configured host. No per-target path configuration. | **decided** (M1, M5) |
| 11 | `02 F2`: "the ATS.OR.127 operational data items the ANSP agrees with the authority (Annex V SLA)" are undefined. | Demo default: out of scope until the SLA names them; the plan reserves no table; when defined they become a dataset through the same outbox (the CISP reserves `ats_operational_data` and `cis.publish:ats_data`). | **open, owner-only**: Annex V SLA between GCAA and Sakaeronavigatsia (spec Q3) |
| 12 | Which surveillance formats the ANSP can hand over (Q3, Q14): ADS-B via dump1090-style outputs, ASTERIX CAT021/CAT062 from the ATM system, or an ATM API. | Demo default: the replay adapter and the dump1090 readers (SBS text and `aircraft.json`) with field names pinned to dump1090's documentation; ASTERIX is a stub that refuses to start with a reason; an ATM API adapter waits for the agreement. | **open, owner-only**: Sakaeronavigatsia's data-release agreement (spec Q3, Q14) |
| 13 | Must a restriction lie inside a designated U-space airspace (Art. 4 says the ATC unit limits the area *inside* U-space airspace), when none is designated yet (Q2)? | Always: a restriction must intersect a current `USPACE` feature in `cis_cache` and names its `uspace_airspace_id` (refused otherwise; `503 cis_stale` when the projection is stale). The CISP is strict too, so a free-standing restriction would be unpublishable; the `require_uspace_airspace = false` option is dropped. The lab publishes a designation for every demo (C-M2, N-M1). | **decided** (M9) |
| 14 | Field naming: `02 F4` says `pressure_alt_m`, `03 §4` and `04 §3.1` say `alt_pressure_m`; `02 F4` calls the message `manned_track.v1`, `04` calls it `track/manned/v1`. | `alt_pressure_m` and `track/manned/v1` (`$id` `https://schemas.uspace.ge/track/manned/v1.json`), E-13 order. Spec erratum for `02 F4` (lab WP-L4). | **decided** (§2.2 ansp 14) |
| 15 | Who owns the schema of `coordination/annex_v/v1` (produced by the USSP, consumed here) and of `cis/change/v1` (CISP)? | The repo whose `api/openapi.yaml` carries the body owns it: **this repo owns `coordination/annex_v/v1`** (`schemas/coordination/annex_v/v1.json` with examples, published by WP-3) and the USSP consumes it; the CISP owns `cis/change/v1`. No `x-pending-schema` wait. Sibling APIs are consumed as pinned copies under `api/clients/<system>.yaml` with a `SOURCE` commit and a CI diff until the lab aggregate (`uspace-lab/api/`, `schemas/`) replaces them. | **decided** (M11, M14) |
| 16 | The F3548 `ConstraintDetails.type` for a dynamic restriction: `04 §3.5` says `DAR`; InterUSS examples use reverse-DNS strings. | `type: "DAR"`; the ED-318 feature in `ConstraintDetails.geozone` where `uspace-core/ed318.ToED269` can map it, else omitted with a counter, the restriction still valid. | **decided** (§2.2 ansp 16) |
| 17 | Occurrence reporting by the ANSP (376 Art. 4(8)) and the 2017/373 record-keeping period (ATM/ANS.OR.B.030, unverified). | Demo default: a console form that queues `occurrence/v1` to the authority (`occurrences.write`) with the 72 h deadline shown; records kept per `05 §4` defaults (restrictions and audit indefinitely, manned tracks 90 days online then archived). | **open, owner-only**: Sakaeronavigatsia's safety office states the period |
| 18 | `uspace-core` version to pin. | `v1.1.0` (released; the newest tag when WP-0 landed), which already carries the JWS helpers (core WP-14), so WP-8 needs no bump. | **decided** (§2.2 ansp 18, M27; WP-0 pinned v1.1.0) |
| 19 | The console's manned picture reaches `web/` from `manned-feed` over WS authenticated by the session cookie; `00 §6.2` describes bearer forwarding by the BFF, which does not apply to WebSockets. | `manned-feed` and `api` accept the `uspace_session` cookie on same-origin WebSocket upgrades checked against an `Origin` allow-list, verified with the shared `uspace-core/auth` verifier, in addition to a bearer; no ticket route (the BFF cannot proxy WebSockets and a ticket in a query string is logged); a `4401` close means "re-login". The kit drops `wsTicket`. | **decided** (M22) |
| 21 | `manned-feed` accepts the session cookie on its WebSocket (M22), but never opens PostgreSQL (CLAUDE.md rule 6), so it cannot read `user_sessions` to see a logout or a revocation. | Proposed (WP-2, revised in review): `api` projects **live** sessions, not ended ones, to a NATS KV bucket `sessions_live` (key = `jti`, value `{user_id, role, expires_at}`, bucket max age = `MaxSessionTTL`, 12 h), and `manned-feed` passes an `auth.SessionChecker` that reads it. (1) **Absence means refuse**: a `jti` with no key, or with `expires_at` passed, is not a live session; a projection of revocations would fail open whenever a write was lost, this one fails closed. (2) **A KV outage refuses**: when the lookup cannot be answered (bucket unreachable, or `manned-feed`'s watch of it lost for longer than one resync period) a cookie-authenticated upgrade is accepted only to be closed with `4401` (re-login), and open cookie-authenticated connections are closed with `4401`; machine bearers do not depend on the bucket and are unaffected. (3) **Write-through plus full resync**: `api` puts the key after the session row commits at sign-in (MFA step) and deletes it after the row is ended (logout, admin disable or reset, idle end, the sweep); a failed put or delete is counted and logged, never retried inline. Every 60 s `api` rewrites the whole bucket from `user_sessions` (`revoked_at IS NULL`, `expires_at > now()`, `last_seen_at` within the idle timeout) and deletes every other key, which repairs any drift, so a lost delete keeps a revoked session usable on the feed for at most one resync period and a lost put refuses a fresh session for at most as long. (4) **Idle for WebSocket-only clients**: the idle timeout (30 min on `last_seen_at`) stays judged by `api` alone, as `CheckSession` does today; an open cookie-authenticated WebSocket on `manned-feed` counts as use, because a supervisor watching the manned picture without clicking is working, not idle. `manned-feed` reports each such `jti` at most once a minute (the `touchEvery` throttle of `api`) on a core subject `ctl.sessions.seen`, and `api` moves `last_seen_at` from it; a tab left open is therefore bounded by the absolute `expires_at`, not by idle. When `api` ends a session for any reason its key goes (write-through or the next resync) and `manned-feed`, watching the bucket, closes that connection with `4401`; it also closes it at `expires_at` without waiting for a delete. Until WP-6 wires it, `manned-feed` has no `SessionChecker` and cannot build a `SessionVerifier`: it accepts machine bearers only. | **open**, for WP-6 |
| 22 | WP-2 serves `POST /v1/auth/login`, `/mfa`, `/logout`, `GET /v1/auth/me`, `GET`/`POST /v1/users`, `POST /v1/users/{id}/reset-mfa` and `/disable` and `/.well-known/jwks.json` before `api/openapi.yaml` exists (WP-3 not merged), and writes RFC 9457 problems itself (`auth.WriteProblem`) before `internal/apierr`. | The patterns and the access table are `auth.AccessTable` (each `x-auth` there); the bodies are documented in `internal/auth/handlers.go`. WP-3 adds the operations to `api/openapi.yaml` under the `auth` tag with these shapes (login `{username, password}` → `{mfa_token, expires_at, enrolment?: {secret, otpauth_uri}}`; mfa `{mfa_token, code}` → `{token, token_type, expires_at, idle_timeout_s, user}`), mounts the handlers on the generated router keeping the table, and replaces `auth.WriteProblem` with `apierr`. | **open**, for WP-3 |
| 20 | Staging has one droplet shared by five systems; the ANSP stack's share. | ≤ 600 MB and ≤ 0.5 vCPU at the demo's load (tens of manned aircraft); measured in WP-13 and recorded. Whether the droplet itself is resized (≥ 4 vCPU / 8 GB) or the DSS and lab move to a second droplet is an open owner question (reconciliation §2.1, money). | **decided for this repo** (§2.2 ansp 20); droplet sizing open, owner-only |

Cross-cutting decisions this plan also follows without a row of its
own: the JWT claim table (M18, M20, M24: `aud` = target host,
`ANSP_AUDIENCES`, client id `ansp-01`, session claims), the error body
(M28), the console frame on every WebSocket (M29), `pnpm` and npmjs-only
kit installs (M32, M34), one `timescaledb-ha` container per system on
the droplet (M37), the shared basemap volume and the kit's CSP (M38),
and `occurrence/v1 reporter.person_ref` in clear over TLS (M13). See D11.
