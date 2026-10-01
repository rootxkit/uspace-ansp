# WP-5: `restrictions`

Branch `feat/WP-5-restrictions`. Milestone N-M1. Owns
`internal/restriction`, `migrations/relational/0030–0039`, the
`restrictions` and `restriction-requests` handlers in `cmd/api`, the
`restr.v1` publisher and the `/v1/restrictions/stream` console WS.
Depends on WP-1 (store, audit, policy), WP-2 (auth), WP-3 (generated
server). On the critical path: WP-8 and WP-9 consume the state machine
and the feature builder. Open the PR when the state machine, validation
and the ED-318 feature pass; finish the handlers in the same PR.

Safety note: a restriction is the ANSP's only act that changes what UAS
may do. A wrong geometry, a wrong vertical reference or a state that
changes without a version is a wrong instruction to every USSP. Nothing
here commands an aircraft; everything here is audited with who, why,
when and until when (N4).

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` D3, D4, D5, D10, `§5.1`
   (`restrictions`, `restriction_versions`, `restriction_requests`),
   `§6` (the restriction operations), `§7` (`restr.v1`), `§15` gaps 3,
   4, 13, 16.
2. Spec `01 §4` N1, N4; `02 F2` (data, states, limits), `F11`; `03 §4`
   `restrictions`, `03 §6` (identifier); `04 §3.4`; `09 §1.4`
   (`Cstr*`), `09 §1.1` ATS.TR.237 rows; `07` N-M1.
3. `uspace-core/ed318` `doc.go`, `model.go` (`UASZone`, `Feature`,
   `Geometry`, `Layer`, `TimePeriod`), `export.go`, `zones.go`
   (`ToZones`); `uspace-core/f3548` `constants.go` (`CstrMaxDurationHours`,
   `CstrMaxPlanningHorizonDays`, `CstrMaxAreaKm2`, `CstrMaxVertices`,
   `CstrMinEffectiveTimeBufferMinutes`), `volume.go` (`Altitude.HAEM`,
   `Volume4DToZonesEnvelope`), the `Volume4D`, `Volume3D`, `Polygon`,
   `Circle`, `Altitude` members of `types.gen.go`; `uspace-core/geodesy`
   (`ValidRing`, `Polygon`, `Circle`, `BBox`); `uspace-core/geoid`
   (`UndulationM`, `HAEFromAMSL`); `uspace-core/zones` (U-space
   containment); `vectors/testdata/ed318_roundtrip.json` (your
   `RunOwned(t, "ansp", ...)` test).
4. LESSONS INV-03, Z-01..Z-06 (the feature you publish must be a valid
   ED-318 document: validate what you export with `ed318.Parse` before
   it leaves), Z-12 (push, never poll), E-01, E-10, E-13, D-01.
5. Reference only: utm U-04 notes in `TASKS.md`; `utm/api/zone_routes.py`
   for the editor's validation errors (shape, not code).

## What to build

### State machine (`internal/restriction/state.go`)

States `planned`, `active`, `ended`, `cancelled`; transitions
`plan` (→ planned), `activate` (planned → active; immediately when
`starts_at ≤ now`, else scheduled: the row stays `planned` with
`activate_at` and a ticker in `api` activates it — on time, counted, and
visible), `extend` (active → active with a new `ends_at`), `end` (active
→ ended, `ends_at` set to now), `cancel` (planned → cancelled), `expire`
(active → ended at `ends_at`, by the ticker). Every transition bumps
`version`, writes a `restriction_versions` row with the feature and the
constraint as of that version, an `events` row (actor, reason, before and
after), and publishes `restr.v1.<state>.<id>`. An illegal transition is
`409` naming both states. Everything in one transaction.

### Validation (`validate.go`)

A `*core.FieldError` list (RFC 9457 `field`/`reason`), all problems
reported, none repaired:

- Geometry: Polygon (one outer ring, `geodesy.ValidRing` with
  `CstrMaxVertices`, no holes in v1, not across the antimeridian) or
  Circle (`center`, `radius_m` > 0); area ≤ `CstrMaxAreaKm2` (geography
  area through PostGIS `ST_Area(geography)` in the store, or
  `geodesy` on the Go side if core offers area; use one and say which).
- Vertical: `lower_m < upper_m`, refs `AMSL` or `WGS84` (`AGL` refused
  with the D3 reason); both limits required (D-01: a limit without its
  reference is refused).
- Time: `starts_at < ends_at`; `ends_at - starts_at ≤
  CstrMaxDurationHours` (else the service offers a chain of re-issues:
  `Plan` returns the list it would create and the handler asks the
  supervisor to confirm with `confirm_chain: true`); `starts_at ≤ now +
  CstrMaxPlanningHorizonDays`; an immediate activation sets `starts_at =
  now`.
- U-space containment (gap 13): with `policy.require_uspace_airspace`,
  the geometry must intersect a `USPACE` feature of `cis_cache`
  (`uspace_airspace_id` chosen or inferred; refused when none intersects,
  `503 cis_stale` when the projection is older than `cis_stale_bound_s`);
  the restriction's `upper_m` may not exceed the airspace's upper limit
  in the same reference (compare only when the references agree;
  otherwise refuse with `reference_mismatch` and ask for the other
  reference — never convert silently).
- `reason_text` ≤ 200 characters (ED-318 `message` bound).

### The published feature (`feature.go`)

`Feature(r Restriction, pol Policy, now) (*ed318.Feature, error)`:
`identifier` D4 (`DAR` + 4 base-36 from a sequence), `country`
`pol.Country`, `name` from `reason_text` (bounded), `type`
`r.ZoneType`, `variant` `COMMON`, `reason` `["DAR"]`, `message`
`[{text: reason_text, lang: "en"}]` (+ `ka` when given),
`limitedApplicability` one `TimePeriod{Permanent: NO, StartDateTime,
EndDateTime}` (UTC with `Z`), `zoneAuthority` one entry from
configuration (`ANSP_AUTHORITY_NAME`, `_SERVICE`, `_EMAIL`, `_PHONE`,
`purpose: INFORMATION`), `extendedProperties` `{ "ansp": {ansp_ref,
restriction_id, version, state, uspace_airspace_id, outside_uspace} }`,
geometry with `layer {upper, upperReference, lower, lowerReference,
uom: "m"}` using the member names of `uspace-core/ed318` exactly. Then
`ed318.Export` and `ed318.Parse` round-trip in a test, and
`ed318.ToZones` yields one zone whose containment agrees with the
input. `FeatureCollection(rs []Restriction)` with `metadata
{creationDateTime, updateDateTime, originator}` for the direct degraded
delivery (WP-8).

### The F3548 volumes (`constraint.go`)

`Volumes(r Restriction, g geoid.Undulator) ([]f3548.Volume4D, error)`:
one `Volume4D` with `Volume3D{OutlinePolygon | OutlineCircle,
AltitudeLower, AltitudeUpper}` in `reference W84`, `units M`: a WGS84
limit passes through; an AMSL limit becomes HAE with `HAEFromAMSL` using
the minimum undulation over the vertices for the lower limit and the
maximum for the upper (conservative envelope, gap 3), the undulations
recorded in `restriction_versions.constraint.derivation`; `time_start`,
`time_end` as F3548 `Time{Format: "RFC3339", Value}`. Refuses when the
geoid is not configured (`503 geoid_unavailable`) rather than writing a
wrong altitude; counts it. `ConstraintDetails{Volumes, Type: "DAR",
Geozone}` (gap 16: `Geozone` filled through `ed318.ToED269` when it
maps, else omitted with a counter).

### Handlers

The generated strict server's restriction and restriction-request
operations (`PLAN §6`), `Idempotency-Key` honoured on `POST
/v1/restrictions` (same key + same body → the same `201`; different body
→ `409`), roles enforced by WP-2's middleware, `restriction_requests`
accept/decline, and `GET /v1/restrictions/stream` (WS, session) relaying
`restr.v1` and, from WP-8, delivery outcomes.

## Tests

- `TestVectorsED318Roundtrip`: `RunOwned(t, "ansp", ...)` through your
  feature builder where the case applies (a case this system does not
  own is skipped with the reason logged).
- State machine: every legal transition and every illegal one (E-01
  pairs), the scheduled activation fires at `starts_at` and the expiry at
  `ends_at` (fake clock), each writes a version and an event and
  publishes on the bus (integration with NATS).
- Validation: accept / refuse for each rule, including the chain
  proposal for 30 h, the antimeridian ring, 1001 vertices (E-10),
  `AGL` refused with the D3 text, containment with a fixture U-space
  airspace (inside, partly outside → refused, no projection → 503).
- Feature: round-trip through `ed318.Export` → `ed318.Parse`
  (equal by value), `ToZones` containment for a point inside and one
  outside; identifier length 7 and uniqueness over 10 000 mints.
- Constraint: AMSL → HAE with a fixture undulation grid where N varies
  across the polygon; the lower limit uses the minimum, the upper the
  maximum; a WGS84 input is unchanged; no geoid → refused and counted.
- Handlers: idempotency replay / conflict; roles; a `viewer` gets
  `403`; the stream delivers a state change within 100 ms.
- `BenchmarkFeature`, `BenchmarkVolumes`.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; vector test
  reported with counts.
- [ ] Coverage ≥ 90 % on `internal/restriction`.
- [ ] A restriction planned, activated, extended and ended through the
  HTTP API leaves four versions, four events and four `restr.v1`
  messages (integration test; paste the assertion).
- [ ] `doc.go` rewritten (the state machine, the feature's members and
  the UNVERIFIED notes inherited from `ed318`); CHANGELOG line.

## Commits

`feat(restriction): add the state machine with versions and audit [WP-5 N-M1]`,
`feat(restriction): validate geometry, limits, window and U-space containment [WP-5 N-M1]`,
`feat(restriction): build the ED-318 feature of a restriction [WP-5 N-M1]`,
`feat(restriction): derive the F3548 volumes in W84 through the geoid [WP-5 N-M1]`,
`feat(api): serve the restriction and restriction-request operations [WP-5 N-M1]`,
`test(restriction): run the ed318 round-trip vectors and the lifecycle end to end [WP-5 N-M1]`.
