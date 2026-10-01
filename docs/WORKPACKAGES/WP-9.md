# WP-9: `dss-constraints`

Branch `feat/WP-9-dss-constraints`. Milestone N-M1. Owns `internal/dss`,
`migrations/relational/0060–0069` (DSS columns and the notification log),
the `GET /uss/v1/constraints/{entityid}` handler. Depends on WP-5
(volumes, versions), WP-8 (the outbox carries `dss_put`, `dss_delete`,
`uss_notify` jobs). Consumers: every USSP with `utm.constraint_processing`
subscriptions; the lab's DSS and simulated USSP; the conformance suite
(L-M4).

Safety note: the DSS constraint is how a third-party USSP learns of a
restriction without reading our CISP. The reference and its details must
describe the same volume as the ED-318 feature (one source: WP-5's
`Volumes`), and the subscribers the DSS names must each be notified
within 5 s or the miss must be visible.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` D6, `§6` (`/uss/v1/constraints`
   and the outbound DSS calls), `§9`, `§15` gap 16.
2. Spec `02 F2` (constraint reference, scope, 5 s), `02 F6` (DSS API
   paths, `uss_base_url`, subscriptions, `ovn`, clocks within
   `TimeSyncMaxDifferentialSeconds`), `09 §1.4` (constraint rows), `05
   §7` F3548 timing, `05 §6` DSS row, `06` T9.
3. `uspace-core/f3548`: `doc.go`, `constants.go`, `types.gen.go`
   members `PutConstraintReferenceParameters{Extents, UssBaseUrl}`,
   `ChangeConstraintReferenceResponse{ConstraintReference, Subscribers}`,
   `ConstraintReference{Id, Manager, Ovn, TimeStart, TimeEnd,
   UssAvailability, UssBaseUrl, Version}`, `SubscriberToNotify{
   Subscriptions, UssBaseUrl}`, `PutConstraintDetailsParameters{
   Constraint, ConstraintId, Subscriptions}`, `Constraint{Details,
   Reference}`, `GetConstraintDetailsResponse`, `Time{Format, Value}`,
   `Scope*`; `SOURCE` (the pinned `utm.yaml` commit — read the DSS
   path templates and the query parameters from that file, never from
   memory).
4. InterUSS DSS: how `PUT /dss/v1/constraint_references/{entityid}`
   and `PUT .../{entityid}/{ovn}` (update) and `DELETE
   .../{entityid}/{ovn}` behave; the `Manager` is derived from the
   token's `sub`; the DSS audience is the host of `ANSP_DSS_URL`
   (M18; InterUSS `accepted_jwt_audiences` are hostnames).
5. LESSONS E-03 (paths and members from the pinned file), E-01, E-02,
   E-10; the lab's `uspace-lab` DSS compose when it exists.

## What to build

- `Client` on WP-2's token source (`utm.constraint_management`, `aud`
  = the DSS's host): `PutReference(ctx, id, extents, ussBaseURL,
  ovn *string) (ChangeConstraintReferenceResponse, error)`,
  `DeleteReference(ctx, id, ovn)`, `GetReference(ctx, id)`; responses
  decoded with a size bound and the `f3548` validators; errors typed
  (`ErrConflict` on a stale `ovn` → re-read and retry once, then fail
  loudly).
- Jobs for the outbox: `dss_put` on activate/extend (extents = WP-5's
  `Volumes` bounding the restriction; `uss_base_url` =
  `ANSP_PUBLIC_BASE_URL`), `dss_delete` on end/cancel/expiry; each
  success stores `dss_constraint_id`, `dss_ovn`, `dss_version` on the
  restriction and emits `restr.v1` with `dss: written`; then one
  `uss_notify` job per `Subscribers[]` entry: `POST
  {uss_base_url}/uss/v1/constraints` with `PutConstraintDetailsParameters
  {ConstraintId, Constraint: {Reference, Details}, Subscriptions}` (on
  delete, `Constraint` omitted) within `CstrPublishedNotificationLatencySeconds`
  of the DSS answer; scope `utm.constraint_processing` with `aud` =
  **the host of the subscriber's `uss_base_url`** as the DSS returned
  it (M18; peers are discovered, not configured, so no mapping through
  the USSP list); every notification logged in
  `deliveries` and in `dss_notifications` (constraint id, subscriber,
  `notification_index`, sent at, status).
- Expiry: the ticker that ends a restriction at `ends_at` (WP-5) enqueues
  the delete; a constraint whose `time_end` passed needs no delete per
  F3548 but one is sent anyway and a `404` is accepted as done.
- `GET /uss/v1/constraints/{entityid}` (scope `utm.constraint_processing`):
  `GetConstraintDetailsResponse{Constraint}` from
  `restriction_versions` of the current version, `Details{Volumes, Type:
  "DAR", Geozone}`; `404` for an unknown or ended constraint after
  `ExternalDataMaxRetentionTimeHours`; answered within 200 ms p99.
- Readiness: `dss: ok | unreachable since T`; a DSS outage never blocks
  the CISP publication (D6) and is shown on the restriction and the
  console as `dss: pending since T`.
- `USSLogSet` is not served in v1 (the ANSP is not a USS for intents);
  record in `doc.go`.

## Tests

- Integration with an in-test DSS stub implementing the three operations
  with `ovn` semantics (and, when the lab's compose is available, a
  `make dss-live` target running the same tests against InterUSS DSS,
  reported as run or skipped):
  - activate → `PUT` with extents equal to WP-5's volumes (deep equal
    on the W84 values), `ovn` stored, two subscribers in the response →
    two `POST`s within 5 s (measured), each with the right
    `notification_index` and the full `Constraint`; the subscriber stub
    verifies the token's `aud` and scope.
  - extend → `PUT` with the previous `ovn`; a stale `ovn` → one re-read
    and retry, then success.
  - end → `DELETE` with `ovn`; subscribers get the deletion
    notification (no `Constraint`).
  - DSS down → the CISP publication still happens (twin assertion from
    WP-8's stub), `dss: pending since T` on `restr.v1`, retries, then
    written when back.
  - a subscriber `5xx` → retried; the other subscriber unaffected.
- Handler: a USSP with the scope reads the details and gets exactly the
  feature's volume; without the scope `403`; after the retention window
  `404`.
- E-10: a DSS response with 10 001 subscribers refused and alarmed
  (bound from policy), the body size cap.
- `BenchmarkConstraintDetails`.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; the measured
  DSS-answer-to-last-notification latency in the PR.
- [ ] Coverage ≥ 90 % on `internal/dss`.
- [ ] Every DSS path and member in the code is traceable to
  `uspace-core/f3548/SOURCE`'s `utm.yaml` (a test reads the paths from a
  small table in `dss/paths.go` whose comment cites the file).
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(dss): write and delete constraint references with ovn handling [WP-9 N-M1]`,
`feat(dss): notify the subscribers the DSS names within five seconds [WP-9 N-M1]`,
`feat(api): serve F3548 constraint details for a restriction [WP-9 N-M1]`,
`test(dss): prove the DSS path end to end against a stub with ovn semantics [WP-9 N-M1]`.
