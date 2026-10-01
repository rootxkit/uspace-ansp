# WP-6: `manned-feed`

Branch `feat/WP-6-manned-feed`. Milestone N-M1. Owns `internal/picture`,
`internal/feed`, `internal/sources`, `cmd/manned-feed`,
`migrations/timeseries/0010–0019` (additions only). Depends on WP-1
(timeseries writer, policy follower), WP-2 (token middleware, session
cookie on WS), WP-4 (`track/manned/v1`, `src.v1`). Consumers: the USSP
and the authority (F4), the console (WP-12), the lab.

Safety note: this process is what the USSP's traffic information and the
authority's picture see of manned aviation. A stale aircraft shown as
live, an aircraft hidden because its adapter was switched off, or an
empty stream that looks like an empty sky are each a safety defect
(`02 §1` failure rule, B-11, SC-22).

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §2` (the process table), `§5.2`, `§6`
   (`/v1/manned-traffic/*`), `§7`, `§9` (feed budgets), `§15` gaps 8,
   19.
2. Spec `02 F4` (data, relevance margin, scope, failure), `04 §2`
   (`trust`, `source`, a disabled source's tracks age out as
   `source_disabled`), `04 §3.6`, `05 §3` (consumer throttle), `05 §5`
   (backpressure rows for console WS and the writer), `05 §6`, `06` T8.
3. `uspace-core/sources` (`State`, `Follower`, `Query`, the B-10
   semantics in its `doc.go`), `vectors/testdata/source_control.json`
   (`RunOwned(t, "ansp", ...)`), `uspace-core/zones` (`Zone`,
   `ContainsHorizontally`, `Index`), `uspace-core/ed318.ToZones`,
   `uspace-core/geodesy.BBox.PadM`.
4. LESSONS B-07, B-08, B-09, B-10, B-11, B-12, B-13 (replay shows holes;
   applies to the snapshot's `age_s`), C-12, T-04, T-06, T-10, E-02,
   E-10; `scenarios.md` SC-08, SC-15, SC-22.
5. Reference only: `utm/api/live.py`, `utm/api/telemetry_ws.py`
   (viewport subscription and throttle), `utm/gateway/live_state.py`.

## What to build

### `internal/sources`

The system-side wrapper of `uspace-core/sources`: `Writer` (api; WP-1's
transaction + KV put + `ctl.sources` push, 503 when KV refuses, B-09),
`Follower` (feed and adapters; reads KV at start with the 3-retry rule,
subscribes `ctl.sources`, re-reads every 60 s to repair a lost push),
`Decision(sourceType, instance)` with the `Why`. `TestVectorsSourceControl`
runs the vector cases this system owns through `Follower`.

### `internal/picture`

```go
type Picture struct{...}     // the live manned picture
func New(pol policy.Follower, src sources.Follower, cis cis.Follower, clock) *Picture
func (p *Picture) Observe(t manned.Track) Verdict      // upsert by icao24; drops out-of-order (T-03) and backlog (T-04: recorded to TSDB by the writer, never shown as live); counts
func (p *Picture) Tick(now) Ageing                     // marks stale after stale_after_s since captured_at (T-06), source_disabled when the follower says so (B-11), evicts after evict_after_s; returns what changed
func (p *Picture) Snapshot(bbox *geodesy.BBox) []Entry // entries carry age_s, state (live|stale|source_disabled|backlog_only), relevant
func (p *Picture) Relevant(t manned.Track) bool        // inside any U-space volume of the CIS projection padded by feed_margin_lateral_m and below its upper + feed_margin_vertical_m (judged on alt_pressure_m against an AMSL ceiling with the pressure-uncertainty widening of 04 §3.1: within_band false → still relevant, flagged)
```

Bounded by `max_aircraft` with eviction of the oldest counted
(E-10). With no CIS projection, `Relevant` returns `true` for every
aircraft and the status says `relevance: not evaluated (no CIS
projection)` — an empty filter must never look like an empty sky
(SC-22).

### `internal/feed`

- `GET /v1/manned-traffic/snapshot?bbox=`: the picture's entries, plus
  `degraded[]` (`adapters_silent`, `cis_projection_stale`, `nats`),
  `adapters[]` from the last `src.v1` of each, `policy_version`,
  `cis_version`, `cis_age_s`, `generated_at`.
- `GET /v1/manned-traffic/stream?bbox=` (WS): on connect the snapshot,
  then NDJSON frames of `track/manned/v1` at ≤ 1 Hz per aircraft, plus
  `feed/status/v1` every 2 s (adapters, ages, degraded, `dropped_frames`
  for this client), plus a `track/manned/v1` frame with `state: stale`
  or `source_disabled` when an aircraft ages (the consumer learns the
  change; nothing disappears silently). Per-client send queue bounded
  (slow consumer: drop oldest, count, tell the client in the next status
  frame; never block the picture). Connection cap per client id and
  total; `ansp.traffic` scope or session cookie (same origin) per WP-2;
  mTLS per `ANSP_MTLS_REQUIRED`.
- The console stream is the same endpoint with the session cookie; the
  console gets every aircraft (relevant or not, flagged) when it asks
  `?all=true` and the role allows.
- `feed_products` sampling at 0.1 Hz per client (WP-1 table).

### `cmd/manned-feed`

Subscribes `man.v1.>` (core) and `src.v1.manned.>`; writes every valid
sample (live and backlog) to `manned_tracks` through WP-1's `Writer` in
batches (1 s or 500 rows), with the bounded buffer of B-07 and the
JetStream mirror replay after an outage (`MAN_MIRROR` pull consumer with
explicit ack, deduplicated by `msg_id`); serves the feed; readiness lists
`nats`, `timeseries`, `cis_projection (age)`, `source_control (version)`,
`policy (version)`.

## Tests

- `TestVectorsSourceControl` through the follower (report counts).
- Picture: observe / out-of-order dropped; live / stale after
  `stale_after_s` / evicted; enabled / disabled → `source_disabled`
  within one tick and only that adapter's aircraft (SC-08 steps 2–3 in
  unit form); relevant inside / outside / with no projection (the
  "not evaluated" status asserted, E-02); backlog recorded, not shown
  live, and the twin: the same sample without `backlog` is shown.
- Feed (integration with NATS and TimescaleDB): a replay adapter's
  frames reach a WS client within 250 ms p99 over 60 s (measured,
  printed); a slow client's drops are counted and reported in its status
  frame; the snapshot of an empty picture says `aircraft: []` with
  `degraded: [adapters_silent]`, not merely `[]`; stop the writer's
  database for 30 s → the buffer holds, the counter moves, nothing is
  lost after it returns (B-07; assert row counts equal frames sent).
- SC-15 end to end: pause the adapter process (or its input) for 30 s
  with the replay's feed clock → no sample is shown live with a
  `captured_at` newer than its own time; the stall counter moves.
- Auth: a token without `ansp.traffic` gets `403`; with it `101`; the
  session cookie on a cross-origin request is refused.
- E-10: `max_aircraft + 1` → eviction counted; connection cap + 1 →
  refused with `503` and `Retry-After`.
- `BenchmarkPictureObserve`, `BenchmarkRelevance`, `BenchmarkSnapshot100`.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; benchmarks
  within `PLAN §9`.
- [ ] Coverage ≥ 90 % on `picture`, `feed`, `sources`.
- [ ] The measured adapter→WS latency printed in the PR (E-04).
- [ ] `doc.go` rewritten; CHANGELOG line.

## Commits

`feat(sources): write and follow source switches on uspace-core/sources [WP-6 N-M1]`,
`feat(feed): keep the live manned picture with ages, relevance and switches [WP-6 N-M1]`,
`feat(feed): serve the F4 snapshot and stream with status frames [WP-6 N-M1]`,
`feat(feed): write every sample to the hypertable with a bounded buffer and replay [WP-6 N-M1]`,
`test(feed): prove stale, disabled and stalled aircraft are never shown live [WP-6 N-M1]`.
