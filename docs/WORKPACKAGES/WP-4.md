# WP-4: `manned-adapter`

Branch `feat/WP-4-manned-adapter`. Milestone N-M1. Owns
`internal/manned` (`model.go`, `normalise.go`, `adapter/`, `replay/`,
`dump1090/`, `asterix/` stub), `cmd/manned-adapter`,
`testdata/replay/`. Depends on WP-0 (bus, config, obs). Consumer: WP-6
(`manned-feed`), the lab (the replay adapter is what the lab's "ANSP
feed" simulator drives).

Safety note: this is the only place where manned aircraft positions
enter U-space from the ANSP. A frame stamped at the wrong time or dropped
silently becomes a missed or false proximity alert at the USSP (T-11,
SC-15). The adapter never commands, never writes to its feed, and opens
its feed socket read-only.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §1.2` D1, D2, `§3`, `§7` (`man.v1`,
   `src.v1`), `§9` (budgets), `§10.2`.
2. Spec `02 F4` (data, scope, failure), `04 §2` (envelope: `ts`,
   `rx_ts`, `captured_at`, `time_source`, `backlog`, `trust`, `source`),
   `04 §3.1` `track/manned/v1`, `04 §3.6` `source/status/v1`, `03 §4`
   `manned_tracks`, `06` T11, `08` Q3, Q14.
3. `uspace-core/timeplace` (`PlaceBatch`, `Times`), `core/time.go`,
   `core/enums.go` (`TrustSurveillance`), `core/counters.go`.
4. LESSONS T-01, T-02, T-03, T-11, T-12, T-13, D-03 (ADS-B gives
   barometric and geometric altitude; map by definition, not name), E-03,
   E-09, E-10, B-08, B-12, B-16, C-12; `scenarios.md` SC-15.
5. dump1090 (`flightaware/dump1090` or `wiedehopf/readsb`): fetch
   `README-json.md` for `aircraft.json` and the SBS/BaseStation port 30003
   description at a pinned commit; record repo, commit and SHA-256 of the
   document in `internal/manned/dump1090/SOURCE`. **Do not write a field
   name or a column position from memory**; copy from the pinned document
   and keep sample lines captured from a real dump1090 run (or its
   documented examples) in `testdata/`.
6. Reference only: `utm/gateway/classify.py` and the P1-16 / U-07 notes
   in `utm/TASKS.md` (manned traffic was never built there; the notes say
   what was wanted).

## What to build

### Model (`internal/manned/model.go`)

```go
type Track struct {           // track/manned/v1 (schemas/track/manned/v1.json, WP-3)
    Schema string             // "track/manned/v1"
    MsgID, Producer string
    Times core.Times          // TS (feed clock, nil if the feed gives none), RxTS, CapturedAt, Source, Backlog
    Trust core.Trust          // always TrustSurveillance
    Source, SourceInstance string   // "ansp_feed", adapter id
    ICAO24 string             // lower-case hex, 6 chars; refused otherwise
    Callsign *string
    Position core.LatLon
    AltPressureM *float64     // barometric, ISA; never written to an AMSL field
    AltWGS84M *float64        // geometric (HAE) when the feed gives it
    GSMS, TrackDeg, VRateMS *float64
    Emergency *bool
    Squawk *string
    SourceClass string        // ads_b | mode_s | ssr | atm_feed | ads_l
    Quality map[string]any    // the feed's quality block as received (NIC, NACp, ...), bounded
    PolicyVersion uint64
}
func (t Track) Validate() error     // *core.FieldError: icao24, position, finite numbers, bounds
```

### Adapter interface and normalisation

```go
type Adapter interface {
    Kind() string
    Run(ctx context.Context, out chan<- RawSample) error   // read-only; returns when ctx ends or the feed is gone (the runner reconnects, B-08)
}
type RawSample struct{ FeedTS *time.Time; ReadAt time.Time; Fields ... }   // what the feed said, before judgement
type Normaliser struct{...}   // one per adapter instance
func (n *Normaliser) Take(batch []RawSample, rxTS time.Time) []Track
```

Rules:

- **Time placement** (T-01, T-02): `rx_ts` is the adapter's clock at
  read; `captured_at = rx_ts - (newest FeedTS in the batch - FeedTS)`
  through `timeplace.PlaceBatch` with `maxSpacing` from policy; `ts` is
  the feed's time when it gives one, else nil and `time_source: system`
  with the sample counted `placed_at_arrival` (T-12). Never compare the
  feed clock with anything but itself.
- **Stall detection** (T-11, SC-15): the runner measures the gap between
  consecutive reads; a read after a gap longer than `stall_after_s`
  (policy, default 5 s) marks every sample in the drained burst
  `backlog: true` when the feed gives no time base, and places them by
  the feed's time when it does; counts `stalled_reads`,
  `backlog_samples`. A sample whose `captured_at` would be in the future
  by more than the policy tolerance is clamped and counted (T-13).
- **Order** (T-03): within one `icao24`, a sample older on the feed's
  clock than the one held is dropped and counted `out_of_order`.
- **Dedupe**: a window of `dedupe_window_s` (2 s) per `icao24` on
  `(FeedTS, position)` — the SBS stream repeats positions across message
  types; counted `duplicates`.
- **Do not filter at the edge** (B-12): every valid sample is published
  whatever its position; relevance to U-space is WP-6's flag.
- **Refusals** are counted by field (`refused_icao24`, `refused_position`,
  …) and logged once per `icao24` per minute, never per frame.
- Status (`src.v1.manned.<adapter>`) every 2 s: `enabled`, `connected`,
  `last_frame_at`, `aircraft_seen`, every counter, `policy_version`,
  `stalled` (bool, true while a stall is in progress), `feed_clock`
  (`present` / `absent`).
- Source switch: the adapter follows `ctl.sources` for its own
  `(manned, <id>)`; disabled, it stops publishing (keeps reading and
  counting `refused_disabled`) and says `disabled by <actor>: <reason>`
  in its status (B-11); re-enabled, it resumes within one tick.

### Adapters

- `replay`: reads NDJSON of `track/manned/v1`-shaped records (the
  `testdata/replay/*.ndjson` files, synthetic) with their original `ts`,
  replays at wall speed (or `--speed`), loops when asked, and sets
  `trust: surveillance`, `source_class` from the file header. Refuses to
  start unless `ANSP_ADAPTER_REPLAY_ALLOWED=true` (never on by default;
  `06` T11) and shows `replay` in its status. The lab's "ANSP feed"
  simulator uses this.
- `dump1090_sbs`: TCP client of the BaseStation text port; parses the
  message types that carry position, altitude, speed, track, vertical
  rate, callsign, squawk and emergency/alert flags, using the column
  positions from the pinned document; a line that does not parse is
  counted, never crashes (fuzz). Reconnects forever with backoff.
- `dump1090_json`: polls `aircraft.json` at 1 Hz; `now` and each
  aircraft's `seen`/`seen_pos` (names from the pinned document) give the
  feed time base; samples older than `max_age_s` are `backlog`.
- `asterix_cat021`: a stub whose `Run` returns an error naming the
  deferral (gap 12) so a misconfigured deployment fails loudly, not
  silently.
- Altitude mapping by definition (D-03): barometric altitude →
  `alt_pressure_m` (feet × `core.FeetToMetres` exactly); geometric
  altitude → `alt_wgs84_m`; never into each other; speed knots → m/s,
  vertical rate ft/min → m/s, with the conversion constants in one file
  and a test for each.

### `cmd/manned-adapter`

Flags/env: `ANSP_ADAPTER_KIND`, `ANSP_ADAPTER_ID`,
`ANSP_ADAPTER_SOURCE_CLASS`, the kind's connection settings. Publishes
`man.v1.<id>.<icao24>` (core NATS) and `src.v1.manned.<id>`; exposes
metrics and readiness (`feed: connected | reconnecting since T`).

## Tests

- Unit per rule above, every one with its E-01 twin: in-order accepted /
  out-of-order dropped; fresh / duplicate; feed time present / absent;
  no stall / 30 s stall (the SC-15 case: 30 s of buffered input is
  placed by feed time, or flagged `backlog`, and the counter moves);
  enabled / disabled; future `captured_at` clamped.
- E-02: the healthy status line is asserted field by field after a
  clean run; the feed removed mid-run gives `reconnecting since T` and
  the counter, and the reconnection resumes publishing.
- Golden tests: pinned SBS sample lines and `aircraft.json` samples →
  expected `Track`s (the expected values written from the document's
  field definitions, with the document section cited in the test).
- E-10: `max_aircraft` per adapter exceeded → eviction counted; a line
  longer than the bound refused.
- `FuzzSBSLine`, `FuzzAircraftJSON`, `FuzzReplayFrame`: never panic.
- Integration (NATS service): an adapter publishes, a test subscriber
  receives and checks the envelope; the switch flips and publishing
  stops within one status tick and resumes.
- `BenchmarkNormalise` (one batch of 50), `BenchmarkParseSBSLine`.

## Done when

- [ ] `make lint`, `make race`, `make integration` green; fuzz clean
  10 s; benchmarks reported.
- [ ] Coverage ≥ 90 % on `internal/manned/...`.
- [ ] `internal/manned/dump1090/SOURCE` records the document, commit and
  hash; no field name appears that is not in the document.
- [ ] `testdata/replay/` holds at least: `two-aircraft-converging.ndjson`
  (used by the USSP's CPA scenario), `helicopter-near-uspace.ndjson`,
  `stale-then-resume.ndjson`; all synthetic, header says so.
- [ ] `doc.go` rewritten; CHANGELOG line; PR reports the SC-15 unit
  result verbatim.

## Commits

`feat(adapter): add the manned track model and normalisation rules [WP-4 N-M1]`,
`feat(adapter): place feed samples on the ingest clock and detect stalls [WP-4 N-M1]`,
`feat(adapter): add the replay adapter for the lab and tests [WP-4 N-M1]`,
`feat(adapter): read dump1090 SBS and aircraft.json with pinned field names [WP-4 N-M1]`,
`feat(adapter): run one adapter per process and publish status [WP-4 N-M1]`,
`test(adapter): fuzz the readers and prove the stall case [WP-4 N-M1]`.
