# WP-1: `store-migrations`

Branch `feat/WP-1-store-migrations`. Milestone N-M0. Owns
`migrations/relational/0001–0019`, `migrations/timeseries/0001–0009`,
`internal/store` (pools, goose runner, sqlc setup and the queries of the
tables it creates), `internal/audit`, `internal/policy`. Depends on WP-0.
On the critical path: WP-5 needs `restrictions`, `events` and the policy
projection.

## Read first

1. `CLAUDE.md`, `docs/PLAN.md §5` (every table and column), `§7` (KV
   `policy`), `§14`.
2. Spec `03` conventions paragraph and `§4`; `05 §4` (retention,
   compression); `06 §2` T7 (hash chain), `04 §3.6` (`policy/updated/v1`).
3. LESSONS INV-03, B-06, B-09 (the switch write rule, implemented by
   WP-6's `sources` on top of your `source_controls` table), B-15, E-10,
   E-13.
4. Reference only: `utm/infra/migrations/` (two trees, `events`,
   `source_controls` with `version` and `epoch`), `utm/api/sources.py`.

## What to build

### Migrations

`migrations/relational/0001_extensions.sql` (`postgis`), `0002_events.sql`
(append-only, monthly partitions, `prev_hash`, `hash`; a trigger that
refuses `UPDATE`/`DELETE`; the application role without those grants),
`0003_ansp_policy.sql` (the row of `PLAN §5.1` with defaults, a check
that every threshold is positive, `policy_version` sequence),
`0004_source_controls.sql` (`version` from a sequence, `epoch` set once by
a default `gen_random_uuid()` on an `epochs` singleton row),
`0005_restrictions.sql` (`restrictions`, `restriction_versions`,
`restriction_requests`; geometry `geometry(Geometry, 4326)` constrained
to Polygon or Point, `radius_m` only with Point; GiST index; a check
`ends_at > starts_at`; the state enum), `0006_adapters.sql`. Each with
`-- +goose Down`. Numbers 0007–0019 stay free for your fixes.

`migrations/timeseries/0001_extensions.sql` (`timescaledb`, `postgis`),
`0002_manned_tracks.sql` (hypertable on `captured_at`, 1-day chunks,
`compress_segmentby = 'icao24'`, `compress_orderby = 'captured_at DESC'`,
compression policy after 7 days, retention policy 90 days, GiST on
`geom`, the application role without `UPDATE`/`DELETE`),
`0003_feed_products.sql`.

Version tables: `goose_db_version_relational` and
`goose_db_version_timeseries` (goose `SetTableName` per tree). A test
runs each tree up, down to zero and up again against the CI service
databases, and a test greps each tree for the other tree's table names
(B-15).

### `internal/store`

- `OpenRelational(ctx, dsn) (*Relational, error)`,
  `OpenTimeseries(ctx, dsn) (*Timeseries, error)` on `pgxpool` with
  bounded pool sizes and statement timeouts from config; `Migrate(ctx,
  tree)` with the embedded files (`embed.FS` per tree); `Ping` for
  readiness.
- sqlc: `sqlc.yaml` with two packages (`store/relational`,
  `store/timeseries`), pgx v5 driver, queries in
  `internal/store/queries/{relational,timeseries}/*.sql`; generated
  `*.sql.go` committed and checked by `generate-check`. Geometry crosses
  sqlc as GeoJSON text (`ST_AsGeoJSON`, `ST_GeomFromGeoJSON`) and is
  parsed with `uspace-core/geodesy` ring types on the Go side; no
  geometry library.
- `Tx(ctx, fn)` helper; every write that must pair with a KV put (switch,
  policy) takes a `func(tx) error` so WP-6 and this WP's `policy` can
  refuse with 503 when KV fails (B-09).
- A `Writer` for the hypertable: `Insert(ctx, rows []MannedTrackRow)`
  with `CopyFrom`, used by WP-6.

### `internal/audit`

`Record(ctx, tx, Event)` computing `hash = sha256(prev_hash || canonical
json)` under an advisory lock per month; `Verify(ctx, month) (ok bool,
brokenAt *int64, err error)`; a `Query` for `/v1/audit`. Every event
carries `actor_type`, `actor_id`, `purpose`, `entity_type`, `entity_id`,
`event_type`, `payload`.

### `internal/policy`

`Load(ctx) (Policy, error)`, `Update(ctx, actor, Policy) (version, error)`
inside a transaction that also puts the row into KV `policy` and publishes
`ctl.policy` (refused with 503 if KV cannot take it), `Follower` for the
hot path (keeps the last applied version; with none, the compiled
defaults, logged as `policy: defaults, KV empty`), and the defaults of
`PLAN §5.1` in one place with their units in the field names.

## Tests

- Integration (real databases): migrations up/down/up for both trees;
  the application role cannot `UPDATE` `events` (assert the error) and
  can `INSERT` (the twin); the hash chain verifies and a tampered row is
  detected (`Verify` returns `ok=false` with the id); compression and
  retention policies exist (`timescaledb_information.jobs`); a
  `CopyFrom` of 10 000 rows lands and is read back by `icao24` and
  window.
- Unit: policy defaults have positive values and units in names (a
  reflection test over the struct's field names: every numeric field
  ends in `_m`, `_s`, `_hz` or is a count); `Follower` with no KV serves
  defaults and says so; a lower version is ignored and counted.
- E-10: the pool refuses the 1 + max connection with the configured
  timeout, not a hang.

## Done when

- [ ] `make lint` clean (pinned versions), `make race` green,
  `make integration` green in CI (paste the job tail).
- [ ] `make generate-check` clean (sqlc output committed).
- [ ] Coverage ≥ 85 % on `store`, `audit`, `policy`.
- [ ] `doc.go` of each package rewritten; CHANGELOG line.

## Commits

`feat(store): add the two goose trees and the relational schema [WP-1 N-M0]`,
`feat(store): add the manned_tracks hypertable with compression and retention [WP-1 N-M0]`,
`feat(store): open pools, run migrations and generate queries with sqlc [WP-1 N-M0]`,
`feat(audit): append hash-chained events and verify a month [WP-1 N-M0]`,
`feat(policy): load, update and project the thresholds row [WP-1 N-M0]`,
`test(store): run both trees up and down against real databases [WP-1 N-M0]`.
