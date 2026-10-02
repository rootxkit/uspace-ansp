# Changelog

All notable changes to `uspace-ansp`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning, and the published API `api/openapi.yaml` changes
additively within `/v1`. One line per work package.

## [Unreleased]

### Added

- WP-0 scaffold: the Go module pinned to `uspace-core` v1.1.0; the
  `api`, `manned-adapter` and `manned-feed` stubs serving `/healthz`,
  `/readyz` (every dependency named with its state and why) and
  `/metrics`, draining on SIGTERM, with a `migrate` subcommand for WP-1;
  the `ANSP_*` configuration (unknown and malformed variables refused by
  name, secrets from files, redacted start-up line) and the one token
  verifier configuration with `StrictSessionClaims`; slog JSON logging,
  Prometheus with `core.Counters` export, OpenTelemetry; the NATS
  connection that reconnects forever and starts degraded, with the
  streams and buckets of `docs/PLAN.md` section 7; the layout test; the
  Makefile, the lean CI workflow, the Dockerfile and the development
  compose.
- WP-1 store and migrations: the two goose trees (relational: PostGIS,
  the hash-chained append-only `events`, `ansp_policy`, `source_controls`
  with version and epoch, `restrictions`, `restriction_versions`,
  `restriction_requests`, `adapters`; timeseries: the `manned_tracks`
  hypertable with compression after 7 days and retention of 90 days,
  `feed_products`), each with its own version table and an application
  role without UPDATE or DELETE on the insert-only tables; the `migrate`
  subcommand and the start-up schema check (M36); bounded pgx pools
  (`ANSP_DB_*`), sqlc queries, the COPY writer of manned tracks;
  `internal/audit` (record, verify a month, query) and `internal/policy`
  (load, update through KV, follower with the compiled defaults);
  `uspace-core` v1.2.0.
