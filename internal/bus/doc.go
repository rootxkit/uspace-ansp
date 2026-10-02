// Package bus is the NATS and JetStream connection of every process
// (docs/PLAN.md section 7, LESSONS B-08): it reconnects forever, logs
// once per transition, starts degraded after three failed attempts
// instead of exiting, and reports its state to readiness. The subject,
// stream and bucket names of section 7 are constants here, and
// EnsureStreams declares the streams and buckets idempotently (with
// sessions_live, the live-session projection of section 15 row 21). KV
// is one bucket resolved on first use and again after a failure, for
// the readers and writers that start before the api has declared it.
package bus
