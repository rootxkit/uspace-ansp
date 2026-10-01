// Package bus is the NATS and JetStream connection of every process
// (docs/PLAN.md section 7, LESSONS B-08): it reconnects forever, logs
// once per transition, starts degraded after three failed attempts
// instead of exiting, and reports its state to readiness. The subject,
// stream and bucket names of section 7 are constants here, and
// EnsureStreams declares the streams and buckets idempotently.
package bus
