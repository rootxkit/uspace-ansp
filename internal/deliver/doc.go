// Package deliver is the outbox (docs/PLAN.md D5, D6, section 5.1
// deliveries, section 7 deliver.v1; WP-8): every outbound side effect of
// a restriction goes through one JetStream work queue with the body pair
// (ansp_ref, ansp_version) as the idempotency key and a log row per job
// and per attempt.
//
// Outbox.Enqueue writes the deliveries row (queued) in the caller's
// transaction; Outbox.Committed publishes deliver.v1.<kind> after the
// commit, and Outbox.Scan, every 5 s, publishes the rows whose publish
// was lost and the rows whose message is overdue (B-05), each counted.
//
// Worker is the pull consumer of DELIVER (in cmd/api, at most
// Policy.InFlight attempts at once). It leases the row on the database
// clock (no lock is held while the request is in flight, and versions of
// one restriction to one target go in order), fixes the request at the
// first attempt (every retry sends the same bytes, which the CISP's
// replay rule needs), sends, writes the outcome and only then acks the
// message. 5xx, 408, 409, 429, timeouts and network errors are retried
// with backoff from 1 s doubling to 60 s (Nak with that delay) for the
// policy's window (24 h) and at most Policy.MaxAttempts times, then the
// job is abandoned with an alarm; any other 4xx fails at once with the
// response excerpt and an alarm. Both alarms stay open until a person
// acknowledges them with a reason (Alarms, audited). A message for a
// row that is already settled does nothing.
//
// CISP publications (02 F2, api/clients/cisp.yaml): POST
// /v1/restrictions with the generated cis/restriction/v1 body (member
// ansp_version, M4) for a planned create, or for the first publication
// of an active restriction; PATCH /v1/restrictions/{ansp_ref}?by=ansp_ref
// {op, ansp_version, ends_at?, feature?} for activate, extend, end and
// cancel. Each attempt carries a token with cis.publish:restrictions
// whose aud is the CISP's host, the client certificate of
// ANSP_CISP_CLIENT_CERT_FILE (mTLS, M24), and the detached JWS of
// core's SignDetached over the exact body in X-JWS-Signature (M26, M27).
// A 2xx records published_version and puts restr.v1 with published true.
// An expiry is not sent: the CISP expires a restriction at ends_at on
// its own clock.
//
// Monitor raises cisp_not_published on restr.v1 for a restriction active
// for more than cisp_alarm_after_s without a CISP publication of its
// current version, and starts the degraded direct delivery: POST
// {base_url}/v1/cis/notifications on every USSP of the CIS list and the
// authority, a cis/change/v1 record as a compact JWS of core's
// SignCompact (iss this system, aud the target's host, sub the
// restriction id, jti the delivery id). The publication clears the alarm
// with its duration and cancels the direct jobs still queued
// (superseded_by_cisp).
//
// Heartbeat posts {sent_at, active_refs} to /v1/publishers/heartbeat
// every cisp_heartbeat_s; a failure shows as "unreachable since T" in
// readiness, never as data loss, and the first answer after it runs
// Reconciler, which re-queues every active restriction the CISP does not
// hold at its current version.
//
// Every refusal, retry, cancellation and repaired gap is a counter
// (E-09); the package logs only through the logger the process gives it.
package deliver
