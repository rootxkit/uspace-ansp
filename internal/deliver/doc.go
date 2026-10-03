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
// job is abandoned with an alarm; any other 4xx, and a CISP 409 on a
// publication (deterministic: the pair with another body, or a lower
// ansp_version), fails at once with the response excerpt and an alarm. Both alarms stay open until a person
// acknowledges them with a reason (Alarms, audited). An occurrence
// report is the exception to abandonment: it is held queued until the
// authority takes or refuses it, every OccurrenceHold past its window,
// and an authority that does not serve its intake (404, 405, 501) holds
// it rather than failing it. A message for a
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
// The DSS channel (WP-9, dss.go; internal/dss) rides the same outbox
// beside the CISP publication and never waits for it (D6): dss_put on an
// activation or extension and dss_delete on an end or expiry, queued in
// the version's transaction, ordered per restriction as one channel; one
// re-read of a stale ovn, then a failure with an alarm; what the DSS
// accepted recorded with the attempt, and one uss_notify per subscriber
// it named queued in the same transaction and published at once (a
// notification still queued past NotifyLatency raises uss_notify_late).
// The restriction's DSS standing (none, pending since T, written,
// deleted, failed) is on restr.v1 and on the restriction.
//
// Every refusal, retry, cancellation and repaired gap is a counter
// (E-09); the package logs only through the logger the process gives it.
package deliver
