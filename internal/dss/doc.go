// Package dss is the F3548 constraint manager of the ANSP (WP-9; spec 02
// F2, 02 F6, 09 section 1.4; docs/PLAN.md D6): a restriction's
// constraint reference in the DSS, the notification of the subscribers
// the DSS names, and the constraint details USSPs read from this system.
//
// # Wire
//
// Every path, operation, scope and member is the pinned standard's
// (CLAUDE.md rule 8, E-03): the operations are the table of paths.go,
// read from interuss/astm-utm-protocol utm.yaml at the commit
// uspace-core's f3548/SOURCE pins and held equal to it by a test; the
// bodies are uspace-core/f3548's generated types (one struct, D7). The
// DSS is ANSP_DSS_URL; its token carries utm.constraint_management with
// aud the DSS's host (M18). A subscriber notification (POST
// {uss_base_url}/uss/v1/constraints) carries the scope the standard
// gives notifyConstraintDetailsChanged, utm.constraint_management (not
// utm.constraint_processing as the plan first said; docs/PLAN.md
// section 15 row 41), with aud the host of the uss_base_url as the DSS
// returned it: peers are discovered, never mapped through a configured
// list.
//
// # Client
//
// Client.PutReference creates a reference (no ovn) or updates it at its
// ovn, DeleteReference deletes it at its ovn, GetReference reads it (the
// ovn is there: this system is the manager). Each answer is read up to
// a byte bound (f3548.MaxMessageBytes) and decoded by DecodeChange or
// DecodeReference, which check what the outbox rests on: the id, the
// manager, the times, the ovn of a write, every subscriber's uss_base_url
// and subscriptions, and at most the policy's number of subscriptions
// (an answer past it is refused whole, never cut: ErrTooManySubscribers).
// uspace-core v1.3.0 has no validator for these responses (it validates
// operational intents), so the checks are here; they judge the shape,
// not airspace. Failures are typed: ErrConflict (409), ErrNotFound
// (404), ErrUnavailable (no answer, 5xx, 408, 429: retried),
// ErrRefused, ErrMalformed. Health is the readiness line's view: ok, or
// unreachable since T; Ping reads a reference that does not exist so the
// line knows the DSS before the first write.
//
// # The outbox
//
// The DSS work rides internal/deliver's outbox (D5): a dss_put on an
// activation or extension and a dss_delete on an end or expiry are
// written in the version's transaction and sent after the commit, in
// order per restriction across replicas (the row lease, and the put and
// delete of one restriction are one channel); a stale ovn is re-read
// once and the write retried, a second 409 fails loudly with an alarm.
// What the DSS accepted is recorded with the attempt (the ovn, the
// version, the reference, dss_constraint_writes), and one uss_notify per
// subscriber in the same transaction; the notifications are published at
// once and sent by the work queue, never inline in the DSS write, with
// bounded retries (NotifyWindow). A notification still queued
// CstrPublishedNotificationLatencySeconds after the DSS answered raises
// uss_notify_late (open until delivered, superseded or given up). A DSS
// outage never holds the CISP publication: the restriction shows dss
// pending since T, readiness dss unreachable since T, and the write goes
// when the DSS answers. A planned or cancelled restriction is never in
// the DSS.
//
// # Details
//
// Details serves GET /uss/v1/constraints/{entityid}: the constraint as
// the DSS last accepted it (the standard: unknown before the DSS
// answered the first write), its details the version's F3548 volumes
// exactly as internal/restriction derived them (type DAR, D3, gap 16),
// served for ExternalDataMaxRetentionTimeHours after the restriction
// ended, then 404; one indexed query, BenchmarkConstraintDetails.
//
// USSLogSet (GET /uss/v1/log_sets/{log_set_id}) is not served in v1:
// the ANSP is a constraint manager, not a USS of operational intents.
//
// dsstest is an in-test DSS with the ovn semantics and an in-test
// subscriber; no process imports it.
package dss
