// Package adapter is the Adapter interface, the registry of kinds and
// the Runner of one surveillance adapter process (B-16).
//
// An Adapter reads one feed read-only and reports to a Sink: Connected,
// Heard (any input, heartbeats included), Sample, Refuse, Count. The
// Runner:
//
//   - runs the adapter and reconnects it forever with a doubling backoff
//     (B-08); a permanent error (ErrPermanent: a replay not allowed, the
//     deferred ASTERIX stub) stops it, so the process fails loudly;
//   - batches what is queued and detects stalls (T-11, SC-15): a read
//     after a silence longer than stall_after_s is a suspected stall and
//     its burst is drained until the queue is quiet; the stall is
//     confirmed when the burst spans more than stall_after_s on the
//     feed's own clock (it buffered) or carries no feed time; samples
//     with a feed time are then placed by it, samples without one are
//     backlog, and stalled_reads moves. A quiet sky that resumes is not
//     a stall;
//   - follows the switch of (manned, <instance>): disabled, it keeps
//     reading and normalising, publishes nothing and counts every track
//     refused_disabled; re-enabled, the next batch is published (B-11).
//     KVSwitch reads the source-control document proposed in
//     docs/PLAN.md section 15 gap 26 on uspace-core's sources.Follower;
//   - publishes every track on man.v1.<instance>.<icao24> and, every
//     status_period_s, source/status/v1 on src.v1.manned.<instance> with
//     state (live, stale, disabled, down, unknown), since, age_s, who
//     disabled it and why, every counter, and this adapter's enabled,
//     connected, feed ("connected" or "reconnecting since T"),
//     last_frame_at, aircraft_seen, policy_version, stalled, feed_clock;
//   - answers readiness (Check): feed ok, degraded when switched off,
//     down with "reconnecting since T".
//
// The runner never logs; it reports Events for the process to log.
package adapter
