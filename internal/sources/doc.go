// Package sources is this system's side of the source switches (spec
// 04 §3.6, predecessor U-15, LESSONS B-09, B-10, B-11) on
// uspace-core/sources, which holds every judgement: Query, the version
// within epoch rule and the never-fail-closed default (CLAUDE.md rule
// 3). Nothing here decides whether a source is enabled; it carries the
// state to where core decides it, with who, when and why.
//
// # The document
//
// Doc is the state as it travels: the value of key KVKey ("current") in
// the KV bucket source_control and the same bytes on the core subject
// ctl.sources: {version, epoch, default_deny, controls: [{source_type,
// instance_id (null for the whole type), enabled, reason, actor,
// changed_at}]}. It mirrors WP-1's source_controls columns and core's
// State; version is the highest row version (the database sequence) and
// epoch the database's (source_control_epoch). WP-4 proposed it
// (docs/PLAN.md section 15 gap 26) and its adapter decodes it; WP-6
// confirms it unchanged and this package writes exactly it. DecodeDoc
// is strict (unknown members, a missing epoch, a malformed row and
// anything past MaxDocBytes or MaxRows are refused) and never panics.
//
// # Writer (api)
//
// Writer.Set changes one switch: it checks that the bucket answers
// (ErrKVUnavailable, 503, and nothing changed when it does not), then
// the Repo commits the row under the writers' advisory lock with the
// next version and an audit event, and only after the commit is the
// whole state put to KV and pushed on ctl.sources. The put is a
// compare-and-set that never replaces a newer state of the same epoch,
// so two replicas committing in one order cannot reach KV in the other.
// A put that fails after the commit is counted (source_kv_put_failed),
// the switch stays set in the database of record, and Republish (every
// RepublishPeriod) writes the database's state again: KV is never behind
// for longer than one period.
//
// # Follower (manned-feed, adapters)
//
// Follower holds the last state through core's sources.Follower. Follow
// reads the bucket at start (three attempts, then it runs degraded and
// says so), applies every ctl.sources push and every watched put, and
// reads the bucket again every RereadPeriod to repair a lost push.
// Decision answers for (source_type, instance) with core's Why and the
// deciding row's actor, reason and changed_at; while nothing has been
// read every source is enabled (B-09: a follower never fails closed) and
// Known is false, which the status says.
//
// Vectors: uspace-core vectors/testdata/source_control.json, every case
// that names ansp, run through Follower by TestVectorsSourceControl.
package sources
