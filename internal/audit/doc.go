// Package audit is the append-only, monthly hash-chained audit log of
// uspace-ansp (docs/PLAN.md section 5.1 events, spec 06 section 2 T7):
// every write, switch, view of the inbox and export.
//
// Record writes one Event inside the caller's transaction, so the event
// commits or rolls back with the act it records. Every event carries
// actor_type (user, client, system), actor_id, purpose, entity_type,
// entity_id, event_type and a JSON object payload, each bounded. Its
// time is the database clock. Under an advisory lock per UTC month it
// takes the next id and links the row to the previous one:
//
//	hash = hex(sha256(prev_hash || canonical JSON of the row))
//
// where the canonical JSON is every column but prev_hash and hash in a
// fixed order, ts in UTC with microseconds and the payload with sorted
// keys as PostgreSQL stored it. The first row of a month links to the
// last row before it; the first row ever to 64 zeros.
//
// Verify recomputes one month and returns ok=false with the id of the
// first row whose link or content does not hold; VerifyMonth also says
// how many rows it checked, so "verified" is never an empty claim.
// Query pages the log newest first for GET /v1/audit.
//
// The application role ansp_app may only SELECT and INSERT events, and
// a trigger refuses UPDATE, DELETE and TRUNCATE for every role. The
// package imports only the generated relational queries, never
// internal/store, so internal/store can record events in its own
// transactions.
package audit
