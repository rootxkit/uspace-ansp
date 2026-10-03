// Package coord is the Annex V coordination inbox and the occurrence
// outbox of the ANSP (docs/PLAN.md sections 5.1, 6, 7, 15 rows 6, 23,
// 24, 42, 43; WP-10): Reg. (EU) 2021/664 Art. 13(2) and Annex V, Reg.
// (EU) 376/2014 Art. 4(8).
//
// # Intake
//
// Service.Submit takes a coordination/annex_v/v1 body (this system's
// schema, M14) from a USSP's machine token. The sender's sub must belong
// to a USSP of the CIS USSP list (its ussp_id, or the client id
// ussp-<ussp_id>-NN of M24) and the body's ussp_id must be that USSP's;
// otherwise 403, with an audit row (and 503 when the row cannot be
// written: a refusal is never silent). While no list is projected the
// notice is accepted and flagged sender_unverified, counted: this system
// never refuses a safety notice for lack of its own data. DecodeNotice
// checks the body member by member and never panics (FuzzAnnexVNotice):
// the kinds, each intent's F3548 entity id as a UUID, its authorisation
// number and DSS state, the times in order, every volume through
// uspace-core's f3548 envelope and altitude checks (CLAUDE.md rule 3),
// the nonconformance member a nonconformance notice carries, and the
// bounds (1 MiB, 100 intents, 100 volumes each). Unknown members are
// kept. The planned or active restrictions the notice's volumes
// intersect in space and time (the volumes' envelopes against the
// restrictions in PostGIS) are recorded with it. The row and its audit
// event commit together, and only then is the notice put on coord.v1
// (B-05) and the receipt answered: 202 {ack_id, state: received,
// received_at} (M2). A repeat of a notice_ref with the same body
// answers the first receipt with 200 and stores nothing; with another
// body it is refused 409, so a second notice is never answered with the
// first one's receipt.
//
// # The two-state acknowledgement and the escalation
//
// A notice is received (the receipt) and then acknowledged by a person
// (a watch_supervisor on the console, Service.Acknowledge, audited with
// an optional note): the two states of docs/PLAN.md section 15 gap 6.
// The sender polls GET /v1/coordination/notices/{ack_id} and reads the
// role of the person and when, never a name, never the note. A
// nonconformance or contingent notice needs that person: not
// acknowledged within notice_escalation_s (the ansp_policy row, 60 s)
// it is escalated (escalated_at) and escalated again every
// EscalationRepeat (30 s) until acknowledged, each escalation a frame of
// coordination/notice/v1, counted notices_escalated and logged at error
// level by the process; the console renders it as the loudest state. An
// intent_notice or ended notice is informational and never escalates.
// The escalation lives on the row (escalated_at, last_escalated_at,
// escalations) and is judged on the database clock by a query every
// replica runs with SKIP LOCKED, so a restart, a rolling update with a
// new hostname or another replica carries it on and never clears or
// repeats it. Every change has a sequence number; a change whose
// coord.v1 publish failed is published by the next tick, so a missed
// escalation or acknowledgement is never forgotten.
//
// # Frames
//
// coord.v1.<kind>.<ack_id> and GET /v1/coordination/stream carry
// coordination/notice/v1 (schemas/coordination/notice/v1.json, owned
// here): the inbox item in the 04 section 2 envelope, the USSP's body
// as its payload. It is not coordination/annex_v/v1, the request body:
// a frame's body is the message its schema names (row 24, settled).
//
// # Occurrences
//
// Occurrences.Create stores a staff report with the reporter's opaque
// person reference sealed under ANSP_SECRETS_KEY_FILE (AES-256-GCM,
// bound to the report id; without the key a report with a reference is
// refused 503, never stored in clear), its outbox job (deliveries kind
// occurrence, no restriction) and its audit event in one transaction,
// with deadline_at = became_aware_at + 72 h. The outbox worker calls
// SendOccurrence at each attempt, which opens the reference and posts
// the occurrence/v1 body (the 04 section 3.3 field list until the
// authority publishes its schema, row 23) to the authority with a token
// of scope occurrences.write whose aud is the authority's host; the
// reference travels in clear over TLS (M13) and is taken out of
// whatever the authority answers before the answer is logged or stored.
// Occurrences.Monitor raises occurrence_undelivered for a report not
// delivered 60 h after became_aware_at (12 h before the deadline),
// which a person's acknowledgement leaves open until the delivery.
//
// # What is never logged
//
// The reporter's person reference: it is in no type this package
// returns, logs, streams or exports (a reflection test walks them), in
// no audit payload (has_reporter_ref says whether there was one), and
// in no delivery row (the occurrence job keeps no body). The account id
// of the person who acknowledged a notice is kept for the audit and
// never given to the sender. A library package never logs: outcomes are
// returned and counted, and the process logs them.
package coord
