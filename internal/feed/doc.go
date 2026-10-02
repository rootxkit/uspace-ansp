// Package feed is the F4 manned traffic information service of
// manned-feed (2021/665 ATS.OR.127(a); spec 02 F4, 04 §2, §3.1; docs/
// PLAN.md sections 2, 6 and 9): the snapshot, the WebSocket stream, the
// degraded markers, the per-client limits and the writer of every
// sample to manned_tracks.
//
// # Ingest
//
// DecodeTrack takes one track/manned/v1 message from man.v1.<adapter>.
// <icao24> as the adapter publishes it, bounded (MaxMessageBytes),
// validated against the schema's members and the adapter's bounds; only
// state live is taken. A sample whose subject names another adapter
// than its body is refused. Adapters remembers every adapter's last
// source/status/v1 (src.v1.manned.<adapter>), bounded by MaxAdapters; an
// adapter whose status is older than source_liveness_s is down.
//
// # The stream and the snapshot
//
// Service.Ingest puts a sample in the picture and, when it is shown,
// sends it to every client it concerns: at most one frame per aircraft
// per MinTrackInterval (2 Hz; a newer sample within it waits and only the
// latest goes, flushed every 100 ms). Service.Run ages the picture every
// TickPeriod and sends every change (stale, source_disabled): nothing
// disappears silently. Every frame is the 04 §2 envelope with a body
// named by schema (M12, M29): console/status/v1 on connect and every
// StatusPeriod (2 s) with connection_id, server_ts, policy_version,
// stale_after_s, live_max_age_s, the client's dropped_frames,
// degraded[], sources[] (each adapter's source/status/v1 body) and this
// system's adapters[], cis_version, cis_age_s, nats and relevance;
// console/snapshot/v1 on connect and on every console/subscribe/v1; and
// track/manned/v1 with the sample's own times (never restamped), its
// state, relevant and age_s. There is no feed/status/v1.
//
// A machine client (scope ansp.traffic, its certificate bound per
// ANSP_MTLS_MODE by the guard) receives the relevant aircraft; the
// console (the uspace_session cookie, M22) receives every aircraft,
// flagged relevant or not (the pinned console/subscribe/v1 has no "all"
// layer, docs/PLAN.md section 15 row 33). A backlog-only aircraft is
// never sent. Each client has a bounded send queue: past SendQueue the
// oldest frame is dropped, counted and said in its next status frame,
// and the picture is never blocked; a write that does not finish within
// WriteTimeout closes the client with 1013. Streams are capped in total
// and per client id; past a cap the upgrade is refused 503 with
// Retry-After (06 T8). A console stream re-checks its session every
// status period and closes with 4401 when it has ended or cannot be
// checked (docs/PLAN.md section 15 row 21), and reports the session in
// use at most once a minute.
//
// The snapshot answers every aircraft the caller is served with its age,
// plus degraded[] (adapters_silent: no adapter live; cis_projection_stale:
// no CIS projection or one older than cis_stale_bound_s; nats; and
// timeseries_writer while inserts fail), adapters[], cis_version,
// cis_age_s, policy_version and generated_at: an empty picture is
// manned: [] with degraded saying why, never merely [] (SC-22).
// feed_products is sampled per client every ProductPeriod (0.1 Hz)
// through a bounded ProductQueue.
//
// # The writer
//
// Recorder reads MAN_MIRROR through a durable pull consumer with
// explicit ack and writes every valid sample (live and backlog,
// relevant or not: B-12) to manned_tracks in batches of BatchRows or
// BatchWait, acknowledging a sample only after its batch committed.
// While the database is down the batch is handed back with a growing
// delay and the samples wait in the stream, bounded by MaxUnwritten
// unacknowledged (B-07); the failure is counted and said (Status,
// Degraded). A sample delivered twice lands once (msg_id, migration
// 0010). A jump in the stream sequence of first deliveries, or samples
// that expired from the stream before the consumer's floor, are a gap:
// counted (writer_gap_samples) and said, never silent.
package feed
