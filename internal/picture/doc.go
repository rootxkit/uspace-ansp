// Package picture is the live manned picture of manned-feed: the last
// sample per icao24 with its age, its state and its relevance to U-space
// (spec 02 F4, 04 §2, §3.1; docs/PLAN.md section 2). It holds no
// judgement of its own: containment, the padded box, the ceiling with
// the pressure uncertainty and the source switches are calls into
// uspace-core (CLAUDE.md rule 3), and every threshold comes from the
// followed ansp_policy (stale_after_s, feed_margin_lateral_m,
// feed_margin_vertical_m) or Limits (max_aircraft, evict_after_s; not
// policy columns yet, docs/PLAN.md section 15 gap 32).
//
// Observe takes one track/manned/v1 sample. A sample not newer than the
// one held for its icao24 is dropped and counted (T-03). A backlog
// sample is history: the writer records it, the picture never shows it
// live, and an aircraft known only from backlog is backlog_only (T-04).
// A sample of a switched-off source is not shown (B-11). A sample that
// arrives older than stale_after_s is shown stale, never live, and
// counted picture_arrived_stale (SC-15: a stalled feed's samples keep
// their own time). Past MaxAircraft the aircraft heard longest ago is
// evicted, counted (E-10).
//
// Tick ages the picture: an aircraft whose source the follower says is
// switched off becomes source_disabled with who, when and why, within
// one tick and only for that source; one without a sample for
// stale_after_s since its captured_at becomes stale (T-06); one without
// a sample for evict_after_s is removed. Every change is returned, so
// the stream tells its consumers: nothing disappears silently. A stale
// or source_disabled aircraft becomes live again only with a new sample.
//
// Relevance is inside any U-space volume of the CIS projection, its
// bounding box padded by feed_margin_lateral_m (geodesy.BBox.PadM; core
// holds no buffer of a polygon, so the margin errs towards relevant),
// and below its ceiling plus feed_margin_vertical_m, judged by
// zones.JudgeVertical on alt_pressure_m with core's pressure
// uncertainty: inside only the widened band is still relevant and
// flagged (within_band false), and a ceiling that cannot be judged (no
// altitude, an AGL or WGS84 ceiling here) is relevant and flagged. It is
// a flag on every sample, never a filter at the edge (B-12). With no CIS
// projection every aircraft is relevant, not evaluated, and
// RelevanceStatus says "relevance: not evaluated (no CIS projection)"
// (SC-22: an empty filter never looks like an empty sky).
//
// Snapshot is every entry in a bounding box with its age, sorted by
// icao24. The picture is safe for concurrent use.
package picture
