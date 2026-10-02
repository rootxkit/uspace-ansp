// Package manned is the manned traffic the ANSP hands to U-space
// (ATS.OR.127(a), spec 02 F4): the track/manned/v1 model and the
// normalisation of what a surveillance feed said into it. It is the only
// place where manned positions enter U-space from the ANSP, so a sample
// stamped at the wrong time or dropped in silence becomes a missed or
// false proximity alert at the USSP (T-11, SC-15).
//
// Model (model.go, wire.go): Track is one aircraft as published on
// man.v1.<adapter>.<icao24>, in the 04 §2 envelope. Altitudes are kept by
// definition, never converted into each other (D-03): AltPressureM is
// barometric (ISA) and never an AMSL value, AltWGS84M geometric height
// above the ellipsoid. Units are in every name (E-13); the feed units are
// converted at the reader boundary with the constants of units.go.
//
// Normalisation (normalise.go), per adapter instance:
//
//   - time placement (T-01, T-02, T-12): rx_ts is the adapter's clock at
//     read; a sample with a feed time is placed at rx_ts - (newest feed
//     time of the batch, the feed's own "now" included - its feed time)
//     through timeplace.PlaceBatch, time_source source_clock; a sample
//     without one is placed at its read, ts null, time_source system,
//     counted placed_at_arrival. The feed's clock is never compared with
//     anything but itself;
//   - a captured_at ahead of the clock beyond future_tolerance_s is
//     clamped and counted (T-13);
//   - order (T-03): within one icao24 a sample older on the feed's clock
//     than the one held is dropped, out_of_order;
//   - dedupe: the same (feed time, position) of one icao24 inside
//     dedupe_window_s is dropped, duplicates;
//   - refusals by field (refused_icao24, refused_position, ...); an
//     optional member that is not a measurement is cleared and counted
//     (cleared_<field>) and the aircraft still published (CLAUDE.md
//     rule 4); nothing is filtered by position (B-12);
//   - the aircraft held are bounded by max_aircraft, the least recently
//     heard evicted and counted (E-10).
//
// Policy (policy.go): every threshold and bound is a Policy value with
// its default in Defaults, travelling with the policy_version of the
// followed ansp_policy row (docs/PLAN.md section 15 gap 25: the row does
// not carry the adapter's values yet). The stall rule, the switch and
// the status are the runner's (package adapter); the readers are in
// replay and dump1090; asterix is a stub. The package never logs; the
// process does, refusals at most once per icao24 per minute
// (RefusalLimiter).
package manned
