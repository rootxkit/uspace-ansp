package manned

import (
	"errors"
	"math"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/timeplace"
)

// Policy is every threshold, window and bound the adapter judges with
// (CLAUDE.md rule 5, INV-03). The ansp_policy row of WP-1 carries
// none of them yet (docs/PLAN.md section 15 gap 25), so they come from
// Defaults, in this one place, and travel with the policy_version of the
// ansp_policy row the process follows; SourceLivenessS is that row's
// source_liveness_s. Units are in the names (E-13).
type Policy struct {
	// StallAfterS is the read gap past which the next read is a
	// suspected stall (T-11, SC-15).
	StallAfterS float64 `json:"stall_after_s"`
	// DedupeWindowS is the per-aircraft window of the (feed time,
	// position) dedupe.
	DedupeWindowS float64 `json:"dedupe_window_s"`
	// MaxSpacingS bounds the spacing timeplace.PlaceBatch keeps (T-02).
	MaxSpacingS float64 `json:"max_spacing_s"`
	// FutureToleranceS is how far ahead of the adapter's clock a
	// captured_at may be before it is clamped (T-13).
	FutureToleranceS float64 `json:"future_tolerance_s"`
	// MaxAircraft bounds the aircraft held per adapter (E-10).
	MaxAircraft int `json:"max_aircraft"`
	// MaxAgeS is the age of an aircraft.json position past which the
	// sample is backlog.
	MaxAgeS float64 `json:"max_age_s"`
	// HeldFieldMaxAgeS is how long, on the feed's clock, a field of an
	// SBS line without a position is merged into a later position.
	HeldFieldMaxAgeS float64 `json:"held_field_max_age_s"`
	// BurstSettleS ends the drain of a burst after a suspected stall:
	// the burst is over when no sample arrives for this long.
	BurstSettleS float64 `json:"burst_settle_s"`
	// MaxBatch bounds one batch and the queue between reader and
	// normaliser (E-10).
	MaxBatch int `json:"max_batch"`
	// StatusPeriodS is the period of src.v1.manned.<adapter>.
	StatusPeriodS float64 `json:"status_period_s"`
	// FeedIdleTimeoutS ends a TCP session that delivers nothing, not
	// even a heartbeat, for this long (dump1090 sends one every 60 s by
	// default), so a half-open connection is reconnected.
	FeedIdleTimeoutS float64 `json:"feed_idle_timeout_s"`
	// PollPeriodS is the aircraft.json poll period (1 Hz).
	PollPeriodS float64 `json:"poll_period_s"`
	// ReconnectMinS and ReconnectMaxS bound the reconnect backoff (B-08).
	ReconnectMinS float64 `json:"reconnect_min_s"`
	ReconnectMaxS float64 `json:"reconnect_max_s"`
	// MaxLineBytes bounds one SBS line; MaxJSONBytes one aircraft.json
	// document; MaxRecordBytes one replay record (E-10).
	MaxLineBytes   int `json:"max_line_bytes"`
	MaxJSONBytes   int `json:"max_json_bytes"`
	MaxRecordBytes int `json:"max_record_bytes"`
	// MaxQualityKeys bounds the quality block carried as received.
	MaxQualityKeys int `json:"max_quality_keys"`
	// RefusalLogEveryS is the period of the refusal log per icao24.
	RefusalLogEveryS float64 `json:"refusal_log_every_s"`
	// The plausibility bounds of a sample: a value outside them is not a
	// measurement and is cleared (optional fields) and counted.
	MinAltM    float64 `json:"min_alt_m"`
	MaxAltM    float64 `json:"max_alt_m"`
	MaxGSMS    float64 `json:"max_gs_ms"`
	MaxVRateMS float64 `json:"max_vrate_ms"`
	// SourceLivenessS is ansp_policy.source_liveness_s: a connected
	// feed with no sample for this long is stale.
	SourceLivenessS float64 `json:"source_liveness_s"`
}

// Defaults are the WP-4 defaults (docs/WORKPACKAGES/WP-4.md: stall 5 s,
// dedupe 2 s, 1 Hz poll, 2 s status; T-02: 120 s spacing; plan section
// 9: 5000 aircraft) and the source liveness of policy.Defaults.
func Defaults() Policy {
	return Policy{
		StallAfterS:      5,
		DedupeWindowS:    2,
		MaxSpacingS:      timeplace.DefaultMaxBatchSpacing.Seconds(),
		FutureToleranceS: 1,
		MaxAircraft:      5000,
		MaxAgeS:          30,
		HeldFieldMaxAgeS: 10,
		BurstSettleS:     0.2,
		MaxBatch:         5000,
		StatusPeriodS:    2,
		FeedIdleTimeoutS: 150,
		PollPeriodS:      1,
		ReconnectMinS:    0.5,
		ReconnectMaxS:    30,
		MaxLineBytes:     512,
		MaxJSONBytes:     4 << 20,
		MaxRecordBytes:   64 << 10,
		MaxQualityKeys:   32,
		RefusalLogEveryS: 60,
		MinAltM:          -1000,
		MaxAltM:          30000,
		MaxGSMS:          1000,
		MaxVRateMS:       200,
		SourceLivenessS:  15,
	}
}

// Validate refuses a policy that would disarm a check: a duration or
// bound that is zero, negative or not finite, or an altitude range that
// is empty. Every field at fault is named.
func (p *Policy) Validate() error {
	var errs []error
	for _, f := range []struct {
		name string
		v    float64
	}{
		{"stall_after_s", p.StallAfterS}, {"dedupe_window_s", p.DedupeWindowS}, {"max_spacing_s", p.MaxSpacingS},
		{"future_tolerance_s", p.FutureToleranceS}, {"max_age_s", p.MaxAgeS}, {"held_field_max_age_s", p.HeldFieldMaxAgeS},
		{"burst_settle_s", p.BurstSettleS}, {"status_period_s", p.StatusPeriodS}, {"feed_idle_timeout_s", p.FeedIdleTimeoutS},
		{"poll_period_s", p.PollPeriodS}, {"reconnect_min_s", p.ReconnectMinS}, {"reconnect_max_s", p.ReconnectMaxS},
		{"refusal_log_every_s", p.RefusalLogEveryS}, {"max_gs_ms", p.MaxGSMS}, {"max_vrate_ms", p.MaxVRateMS},
		{"source_liveness_s", p.SourceLivenessS},
	} {
		if !core.IsFinite(f.v) || f.v <= 0 {
			errs = append(errs, core.Fieldf(f.name, "must be a finite number greater than zero"))
		}
	}
	for _, f := range []struct {
		name string
		v    int
	}{
		{"max_aircraft", p.MaxAircraft}, {"max_batch", p.MaxBatch}, {"max_line_bytes", p.MaxLineBytes},
		{"max_json_bytes", p.MaxJSONBytes}, {"max_record_bytes", p.MaxRecordBytes}, {"max_quality_keys", p.MaxQualityKeys},
	} {
		if f.v <= 0 {
			errs = append(errs, core.Fieldf(f.name, "must be greater than zero"))
		}
	}
	if !core.IsFinite(p.MinAltM) || !core.IsFinite(p.MaxAltM) || p.MinAltM >= p.MaxAltM {
		errs = append(errs, core.Fieldf("min_alt_m", "must be finite and below max_alt_m"))
	}
	if p.ReconnectMinS > p.ReconnectMaxS {
		errs = append(errs, core.Fieldf("reconnect_min_s", "must not exceed reconnect_max_s"))
	}
	return errors.Join(errs...)
}

// Seconds converts a policy value in seconds to a duration, rounded to
// the microsecond; a value that is not finite or not positive is 0, one
// beyond a day is a day, so no policy value can overflow time arithmetic.
func Seconds(s float64) time.Duration {
	if math.IsNaN(s) || s <= 0 {
		return 0
	}
	if s >= (24 * time.Hour).Seconds() {
		return 24 * time.Hour
	}
	return time.Duration(math.Round(s*1e6)) * time.Microsecond
}

// PolicySource is the policy the hot path judges with now and the
// policy_version it travels with (0 while the process serves the
// compiled defaults because KV gave it nothing).
type PolicySource interface {
	Current() (Policy, uint64)
}

// StaticPolicy is a PolicySource that never changes (tests, and a
// process without a policy follower).
type StaticPolicy struct {
	Policy  Policy
	Version uint64
}

// Current is the fixed policy.
func (s StaticPolicy) Current() (Policy, uint64) { return s.Policy, s.Version }
