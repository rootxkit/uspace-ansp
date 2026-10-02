package policy

import (
	"errors"
	"regexp"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// The zone types a restriction may default to (docs/PLAN.md 5.1).
const (
	ZoneProhibited       = "PROHIBITED"
	ZoneReqAuthorization = "REQ_AUTHORIZATION"
)

// Thresholds are the values of one policy version, the ansp_policy row
// of docs/PLAN.md section 5.1. Units are in the names (E-13); every
// number is finite and positive (INV-03).
type Thresholds struct {
	FeedMarginLateralM  float64 `json:"feed_margin_lateral_m"`
	FeedMarginVerticalM float64 `json:"feed_margin_vertical_m"`
	StaleAfterS         float64 `json:"stale_after_s"`
	SourceLivenessS     float64 `json:"source_liveness_s"`
	CISPAlarmAfterS     float64 `json:"cisp_alarm_after_s"`
	CISPHeartbeatS      float64 `json:"cisp_heartbeat_s"`
	CISReconcileS       float64 `json:"cis_reconcile_s"`
	CISStaleBoundS      float64 `json:"cis_stale_bound_s"`
	NoticeEscalationS   float64 `json:"notice_escalation_s"`
	DefaultZoneType     string  `json:"default_zone_type"`
	Country             string  `json:"country"`
}

// Defaults are the documented defaults of docs/PLAN.md section 5.1, in
// this one place. They equal the column defaults and the seeded version
// 1 of migration 0003_ansp_policy (an integration test compares them),
// and a Follower with no policy from KV serves them.
func Defaults() Thresholds {
	return Thresholds{
		FeedMarginLateralM:  5000,
		FeedMarginVerticalM: 1500,
		StaleAfterS:         15,
		SourceLivenessS:     15,
		CISPAlarmAfterS:     10,
		CISPHeartbeatS:      15,
		CISReconcileS:       60,
		CISStaleBoundS:      300,
		NoticeEscalationS:   60,
		DefaultZoneType:     ZoneProhibited,
		Country:             "GEO",
	}
}

func (t *Thresholds) numbers() []struct {
	field string
	value float64
} {
	return []struct {
		field string
		value float64
	}{
		{"feed_margin_lateral_m", t.FeedMarginLateralM},
		{"feed_margin_vertical_m", t.FeedMarginVerticalM},
		{"stale_after_s", t.StaleAfterS},
		{"source_liveness_s", t.SourceLivenessS},
		{"cisp_alarm_after_s", t.CISPAlarmAfterS},
		{"cisp_heartbeat_s", t.CISPHeartbeatS},
		{"cis_reconcile_s", t.CISReconcileS},
		{"cis_stale_bound_s", t.CISStaleBoundS},
		{"notice_escalation_s", t.NoticeEscalationS},
	}
}

var countryPattern = regexp.MustCompile(`^[A-Z]{3}$`)

// Validate refuses a value that would disarm a check: zero, negative,
// NaN or infinite numbers, an unknown zone type, a malformed country.
// Every field at fault is named.
func (t *Thresholds) Validate() error {
	var errs []error
	for _, n := range t.numbers() {
		if !core.IsFinite(n.value) || n.value <= 0 {
			errs = append(errs, core.Fieldf(n.field, "must be a finite number greater than zero"))
		}
	}
	if t.DefaultZoneType != ZoneProhibited && t.DefaultZoneType != ZoneReqAuthorization {
		errs = append(errs, core.Fieldf("default_zone_type", "must be PROHIBITED or REQ_AUTHORIZATION"))
	}
	if !countryPattern.MatchString(t.Country) {
		errs = append(errs, core.Fieldf("country", "must be an ISO 3166-1 alpha-3 code"))
	}
	return errors.Join(errs...)
}

// Policy is one stored version: the thresholds, the policy_version that
// travels on every status line and delivery, who changed it and when.
type Policy struct {
	Version int64 `json:"policy_version"`
	Thresholds
	ChangedBy string    `json:"changed_by"`
	ChangedAt time.Time `json:"changed_at"`
}
