package bus

import "time"

// Subjects of docs/PLAN.md section 7. A trailing "." marks a prefix the
// publisher completes (adapter, icao24, state, kind, id).
const (
	// SubjectMannedPrefix: man.v1.<adapter>.<icao24>, track/manned/v1.
	SubjectMannedPrefix = "man.v1."
	// SubjectSourceStatusPrefix: src.v1.manned.<adapter>, source/status/v1.
	SubjectSourceStatusPrefix = "src.v1.manned."
	// SubjectRestrictionPrefix: restr.v1.<state>.<restriction_id>.
	SubjectRestrictionPrefix = "restr.v1."
	// SubjectDeliverPrefix: deliver.v1.<kind>, a delivery job.
	SubjectDeliverPrefix = "deliver.v1."
	// SubjectCISPrefix: cis.v1.<dataset>, the projected dataset.
	SubjectCISPrefix = "cis.v1."
	// SubjectCoordPrefix: coord.v1.<kind>.<ack_id>.
	SubjectCoordPrefix = "coord.v1."
	// SubjectControlSources is the push of the source-control state.
	SubjectControlSources = "ctl.sources"
	// SubjectControlPolicy is the push of the ansp_policy row.
	SubjectControlPolicy = "ctl.policy"
)

// JetStream streams.
const (
	StreamMannedMirror = "MAN_MIRROR"
	StreamRestriction  = "RESTR"
	StreamDeliver      = "DELIVER"
	StreamCoord        = "COORD"
)

// KV buckets.
const (
	BucketCISCurrent    = "cis_current"
	BucketSourceControl = "source_control"
	BucketPolicy        = "policy"
)

// Retention of the streams (docs/PLAN.md section 7).
const (
	MannedMirrorMaxAge = time.Hour
	RestrictionMaxAge  = 30 * 24 * time.Hour
	DeliverMaxAge      = 24 * time.Hour
	CoordMaxAge        = 30 * 24 * time.Hour
)
