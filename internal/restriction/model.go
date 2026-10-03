package restriction

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// State is a restriction's lifecycle state (docs/PLAN.md section 5.1).
type State string

// The states.
const (
	StatePlanned   State = "planned"
	StateActive    State = "active"
	StateEnded     State = "ended"
	StateCancelled State = "cancelled"
)

// Valid reports whether s is one of the four states.
func (s State) Valid() bool {
	switch s {
	case StatePlanned, StateActive, StateEnded, StateCancelled:
		return true
	}
	return false
}

// Terminal reports whether no transition leaves s.
func (s State) Terminal() bool { return s == StateEnded || s == StateCancelled }

// Op is one transition of the state machine (state.go).
type Op string

// The transitions. OpPlan creates the restriction; OpExpire and the
// scheduled half of OpActivate are the ticker's.
const (
	OpPlan     Op = "plan"
	OpActivate Op = "activate"
	OpExtend   Op = "extend"
	OpEnd      Op = "end"
	OpCancel   Op = "cancel"
	OpExpire   Op = "expire"
)

// EventType is the audit event of op (internal/audit: snake_case).
func (op Op) EventType() string { return "restriction_" + string(op) }

// The vertical references a restriction limit may have (D3): AGL is
// refused with ReasonAGL.
const (
	RefAMSL  = core.RefAMSL
	RefWGS84 = core.RefWGS84
)

// Shape is a restriction's area: a polygon (Ring, one closed outer ring,
// no holes in v1) or a circle (Center and RadiusM). Positions are WGS84
// degrees (SRID 4326).
type Shape struct {
	Ring    []core.LatLon
	Center  *core.LatLon
	RadiusM float64
}

// IsCircle reports whether s is a circle.
func (s Shape) IsCircle() bool { return s.Center != nil }

// GeoJSON is s as a GeoJSON geometry, positions [lng, lat]: a Polygon,
// or a Point (the circle's centre; its radius travels beside it).
func (s Shape) GeoJSON() string {
	var b strings.Builder
	if s.IsCircle() {
		b.WriteString(`{"type":"Point","coordinates":`)
		writePos(&b, *s.Center)
		b.WriteString(`}`)
		return b.String()
	}
	b.WriteString(`{"type":"Polygon","coordinates":[[`)
	for i, p := range s.Ring {
		if i > 0 {
			b.WriteByte(',')
		}
		writePos(&b, p)
	}
	b.WriteString(`]]}`)
	return b.String()
}

// Radius is the circle's radius for a store column: nil for a polygon.
func (s Shape) Radius() *float64 {
	if !s.IsCircle() {
		return nil
	}
	r := s.RadiusM
	return &r
}

func writePos(b *strings.Builder, p core.LatLon) {
	b.WriteByte('[')
	b.WriteString(strconv.FormatFloat(p.LonDeg, 'f', -1, 64))
	b.WriteByte(',')
	b.WriteString(strconv.FormatFloat(p.LatDeg, 'f', -1, 64))
	b.WriteByte(']')
}

// Actor is who changed a restriction: a console user (ID the account
// id, Role its role, the *_by columns and changed_by), or the system
// (the ticker's scheduled activation and expiry).
type Actor struct {
	Type string // audit.ActorUser or audit.ActorSystem
	ID   string
	Role string
}

// SystemActor is the ticker.
var SystemActor = Actor{Type: "system", ID: "restriction-ticker", Role: RoleSystem}

// RoleSystem is the changed_by of a version the ticker made.
const RoleSystem = "system"

// Restriction is one restriction row and its current feature.
type Restriction struct {
	ID               string
	AnspRef          string
	Identifier       string
	UspaceAirspaceID string
	ZoneType         core.ZoneType
	Shape            Shape
	LowerM           float64
	LowerRef         core.VerticalRef
	UpperM           float64
	UpperRef         core.VerticalRef
	StartsAt         time.Time
	EndsAt           time.Time
	ReasonText       string
	State            State
	AnspVersion      int64
	// ActivateAt is set while a planned restriction waits for the
	// ticker to activate it at StartsAt.
	ActivateAt    *time.Time
	CreatedBy     string
	ActivatedBy   *string
	EndedBy       *string
	CancelledBy   *string
	CreatedAt     time.Time
	ActivatedAt   *time.Time
	EndedAtActual *time.Time
	RequestID     *string
	SupersedesID  *string
	// PublishedVersion is the version the CISP confirmed (WP-8).
	PublishedVersion *int64
	DSSConstraintID  string
	DSSVersion       *int64
	// DSSState is the restriction's standing in the DSS (WP-9: none,
	// pending, written, deleted, failed), DSSPendingSince set while
	// pending or failed, DSSReference the ConstraintReference the DSS
	// last accepted a put of DSSPutVersion with.
	DSSState        string
	DSSPendingSince *time.Time
	DSSReference    json.RawMessage
	DSSPutVersion   *int64
	// CISVersion is the CIS projection the restriction was placed
	// against, CISAgeS that projection's age now (database clock).
	CISVersion *string
	CISAgeS    *float64
	// Feature is the ED-318 feature of the current version.
	Feature json.RawMessage
	// Constraint is the stored constraint document of the current
	// version ({details, derivation}), nil when none was derived.
	Constraint json.RawMessage
}

// Version is one restriction_versions row.
type Version struct {
	RestrictionID string
	Version       int64
	State         State
	StartsAt      time.Time
	EndsAt        time.Time
	MsgID         string
	Feature       json.RawMessage
	Constraint    json.RawMessage
	ChangedBy     string
	ChangedAt     time.Time
	ChangeReason  string
	// AnspRef is the restriction's, for the bus message.
	AnspRef string
}

// Request is one restriction_requests row (F11).
type Request struct {
	ID             string
	Requester      string
	Source         string
	ClientRef      string
	Payload        json.RawMessage
	PayloadSHA256  string
	ReceivedAt     time.Time
	State          string
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason *string
	RestrictionID  *string
}

// The request states and sources.
const (
	RequestReceived = "received"
	RequestAccepted = "accepted"
	RequestDeclined = "declined"

	SourceAuthority = "authority"
	SourceConsole   = "console"
)
