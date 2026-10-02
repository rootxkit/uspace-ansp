package restriction

import (
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// MaxDuration bounds one restriction's window (F3548
// CstrMaxDurationHours); a longer one is a chain of re-issues.
const MaxDuration = time.Duration(f3548.CstrMaxDurationHours) * time.Hour

// MaxHorizon bounds how far ahead a restriction may start (F3548
// CstrMaxPlanningHorizonDays).
const MaxHorizon = time.Duration(f3548.CstrMaxPlanningHorizonDays) * 24 * time.Hour

// StartLead is how far before now a planned starts_at may lie: the
// console's "now" crosses a network and a clock; a start older than this
// is refused, never moved (an immediate restriction starts now). It is
// the activation lead the CISP gives an active create (uspace-cisp
// restriction.ActivationLead), so a restriction this system accepts
// immediately is one the CISP accepts as active.
const StartLead = 60 * time.Second

// TransitionError is an illegal transition: op from a state that does
// not allow it. The handler answers 409 naming both.
type TransitionError struct {
	Op   Op
	From State
	// Reason, when set, says why op is refused in a state that would
	// otherwise allow it (an activation after the window has passed).
	Reason string
}

func (e *TransitionError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s is not allowed from %s: %s", e.Op, e.From, e.Reason)
	}
	return fmt.Sprintf("%s is not allowed from %s (%s)", e.Op, e.From, allowedFrom(e.Op))
}

func allowedFrom(op Op) string {
	switch op {
	case OpActivate, OpCancel:
		return "only from planned"
	case OpExtend, OpEnd, OpExpire:
		return "only from active"
	case OpPlan:
		return "never: plan creates a restriction"
	}
	return "never"
}

// Change is what a transition does to a restriction.
type Change struct {
	// Next is the restriction after the transition.
	Next Restriction
	// Versioned is false for a scheduled activation: the row records
	// activate_at, writes an event, and keeps its version (the version
	// moves when the ticker activates it).
	Versioned bool
}

// Transition applies op at now (the database's clock) by actor. newEnd
// is an extend's new ends_at (nil otherwise). It judges the state and
// the window only; validation of the area happened at plan. A refused
// transition is a *TransitionError (409) or a *core.FieldError naming
// ends_at (400).
func Transition(r Restriction, op Op, now time.Time, actor Actor, newEnd *time.Time) (Change, error) {
	next := r
	role := actor.Role
	switch op {
	case OpActivate:
		if r.State != StatePlanned {
			return Change{}, &TransitionError{Op: op, From: r.State}
		}
		if !r.EndsAt.After(now) {
			return Change{}, &TransitionError{Op: op, From: r.State, Reason: "its window ended at " + stamp(r.EndsAt)}
		}
		if r.StartsAt.After(now) {
			// Scheduled: stays planned until the ticker activates it.
			at := r.StartsAt
			next.ActivateAt = &at
			next.ActivatedBy = &role
			return Change{Next: next, Versioned: false}, nil
		}
		next.State = StateActive
		next.ActivateAt = nil
		next.ActivatedAt = &now
		if r.ActivatedBy == nil || actor.Type != SystemActor.Type {
			next.ActivatedBy = &role
		}
	case OpCancel:
		if r.State != StatePlanned {
			return Change{}, &TransitionError{Op: op, From: r.State}
		}
		next.State = StateCancelled
		next.ActivateAt = nil
		next.CancelledBy = &role
	case OpEnd:
		if r.State != StateActive {
			return Change{}, &TransitionError{Op: op, From: r.State}
		}
		next.State = StateEnded
		next.EndsAt = now
		next.EndedAtActual = &now
		next.EndedBy = &role
	case OpExpire:
		if r.State != StateActive {
			return Change{}, &TransitionError{Op: op, From: r.State}
		}
		if r.EndsAt.After(now) {
			return Change{}, core.Fieldf("ends_at", "%s is after now %s: a restriction expires at its ends_at, never before", stamp(r.EndsAt), stamp(now))
		}
		next.State = StateEnded
		next.EndedAtActual = &r.EndsAt
		next.EndedBy = &role
	case OpExtend:
		if r.State != StateActive {
			return Change{}, &TransitionError{Op: op, From: r.State}
		}
		if err := checkExtend(r, now, newEnd); err != nil {
			return Change{}, err
		}
		next.EndsAt = newEnd.UTC()
	case OpPlan:
		return Change{}, &TransitionError{Op: op, From: r.State}
	default:
		return Change{}, &TransitionError{Op: op, From: r.State}
	}
	next.AnspVersion = r.AnspVersion + 1
	return Change{Next: next, Versioned: true}, nil
}

// reasonNeedsReissue is the refusal of an extend past MaxDuration from
// starts_at: the service answers such an extend with a linked re-issue.
const reasonNeedsReissue = "is more than F3548 CstrMaxDurationHours after starts_at; the extension is a linked re-issue"

func checkExtend(r Restriction, now time.Time, newEnd *time.Time) error {
	if newEnd == nil {
		return core.Fieldf("ends_at", "is required by an extend")
	}
	end := newEnd.UTC()
	switch {
	case !end.After(r.EndsAt):
		return core.Fieldf("ends_at", "%s is not after the current ends_at %s", stamp(end), stamp(r.EndsAt))
	case !end.After(now):
		return core.Fieldf("ends_at", "%s is not after now %s", stamp(end), stamp(now))
	case end.Sub(r.StartsAt) > MaxDuration:
		return core.Fieldf("ends_at", "%s %s", stamp(end), reasonNeedsReissue)
	}
	return nil
}

// NeedsReissue reports whether an extend of r to newEnd is beyond
// MaxDuration from starts_at (and otherwise valid): the service then
// plans a linked re-issue from r's ends_at to newEnd.
func NeedsReissue(r Restriction, now time.Time, newEnd time.Time) bool {
	end := newEnd.UTC()
	return r.State == StateActive && end.After(r.EndsAt) && end.After(now) && end.Sub(r.StartsAt) > MaxDuration
}

// stamp is t as the wire writes it: RFC 3339 UTC with Z and
// milliseconds (02 section 1).
func stamp(t time.Time) string { return t.UTC().Format(TimeFormat) }

// TimeFormat is the wire format of every instant (02 section 1).
const TimeFormat = "2006-01-02T15:04:05.000Z"
