package dss

import (
	"net/url"
	"strings"

	"github.com/rootxkit/uspace-core/f3548"
)

// Operation is one F3548 operation this package calls or serves.
type Operation struct {
	ID     string
	Method string
	// Path is the template as the standard writes it.
	Path string
	// Scopes is the operation's security requirement (any one of them
	// admits); the first is the one this system asks for.
	Scopes []f3548.Scope
	// Success is the status the standard answers on success.
	Success int
}

// Operations is every F3548 constraint operation this system uses, read
// from the pinned standard file, never from memory (CLAUDE.md rule 8,
// E-03): interuss/astm-utm-protocol utm.yaml at commit
// 1d3d8fbe75414e23d7e19ce35955770bea5e413f (SHA-256
// 63482b2a665ecd836b269028a13b19adfde7a5c32b01301c168d87ca3313dd15), the
// file uspace-core v1.3.0's f3548/SOURCE pins and generates f3548's types
// from. paths_test.go holds this table equal to the lines extracted from
// that file (testdata/utm-constraint-operations.txt) and the pins equal
// to core's SOURCE.
//
// Note what the file says and the plan did not: a subscriber
// notification (notifyConstraintDetailsChanged) is secured by
// utm.constraint_management, the scope of the constraint manager that
// sends it, not utm.constraint_processing (docs/PLAN.md section 15).
var Operations = []Operation{
	{ID: OpGetReference, Method: "GET", Path: "/dss/v1/constraint_references/{entityid}",
		Scopes: []f3548.Scope{f3548.ScopeConstraintManagement, f3548.ScopeConstraintProcessing}, Success: 200},
	{ID: OpCreateReference, Method: "PUT", Path: "/dss/v1/constraint_references/{entityid}",
		Scopes: []f3548.Scope{f3548.ScopeConstraintManagement}, Success: 201},
	{ID: OpUpdateReference, Method: "PUT", Path: "/dss/v1/constraint_references/{entityid}/{ovn}",
		Scopes: []f3548.Scope{f3548.ScopeConstraintManagement}, Success: 200},
	{ID: OpDeleteReference, Method: "DELETE", Path: "/dss/v1/constraint_references/{entityid}/{ovn}",
		Scopes: []f3548.Scope{f3548.ScopeConstraintManagement}, Success: 200},
	{ID: OpNotifyDetails, Method: "POST", Path: "/uss/v1/constraints",
		Scopes: []f3548.Scope{f3548.ScopeConstraintManagement}, Success: 204},
	{ID: OpGetDetails, Method: "GET", Path: "/uss/v1/constraints/{entityid}",
		Scopes: []f3548.Scope{f3548.ScopeConstraintProcessing}, Success: 200},
}

// The operation ids of the standard.
const (
	OpGetReference    = "getConstraintReference"
	OpCreateReference = "createConstraintReference"
	OpUpdateReference = "updateConstraintReference"
	OpDeleteReference = "deleteConstraintReference"
	OpNotifyDetails   = "notifyConstraintDetailsChanged"
	OpGetDetails      = "getConstraintDetails"
)

// Op is the operation of Operations with id, the zero Operation for an
// id the table does not hold (the ids are this package's constants, and
// paths_test.go finds each in the table).
func Op(id string) Operation {
	for _, o := range Operations {
		if o.ID == id {
			return o
		}
	}
	return Operation{Scopes: []f3548.Scope{""}}
}

// Path is op's path with its parameters filled, each escaped as one
// path segment.
func (o Operation) path(params map[string]string) string {
	p := o.Path
	for k, v := range params {
		p = strings.ReplaceAll(p, "{"+k+"}", url.PathEscape(v))
	}
	return p
}

// ReferencePath is the DSS path of constraint reference id: with ovn the
// update and delete path, without it the create and read path.
func ReferencePath(id string, ovn *string) string {
	if ovn == nil {
		return Op(OpCreateReference).path(map[string]string{"entityid": id})
	}
	return Op(OpUpdateReference).path(map[string]string{"entityid": id, "ovn": *ovn})
}

// NotifyPath is the subscriber's notification path, appended to its
// uss_base_url (which the standard says has no trailing '/').
func NotifyPath() string { return Op(OpNotifyDetails).Path }

// Scope is the scope this system asks for to call op.
func (o Operation) Scope() string { return string(o.Scopes[0]) }
