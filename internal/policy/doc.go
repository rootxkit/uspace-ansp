// Package policy is the ansp_policy row of uspace-ansp (docs/PLAN.md
// sections 5.1 and 7, INV-03): the thresholds every judgement runs with,
// its policy_version, the KV projection and the follower of the hot
// path.
//
// Defaults is the one place the documented defaults live, with their
// units in the field names; the migration seeds version 1 with the same
// values. Thresholds.Validate refuses a value that would disarm a check
// (zero, negative, NaN, infinite, an unknown zone type).
//
// Service is api's: Load reads the newest version; Update stores the
// next version through Repo in one transaction with its audit event and
// a put of the stored row into the KV bucket policy, and refuses with
// ErrKVUnavailable (503) when KV cannot take it, so a version never
// exists without KV (LESSONS B-09); after the commit it pushes the row
// on ctl.policy, counting a failed push. Republish repairs a lost
// bucket from the database.
//
// Follower is the hot path's: it applies only a higher, valid version
// (a lower one is ignored and counted), and with nothing from KV serves
// Defaults and says "policy: defaults, KV empty". Run watches the KV
// key. The package imports no database code: Repo is implemented by
// internal/store.PolicyRepo, which api wires in.
package policy
