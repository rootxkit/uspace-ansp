// Package schemas holds the JSON Schemas (draft 2020-12) of the messages
// this system owns (spec 04 §1, decision record M14): track/manned/v1,
// restriction/state/v1, coordination/annex_v/v1 (the USSP's request
// body, owned here because this system's API carries it) and
// coordination/notice/v1 (the inbox item on coord.v1 and the console
// stream, WP-10), each at
// <family>/<name>/v1.json with $id https://schemas.uspace.ge/<family>/<name>/v1.json,
// and their examples under examples/<family>/<name>/v1/ (valid ones at
// the top, refused ones under invalid/). uspace-lab mirrors this
// directory read-only.
//
// common/ is a pinned, unmodified copy of the uspace-lab common schemas
// this system consumes (the envelope, problem/v1, source/status/v1, the
// console frames and track/telemetry/v1, which console/snapshot/v1
// references), each named with its commit in common/SOURCE and diffed
// against the lab in CI (scripts/check-contracts.sh) until the lab
// aggregate replaces it.
//
// The tests validate every example both ways, round-trip the valid ones
// through the generated Go types of api/gen, and hold each body's
// members equal to its component in api/openapi.yaml (api tests).
package schemas
