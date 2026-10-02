// Package apierr is the one error body of every HTTP answer this system
// writes (CLAUDE.md "One error body", docs/PLAN.md section 6, M28): RFC
// 9457 application/problem+json with {type, title, status, detail,
// instance, errors: [{field, reason}], truncated?}, where type is
// https://schemas.uspace.ge/problems/<slug> and slug is the counter or
// refusal name. The shape mirrors uspace-lab schemas/common/problem/v1
// (pinned under schemas/common/problem/v1/) and the Problem component of
// api/openapi.yaml; the tests hold all three equal.
//
// Inside the system a refusal is a *core.FieldError (or a joined tree
// of them) or a *Problem; Invalid and FromError turn the former into the
// latter. Every write is bounded: at most MaxErrors field problems (the
// rest dropped and truncated set), and detail, field and reason cut to
// MaxDetailBytes, MaxFieldBytes and MaxReasonBytes at a UTF-8 boundary.
// A problem never carries a token, a password or a secret: the details
// and reasons are written by this system's code, never copied from a
// request header, and an error that is not a refusal is answered as 500
// internal without its text (which may name a table or a value).
//
// Every 429 and 503 carries Retry-After (at least one second), as the
// OpenAPI file promises.
package apierr
