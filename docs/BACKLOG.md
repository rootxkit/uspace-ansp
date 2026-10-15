# Backlog

Ranked table of open items. Source is not recorded in the list this was built from.

| # | Severity (high/medium/low) | Item | Where (file:line if given) | Source (the review that found it) |
|---|---|---|---|---|
| 1 | medium | deliveries.sql:166-168: the settled-delivery NOT EXISTS clause never decides alone, and is untested. | internal/store/queries/relational/deliveries.sql:167-169 (moved) | not recorded |
| 2 | medium | WP-13 N-M1/N-M2: the restriction chain, CISP-down, SC-08, inbox and occurrence live proofs need a supervisor session (see docs/runbooks/n-m1.md). | docs/runbooks/n-m1.md | not recorded |
| 3 | low | internal/obs: a second Serve with a caller's Mux panics on re-registering /healthz. | internal/obs/serve.go | not recorded |
| 4 | low | The outline debounce and the openapi constant pins, same as the authority. | web/src/console/outline.ts; api/openapi.yaml | not recorded |
| 5 | low | manned_tracks has no hold gate below 90 days. | - | not recorded |
