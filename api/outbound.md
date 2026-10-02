# Outbound calls

The calls this system makes. Their contracts are owned elsewhere and are
not in `openapi.yaml`; they are described in `docs/PLAN.md` section 6
("Outbound calls") and consumed from the owner's published file (a
pinned copy in `clients/`) or the standard.

| Call | Owner | Contract | Client | Spec |
|---|---|---|---|---|
| `POST /v1/restrictions`, `PATCH /v1/restrictions/{id}` on the CISP (`cis/restriction/v1`, detached JWS in `X-JWS-Signature`, idempotent on `(ansp_ref, ansp_version)`) | uspace-cisp | `clients/cisp.yaml` | `clients/cispclient` | `02 F2` |
| `POST /v1/publishers/heartbeat {sent_at, active_refs}` every `cisp_heartbeat_s` | uspace-cisp | `clients/cisp.yaml` | `clients/cispclient` | `02 F2` failure rule |
| `GET /v1/uspace_airspace`, `GET /v1/ussp_list`, `GET /v1/restrictions` with `ETag`; `POST /v1/subscriptions` | uspace-cisp | `clients/cisp.yaml` | `clients/cispclient` | `02 F3` |
| `PUT /dss/v1/constraint_references/{entityid}`, `DELETE .../{entityid}/{ovn}`, `GET .../{entityid}` | InterUSS DSS | ASTM F3548-21 `utm.yaml` (`uspace-core/f3548/SOURCE`) | `uspace-core/f3548` types | `02 F2`, `02 F6` |
| `POST {uss_base_url}/uss/v1/constraints` to each subscriber | each USSP | ASTM F3548-21 | `uspace-core/f3548` types | `02 F6` |
| Degraded direct delivery: `POST {base_url}/v1/cis/notifications` (compact JWS of `cis/change/v1`) on every USSP of the CIS list and on the authority | uspace-ussp, uspace-authority | `clients/ussp.yaml` (`receiveCISNotification`); the body is the CISP's `Change` | `clients/cispclient` (`Change`) | `02 F2` failure rule |
| `POST /v1/occurrences` on the authority (`occurrence/v1`) | uspace-authority | not yet in `clients/authority.yaml` (`docs/PLAN.md` section 15 gap 23) | none until published | `02 F7`, `F11` |
| `POST /oauth/token`, `GET /.well-known/jwks.json` on the authority | uspace-authority | `clients/authority.yaml` | `internal/auth` (client credentials) | `06 §3` |
