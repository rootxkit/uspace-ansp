# Conformance target

What `uspace-lab`'s conformance suite (its WP-L7, milestone L-M4) runs
against: the ANSP as the F3548 constraint manager with the lab DSS, and
the national OpenAPI contract tests from `api/openapi.yaml`
(`docs/PLAN.md` section 10.1, conformance row).

- `target.yaml`: the role, the client ids, the scopes and the operations
  the suite calls. It is this repository's own description; the lab
  writes the `uss_qualifier` configuration from it at the InterUSS commit
  it pins.
- `make conformance-target` (`scripts/conformance-target.sh`): builds and
  starts the development stack (`deploy/compose.yaml`) with the overlay
  `deploy/compose.conformance.yaml`, which points the token verifier, the
  token client and the DSS at the lab, and prints the base URLs and the
  client ids. `make compose-down` removes it.

The lab supplies (environment, never committed):

| Variable | What |
|---|---|
| `LAB_ISSUER` | the lab issuer's `iss` (https; plain http only for localhost: api refuses to start otherwise, and also when the JWKS does not answer) |
| `LAB_JWKS_URL` | its JWKS |
| `LAB_TOKEN_URL` | its token endpoint, for `ansp-01` |
| `LAB_CLIENT_SECRET_FILE` | the file holding `ansp-01`'s lab-issued secret |
| `LAB_DSS_URL` | the lab DSS base URL (its host is the DSS audience) |
| `ANSP_CONFORMANCE_PUBLIC_BASE_URL` | where the DSS and the suite reach this ANSP (`uss_base_url`); default `http://host.docker.internal:58080` |
| `ANSP_CONFORMANCE_AUDIENCE` | the host the suite's tokens name as `aud`; default the public base URL's host |

Status: the lab's suite does not exist yet (uspace-lab has no
`conformance/` directory on its main at the time of WP-13), so the
target has not been used by the lab; `docs/runbooks/n-m2.md` keeps the
open item.
