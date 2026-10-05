# Degraded direct delivery: the contract fixture

What the receivers of the ANSP's degraded direct delivery (02 F2 failure
rule, cross-plan M4, M5) replay in their contract tests: uspace-ussp and
uspace-authority vendor this directory with the commit it came from.

| File | What |
|---|---|
| `jwks.json` | the public key set the signatures verify with (the key was generated when the fixture was written; it is in no deployment) |
| `<case>.change.json` | the `cis/change/v1` record posted to `POST /v1/cis/notifications`, a compact JWS kept as its three parts (join them with `.`): `iss` `https://ansp.test`, `aud` `receiver.test`, `sub` the restriction id, `jti` the delivery id |
| `<case>.direct.json` | the `restriction/direct/v1` body its `pull_url` (`GET /v1/restrictions/{id}/direct`) serves, without the trailing newline of the file |
| `<case>.direct.jws` | that body's `X-JWS-Signature` (detached, RFC 7797 `b64` false) |

Cases: `activated` (ansp_version 2, signed at 2026-10-02T12:00:10Z) and
`ended` (ansp_version 3, signed at 2026-10-02T13:00:01Z). The record's
`version` member carries the restriction's `ansp_version`, never a CIS
dataset version. A receiver verifies with its clock at the signing time.

`internal/deliver/contract_test.go` checks that every file is what this
system's code makes of the inputs there, and rewrites them with
`go test ./internal/deliver -run TestDirectContractFixture -update-contract`.
