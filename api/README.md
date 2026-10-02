# api: the published national API of the ANSP

`openapi.yaml` is the contract (CLAUDE.md rule 7): an endpoint that is
not in it does not exist. Every operation carries:

- `x-process`: the process that serves it (`api`, `manned-feed`, or
  `each` for `/healthz`, `/readyz` and `/metrics`, which every process
  serves through `internal/obs`);
- `x-spec`: the spec section it implements;
- `x-auth`: the access rule the server enforces before any parameter is
  bound or any body read (`internal/auth.ParseAccess`): `public`,
  `jws:<signer>`, `session`, `session:<role>[|<role>]`,
  `token:<scope>[+<scope>][+mtls]`, alternatives joined by ` or `;
- `x-websocket: true` on a WebSocket upgrade, whose `101` content is the
  schema of every frame the server sends (the `04 §2` envelope with a
  `body` named by `schema`) and whose client frame is named by
  `x-client-frame`.

The table of `docs/PLAN.md` section 6 lists the same operations; a test
fails when the two differ.

## Generated code

| Output | From | Generator |
|---|---|---|
| `gen/api.gen.go` | `openapi.yaml`, `oapi-codegen.yaml` | oapi-codegen v2.8.0: the `net/http` server interface, the strict server, the models and the client |
| `gen/operations.gen.go` | `openapi.yaml` | `internal/opsgen`: every operation with its pattern and extensions (the router's input), and `gen.Unimplemented` (501 for every operation) |
| `stub_gen_test.go` | `openapi.yaml` | `internal/opsgen`: the contract tests' strict-server stub |
| `clients/cispclient/cispclient.gen.go` | `clients/cisp.yaml` | oapi-codegen v2.8.0: the client and models of the CISP's API |
| `gen/SOURCE` | | `scripts/generate.sh`: the SHA-256 of the inputs |

Regenerate with `make generate` (`scripts/generate.sh`) and commit the
result; CI's `make generate-check` fails on any difference. Never edit a
generated file. A work package that serves an operation embeds
`gen.Unimplemented` in its strict server and overrides that operation; it
adds an operation by editing `openapi.yaml`, the table of
`docs/PLAN.md` section 6 and regenerating in the same pull request.

## Compatibility

Changes within `/v1` are additive only (spec `00 §7`, `02 §1`): new
optional fields, new operations, new enumeration values announced one
minor ahead. Inbound bodies leave `additionalProperties` open: unknown
members are ignored, never refused. A breaking change is a `/v2` served
in parallel for at least twelve months with `deprecated` markers and a
`Sunset` header.

## Checks

- `make lint-api`: the file lints with `@redocly/cli` (version pinned in
  `scripts/lint-api.sh`, rules in `redocly.yaml`); a warning fails.
- `go test ./api/`: the file validates (with its examples); every
  operation has `x-spec`, `x-auth`, `x-process`, matching security and
  the promised error responses; every example validates against its
  schema; the generated client calls every operation against the strict
  server over a stub that answers its example, behind request validation,
  with every answer checked by response validation; components that
  mirror a JSON Schema hold its members.
- `make check-contracts`: the pinned copies in `clients/` and
  `../schemas/common/` equal their sources (see `clients/README.md`).

The calls this system makes to others are listed in `outbound.md`.
