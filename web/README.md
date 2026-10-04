# web/: the ANSP supervisor console

Next.js (App Router, `output: 'standalone'`) on the shared kit
[`uspace-ui`](https://github.com/rootxkit/uspace-ui), pinned to one
GitHub Release tarball (`0.1.0-rc.1`). It plans, activates, extends,
ends and cancels restrictions through the API and shows what the API
says; it judges nothing: no geometry or geodesy library, no database, no
NATS, no key (`docs/PLAN.md` D9; the lint rules in `eslint-rules/` and
the bundle check enforce it). It never commands an aircraft.

```
app/[locale]/login/            the sign-in with MFA (enrolment QR at a first sign-in)
app/[locale]/(signed-in)/      restrictions, restrictions/new (the map editor),
                               restrictions/<id>, requests, adapters
app/%5Fbff/                    the three BFF routes: /_bff/login, /_bff/logout, /_bff/api/*
src/bff/handlers.ts            the BFF, on the kit's auth/server helpers
src/api/                       generated types (uspace-ui-gen-api) and the typed client
src/console/                   the pages, the status bar and their pure helpers
src/i18n/                      ka.json, en.json (every display string)
eslint-rules/                  no-geometry-import, no-hardcoded-string, no-server-business-logic
test/mock-api.mjs              the Playwright fixture server (stands in for Caddy and the API)
test/e2e/                      the smoke run, and the screenshots run
docs/screenshots/              every page in ka and en against the fixture server
```

## Commands

Node 22 and pnpm through corepack (`corepack enable`; the version is
`packageManager` in `package.json`). The `make web-*` targets at the
repository root run the same.

```
pnpm install --frozen-lockfile          # make web-install
pnpm run types                          # regenerate src/api/generated/ from ../api/openapi.yaml; commit it
pnpm run types:check                    # make web-types: fails when the committed types are stale
pnpm lint && pnpm typecheck             # make web-lint
pnpm test                               # make web-test: vitest
pnpm build && pnpm check:bundle         # make web-build
pnpm e2e                                # make web-e2e: Playwright (pnpm build first;
                                        # `pnpm exec playwright install chromium` once)
SCREENSHOT_DIR=docs/screenshots pnpm e2e screenshots
docker build -t uspace-ansp-web .       # the image (WP-13 publishes it)
```

## How the types are generated

`pnpm run types` runs the kit's `uspace-ui-gen-api` (openapi-typescript,
pinned by the kit) on `../api/openapi.yaml` into
`src/api/generated/types.gen.ts`, whose first line names the generator
and the SHA-256 of the input. The file is committed and never edited;
`make web-types` (CI) fails when it is stale, and `make generate` at the
root regenerates it with the Go code when `node_modules` is installed.
The kit's `no-hand-written-api-types` rule fails a hand-written file in
`src/api/generated/` and any type that redeclares a schema component
name (the names are read from the generated file,
`eslint-rules/components.mjs`). Pages use the generated types through
`src/api/types.ts` and call the API only through the typed client of
`src/api/client.ts`, whose refusals carry the API's RFC 9457 problem
(slug, field errors, `Retry-After`).

## The BFF contract

The BFF is three routes and nothing else, on the kit's helpers:

| Route | What it does |
|---|---|
| `POST /_bff/login` | `{username, password}` → `POST /v1/auth/login`; the API's challenge is sealed (AES-GCM under `WEB_MFA_CHALLENGE_SECRET`) into the `HttpOnly` `uspace_mfa` cookie (`Path=/_bff`) and the page gets `{status: "mfa_required", enrolment?}`. Then `{username, otp}` → `POST /v1/auth/mfa {mfa_token, code}`; its session sets `uspace_session` (`HttpOnly; Secure; SameSite=Strict`) and the readable `uspace_csrf`. The sign-in requires a same-origin `Origin`. |
| `POST /_bff/logout` | the CSRF pair checked, `POST /v1/auth/logout` with the bearer, both cookies cleared whatever the API answers |
| `/_bff/api/*` | the cookie forwarded as `Authorization: Bearer`; every unsafe method needs `X-CSRF-Token` equal to `uspace_csrf`; only `/v1/restrictions*`, `/v1/restriction-requests*`, `/v1/delivery-alarms*`, `/v1/adapters*`, `/v1/sources*` and `/v1/auth/me` are reached. An `Idempotency-Key` of the contract's shape is passed on `POST /v1/restrictions` (the kit forwards a fixed header list without it). |

The BFF never verifies a token: the API decides every request. There is
no ticket route: the restriction stream `WS /v1/restrictions/stream` is
opened same-origin and the session cookie rides the upgrade (the API
checks `Origin` against `ANSP_WS_ALLOWED_ORIGINS`); a `4401` close, like
a `401` answer, is shown as "signed out, sign in again". The signed-in
layout reads the cookie's claims without verification
(`sessionDisplay`, display only) and `GET /v1/auth/me` for the account.

## Running against compose

`make compose-up` at the root runs the API on `127.0.0.1:58080`. The
compose file has no web service yet (WP-13), so run the console beside
it:

```
cd web
WEB_DEV_API_URL=http://127.0.0.1:58080 WEB_API_INTERNAL_URL=http://127.0.0.1:58080 \
  WEB_MFA_CHALLENGE_SECRET="$(openssl rand -base64 32)" \
  NEXT_PUBLIC_MAP_CENTER=44.80,41.715 NEXT_PUBLIC_MAP_ZOOM=10 pnpm dev
```

`WEB_DEV_API_URL` rewrites `/v1/*` and `/.well-known/*` to the API in
`pnpm dev` only, as Caddy does in a deployment; a rewrite does not carry
a WebSocket, so under `pnpm dev` the status bar shows the stream down
and the pages read REST only. Add `127.0.0.1:3000` to the API's
`ANSP_WS_ALLOWED_ORIGINS` and put Caddy (or `test/mock-api.mjs`'s way of
passing pages through) in front for the stream. Without an API, the
fixture server answers every operation the console uses: `pnpm build`,
then `pnpm exec next start --port 3100` with the variables of
`playwright.config.ts`, and `MOCK_UPSTREAM=http://127.0.0.1:3100 node
test/mock-api.mjs`; open `http://127.0.0.1:3000/en` and sign in as
`super1` (test data in the file).

## Configuration

Read at start or at request time, never at build (the image is built
once in CI). The names are `WEB_*`, not `ANSP_*`: the Go processes refuse
unknown `ANSP_*` names.

| Variable | Meaning |
|---|---|
| `WEB_API_INTERNAL_URL` | the API as the BFF reaches it (`http://api:8080` in compose); unset, every BFF route answers 503 naming it |
| `WEB_MFA_CHALLENGE_SECRET` | seals the MFA challenge between the two sign-in steps; at least 32 bytes from the deployment's secret store; unset or shorter, every BFF route answers 503 naming it |
| `WEB_TRUSTED_PROXY_HOPS` | reverse proxies in front of Next.js that append to `X-Forwarded-For` (1 behind Caddy); the API lists the web container in `ANSP_TRUSTED_PROXIES` |
| `WEB_SESSION_MAX_AGE_S` | ceiling of the session cookie's `Max-Age` (43200); the API's `expires_at` shortens it |
| `WEB_UPSTREAM_TIMEOUT_MS` | timeout of each BFF call to the API (10000) |
| `WEB_BRANDING_FILE` | JSON `{name, short_name, logo_url, contact, accent}`; unset uses the code-name defaults; an unknown member fails the page naming it |
| `NEXT_PUBLIC_MAP_CENTER`, `NEXT_PUBLIC_MAP_ZOOM` | the map's first view, `"lng,lat"` and a zoom; unset, the map names the variable instead of choosing a place |

## Fonts, basemap and CSP

The fonts are the kit's Noto Sans and Noto Sans Georgian through
`next/font/local`, built into the image. The map reads the self-hosted
PMTiles bundle at `/basemap/` on the same origin, which the deployment's
Caddy serves from the shared volume (M38); without it the kit says "no
base map" and draws on a plain background. The CSP (`src/csp.ts`, set
per request with its nonce in `proxy.ts`) allows `connect-src 'self'`,
`font-src 'self'` and `worker-src blob:`; the smoke run asserts that
every request the page makes goes to its own origin.

## What the console does not do

It never judges an area: the editor sends the vertices as clicked or
typed (the ring closed, nothing else), and the API answers containment,
size, vertices and limits through uspace-core, its problems put on the
fields. A circle is drawn as its centre: the API sends no outline, and
drawing one would be geodesy. The gaps the brief met in the contract are
in `docs/PLAN.md` section 15 (rows 45 to 50).
