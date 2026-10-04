# N-M1 proof: restrictions and the manned feed

The N-M1 done-when of `docs/PLAN.md` section 12 (spec `07` Phase 5),
observed against the staging droplet and the lab, with each number's
source next to it (E-04). WP-13 brief: `docs/WORKPACKAGES/WP-13.md`.

**State on 2026-10-04: N-M1 is not proven.** The deployment half passes
(images signed and verified, the site live, the routes as planned). The
proof half has not been run on the droplet: it needs a supervisor to
activate a restriction and a SITL aircraft flying against the staging
stack, which are writes to the server, and this round was read-only. The
lab's own run of the restriction scenario against the systems stack
failed (below). Every row says what decided it.

## Sources and how they were read

| Source | Read how | When (UTC) |
|---|---|---|
| The live host `uspace-ansp.<domain>` (domain in `uspace-deploy` `config/hosts.env`) | `curl` from outside, `GET` only, no credential | 2026-10-04 13:21 to 13:40 |
| The CISP's public surface `uspace-cisp.<domain>` | `curl`, `GET` only | 2026-10-04 13:25, 13:40 |
| The deployed images | `deploy/verify.sh` (cosign v2.4.1, the pinned image) from a workstation | 2026-10-04 13:30 |
| CI of the deployed commit | `gh run view 37191152309` | 2026-10-04 |
| What the deployment observed on the droplet | `uspace-deploy` `docs/RUNBOOKS/deploy.md`, "Observed on the droplet" rounds one to five (main at 11b3ac7) | as recorded there |
| The lab's systems runs | `uspace-lab` `results/20261004-systems-rerun/` (main at 216fa56) | 2026-10-04 02:05 to 04:10 |

SSH to the droplet was not used: a shell on the production host was not
permitted for this round, so nothing below comes from `docker logs`,
`docker stats`, `psql` or `/readyz` on the host. Rows that need those say
so.

## Deployment

| Check | Result | Evidence |
|---|---|---|
| Images published and signed from `main` | **pass** | CI run 37191152309 on e41dec9 (main, push): `images`, `SBOMs`, `attest SBOMs` success. `deploy/verify.sh ghcr.io/rootxkit/uspace-ansp@sha256:9496f3f5... ghcr.io/rootxkit/uspace-ansp-web@sha256:9c9f6322...` printed `ok signature` and `ok SBOM (spdx)` for both and `2 image(s) verified`, exit 0. The SBOM predicates: SPDX-2.3, 160 packages (Go image), 287 (web). The same script refused a CISP digest (`none of the expected identities matched ... uspace-cisp`) and a tag reference, exit 1. |
| The digests verified are the ones deployed | **pass (as recorded by the deployment)** | `uspace-deploy` `compose/images.env` pins those two digests for ansp e41dec9; its fifth round records them cosign-verified and `./deploy.sh` ok. Not read from the host in this round. |
| `deploy/verify.sh` passes on the droplet | **not run** | Needs a shell on the host. The deployment's own `deploy.sh --verify-only` performs the same keyless check with the same identity (its runbook, "Verify"). |
| The site live on the staging subdomain through `uspace-deploy` | **pass** | `GET /healthz` 200 `{"instance":"staging","process":"api","status":"alive"}`; Let's Encrypt certificate for the host (`issuer=... CN=YE1`, verify return 0); the console redirects `/` to `/ka/login` 200 with the kit's CSP (`connect-src 'self'`, `font-src 'self'`, `worker-src blob:`). |
| Route groups as `PLAN` section 11 | **pass** | `/.well-known/jwks.json` 200 `application/jwk-set+json` (two RS256 keys); `/v1/restrictions` 401 `no bearer token`; `/v1/coordination/inbox` 401; `/uss/v1/constraints/x` 401 (api answers, problem+json); `/v1/manned-traffic/stream` 403 `the Origin of this upgrade is not allowed` (manned-feed answers); `/metrics` 404 with no body from Caddy. |
| `/readyz` not routed to api | **pass, differs from this repo's site** | Live: `/readyz` 307 to `/ka/readyz` (the deployment sends it to web, which redirects to its locale), so api's readiness is not served outside. `deploy/caddy/ansp.caddy` answers it 404 from Caddy; `deploy/caddy/proof.sh` checks that. |
| Caddy asks for a client certificate (`verify_if_given`) | **pass** | `openssl s_client` lists `Acceptable client certificate CA names: O=uspace staging, CN=uspace staging mTLS CA`; a request without one is served (above). |
| `X-Client-Cert-Subject` forwarded only on the mTLS groups and stripped elsewhere | **pass (proof of the site, not of the host)** | `deploy/caddy/proof.sh`: 22 checks against Caddy 2.10.2 with stub upstreams: a forged header reaches no upstream on any route; a verified certificate's subject (`CN=authority-01,O=proof`) reaches `/v1/coordination/*` and `/v1/manned-traffic/*` and replaces a forged one; never forwarded on `/v1/restrictions` or `/`; a certificate of another CA ends the handshake. With the header strip removed the proof fails 5 checks (run once to see it fail). The deployment's `tests/caddy-proof.sh` (82 checks) is its proof of the composed Caddyfile. |
| Staging `mtls: off` line at error level (E-02) | **not observed** | Needs the api's log on the host: `docker logs uspace-ansp-api-1 \| grep 'mTLS is off'`, the error line `internal/obs/serve.go` writes every status period. The deployment's runbook requires it ("What the status lines must show on staging: `mtls: off` at error level"). |
| `required` exercised once with a lab certificate | **not run** | Needs `ANSP_MTLS_MODE=required` and `ANSP_MTLS_BINDINGS_FILE` deployed (a server change), then an uncertified call refused 403 and a certified one accepted (the deployment's runbook, "mTLS on staging", step 4). |

## The N-M1 criteria

| Criterion (`PLAN` section 12) | Result | Evidence |
|---|---|---|
| Baseline (E-06): stack idle 10 min, counters at zero, feed status `adapters: replay running`, picture empty with the SC-22 text | **not run** | Needs `/readyz`, `/metrics` and the status stream from inside the host. |
| A supervisor activates a restriction over a SITL aircraft | **not run on staging; FAIL in the lab** | Staging: the CISP's public restrictions dataset answers 404 `dataset: restrictions has no version yet; its ETag is "restrictions:0"` (13:40): no restriction has ever been published through the CISP on the droplet. Lab: `ussp-wp12-restriction` FAIL: the ANSP 7fc3ef1 answered 500 to `POST /v1/restrictions` twice in runner executions with no log line, while the same request by hand was answered 201 five times (lab finding C); the USSP's intent stayed `pending_dss` (finding B, the USSP's #19 then unmerged). |
| CISP publishes within 1 s | **not run** | No publication on staging (above). Source when run: `deliveries` (CISP `201` time) against `events` (commit time). |
| DSS constraint written and subscribers notified within 5 s | **not run** | Source when run: `deliveries` (DSS `PUT`, subscriber `POST`s). |
| USSP raises `restriction_activated` on the affected intent within one tick | **not run; FAIL in the lab** | Lab: `restriction-activated-on-the-intent: raise: mark "activate" never happened`. |
| The authority shows it | **not run** | |
| A recorded synthetic ADS-B file streams as manned traffic to the USSP and the authority (ATS.OR.127) | **partial pass** | Staging, as the deployment recorded (first round): the authority's manned-ingest opened the ANSP's stream, 120 aircraft published in its first minute, from the replay adapter of `compose/ansp.yaml` (`two-aircraft-converging.ndjson`, looped). Lab: `ansp-inv02-manned` with the U-space airspace about the origin: the ANSP showed the track live at +20.4 s and stale at +104.5 s; the USSP half failed (`pending_dss`, 175 samples `refused_intent_state`). With the airspace 60 km away the ANSP showed no track: manned traffic is filtered to the U-space volumes (`relevance: CIS version 3, 1 volumes`, lab finding D, by design per `PLAN` section 9 `BenchmarkRelevance`). `helicopter-near-uspace.ndjson` has not been streamed on staging. |
| Every delivery is in the log | **not run** | `deliveries` on the host. |
| The console shows it all | **partial** | The login page is served over HTTPS (above); nothing behind sign-in was looked at (no credential used). |
| Deactivation: the same chain for the end of the restriction | **not run** | |
| Every delivery row `sent`; the audit hash chain verifies | **not run** | `internal/audit.Verify` exists; no command exposes it on the host yet (`make verify-audit` of the brief is not built). |

## To run the proof (writes to staging)

Each step below changes the server; none was done in this round.

1. Baseline: on the host, `docker compose -p uspace-ansp logs --since 10m
   api manned-feed | grep -E 'mTLS is off|status'`; api's `/readyz` from the
   project network (`deploy.sh --verify-only ansp` prints it).
2. Lab: `sim/fly.py` with the SITL aircraft inside the demo U-space
   airspace (`seed/demo-zones.json` in `uspace-deploy`) and an activated
   intent at the USSP (needs the USSP's DSS writer, merged since the
   lab's run as its #19).
3. Console: a supervisor plans and activates a restriction over it.
   Record `events` (commit), `deliveries` (CISP 201, DSS PUT, subscriber
   POSTs), the CISP's change notification in its log, the USSP's alert
   stream, the authority's display.
4. Switch the replay adapter to `helicopter-near-uspace.ndjson`
   (`ANSP_REPLAY_FILE`), observe it at the USSP's traffic WS and the
   authority's picture as `surveillance` with ages.
5. End the restriction; record the same chain.
6. `SELECT state, count(*) FROM deliveries GROUP BY 1` all `sent`; the
   hash chain verified.

Open, for the owner: lab finding C (the 500 on `POST /v1/restrictions`
in the runner's executions) has no issue yet and needs one before the
proof is rerun.
