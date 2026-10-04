# N-M2 proof: coordination and the degraded paths

The N-M2 done-when of `docs/PLAN.md` section 12 (spec `07` Phase 5),
with each result's source (E-04). Sources and how they were read are the
table of [n-m1.md](n-m1.md): outside `GET`s against the live host, the
deployment's recorded observations, the lab's systems runs; no shell on
the droplet.

**State on 2026-10-04: N-M2 is not proven.** Every N-M2 criterion needs
writes to staging (a notice from the USSP, the CISP stopped, an adapter
paused or switched off, a report filed) or the host's logs and counters;
none was done in this round. The lab's systems runs exercised none of the
ANSP's N-M2 paths.

## The N-M2 criteria

| Criterion (`PLAN` section 12) | Result | Evidence |
|---|---|---|
| The Annex V inbox receives intents touching the restricted volume and non-conformance notices, answers with `ack_id` | **not run** | Live: `/v1/coordination/inbox` answers 401 without a token (api serves the route). No USSP notice to the staging ANSP is recorded: the lab's `ussp-wp10-conformance` PASS (non-conformance raised and cleared three times, the nearby operator told each time) shows the USSP's side only; no ANSP inbox row is in its result. |
| A supervisor acknowledges them, and the USSP observes it (Art. 13(2)) | **not run** | |
| CISP down: the restriction reaches the USSPs and the authority by the direct path | **not run** | Needs `docker compose -p uspace-cisp stop api` for 2 min on the host and an active restriction (none exists on staging: the CISP's restrictions dataset has no version, see n-m1.md). |
| The supervisor alarm fires after 10 s | **not run** | Source when run: `/v1/delivery-alarms` and the console banner. |
| The CISP reconciles when back | **not run** | Source when run: `deliveries` (the queued CISP job `sent` after restart) and the CISP's restrictions dataset version. |
| An adapter stalled for 30 s raises nothing from old positions (SC-15) | **not run on staging** | Covered below the milestone by the T-11 stall tests of every adapter (`docs/PLAN.md` section 10.2) and the replay file `testdata/replay/stale-then-resume.ndjson`; those are unit and integration tests, not the milestone proof. |
| A disabled adapter ages out as `source_disabled`, other adapters untouched (SC-08) | **not run on staging** | The lab's SC-08 run (`authority-sc08-rid-switch` PASS) is the authority's Remote ID switch, not the ANSP's adapters. Staging runs one adapter (replay), so "other adapters untouched" needs a second adapter instance first. |
| An occurrence report reaches the authority | **not run** | |

## Resource usage of the ANSP stack (`PLAN` section 15 row 20)

The plan's figure: at most 600 MB and 0.5 vCPU at the demo's load.

| What | Value | Source |
|---|---|---|
| Limits on staging (memory) | timescaledb 384, nats 96, api 256, manned-feed 96, manned-adapter 64: **896 MiB**; web 224 more | `uspace-deploy` `docs/BUDGET.md`, `compose/ansp.yaml`; the same in `deploy/compose.prod.yaml` |
| Limits on staging (CPU) | 0.75 + 0.25 + 0.5 + 0.25 + 0.25 (+ web 0.5) | `compose/ansp.yaml` |
| Measured use, ANSP containers alone | **not measured** | Needs `docker stats --no-stream $(docker ps -q --filter label=com.docker.compose.project=uspace-ansp)` on the host over the run. |
| Measured use, recorded by the deployment for every system | idle, first deploy: every Go process under 15 MiB, each timescaledb 71 to 119 MiB; fifth round: 2140 MiB in all containers of all systems | `uspace-deploy` `docs/RUNBOOKS/deploy.md` |
| Before core v1.4.0 | api held the EGM2008 grid, about 80 MiB, and processes under 128 MiB were OOM-killed; since v1.4.0 (`geoid_mapped: true`) the grid is shared in the page cache | same, third and fourth rounds |

The limits add up to more than the plan's 600 MB because they are
ceilings set after the OOM kills, not use. Whether the use stays within
600 MB and 0.5 vCPU at the demo's load is the open measurement; this
round did not lower the limits on a guess. The droplet's own sizing stays
the owner's question (lab deploy plan D8).

## To run the proof (writes to staging)

1. The USSP sends an intent notice for an intent touching an active
   restriction and, with the lab flying the SITL aircraft out of its
   volume, a non-conformance notice; record each `ack_id` (`202`), the
   inbox rows, the supervisor's acknowledgement time and the USSP's
   `GET /v1/coordination/notices/{ack_id}` answer.
2. `docker compose -p uspace-cisp stop api` for 2 min with a restriction
   change in flight; record the alarm time, the direct deliveries
   (`deliveries` with the USSP's and the authority's targets), their
   verification at the receivers, then `start` and the reconciliation.
3. SC-15: pause the replay adapter 30 s (`docker compose -p uspace-ansp
   pause manned-adapter`), resume; nothing live from old positions
   (`backlog` or placed by its own time base).
4. SC-08: switch the adapter off and on (`PUT /v1/sources/...`), record
   the `source_disabled` ageing within one tick; a second adapter
   instance stays live.
5. File an occurrence report from the console; record the authority's
   receipt.
6. Throughout: `docker stats` of the project every 30 s.
