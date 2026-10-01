# uspace-ansp

U-space interface of the air navigation service provider
(Sakaeronavigatsia; branding is configuration) in the Georgian U-space
system-of-systems: dynamic airspace reconfiguration (time-bounded
restrictions inside designated U-space airspace, published to the CISP
and written to the DSS as F3548 constraints), the manned traffic feed
into U-space (ATS surveillance normalised and streamed to USSPs and the
authority), and the Annex V coordination inbox (intents and
non-conformance notices from USSPs, acknowledged by the watch
supervisor).

It is an interface, not an ATM system: no clearances, no separation, no
alerts to operators, and nothing that can reach an aircraft.

Regulation: Reg. (EU) 2021/664 Art. 4, 5(2), 7(3), 13(2), Annex V;
2021/665 ATS.OR.127, ATS.TR.237. Standards: ASTM F3548-21 (constraints),
EUROCAE ED-318 (restriction features).

## Status

Planning. `docs/PLAN.md` is the implementation plan; `docs/WORKPACKAGES/`
holds one brief per work package (WP-0 to WP-13, five waves); `CLAUDE.md`
holds the rules. No product code yet: WP-0 scaffolds the module.

Milestones (spec `07` Phase 5): N-M0 scaffold and contracts, N-M1
restrictions and manned feed (first demo), N-M2 coordination and degraded
paths, N-M3 release.

## Layout (planned)

```
cmd/api              restrictions, coordination, outbox, DSS and CIS clients, accounts, audit
cmd/manned-adapter   one surveillance feed -> track/manned/v1 on NATS (one process per feed)
cmd/manned-feed      live manned picture, F4 stream and snapshot, TimescaleDB writer
api/openapi.yaml     the published national API (generated server, client and TypeScript types)
schemas/             JSON Schemas of the messages this system produces
migrations/          two goose trees: relational (PostgreSQL + PostGIS), timeseries (TimescaleDB)
web/                 dispatcher console (Next.js on uspace-ui, ka/en)
deploy/              image, compose, Caddy block
```

## Links

- Spec: `uspace-lab/docs/spec/` (`01 §4` ANSP role, `02 F2, F4, F11,
  F13`, `03 §4`, `07` Phase 5)
- Knowledge: `uspace-lab/knowledge/LESSONS.md`, `scenarios.md`
- Shared library: [`rootxkit/uspace-core`](https://github.com/rootxkit/uspace-core)
- UI kit: [`rootxkit/uspace-ui`](https://github.com/rootxkit/uspace-ui)
- Siblings: `uspace-authority`, `uspace-cisp`, `uspace-ussp`, `uspace-lab`

Go 1.27, module `github.com/rootxkit/uspace-ansp`. Public repository: no
secrets, keys, hostnames or real traffic data are ever committed.
