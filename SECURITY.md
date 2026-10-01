# Security policy

`uspace-ansp` is the U-space interface of the air navigation service
provider in the Georgian U-space system-of-systems: dynamic airspace
reconfiguration, the manned traffic feed into U-space and the Annex V
coordination inbox. It never commands an aircraft. Report a
vulnerability privately to the repository owner through GitHub's
private vulnerability reporting on this repository (Security tab,
"Report a vulnerability"). Do not open a public issue.

We acknowledge a report within 7 days and aim to publish a fix, or an
agreed statement, within 90 days of the report. A deployed instance is
patched by a new image built in CI and rolled out by tag; the advisory
names the first fixed image tag.

Scope: the code in this repository (the `api`, `manned-adapter` and
`manned-feed` processes, the console under `web/`, the published API
`api/openapi.yaml`, the migrations and the reference deployment files
under `deploy/`). Out of scope: `uspace-core` and `uspace-ui` (each has
its own policy), the other systems of the ecosystem, the surveillance
sources themselves, and a deployment's own infrastructure (the shared
Caddy, the hosts, their keys).

This repository is public. No secret, key, certificate, hostname or
real traffic data is ever committed, including test keys and
development passwords; `gitleaks` runs in CI. Test keys are generated
at test time, every credential is configuration read from a file
(`deploy/.env.example` lists the variables, never their values), and
`make compose-up` generates its local password and NATS keys into the
git-ignored `local/`.
