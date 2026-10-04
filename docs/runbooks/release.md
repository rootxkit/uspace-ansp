# Releasing, verifying and rolling back

How a version of uspace-ansp is made, checked and undone (WP-13, N-M3).
The owner tags; nobody else does.

## Tag

1. `main` is green: the last CI run on `main` passed every job, `images`,
   `SBOMs` and `attest SBOMs` included (`gh run list --branch main`).
2. `CHANGELOG.md`: move the `[Unreleased]` entries under the version
   heading with the date; the `1.0.0` section is prepared for N-M3.
3. The owner tags the merge commit: `git tag -s v1.0.0 <sha>` and
   `git push origin v1.0.0`. Never a tag on a commit that is not on
   `main`; never a moved tag.

## What CI does on a tag

The same workflow as on `main` (`.github/workflows/ci.yml`): every gate,
then `images` pushes `ghcr.io/rootxkit/uspace-ansp:<short sha>` and
`:<tag>`, and the same for `uspace-ansp-web`, built with
`VERSION=<tag>`; signs each digest keyless with cosign and verifies the
signature; `SBOMs` makes an SPDX SBOM of each image with syft;
`attest SBOMs` attaches them as signed attestations. The step summary of
`images` lists the two digests: those, not the tags, are what a
deployment pins.

## Verify an image

```
deploy/verify.sh ghcr.io/rootxkit/uspace-ansp@sha256:<digest> \
                 ghcr.io/rootxkit/uspace-ansp-web@sha256:<digest>
```

It refuses a reference that is not by digest, then checks the signature
and the SPDX attestation against this repository's workflow on `main` or
a `v*` tag (issuer `https://token.actions.githubusercontent.com`). cosign
from the host, else the pinned cosign image. Observed on 2026-10-04 for
e41dec9: both images `ok signature`, `ok SBOM (spdx)`, exit 0; a CISP
digest and a tag reference refused, exit 1 (docs/runbooks/n-m1.md).

## Deploy

The deployment repository pins the digests (on staging `uspace-deploy`
`compose/images.env`, with this repository's deploy files vendored at the
same commit) and runs `deploy/compose.prod.yaml`'s shape: verify, pull by
digest, the one-shot `migrate` of both trees, then the processes. Before a
deploy whose migrations are not additive, take a backup
(`deploy/backup.sh`).

## Roll back

See [deploy/rollback.md](../../deploy/rollback.md): by image digest, the
previous one, verified again.

## Restore a backup

`deploy/backup.sh` writes `ansp-<stamp>.dump` and `ansp_ts-<stamp>.dump`
(pg_dump custom format, each read back with `pg_restore --list`). With
the stack stopped except timescaledb:

```
docker exec -i <timescaledb> psql -U postgres -c 'DROP DATABASE ansp' -c 'CREATE DATABASE ansp'
docker exec -i <timescaledb> pg_restore -U postgres -d ansp < ansp-<stamp>.dump
docker exec -i <timescaledb> psql -U postgres -c 'DROP DATABASE ansp_ts' -c 'CREATE DATABASE ansp_ts'
docker exec -i <timescaledb> psql -U postgres -d ansp_ts \
  -c 'CREATE EXTENSION IF NOT EXISTS timescaledb' -c 'SELECT timescaledb_pre_restore()'
docker exec -i <timescaledb> pg_restore -U postgres -d ansp_ts < ansp_ts-<stamp>.dump
docker exec -i <timescaledb> psql -U postgres -d ansp_ts -c 'SELECT timescaledb_post_restore()'
```

Then start the stack; `migrate` finds both trees at their version.
Rehearsed on 2026-10-04 against a throwaway timescaledb-ha:pg16 (the
pinned digest) with a hypertable: both dumps written and listed (33 and
34 entries), both restored, the rows read back. The image's template
database already carries the extension, hence `IF NOT EXISTS`.
