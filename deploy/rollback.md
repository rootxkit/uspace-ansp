# Rollback

By image digest (S-21). The previous release's digests are in the
deployment's history (on staging `uspace-deploy` `state/history/` and
`rollback.sh`).

1. Pick the digests to return to, from the deployment history or from
   the `images` step summary of that commit's CI run.
2. `deploy/verify.sh <go image@sha256:...> <web image@sha256:...>`; stop
   if either does not verify.
3. Set `ANSP_IMAGE` and `ANSP_WEB_IMAGE` to them and run the compose
   again (`docker compose -p uspace-ansp ... up -d --wait`). api,
   manned-feed and every adapter share one image and move together.
4. Migrations are forward-only. An older binary against a newer schema is
   safe only when the newer release's CHANGELOG says its migrations are
   additive (every migration so far is). When it is not, restore the
   backup taken before the deploy (docs/runbooks/release.md, "Restore a
   backup") before starting the older image.
5. Check: `/healthz` of every process; api's `/readyz` from the project
   network; the api log's start line names the version.
6. Record the rollback in the deployment's log and commit the rolled-back
   digests there once the system is healthy.
