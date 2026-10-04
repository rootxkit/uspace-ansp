#!/usr/bin/env bash
# The deploy/ checks (`make check-deploy`, CI job `deploy`):
#
#   1. shellcheck of every deploy script;
#   2. deploy/compose.prod.yaml rendered by `docker compose config` with
#      deploy/compose.prod.env.example, for each adapter profile, and the
#      rendered file read back for what it must say (no published port,
#      a memory limit on every service), and refused without an image;
#   3. deploy/caddy/proof.sh against the pinned Caddy.
#
# Needs docker and, for step 1, shellcheck: without it step 1 says
# SKIPPED, and CI (where it is installed) never skips.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts=(deploy/verify.sh deploy/backup.sh deploy/caddy/proof.sh scripts/check-deploy.sh scripts/conformance-target.sh)

if type -P shellcheck >/dev/null 2>&1; then
  shellcheck "${scripts[@]}"
  echo "check-deploy: shellcheck ok (${#scripts[@]} scripts)"
elif [ -n "${CI:-}" ]; then
  echo "check-deploy: shellcheck is not installed in CI" >&2
  exit 1
else
  echo "check-deploy: shellcheck SKIPPED, not installed"
fi

# The secrets the compose names, as empty files in a temporary directory:
# compose reads env files when it renders.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if type -P cygpath >/dev/null 2>&1; then tmp="$(cygpath -m "$tmp")"; fi
mkdir -p "$tmp/secrets"
: > "$tmp/secrets/app.env"; : > "$tmp/secrets/db.env"; : > "$tmp/secrets/web.env"

for profiles in "" replay feed "replay feed"; do
  args=()
  for p in $profiles; do args+=(--profile "$p"); done
  out="$tmp/rendered.yaml"
  ANSP_SECRETS_DIR="$tmp/secrets" docker compose --env-file deploy/compose.prod.env.example \
    -f deploy/compose.prod.yaml "${args[@]}" config > "$out"
  services="$(ANSP_SECRETS_DIR="$tmp/secrets" docker compose --env-file deploy/compose.prod.env.example \
    -f deploy/compose.prod.yaml "${args[@]}" config --services | sort | tr '\n' ' ')"
  if grep -q '^ *ports:' "$out" || grep -q 'published:' "$out"; then
    echo "check-deploy: a service publishes a port (profiles: ${profiles:-none})" >&2
    exit 1
  fi
  n_services="$(wc -w <<<"$services" | tr -d ' ')"
  n_limits="$(grep -c '^ *memory: "[0-9]*"$' "$out" || true)"
  if [ "$n_limits" -ne "$n_services" ]; then
    echo "check-deploy: $n_limits memory limits for $n_services services (profiles: ${profiles:-none})" >&2
    exit 1
  fi
  echo "check-deploy: compose.prod renders (profiles: ${profiles:-none}): $services; $n_limits memory limits; no published port"
done

# Without the image the compose refuses to render (fail closed).
if ANSP_SECRETS_DIR="$tmp/secrets" ANSP_IMAGE='' docker compose --env-file deploy/compose.prod.env.example \
    -f deploy/compose.prod.yaml config >/dev/null 2>"$tmp/err"; then
  echo "check-deploy: compose.prod rendered without ANSP_IMAGE" >&2
  exit 1
fi
echo "check-deploy: compose.prod refuses to render without ANSP_IMAGE ($(grep -o 'the uspace-ansp image by digest' "$tmp/err" | head -n 1))"

deploy/caddy/proof.sh
