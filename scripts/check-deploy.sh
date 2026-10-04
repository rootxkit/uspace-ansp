#!/usr/bin/env bash
# The deploy/ checks (`make check-deploy`, CI job `deploy`):
#
#   1. shellcheck of every deploy script;
#   2. deploy/compose.prod.yaml rendered by `docker compose config` with
#      deploy/compose.prod.env.example, for each adapter profile, and the
#      rendered file read back for what it must say (no published port,
#      a memory limit on every service), and refused without an image;
#   3. the rendered shape read per service (jq): api's client secret
#      file is a non-empty file under a directory api mounts, and no
#      setting of the deployment empties it; each process gets only the
#      database DSN it opens;
#   4. deploy/caddy/proof.sh against the pinned Caddy.
#
# Needs docker, jq and, for step 1, shellcheck: without shellcheck step 1
# says SKIPPED, and CI (where it is installed) never skips.
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

if ! type -P jq >/dev/null 2>&1; then
  echo "check-deploy: jq is not installed" >&2
  exit 1
fi

# The secrets directory in the shape the deployment generates it, with
# placeholder values (no real secret): compose reads env files when it
# renders, and step 3 reads the key files the rendered paths name.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if type -P cygpath >/dev/null 2>&1; then tmp="$(cygpath -m "$tmp")"; fi
mkdir -p "$tmp/secrets/keys" "$tmp/secrets/nats"
printf 'ANSP_RELATIONAL_DSN=postgres://ansp:placeholder@timescaledb:5432/ansp\n' > "$tmp/secrets/relational.env"
printf 'ANSP_TIMESERIES_DSN=postgres://ansp:placeholder@timescaledb:5432/ansp_ts\n' > "$tmp/secrets/timeseries.env"
printf 'POSTGRES_PASSWORD=placeholder\n' > "$tmp/secrets/db.env"
: > "$tmp/secrets/web.env"
for k in session.pem secrets.key delivery.pem ansp-01.secret mtls-bindings.json; do
  printf 'placeholder\n' > "$tmp/secrets/keys/$k"
done

fail() { echo "check-deploy: $*" >&2; exit 1; }

# render <out.json> [compose args...]: the rendered compose as JSON.
render() {
  local out="$1"; shift
  ANSP_SECRETS_DIR="$tmp/secrets" docker compose --env-file deploy/compose.prod.env.example \
    -f deploy/compose.prod.yaml "$@" config --format json > "$out"
}

# secret_file_ok <rendered.json>: api's ANSP_CLIENT_SECRET_FILE names a
# file under one of api's bind mounts, and that file is not empty. An
# empty value would start api with no token client: every CISP and DSS
# call refused, which only the readiness line would say.
secret_file_ok() {
  local json="$1" path src
  # -j: no newline, which a Windows jq would write as CRLF.
  path="$(jq -j '.services.api.environment.ANSP_CLIENT_SECRET_FILE // ""' "$json")"
  [ -n "$path" ] || fail "api's ANSP_CLIENT_SECRET_FILE renders empty"
  # MSYS_NO_PATHCONV: Git Bash would rewrite the /run/... argument.
  src="$(MSYS_NO_PATHCONV=1 jq -j --arg p "$path" 'first(.services.api.volumes[] as $v
    | select($v.type == "bind" and ($p | startswith($v.target + "/")))
    | $v.source + ($p | ltrimstr($v.target))) // ""' "$json")"
  [ -n "$src" ] || fail "api's ANSP_CLIENT_SECRET_FILE $path is under none of api's mounts"
  [ -s "$src" ] || fail "api's ANSP_CLIENT_SECRET_FILE $path is mounted from $src, which is missing or empty"
  echo "$path"
}

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

# Each process gets only the DSN of the database it opens (CLAUDE.md
# rule 6): migrate both trees, api the relational database, manned-feed
# the hypertable, the adapters and everything else none.
render "$tmp/rendered.json" --profile replay --profile feed
got="$(jq -j '.services | to_entries[] | "\(.key) \((.value.environment.ANSP_RELATIONAL_DSN // "") != "") \((.value.environment.ANSP_TIMESERIES_DSN // "") != "")\n"' \
  "$tmp/rendered.json" | tr -d '\r' | sort)"
want="api true false
manned-adapter-feed false false
manned-adapter-replay false false
manned-feed false true
migrate true true
nats false false
timescaledb false false
web false false"
if [ "$got" != "$want" ]; then
  fail "the DSNs per service (service relational timeseries) are
$got
want
$want"
fi
echo "check-deploy: DSNs per process: migrate both, api relational, manned-feed timeseries, adapters none"

# api's client secret: set and non-empty in the rendered shape, also when
# the deployment sets ANSP_API_CLIENT_SECRET_FILE empty, and refused when
# the file it names is empty.
render "$tmp/rendered.json"
path="$(secret_file_ok "$tmp/rendered.json")"
echo "check-deploy: api reads its client secret from $path (non-empty)"
ANSP_API_CLIENT_SECRET_FILE='' render "$tmp/rendered.json"
secret_file_ok "$tmp/rendered.json" >/dev/null
echo "check-deploy: an empty ANSP_API_CLIENT_SECRET_FILE still renders $path"
: > "$tmp/secrets/keys/ansp-01.secret"
if (secret_file_ok "$tmp/rendered.json") >/dev/null 2>&1; then
  fail "an empty ansp-01.secret was accepted"
fi
printf 'placeholder\n' > "$tmp/secrets/keys/ansp-01.secret"
echo "check-deploy: an empty ansp-01.secret is refused"

deploy/caddy/proof.sh
