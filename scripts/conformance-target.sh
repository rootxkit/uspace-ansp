#!/usr/bin/env bash
# `make conformance-target`: the ANSP stack for uspace-lab's conformance
# suite (testdata/conformance/README.md). Builds and starts the
# development stack with deploy/compose.conformance.yaml, which points the
# token verifier, the token client (ansp-01) and the DSS at the lab, waits
# for every process to answer /healthz, prints /readyz of api (what is
# reachable and what is not, E-02), then the base URLs and the client ids
# the suite configures. `make compose-down` removes everything.
#
# Refuses to start without the lab's values: a target that verifies no
# lab token would make every suite check fail for the wrong reason.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=""
for v in LAB_ISSUER LAB_JWKS_URL LAB_TOKEN_URL LAB_CLIENT_SECRET_FILE LAB_DSS_URL; do
  if [ -z "${!v:-}" ]; then missing="$missing $v"; fi
done
if [ -n "$missing" ]; then
  echo "conformance-target: not set:$missing (testdata/conformance/README.md)" >&2
  exit 2
fi
if [ ! -r "$LAB_CLIENT_SECRET_FILE" ]; then
  echo "conformance-target: LAB_CLIENT_SECRET_FILE is not a readable file" >&2
  exit 2
fi

public="${ANSP_CONFORMANCE_PUBLIC_BASE_URL:-http://host.docker.internal:58080}"
host="${public#*://}"; host="${host%%/*}"
export ANSP_CONFORMANCE_AUDIENCE="${ANSP_CONFORMANCE_AUDIENCE:-$host}"

# A throwaway delivery key for this target (git-ignored local/): the
# lab's DSS and subscribers verify what this ANSP signs with it.
mkdir -p local/conformance
key=local/conformance/delivery.pem
if [ ! -s "$key" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" 2>/dev/null
  echo "conformance-target: wrote $key (throwaway delivery key)"
fi
# The distroless image runs as nonroot and reads it through a bind mount.
chmod 0644 "$key"

if [ ! -f local/dev.env ]; then
  echo "conformance-target: local/dev.env is missing; run make conformance-target" >&2
  exit 2
fi
scripts/nats-creds.sh
compose=(docker compose --env-file local/dev.env -f deploy/compose.yaml -f deploy/compose.conformance.yaml)
"${compose[@]}" up -d --build --wait

# Every process answers /healthz (bounded: --max-time on each call).
for p in api:58080 manned-feed:58081 manned-adapter:58082; do
  name="${p%%:*}"; port="${p##*:}"
  if body="$(curl -fsS --max-time 5 "http://127.0.0.1:$port/healthz")"; then
    echo "conformance-target: $name /healthz $body"
  else
    echo "conformance-target: $name does not answer /healthz on 127.0.0.1:$port" >&2
    exit 1
  fi
done
echo "conformance-target: api /readyz:"
curl -sS --max-time 5 "http://127.0.0.1:58080/readyz" || true
echo

cat <<EOF
conformance-target: ready for uspace-lab/conformance (testdata/conformance/target.yaml)
  base URL (api)          ${ANSP_CONFORMANCE_BASE_URL:-http://127.0.0.1:58080}
  feed URL (manned-feed)  ${ANSP_CONFORMANCE_FEED_URL:-http://127.0.0.1:58081}
  uss_base_url (DSS)      $public
  token audience          $ANSP_CONFORMANCE_AUDIENCE
  ANSP client id          ansp-01 (lab-issued secret mounted)
  suite client id         lab-01
  DSS                     $LAB_DSS_URL
  issuer                  $LAB_ISSUER
  stop with               make compose-down
EOF
