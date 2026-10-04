#!/usr/bin/env bash
# Proves deploy/caddy/ansp.caddy against a running Caddy (the pinned
# image), not against its text: every route class reaches the upstream it
# names, /metrics and /readyz reach none, and the certificate subject
# header reaches an upstream only from a verified client certificate on
# the two mTLS route groups (E-01: each absence is paired with the
# presence that makes it happen).
#
#   deploy/caddy/proof.sh            (make check-deploy runs it)
#
# Stub upstreams inside the same Caddy answer with their own name and the
# subject header they received. A throwaway CA and client certificates
# are made with openssl in a temporary directory. The container is
# removed on exit and its absence checked.
set -euo pipefail

# Schannel (Windows curl) cannot present a PEM client certificate: every
# certificate check would fail, and the refusal check would pass for the
# wrong reason. Refuse to prove anything with it.
if curl -V | head -n 1 | grep -q Schannel && ! curl -V | head -n 1 | grep -q OpenSSL; then
  echo "proof: this curl uses Schannel, which cannot send a PEM client certificate; run it on Linux or in WSL" >&2
  exit 2
fi

CADDY_IMAGE="${CADDY_IMAGE:-caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d}"
port="${PROOF_PORT:-58443}"
host=ansp.proof.test
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
name="ansp-caddy-proof-$$"

# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ -n "$(docker ps -aq --filter "name=^${name}\$")" ]; then
    echo "proof: container $name is still present after cleanup" >&2
    exit 1
  fi
}
trap cleanup EXIT

# Git Bash on Windows: a C:/ path, which neither MSYS nor the native
# openssl and docker rewrite (the subjects below are passed unconverted).
if command -v cygpath >/dev/null 2>&1; then work="$(cygpath -m "$work")"; fi

# A CA the site trusts, a client it issued, and a client of another CA.
mkcert() { # <name> <subject>
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "$2" \
    -keyout "$work/$1.key" -out "$work/$1.pem" >/dev/null 2>&1
}
mkclient() { # <name> <subject> <ca name>
  openssl req -newkey rsa:2048 -nodes -subj "$2" \
    -keyout "$work/$1.key" -out "$work/$1.csr" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$work/$1.ext"
  openssl x509 -req -in "$work/$1.csr" -CA "$work/$3.pem" -CAkey "$work/$3.key" \
    -CAcreateserial -days 1 -extfile "$work/$1.ext" -out "$work/$1.pem" >/dev/null 2>&1
}
MSYS_NO_PATHCONV=1 mkcert ca "/O=proof/CN=proof mTLS CA"
MSYS_NO_PATHCONV=1 mkcert otherca "/O=other/CN=other CA"
MSYS_NO_PATHCONV=1 mkclient client "/O=proof/CN=authority-01" ca
MSYS_NO_PATHCONV=1 mkclient stranger "/O=other/CN=stranger" otherca
chmod 0644 "$work"/*.pem "$work"/*.key

cp "$here/ansp.caddy" "$work/ansp.caddy"
cat > "$work/Caddyfile" <<'CADDY'
{
	admin off
	local_certs
	skip_install_trust
	auto_https disable_redirects
	https_port 8443
	http_port 8080
	log {
		output discard
	}
}

import /work/ansp.caddy

:9001 {
	respond "upstream=api subject=[{header.X-Client-Cert-Subject}]" 200
}
:9002 {
	respond "upstream=feed subject=[{header.X-Client-Cert-Subject}]" 200
}
:9003 {
	respond "upstream=web subject=[{header.X-Client-Cert-Subject}]" 200
}
CADDY

MSYS_NO_PATHCONV=1 docker run -d --name "$name" \
  -p "127.0.0.1:${port}:8443" \
  -e ANSP_HOST="$host" -e ANSP_MTLS_CA=/work/ca.pem \
  -e ANSP_API_UPSTREAM=127.0.0.1:9001 -e ANSP_FEED_UPSTREAM=127.0.0.1:9002 \
  -e ANSP_WEB_UPSTREAM=127.0.0.1:9003 \
  -v "$work:/work:ro" \
  "$CADDY_IMAGE" caddy run --config /work/Caddyfile --adapter caddyfile >/dev/null

fail=0
pass=0
ok() { echo "ok     $*"; pass=$((pass + 1)); }
bad() { echo "FAIL   $*"; fail=1; }

# curl against the proof host. --ssl-no-revoke: Windows curl (Schannel)
# asks for a revocation list the internal CA does not publish; other TLS
# backends ignore it. -k: the site certificate is Caddy's internal one.
pc() { # <path> [curl args...]
  local path="$1"; shift
  curl -sk --max-time 10 --ssl-no-revoke --resolve "$host:$port:127.0.0.1" \
    -w '\n%{http_code}' "$@" "https://$host:$port$path"
}

# Wait on the condition (Caddy serving), never a fixed sleep.
ready=0
for _ in $(seq 1 100); do
  if pc /healthz >/dev/null 2>&1; then ready=1; break; fi
  if [ -z "$(docker ps -q --filter "name=^${name}\$")" ]; then break; fi
  # A bounded poll of the condition: at most 100 x 0.1 s.
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  echo "proof: Caddy did not serve; its log:" >&2
  docker logs "$name" 2>&1 | tail -n 20 >&2
  exit 1
fi

expect() { # <label> <want code> <want body substring> <path> [curl args...]
  local label="$1" code="$2" want="$3" path="$4"; shift 4
  local out got body
  out="$(pc "$path" "$@" 2>&1 || true)"
  got="$(printf '%s' "$out" | tail -n 1)"
  body="$(printf '%s' "$out" | sed '$d')"
  if [ "$got" = "$code" ] && { [ -z "$want" ] || [[ "$body" == *"$want"* ]]; }; then
    ok "$label: $path -> $got ${body:+($body)}"
  else
    bad "$label: $path -> ${got:-no answer} ($body), want $code with '$want'"
  fi
}

cert=(--cert "$work/client.pem" --key "$work/client.key")
forged=(-H 'X-Client-Cert-Subject: CN=forged')

# Route classes.
expect "api"  200 "upstream=api"  /healthz
expect "api"  200 "upstream=api"  /uss/v1/constraints/x
expect "api"  200 "upstream=api"  /v1/restrictions
expect "api"  200 "upstream=api"  /.well-known/jwks.json
expect "api"  200 "upstream=api"  /v1/coordination/notices
expect "feed" 200 "upstream=feed" /v1/manned-traffic/stream
expect "web"  200 "upstream=web"  /
expect "web"  200 "upstream=web"  /_bff/session
expect "web"  200 "upstream=web"  /ka/login

# Never routed: answered by Caddy itself, with no upstream body.
for p in /metrics /metrics/x /readyz; do
  out="$(pc "$p" || true)"
  if [ "$(printf '%s' "$out" | tail -n 1)" = 404 ] && [[ "$out" != *upstream=* ]]; then
    ok "internal: $p -> 404 from Caddy"
  else
    bad "internal: $p -> $(printf '%s' "$out" | tr '\n' ' ')"
  fi
done

# Absence: a forged subject without a certificate reaches no upstream,
# on the mTLS groups and everywhere else.
expect "forged, no cert" 200 "upstream=api subject=[]"  /v1/coordination/notices "${forged[@]}"
expect "forged, no cert" 200 "upstream=feed subject=[]" /v1/manned-traffic/stream "${forged[@]}"
expect "forged, no cert" 200 "upstream=api subject=[]"  /v1/restrictions "${forged[@]}"
expect "forged, no cert" 200 "upstream=web subject=[]"  / "${forged[@]}"

# Presence: a verified certificate's subject reaches the mTLS groups, and
# replaces a forged one.
expect "cert" 200 "upstream=api subject=[CN=authority-01,O=proof]"  /v1/coordination/notices "${cert[@]}"
expect "cert" 200 "upstream=feed subject=[CN=authority-01,O=proof]" /v1/manned-traffic/stream "${cert[@]}"
expect "cert + forged" 200 "upstream=api subject=[CN=authority-01,O=proof]" /v1/coordination/notices "${cert[@]}" "${forged[@]}"

# A certificate is never forwarded outside the two groups.
expect "cert, other route" 200 "upstream=api subject=[]" /v1/restrictions "${cert[@]}" "${forged[@]}"
expect "cert, other route" 200 "upstream=web subject=[]" / "${cert[@]}"

# A certificate of another CA ends the handshake (verify_if_given
# verifies what is given).
if pc /v1/coordination/notices --cert "$work/stranger.pem" --key "$work/stranger.key" 2>/dev/null | grep -q upstream=; then
  bad "untrusted cert: answered"
else
  ok "untrusted cert: refused at the handshake"
fi

echo "proof: $pass checks passed$([ "$fail" -eq 0 ] || echo ', some FAILED')"
exit "$fail"
