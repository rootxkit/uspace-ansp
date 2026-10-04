#!/usr/bin/env bash
# Verifies the cosign signature and the SBOM attestation of uspace-ansp
# images before they are pulled (spec 06 section 4, WP-13). Run on the
# host that deploys, before `docker compose pull`:
#
#   deploy/verify.sh ghcr.io/rootxkit/uspace-ansp@sha256:<digest> \
#                    ghcr.io/rootxkit/uspace-ansp-web@sha256:<digest>
#
# Every reference must be by digest: a tag can move after it is checked.
# The signature must come from this repository's .github/workflows/ci.yml
# on main or on a v* tag, issued by GitHub's OIDC issuer (keyless); the
# SBOM attestation (SPDX) from the same identity. cosign runs from the
# host when installed, else from the pinned image, so the host needs
# nothing but Docker. Exits non-zero on the first reference that does not
# verify, and says which check failed.
set -euo pipefail

COSIGN_IMAGE="${COSIGN_IMAGE:-gcr.io/projectsigstore/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31}"
REPO="${ANSP_SIGNER_REPO:-rootxkit/uspace-ansp}"
identity="^https://github\.com/${REPO//./\\.}/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9][^ ]*)\$"
issuer=https://token.actions.githubusercontent.com

if [ "$#" -eq 0 ]; then
  echo "usage: deploy/verify.sh <image@sha256:digest>..." >&2
  exit 2
fi

# type -P: the binary on PATH, never this function.
cosign() {
  if type -P cosign >/dev/null 2>&1; then
    command cosign "$@"
  else
    MSYS_NO_PATHCONV=1 docker run --rm "$COSIGN_IMAGE" "$@"
  fi
}

for ref in "$@"; do
  if [[ ! "$ref" =~ ^[a-z0-9./-]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "verify: $ref is not a reference by digest (repo@sha256:<64 hex>)" >&2
    exit 1
  fi
  if ! cosign verify "$ref" --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer" >/dev/null; then
    echo "verify: FAIL signature of $ref" >&2
    exit 1
  fi
  echo "verify: ok signature   $ref"
  if ! cosign verify-attestation --type spdxjson "$ref" \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer" >/dev/null; then
    echo "verify: FAIL SBOM attestation of $ref" >&2
    exit 1
  fi
  echo "verify: ok SBOM (spdx) $ref"
done
echo "verify: $# image(s) verified; pull them by these digests"
