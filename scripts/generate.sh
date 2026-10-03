#!/usr/bin/env bash
# Regenerates everything generated in this repository (CLAUDE.md rule 7):
#   go generate ./...   oapi-codegen v2.8.0 (api/gen, api/clients/cispclient;
#                       the version is pinned once, in each generate.go),
#                       api/internal/opsgen (api/gen/operations.gen.go and the
#                       contract tests' stub) and sqlc (internal/store)
#   api/gen/SOURCE      the SHA-256 of the inputs api/gen was generated from
#   web/                the TypeScript API types (uspace-ui-gen-api, WP-11),
#                       when web/node_modules is installed; the web CI job
#                       checks them with `make web-types` either way
# scripts/generate-check.sh runs this and fails on any difference.
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"

"$GO" generate ./...

sum() { sha256sum "$1" | cut -d' ' -f1; }
{
  echo "# What api/gen was generated from, written by scripts/generate.sh."
  echo "# A stale hash means api/gen is stale: run make generate."
  echo "generator = github.com/oapi-codegen/oapi-codegen/v2 v2.8.0 (api/oapi-codegen.yaml), api/internal/opsgen"
  echo "spec_sha256 = $(sum api/openapi.yaml)"
  echo "annex_v_schema_sha256 = $(sum schemas/coordination/annex_v/v1.json)"
  echo "codegen_config_sha256 = $(sum api/oapi-codegen.yaml)"
} > api/gen/SOURCE

if [ -f web/package.json ]; then
  if [ -d web/node_modules ]; then
    (cd web && pnpm run types)
  else
    echo "generate: web types SKIPPED, web/node_modules is not installed (make web-install); the web job runs make web-types"
  fi
fi
echo "generate: done"
