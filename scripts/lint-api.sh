#!/usr/bin/env bash
# Lints api/openapi.yaml with @redocly/cli, pinned here and nowhere else
# (api/redocly.yaml holds the rules). Fails on any error and on any
# warning: the summary must report none. LINT_API_CONFIG replaces the
# configuration (the CI step that proves a warning fails the lint).
set -euo pipefail
cd "$(dirname "$0")/.."
REDOCLY_VERSION=2.57.0
config="${LINT_API_CONFIG:-api/redocly.yaml}"
# Colour codes are stripped ([[:cntrl:]] is the escape character).
out="$(npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint --config "$config" --format=summary api/openapi.yaml 2>&1 |
  sed 's/[[:cntrl:]][[][0-9;]*m//g')" || { echo "$out"; exit 1; }
echo "$out"
if echo "$out" | grep -Eq '^(warning|error) '; then
  echo "lint-api: warnings or errors above"
  exit 1
fi
echo "lint-api: api/openapi.yaml lints clean with @redocly/cli ${REDOCLY_VERSION}"
