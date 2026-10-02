#!/usr/bin/env bash
# Regenerates everything (scripts/generate.sh) and fails when the result
# differs from what is committed (CLAUDE.md rule 7). The generators
# (oapi-codegen, sqlc, api/internal/opsgen) are `go run` at pinned
# versions, resolved from the module cache or the module proxy.
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"

n="$( (grep -rl --include='*.go' '^//go:generate ' . 2>/dev/null || true) | wc -l | tr -d ' ')"
echo "generate-check: ${n} file(s) with go:generate directives"
GO="$GO" scripts/generate.sh
if ! git diff --exit-code; then
  echo "generate-check: generated files differ from the committed ones: run 'make generate' and commit"
  exit 1
fi
untracked="$(git status --porcelain --untracked-files=all | grep '^??' || true)"
if [ -n "$untracked" ]; then
  echo "$untracked"
  echo "generate-check: generation wrote files that are not committed"
  exit 1
fi
echo "generate-check: generated files are current"
