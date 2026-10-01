#!/usr/bin/env bash
# Regenerates everything `go generate` produces and fails when the result
# differs from what is committed (CLAUDE.md rule 7). Offline: from WP-3
# the generators (oapi-codegen, sqlc) are `go run` at pinned versions or
# go.mod tool directives, resolved from the module cache. WP-0 has no
# generator yet; the check then proves the tree is unchanged.
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"

n="$(grep -rl --include='*.go' '^//go:generate ' . 2>/dev/null | wc -l | tr -d ' ')"
echo "generate-check: ${n} file(s) with go:generate directives"
"$GO" generate ./...
if [ -f web/package.json ]; then
  (cd web && pnpm run types)
fi
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
