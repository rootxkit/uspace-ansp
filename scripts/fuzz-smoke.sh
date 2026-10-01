#!/usr/bin/env bash
# Runs every fuzz target of the module for FUZZTIME each (default 10s),
# one at a time (go test -fuzz takes one target per package run). Lists
# what it ran; zero targets is reported, not hidden.
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"
FUZZTIME="${FUZZTIME:-10s}"

n=0
while IFS=: read -r file _ line; do
  name="$(sed -E 's/^func (Fuzz[A-Za-z0-9_]*)\(.*/\1/' <<<"$line")"
  pkg="./$(dirname "$file")"
  echo "fuzz-smoke: ${pkg} ${name} for ${FUZZTIME}"
  "$GO" test -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" "$pkg"
  n=$((n + 1))
done < <(grep -rn --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]*\(' cmd internal tests 2>/dev/null | sort)
echo "fuzz-smoke: ${n} target(s) ran"
