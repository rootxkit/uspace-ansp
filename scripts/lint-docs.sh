#!/usr/bin/env bash
# Checks every tracked Markdown file: LF line endings, no trailing
# whitespace, no AI attribution (CLAUDE.md), and every relative link
# resolves to a file or directory of the repository. The only CI job a
# docs-only change runs.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
mapfile -t files < <(git ls-files '*.md')
for f in "${files[@]}"; do
  if grep -q $'\r' "$f"; then echo "$f: CRLF line endings"; fail=1; fi
  if grep -nE '[[:space:]]+$' "$f" | head -n 3 | sed "s|^|$f:|" | grep .; then fail=1; fi
  if grep -niE 'co-authored-by|generated with claude' "$f" | sed "s|^|$f:|" | grep .; then fail=1; fi
  dir="$(dirname "$f")"
  while IFS= read -r link; do
    target="${link%%#*}"
    [ -z "$target" ] && continue
    if [ ! -e "$dir/$target" ]; then echo "$f: broken relative link ($link)"; fail=1; fi
  done < <(grep -oE '\]\([^)[:space:]]+\)' "$f" | sed -E 's/^\]\((.*)\)$/\1/' | grep -vE '^[a-z][a-z0-9+.-]*:' || true)
done
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "lint-docs: ${#files[@]} Markdown file(s) clean"
