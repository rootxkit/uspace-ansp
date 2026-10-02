#!/usr/bin/env bash
# The contracts this system consumes from its siblings are pinned copies
# (reconciliation M11): the OpenAPI files in api/clients/ and the
# uspace-lab common schemas in schemas/common/. Each is named by one line
# of a SOURCE file (api/clients/SOURCE, schemas/SOURCE):
#
#   <copy, relative to the SOURCE file's directory> <owner/repo> <commit> <path in that repo>
#
# This script fetches every file at its commit and fails on any byte
# difference, on a malformed line, on a line whose copy is missing and on
# a copy no line names. It needs the network (raw.githubusercontent.com);
# a fetch that fails is a failure, never a pass.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
checked=0

# check <SOURCE file> <find arguments selecting the copies under its directory>
check() {
  local source_file="$1"
  shift
  local dir
  dir="$(dirname "$source_file")"
  declare -A named=()
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    read -r copy repo commit path extra <<<"$line"
    if [ -z "${path:-}" ] || [ -n "${extra:-}" ] || ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
      echo "check-contracts: $source_file: malformed line: $line" >&2
      status=1
      continue
    fi
    named[$copy]=1
    local file="$dir/$copy"
    if [ ! -f "$file" ]; then
      echo "check-contracts: $source_file names $copy but $file is missing" >&2
      status=1
      continue
    fi
    local scratch
    scratch="$(mktemp)"
    if ! curl -fsSL --retry 3 "https://raw.githubusercontent.com/$repo/$commit/$path" -o "$scratch"; then
      echo "check-contracts: cannot fetch $repo@$commit:$path" >&2
      rm -f "$scratch"
      status=1
      continue
    fi
    if diff -u "$scratch" "$file"; then
      echo "check-contracts: $file equals $repo@${commit:0:12}:$path"
      checked=$((checked + 1))
    else
      echo "check-contracts: $file differs from $repo@$commit:$path" >&2
      status=1
    fi
    rm -f "$scratch"
  done < "$source_file"
  local copy
  while IFS= read -r copy; do
    copy="${copy#"$dir"/}"
    if [ -z "${named[$copy]:-}" ]; then
      echo "check-contracts: $dir/$copy has no line in $source_file" >&2
      status=1
    fi
  done < <(find "$dir" "$@" -type f | sort)
}

check api/clients/SOURCE -maxdepth 1 -name '*.yaml'
check schemas/SOURCE -path 'schemas/common/*'

if [ "$checked" -eq 0 ]; then
  echo "check-contracts: no copy was compared" >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
echo "check-contracts: $checked pinned copies equal their sources"
