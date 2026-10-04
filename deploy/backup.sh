#!/usr/bin/env bash
# Nightly backup of both ANSP databases (docs/PLAN.md section 11; the
# S-22 pattern), run by the host's cron as the deploy user:
#
#   20 2 * * *  /srv/uspace-ansp/deploy/backup.sh /var/backups/uspace-ansp
#
# Writes ansp-<UTC stamp>.dump (relational: restrictions, deliveries, the
# hash-chained events) and ansp_ts-<UTC stamp>.dump (TimescaleDB: the
# manned tracks and feed products), pg_dump -Fc from inside the compose
# project's timescaledb container, so the dump tool is the server's own
# version. Each dump is written under a .partial name, read back with
# pg_restore --list (a dump that does not list is not a backup), and only
# then moved into place.
#
# Off the host: with ANSP_BACKUP_REMOTE set (an rclone remote and path,
# for example `spaces:ansp-backups`, the "second account" of PLAN section
# 11), each dump is copied there with rclone and the copy's size compared.
# Which account and region holds it is the owner's open question (lab
# deploy plan D-Q3); without it the run says the dumps stayed on the host.
#
# Then removes local dumps older than ANSP_BACKUP_KEEP_DAYS (14; how long
# backups are kept is a national choice of spec 05 section 4, pending
# GCAA, so the default is configuration, not a decision). A failed step
# exits non-zero and leaves the older dumps alone.
#
# Restoring the TimescaleDB dump: create the database and the extension,
# `SELECT timescaledb_pre_restore();`, pg_restore, then
# `SELECT timescaledb_post_restore();` (docs/runbooks/release.md,
# "Restore a backup").
set -euo pipefail

dir="${1:?usage: deploy/backup.sh <backup directory>}"
keep_days="${ANSP_BACKUP_KEEP_DAYS:-14}"
project="${ANSP_COMPOSE_PROJECT:-uspace-ansp}"
remote="${ANSP_BACKUP_REMOTE:-}"
case "$keep_days" in ''|*[!0-9]*) echo "backup: ANSP_BACKUP_KEEP_DAYS must be a whole number of days" >&2; exit 2 ;; esac
mkdir -p "$dir"

pg="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=timescaledb)"
if [ -z "$pg" ]; then
  echo "backup: no running timescaledb container in compose project $project" >&2
  exit 1
fi
if [ "$(printf '%s\n' "$pg" | wc -l)" -ne 1 ]; then
  echo "backup: more than one timescaledb container in compose project $project" >&2
  exit 1
fi
if [ -n "$remote" ] && ! type -P rclone >/dev/null 2>&1; then
  echo "backup: ANSP_BACKUP_REMOTE is set but rclone is not installed" >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
for db in ansp ansp_ts; do
  partial="$dir/.$db-$stamp.dump.partial"
  final="$dir/$db-$stamp.dump"
  if ! docker exec "$pg" pg_dump -Fc -U postgres "$db" > "$partial"; then
    rm -f "$partial"
    echo "backup: pg_dump $db failed; older dumps kept" >&2
    exit 1
  fi
  # Read it back with the server's own pg_restore.
  if ! entries="$(docker exec -i "$pg" pg_restore --list < "$partial" | grep -cv '^;')"; then
    rm -f "$partial"
    echo "backup: the dump of $db does not list; older dumps kept" >&2
    exit 1
  fi
  mv "$partial" "$final"
  bytes="$(wc -c < "$final" | tr -d ' ')"
  echo "backup: $final ($bytes bytes, $entries entries)"
  if [ -n "$remote" ]; then
    rclone copyto "$final" "$remote/$(basename "$final")"
    copied="$(rclone size --json "$remote/$(basename "$final")" | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')"
    if [ "$copied" != "$bytes" ]; then
      echo "backup: the copy of $final at $remote has ${copied:-no} bytes, not $bytes" >&2
      exit 1
    fi
    echo "backup: copied to $remote/$(basename "$final") ($copied bytes)"
  fi
done
if [ -z "$remote" ]; then
  echo "backup: ANSP_BACKUP_REMOTE is not set; the dumps stayed on this host"
fi

# Rotation: only complete dumps of this job, older than keep_days.
find "$dir" -maxdepth 1 -type f \( -name 'ansp-*.dump' -o -name 'ansp_ts-*.dump' \) -mtime +"$keep_days" -print -delete |
  sed 's/^/backup: rotated out /'
