#!/usr/bin/env bash
# Partout server DB backup — atomic hot snapshot via `partout ctl db-backup`
# (SQLite VACUUM INTO; no sqlite3 CLI needed on the host). Invoked by
# deploy/systemd/partout-backup.timer. The server may be running.
#
# Usage: backup.sh <partout binary> <db path> <backup dir> [retention]
#
# Retention: keep the newest N snapshots (default 14 ≈ two weeks of daily).
# Exit non-zero on any failure so the timer surfaces it in the journal.
set -euo pipefail

BIN=${1:?usage: backup.sh <partout> <db> <backup_dir> [retention]}
DB=${2:?missing db path}
DIR=${3:?missing backup dir}
RETENTION=${4:-14}

if [ ! -f "$DB" ]; then
    echo "backup: db not found: $DB" >&2
    exit 1
fi

mkdir -p "$DIR"
out="$DIR/partout.db.$(date -u +%Y%m%dT%H%M%SZ).bak"

"$BIN" ctl db-backup "$DB" "$out"

# Rotate: delete everything older than the newest $RETENTION.
ls -1t "$DIR"/partout.db.*.bak 2>/dev/null | tail -n +$((RETENTION + 1)) | while read -r old; do
    rm -f -- "$old"
done

echo "backup: $out (keeping $RETENTION)"
