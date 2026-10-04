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

# Retry on SQLITE_BUSY (field feedback F15): the backup timer fires the
# moment it is enabled, which can race the server's boot migrations — one
# failing unit + a critical service_failed alert on a fresh install. A
# short lock wait + retry closes the window.
backup_once() {
    "$BIN" ctl db-backup "$DB" "$out"
}
tries=0
until backup_once; do
    tries=$((tries + 1))
    if [ "$tries" -ge 10 ]; then
        echo "backup: db locked after $tries attempts: $out" >&2
        exit 1
    fi
    sleep 3
done

# Rotate: delete everything older than the newest $RETENTION.
ls -1t "$DIR"/partout.db.*.bak 2>/dev/null | tail -n +$((RETENTION + 1)) | while read -r old; do
    rm -f -- "$old"
done

echo "backup: $out (keeping $RETENTION)"
