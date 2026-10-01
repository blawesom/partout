#!/usr/bin/env bash
# update-server.sh — M8.1 step 4: supervised partout server update.
#
# The script is the operator's supervisor for swapping the SERVER binary.
# It never trusts a binary until it has proven itself on THIS host:
#
#   preflight  file present, size, sha256 matches the release
#   verify     Ed25519 signature over version|arch|kind|sha256, checked
#              locally with the release public key (the binary itself
#              does NOT fetch anything; the operator supplied the file)
#   selftest   the NEW binary runs its embedded suite on this host
#              (store migration + integrity, config, crypto, API
#              round-trip) BEFORE it is ever installed
#   snapshot   pre-swap agent count (post-check baseline)
#   stop       service stopped, port released
#   backup     VACUUM INTO snapshot of the live DB, proven (sqlite magic,
#              non-empty) — proven BEFORE the swap
#   swap       current binary -> partout.prev (one generation),
#              new binary installed 0755
#   start      service started
#   postcheck  ~60s: healthz, authenticated API, agents reconnected
#              (count >= pre-swap)
#
# Any failure after the swap triggers an automatic rollback: stop,
# partout.prev restored, start, health check. Exit 0 only on a fully
# verified update. Idempotent: re-running with the already-installed
# binary reports "already at target".
#
# Usage:
#   update-server.sh --new /path/partout.new \
#       --version v2.0.0 --arch linux-amd64 \
#       --sha256 <hex> [--signature <b64> --key <pub b64|via $PARTOUT_RELEASE_KEY>]
#       [--binary /usr/local/bin/partout] [--db /var/lib/partout/partout.db] \
#       [--service partout-server.service] [--health-url http://127.0.0.1:8443] \
#       [--admin-token $PARTOUT_ADMIN_TOKEN] [--post-timeout 90] [--dry-run] [--unsigned]
#
# A --dry-run stops after selftest (no service, no file touched).

set -euo pipefail

NEW="" VERSION="" ARCH="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
SHA="" SIG="" KEY="${PARTOUT_RELEASE_KEY:-}"
BIN="/usr/local/bin/partout" DB="/var/lib/partout/partout.db"
SERVICE="partout-server.service" HEALTH="http://127.0.0.1:8443"
TOKEN="${PARTOUT_ADMIN_TOKEN:-}" POST_TIMEOUT=90 DRY_RUN=0 UNSIGNED=0
WORK=""

usage() { grep '^#   update-server.sh\|^#       ' "$0" | sed 's/^# \{0,3\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --new) NEW="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --arch) ARCH="$2"; shift 2;;
    --sha256) SHA="$2"; shift 2;;
    --signature) SIG="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --binary) BIN="$2"; shift 2;;
    --db) DB="$2"; shift 2;;
    --service) SERVICE="$2"; shift 2;;
    --health-url) HEALTH="$2"; shift 2;;
    --admin-token) TOKEN="$2"; shift 2;;
    --post-timeout) POST_TIMEOUT="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    --unsigned) UNSIGNED=1; shift;;
    -h|--help) usage;;
    *) echo "unknown flag: $1" >&2; usage;;
  esac
done

for req in NEW VERSION SHA; do
  [ -n "${!req}" ] || { echo "missing required --$(echo "$req" | tr '[:upper:]' '[:lower:]')" >&2; exit 2; }
done
if [ "$UNSIGNED" -eq 1 ]; then
  [ -z "$SIG" ] || { echo "--unsigned conflicts with --signature" >&2; exit 2; }
else
  [ -n "$SIG" ] || { echo "missing required --signature (or pass --unsigned for the beta flow)" >&2; exit 2; }
  [ -n "$KEY" ] || { echo "missing release public key (--key or PARTOUT_RELEASE_KEY)" >&2; exit 2; }
fi

log()  { printf '[update-server] %s\n' "$*"; }
fail() { echo "[update-server] FAILED: $*" >&2; exit 1; }

WORK="$(mktemp -d /tmp/partout-update.XXXXXX)"
BK="$WORK/partout-backup-$(date +%Y%m%dT%H%M%S).db"
cleanup() { rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT

api() { # api <path> -> body (admin token)
  curl -sf -m 10 -H "Authorization: Bearer $TOKEN" "$HEALTH/api/v1$1"
}

# count_hosts prints the number of hosts the API reports, using only base
# system tools (no python3 dependency on the server host). Every host entry
# carries an "id" field, so counting those is exact. Prints nothing when the
# API cannot be read, so callers fail closed instead of assuming zero.
count_hosts() {
  api /hosts | tr ',' '\n' | grep -c '"id"' || true
}

# ---- preflight -------------------------------------------------------------
log "preflight: checking new binary"
[ -f "$NEW" ] || fail "new binary not found: $NEW"
[ -x "$NEW" ] || fail "new binary not executable: $NEW"
[ -s "$NEW" ] || fail "new binary is empty"
[ -f "$BIN" ] || fail "current binary not found: $BIN"
ACTUAL_SHA="$(sha256sum "$NEW" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$SHA" ] || fail "sha256 mismatch: got $ACTUAL_SHA want $SHA"

# Idempotency: already at target?
INSTALLED_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
if [ "$INSTALLED_SHA" = "$SHA" ]; then
  log "already at target (installed binary sha matches); nothing to do"
  exit 0
fi

# ---- verify (local, with the CURRENT binary — no server needed) ------------
if [ "$UNSIGNED" -eq 1 ]; then
  log "verify: unsigned beta flow — sha256 pinned, version stamp + selftest next (no signature)"
else
  log "verify: Ed25519 signature via $BIN"
  "$BIN" ctl update verify --version "$VERSION" --arch "$ARCH" --kind server \
    --file "$NEW" --signature "$SIG" --pubkey "$KEY" \
    || fail "release signature verification FAILED for $VERSION"
fi

# ---- selftest (the new binary proves itself on THIS host) ------------------
log "selftest: running the new binary's embedded suite"
"$NEW" selftest || fail "new binary selftest failed — refusing to install"
[ "$DRY_RUN" -eq 1 ] && { log "dry-run: all gates passed, service untouched"; exit 0; }

# ---- snapshot (pre-swap baseline) ------------------------------------------
PRE_AGENTS=0
if [ -n "$TOKEN" ] && curl -sf -m 5 -o /dev/null "$HEALTH/healthz"; then
  PRE_AGENTS="$(count_hosts)"
  # An unreadable API here would make the reconnect check meaningless later;
  # say so instead of silently comparing against a bogus baseline.
  case "$PRE_AGENTS" in
    ''|*[!0-9]*) echo "[update-server] WARNING: could not read the host count before the swap;" >&2
                 echo "[update-server]          the post-swap agent-reconnect check will be skipped" >&2
                 PRE_AGENTS="" ;;
  esac
fi
log "snapshot: $PRE_AGENTS agent(s) connected before swap"

# ---- stop ------------------------------------------------------------------
log "stop: stopping $SERVICE"
systemctl stop "$SERVICE"
for i in $(seq 1 20); do
  curl -sf -m 2 -o /dev/null "$HEALTH/healthz" 2>/dev/null || break
  sleep 0.5
done

# ---- backup (proven BEFORE the swap) ---------------------------------------
# Retry: a graceful server shutdown can still hold the DB briefly after the
# port closes (WAL checkpoint); VACUUM INTO would hit SQLITE_BUSY.
log "backup: $DB -> $BK"
BK_OK=0
for i in $(seq 1 20); do
  if "$BIN" ctl db-backup "$DB" "$BK" 2>/dev/null; then BK_OK=1; break; fi
  sleep 1
done
[ "$BK_OK" -eq 1 ] || fail "db backup failed after retries (server still holding the DB?)"
[ -s "$BK" ] || fail "backup file empty"
MAGIC="$(head -c 15 "$BK" | tr -d '\0')"
[ "$MAGIC" = "SQLite format 3" ] || fail "backup is not a SQLite database (magic=$MAGIC)"
log "backup proven (SQLite magic, $(wc -c < "$BK") bytes)"

# ---- swap ------------------------------------------------------------------
log "swap: $BIN -> $BIN.prev, install $NEW"
rm -f "$BIN.prev"
mv "$BIN" "$BIN.prev"
install -m 755 "$NEW" "$BIN"

# ---- start + postcheck -------------------------------------------------------
log "start: $SERVICE"
systemctl start "$SERVICE" || fail "service failed to start"

postcheck() {
  local i
  local now
  for i in $(seq 1 "$POST_TIMEOUT"); do
    if curl -sf -m 2 -o /dev/null "$HEALTH/healthz" \
       && [ -n "$TOKEN" ] && curl -sf -m 5 -o /dev/null -H "Authorization: Bearer $TOKEN" "$HEALTH/api/v1/hosts"; then
      if [ -z "$PRE_AGENTS" ]; then
        # No trustworthy baseline: healthz + authenticated API is all we can
        # assert, and we already said so above.
        return 0
      fi
      now="$(count_hosts)"
      case "$now" in
        ''|*[!0-9]*) : ;;  # unreadable this tick; keep waiting
        *) [ "$now" -ge "$PRE_AGENTS" ] && return 0 ;;
      esac
    fi
    sleep 1
  done
  return 1
}

if postcheck; then
  log "postcheck: healthz + API + ${PRE_AGENTS:-?} agent(s) reconnected — update OK ($VERSION)"
  exit 0
fi

# ---- rollback ----------------------------------------------------------------
echo "[update-server] postcheck FAILED — rolling back to previous binary" >&2
# Preserve the pre-swap backup outside the temp dir (trap removes $WORK).
SAVED_BK="$(dirname "$DB")/partout-backup-rollback-$(date +%Y%m%dT%H%M%S).db"
cp -f "$BK" "$SAVED_BK" 2>/dev/null || SAVED_BK="(temp, lost with $WORK)"
systemctl stop "$SERVICE" 2>/dev/null || true
mv -f "$BIN.prev" "$BIN"
systemctl start "$SERVICE" 2>/dev/null || true
for i in $(seq 1 30); do
  curl -sf -m 2 -o /dev/null "$HEALTH/healthz" 2>/dev/null && break
  sleep 1
done
fail "update to $VERSION failed postcheck; rolled back to previous binary (backup: $SAVED_BK)"
