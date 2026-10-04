#!/usr/bin/env bash
# install-server.sh — idempotent day-1 bootstrap for the partout SERVER.
#
# One command takes a Linux box from "I have a binary" to "healthy control
# plane with a backup timer", automating the deploy/systemd/README.md manual
# steps (the DEPLOYMENT_FEEDBACK.md C9 ask):
#
#   preflight   root (or test mode), binary runs + reports its version,
#               repo units/backup script locatable, systemd present
#   early-out   service already active AND healthy AND same binary version
#               -> "already installed", no changes, exit 0
#   binary      install to /usr/local/bin/partout (0755); a DIFFERENT version
#               under a RUNNING service is refused (point at update-server.sh
#               — the supervised swap is the update path, not this script)
#   user+dirs   partout system user, /var/lib/partout (0750), /etc/partout,
#               the file root /home/partout (0750, docs/spec-file-root.md)
#   env         /etc/partout/server.env — created ONLY when missing (it holds
#               operator secrets; re-runs never clobber it)
#   units       partout-server.service + partout-backup.{service,timer} ->
#               /etc/systemd/system (an operator-modified unit is kept as
#               *.partout-orig); --port/--db non-defaults rewrite ExecStart
#   backup      scripts/backup.sh -> /usr/local/sbin/partout-backup.sh
#   doctor      the REAL pre-flight against the effective config, before
#               anything is started (a hard failure aborts the install)
#   start       daemon-reload; enable --now server + backup timer
#   verify      /healthz polls up to 30 s; prints the summary block (URL,
#               password source, generated token, TLS posture, next steps)
#
# Test mode: PARTOUT_INSTALL_TEST_ROOT=<dir> prefixes every system path
# (etc/var/usr/home), skips the root check, user/group creation, and chown,
# and expects systemctl to be a harness-provided mock — used by
# scripts/install-server-test.sh to verify the real layout + a real server
# start from the installed artifacts without needing root or real systemd.
#
# Usage:
#   sudo bash scripts/install-server.sh --binary /path/to/partout [options]
#     --binary PATH        partout binary to install (default: ./partout)
#     --port N             listen port (default 8443; rewrites the unit)
#     --db PATH            SQLite path (default /var/lib/partout/partout.db)
#     --addr ADDR          bind address (default all interfaces; PARTOUT_ADDR)
#     --file-root PATH     agent file-surface root (default /home/partout)
#     --tls on|off         TLS (default off; local root CA bootstrap when on)
#     --tls-names LIST     SANs when TLS is on (PARTOUT_TLS_SERVER_NAMES)
#     --admin-password P   web-UI admin password (default: generated into
#                          <db dir>/admin_password.txt on first server run)
#     --token-admin T      static admin bearer token (default: generated,
#                          printed once in the summary)
#     --token-operator T   static operator token (optional)
#     --token-viewer T     static viewer token (optional)
#     --deploy-dir DIR     unit source dir (default: <repo>/deploy/systemd)
#     --dry-run            print the plan, touch nothing
#
# Removal is `partout uninstall` (deployment §3.11): stop + units + env +
# binary, state kept; --purge also removes state + the partout user.

set -euo pipefail

BIN_SRC="./partout"
PORT=8443
DB="/var/lib/partout/partout.db"
ADDR=""
FILE_ROOT="/home/partout"
TLS="off"
TLS_NAMES=""
ADMIN_PASSWORD=""
TOKEN_ADMIN=""
TOKEN_OPERATOR=""
TOKEN_VIEWER=""
DEPLOY_DIR=""
DRY_RUN=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="${PARTOUT_INSTALL_TEST_ROOT:-}"

usage() { grep '^#   sudo bash\|^#     --' "$0" | sed 's/^# \{0,3\}//'; exit 2; }

# The release bundle ships the binary next to the installer; default to it
# when present (the repo layout keeps ./partout).
[ -x "$SCRIPT_DIR/partout" ] && BIN_SRC="$SCRIPT_DIR/partout"

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BIN_SRC="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --db) DB="$2"; shift 2;;
    --addr) ADDR="$2"; shift 2;;
    --file-root) FILE_ROOT="$2"; shift 2;;
    --tls) TLS="$2"; shift 2;;
    --tls-names) TLS_NAMES="$2"; shift 2;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2;;
    --token-admin) TOKEN_ADMIN="$2"; shift 2;;
    --token-operator) TOKEN_OPERATOR="$2"; shift 2;;
    --token-viewer) TOKEN_VIEWER="$2"; shift 2;;
    --deploy-dir) DEPLOY_DIR="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage;;
    *) echo "install-server: unknown flag: $1" >&2; usage;;
  esac
done

# ---------------------------------------------------------------------------
# paths (test-root aware)
# ---------------------------------------------------------------------------

# p <system path> -> the same path under the test root in test mode.
p() {
  if [ -n "$TEST_ROOT" ]; then printf '%s%s' "$TEST_ROOT" "$1"; else printf '%s' "$1"; fi
}

BIN_INSTALL="$(p /usr/local/bin/partout)"
ETC_DIR="$(p /etc/partout)"
ENV_FILE="$ETC_DIR/server.env"
VAR_DIR="$(p /var/lib/partout)"
FILE_ROOT_P="$(p "$FILE_ROOT")"
UNIT_DIR="$(p /etc/systemd/system)"
BACKUP_INSTALL="$(p /usr/local/sbin/partout-backup.sh)"
DB_P="$(p "$DB")" # the path the doctor call and summary show

# Deploy dir + backup script resolve next to the installer first (the
# release's installer BUNDLE layout: install-server.sh + backup.sh +
# systemd/ side by side), then the repo layout — so the bundle works with
# zero flags and a repo checkout keeps working.
[ -n "$DEPLOY_DIR" ] || DEPLOY_DIR="$SCRIPT_DIR/systemd"
[ -d "$DEPLOY_DIR" ] || DEPLOY_DIR="$SCRIPT_DIR/../deploy/systemd"
BACKUP_SRC="$SCRIPT_DIR/backup.sh"
[ -f "$BACKUP_SRC" ] || BACKUP_SRC="$SCRIPT_DIR/scripts/backup.sh"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

step() { printf '  %-10s %s\n' "$1" "$2"; }
ok()   { printf '  %-10s %s\n' ok "$1"; }
warn() { printf '  %-10s %s\n' WARN "$1"; }
fail() { printf '  %-10s %s\n' FAIL "$1" >&2; exit 1; }

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 24
  else od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; fi
}

http_get() { # <url> -> body on stdout, non-zero on connection failure
  if command -v curl >/dev/null 2>&1; then curl -sf --max-time 3 "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O - -T 3 "$1"
  else return 127; fi
}

service_active() { systemctl is-active --quiet partout-server.service 2>/dev/null; }

healthz() {
  local scheme="http" body url
  [ "$TLS" = "on" ] && scheme="https"
  url="$scheme://127.0.0.1:$PORT/healthz"
  # TLS installs serve a self-signed local-CA cert: skip verification for
  # this localhost probe (field feedback F2: the probe failed cert
  # verification and reported a healthy server as "did not answer").
  if command -v curl >/dev/null 2>&1; then
    body="$(curl -sf --max-time 3 -k "$url" 2>/dev/null)" || return 1
  elif command -v wget >/dev/null 2>&1; then
    if [ "$scheme" = "https" ]; then
      body="$(wget -q -O - -T 3 --no-check-certificate "$url" 2>/dev/null)" || return 1
    else
      body="$(wget -q -O - -T 3 "$url" 2>/dev/null)" || return 1
    fi
  else
    return 127
  fi
  printf '%s' "$body" | grep -q '"status"'
}

bin_version() { "$1" --version 2>/dev/null | awk '{print $2}'; }

run() { # dry-run aware executor
  if [ "$DRY_RUN" -eq 1 ]; then printf '  %-10s %s\n' would "$*"; else "$@"; fi
}

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

[ -f "$BIN_SRC" ] && [ -x "$BIN_SRC" ] || fail "binary not found/executable: $BIN_SRC (build: go build -o partout ./cmd/partout)"
BIN_VERSION="$(bin_version "$BIN_SRC")"
[ -n "$BIN_VERSION" ] || fail "binary does not report a version: $BIN_SRC --version"
[ -d "$DEPLOY_DIR" ] || fail "unit source dir not found: $DEPLOY_DIR (use --deploy-dir)"
for u in partout-server.service partout-backup.service partout-backup.timer; do
  [ -f "$DEPLOY_DIR/$u" ] || fail "missing unit in $DEPLOY_DIR: $u"
done
[ -f "$BACKUP_SRC" ] || fail "backup script not found: $BACKUP_SRC"

if [ -z "$TEST_ROOT" ] && [ "$(id -u)" -ne 0 ]; then
  [ "$DRY_RUN" -eq 1 ] || fail "must run as root (or set PARTOUT_INSTALL_TEST_ROOT)"
fi
if [ -z "$TEST_ROOT" ] && [ "$DRY_RUN" -eq 0 ] && ! command -v systemctl >/dev/null 2>&1; then
  fail "systemctl not found — this script installs systemd units (manual path: deploy/systemd/README.md)"
fi

echo "install-server: partout $BIN_VERSION -> $BIN_INSTALL $( [ -n "$TEST_ROOT" ] && echo "[test root: $TEST_ROOT]" || true )"
[ "$DRY_RUN" -eq 1 ] && echo "  (dry run — nothing below is executed)"

# ---------------------------------------------------------------------------
# early-out: already installed, healthy, same version
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" -eq 0 ] && service_active && healthz; then
  INSTALLED_V="$(bin_version "$BIN_INSTALL" 2>/dev/null || true)"
  if [ "$INSTALLED_V" = "$BIN_VERSION" ]; then
    ok "partout-server already active and healthy at $BIN_VERSION — nothing to do"
    exit 0
  fi
  fail "installed binary is ${INSTALLED_V:-unknown}, --binary is $BIN_VERSION, and the service is running — use scripts/update-server.sh (supervised swap with rollback), not this script"
fi

# ---------------------------------------------------------------------------
# binary
# ---------------------------------------------------------------------------

if [ -x "$BIN_INSTALL" ]; then
  INSTALLED_V="$(bin_version "$BIN_INSTALL")"
  if [ "$INSTALLED_V" != "$BIN_VERSION" ]; then
    if service_active; then
      fail "installed binary is $INSTALLED_V, --binary is $BIN_VERSION, and the service is running — use scripts/update-server.sh (supervised swap with rollback), not this script"
    fi
    warn "replacing binary $INSTALLED_V -> $BIN_VERSION (service not running)"
  fi
fi
step binary "$BIN_SRC ($BIN_VERSION)"
run mkdir -p "$(dirname "$BIN_INSTALL")"
run install -m 0755 "$BIN_SRC" "$BIN_INSTALL"

# ---------------------------------------------------------------------------
# user + directories
# ---------------------------------------------------------------------------

if [ -n "$TEST_ROOT" ]; then
  step user "test mode — user/group creation and chown skipped"
else
  if ! getent group partout >/dev/null 2>&1; then
    step group "creating system group partout"
    run groupadd --system partout
  fi
  if ! getent passwd partout >/dev/null 2>&1; then
    step user "creating system user partout (nologin, home $VAR_DIR)"
    # -g partout: the group was just created above; without it, useradd
    # tries to create a same-named primary group, which fails on
    # RHEL-family ("group partout exists") and aborts the install
    # (field feedback F1).
    run useradd --system --home-dir "$VAR_DIR" --shell /usr/sbin/nologin -g partout partout
  fi
fi

for d in "$VAR_DIR" "$(dirname "$DB_P")" "$ETC_DIR" "$(dirname "$FILE_ROOT_P")" "$UNIT_DIR" "$(dirname "$BACKUP_INSTALL")"; do
  if [ ! -d "$d" ]; then step dir "mkdir $d"; run mkdir -p "$d"; fi
done

if [ -n "$TEST_ROOT" ]; then
  step perms "test mode — chmod/ownership of $VAR_DIR and $FILE_ROOT_P skipped"
else
  run chown partout:partout "$VAR_DIR"
  run chmod 0750 "$VAR_DIR"
  if [ ! -d "$FILE_ROOT_P" ]; then
    step dir "mkdir $FILE_ROOT_P (file root, docs/spec-file-root.md)"
    run mkdir -p "$FILE_ROOT_P"
  fi
  # The root's OWN mode/owner only — never touch operator files inside it.
  run chown partout:partout "$FILE_ROOT_P"
  run chmod 0750 "$FILE_ROOT_P"
fi

# ---------------------------------------------------------------------------
# server.env — created ONLY when missing (operator secrets live here)
# ---------------------------------------------------------------------------

GEN_TOKEN=0
if [ ! -f "$ENV_FILE" ]; then
  if [ -z "$TOKEN_ADMIN" ]; then
    TOKEN_ADMIN="$(rand_hex)"
    GEN_TOKEN=1
  fi
  step env "writing $ENV_FILE$( [ "$GEN_TOKEN" -eq 1 ] && echo ' (admin token generated)' )"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  %-10s %s\n' would "write env (0600, root:root) with TLS=$TLS$( [ -n "$ADDR" ] && echo ", ADDR=$ADDR" )"
  else
    {
      echo "# Partout server runtime environment (loaded by partout-server.service)."
      echo "# Generated by scripts/install-server.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)."
      echo "# Edit freely — re-runs of the installer never overwrite this file."
      echo ""
      [ -n "$ADDR" ] && echo "PARTOUT_ADDR=$ADDR"
      echo "PARTOUT_TLS=$TLS"
      [ -n "$TLS_NAMES" ] && echo "PARTOUT_TLS_SERVER_NAMES=$TLS_NAMES"
      [ -n "$ADMIN_PASSWORD" ] && echo "PARTOUT_ADMIN_PASSWORD=\"$ADMIN_PASSWORD\""
      echo "PARTOUT_TOKEN_ADMIN=$TOKEN_ADMIN"
      [ -n "$TOKEN_OPERATOR" ] && echo "PARTOUT_TOKEN_OPERATOR=$TOKEN_OPERATOR"
      [ -n "$TOKEN_VIEWER" ] && echo "PARTOUT_TOKEN_VIEWER=$TOKEN_VIEWER"
    } > "$ENV_FILE.tmp.$$"
    install -m 0600 "$ENV_FILE.tmp.$$" "$ENV_FILE"
    rm -f "$ENV_FILE.tmp.$$"
    [ -n "$TEST_ROOT" ] || chown root:root "$ENV_FILE"
  fi
else
  ok "env exists — kept ($ENV_FILE holds operator secrets; edit it directly)"
fi

# ---------------------------------------------------------------------------
# units + backup script
# ---------------------------------------------------------------------------

step units "$DEPLOY_DIR -> $UNIT_DIR"
for u in partout-server.service partout-backup.service partout-backup.timer; do
  src="$DEPLOY_DIR/$u"; dst="$UNIT_DIR/$u"; tmp="$(mktemp)"
  cp "$src" "$tmp"
  # Non-default port/db rewrite the unit's ExecStart (the defaults match the
  # shipped template, so a default install rewrites nothing).
  [ "$PORT" = "8443" ] || sed -i "s/--port=8443/--port=$PORT/" "$tmp"
  [ "$DB" = "/var/lib/partout/partout.db" ] || sed -i "s|--db=/var/lib/partout/partout.db|--db=$DB|" "$tmp"
  # Test mode: every system path inside the units points under the test root.
  if [ -n "$TEST_ROOT" ]; then
    sed -i -e "s|/usr/local/bin/partout|$BIN_INSTALL|g" \
           -e "s|/etc/partout|$ETC_DIR|g" \
           -e "s|/var/lib/partout|$VAR_DIR|g" \
           -e "s|/usr/local/sbin/partout-backup.sh|$BACKUP_INSTALL|g" \
           -e "s|/home/partout|$FILE_ROOT_P|g" \
           -e "s|--db=$DB|--db=$DB_P|" "$tmp"
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '  %-10s %s\n' would "install $u -> $dst"
  else
    if [ -f "$dst" ] && ! cmp -s "$tmp" "$dst"; then
      cp -a "$dst" "$dst.partout-orig"
      warn "existing $u differed — saved as $u.partout-orig"
    fi
    install -m 0644 "$tmp" "$dst"
  fi
  rm -f "$tmp"
done

step backup "$BACKUP_SRC -> $BACKUP_INSTALL"
run install -m 0755 "$BACKUP_SRC" "$BACKUP_INSTALL"

# ---------------------------------------------------------------------------
# doctor — the real pre-flight against the effective config
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" -eq 1 ]; then
  step doctor "would run: $BIN_INSTALL doctor --port $PORT --db $DB_P --tls $TLS"
else
  step doctor "pre-flight against the effective config"
  DOCTOR_ARGS=(--port "$PORT" --db "$DB_P" --tls "$TLS")
  [ -n "$ADDR" ] && DOCTOR_ARGS+=(--addr "$ADDR")
  # --env-file: doctor sees the same PARTOUT_* the service will (TLS SAN
  # names, admin password, tokens) — field feedback F3: the pre-flight
  # used to check a different config than the one it just wrote.
  [ -f "$ENV_FILE" ] && DOCTOR_ARGS+=(--env-file "$ENV_FILE")
  if ! "$BIN_INSTALL" doctor "${DOCTOR_ARGS[@]}"; then
    fail "doctor reported a hard failure — fix it and re-run (nothing has been started)"
  fi
fi

# ---------------------------------------------------------------------------
# start + verify
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" -eq 1 ]; then
  step start "would: systemctl daemon-reload; enable --now partout-server.service; enable --now partout-backup.timer"
  echo
  echo "install-server: dry run complete — nothing was changed"
  exit 0
fi

step start "daemon-reload + enable --now partout-server.service"
systemctl daemon-reload
systemctl enable --now partout-server.service

step start "enable --now partout-backup.timer (daily 03:00, Persistent)"
systemctl enable --now partout-backup.timer

step verify "waiting for /healthz on port $PORT"
healthy=0
for _ in $(seq 1 30); do
  if healthz; then healthy=1; break; fi
  sleep 1
done
[ "$healthy" -eq 1 ] || fail "server did not answer /healthz within 30s — check: journalctl -u partout-server.service -n 50"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

scheme="http"; [ "$TLS" = "on" ] && scheme="https"
DB_SHOWN="$DB_P"
echo
echo "──────────────────────────────────────────────────────────────────────"
echo " Partout $BIN_VERSION installed and healthy."
echo
echo "   UI        $scheme://$(hostname 2>/dev/null || echo localhost):$PORT/   (sign in as 'admin')"
if [ -n "$ADMIN_PASSWORD" ]; then
  echo "   Password  set via --admin-password"
else
  echo "   Password  generated into $(dirname "$DB_SHOWN")/admin_password.txt (0600) —"
  echo "             log in, change it, then delete the file"
fi
if [ "$GEN_TOKEN" -eq 1 ]; then
  echo "   CLI token PARTOUT_TOKEN_ADMIN=$TOKEN_ADMIN   (generated; also in $ENV_FILE)"
fi
if [ "$TLS" = "on" ]; then
  echo "   TLS       on — agents need the CA: partout ctl --server <host:$PORT> --token \$ADMIN ca"
else
  echo "   TLS       off — plain HTTP. If this binds beyond loopback, set"
  echo "             PARTOUT_TLS=on in $ENV_FILE and restart (partout doctor warns)."
fi
echo "   Backup    daily 03:00 into $VAR_DIR/backups (partout-backup.timer)"
echo
echo " Provisioning needs PARTOUT_SERVER_HOST (the address new agents dial;"
echo "             the hostname default only works when every target resolves it) —"
echo "             set it in $ENV_FILE when provisioning remote hosts."
echo " Next: onboard a host (UI: Fleet → + Add host), review the preset"
echo " guardrails (Policies / Alerts). Walkthrough: docs/getting-started.md"
echo " Remove: partout uninstall (--dry-run previews; --purge removes state)"
echo "──────────────────────────────────────────────────────────────────────"
