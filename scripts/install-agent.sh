#!/usr/bin/env bash
# install-agent.sh — idempotent day-1 bootstrap for a partout AGENT (the
# manual-install path, docs/deployment.md §3.2 — the counterpart of
# install-server.sh; use `partout ctl provision new` when the server can
# SSH to this host).
#
# Installs the M8.1 layout:
#   /var/lib/partout/bin/partout    the binary (AGENT-WRITABLE — the
#                                   self-swap writes .old/.new here)
#   /usr/local/bin/partout          symlink for operators
#   /usr/local/sbin/partout-update-guard  the M8.1 boot guard
#   /etc/partout/agent.env          runtime environment
#   /etc/systemd/system/partout-agent.service (guard as ExecStart)
#
# Usage:
#   sudo bash scripts/install-agent.sh --binary ./partout \
#        --server host:port --token par_enr_…
#
# Options:
#   --binary PATH        partout binary to install (default: ./partout)
#   --server HOST:PORT   the control-plane address the agent dials
#   --token TOKEN        one-time enrollment token (par_enr_…)
#   --ca-file PATH       the server root CA (PEM) — enables HTTPS + mTLS
#   --file-root PATH     agent file-surface root (default /home/partout)
#   --elevate            enable elevation (installs the sudoers drop-in
#                        from the elevation policy at --elevation-policy,
#                        sets PARTOUT_ELEVATE=sudo)
#   --elevation-policy PATH  elevation policy .json (default: none)
#   --dry-run            print the plan, touch nothing
set -euo pipefail

BIN_SRC="./partout"
SERVER=""
TOKEN=""
CA_FILE=""
FILE_ROOT="/home/partout"
ELEVATE=0
ELEVATION_POLICY=""
DRY_RUN=0

usage() { grep '^#   sudo bash\|^#     --' "$0" | sed 's/^# \{0,3\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BIN_SRC="$2"; shift 2;;
    --server) SERVER="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --ca-file) CA_FILE="$2"; shift 2;;
    --file-root) FILE_ROOT="$2"; shift 2;;
    --elevate) ELEVATE=1; shift;;
    --elevation-policy) ELEVATION_POLICY="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage;;
    *) echo "install-agent: unknown flag: $1" >&2; usage;;
  esac
done

step() { printf '  %-10s %s\n' "$1" "$2"; }
ok()   { printf '  %-10s %s\n' ok "$1"; }
warn() { printf '  %-10s %s\n' WARN "$1"; }
fail() { printf '  %-10s %s\n' FAIL "$1" >&2; exit 1; }

run() { if [ "$DRY_RUN" -eq 1 ]; then printf '  %-10s %s\n' would "$*"; else "$@"; fi; }

# ---- preflight --------------------------------------------------------------
[ -f "$BIN_SRC" ] && [ -x "$BIN_SRC" ] || fail "binary not found/executable: $BIN_SRC"
BIN_VERSION="$("$BIN_SRC" --version 2>/dev/null | awk '{print $2}')"
[ -n "$BIN_VERSION" ] || fail "binary does not report a version"
[ -n "$SERVER" ] || fail "--server is required (the control-plane address)"
[ -n "$TOKEN" ] || fail "--token is required (a one-time enrollment token, par_enr_…)"
if [ "$ELEVATE" -eq 1 ] && [ -z "$ELEVATION_POLICY" ]; then
  fail "--elevate requires --elevation-policy (a .json file)"
fi
if [ -n "$CA_FILE" ]; then
  [ -f "$CA_FILE" ] || fail "--ca-file not found: $CA_FILE"
fi

echo "install-agent: partout $BIN_VERSION (agent mode)"
echo "  server=$SERVER file-root=$FILE_ROOT elevate=$ELEVATE"
[ "$DRY_RUN" -eq 1 ] && echo "  (dry run — nothing below is executed)"

# ---- user + directories ------------------------------------------------------
if ! getent group partout >/dev/null 2>&1; then
  step group "creating system group partout"
  run groupadd --system partout
fi
if ! getent passwd partout >/dev/null 2>&1; then
  step user "creating system user partout (nologin, home /var/lib/partout)"
  run useradd --system --home-dir /var/lib/partout --shell /usr/sbin/nologin -g partout partout
fi

step dir "/var/lib/partout/bin (agent-writable — M8.1 self-swap)"
run install -d -m 0750 -o partout -g partout /var/lib/partout/bin
step dir "/var/lib/partout/agent (data)"
run install -d -m 0750 -o partout -g partout /var/lib/partout/agent
step dir "$FILE_ROOT (file root)"
run install -d -m 0750 -o partout -g partout "$FILE_ROOT"
step dir "/etc/partout"
run install -d -m 0755 /etc/partout

# ---- binary (M8.1 layout: agent-writable + symlink) ------------------------
step binary "$BIN_SRC ($BIN_VERSION) -> /var/lib/partout/bin/partout"
run install -m 0755 -o partout -g partout "$BIN_SRC" /var/lib/partout/bin/partout

step symlink "/usr/local/bin/partout -> /var/lib/partout/bin/partout"
run rm -f /usr/local/bin/partout
run ln -s /var/lib/partout/bin/partout /usr/local/bin/partout

# ---- update guard (M8.1 boot guard) -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_SRC=""
for candidate in "$SCRIPT_DIR/../deploy/systemd/partout-update-guard.sh" \
                "$SCRIPT_DIR/deploy/systemd/partout-update-guard.sh" \
                "$SCRIPT_DIR/partout-update-guard.sh" \
                "/usr/local/sbin/partout-update-guard"; do
  [ -f "$candidate" ] && GUARD_SRC="$candidate" && break
done
if [ -n "$GUARD_SRC" ]; then
  step guard "$GUARD_SRC -> /usr/local/sbin/partout-update-guard"
  run install -m 0755 -o root -g root "$GUARD_SRC" /usr/local/sbin/partout-update-guard
else
  warn "partout-update-guard.sh not found (looked next to the script and in deploy/systemd/) — M8.1 rollback will not be available"
fi

# ---- agent.env --------------------------------------------------------------
step env "/etc/partout/agent.env"
if [ "$DRY_RUN" -eq 0 ]; then
  {
    echo "PARTOUT_MODE=agent"
    echo "PARTOUT_SERVER=$SERVER"
    echo "PARTOUT_TOKEN=$TOKEN"
    echo "PARTOUT_DATA_DIR=/var/lib/partout/agent"
    [ -n "$CA_FILE" ] && echo "PARTOUT_TLS_CA=/etc/partout/ca.crt"
    if [ "$ELEVATE" -eq 1 ]; then
      echo "PARTOUT_ELEVATE=sudo"
      echo "PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d"
    fi
  } > /etc/partout/agent.env
  chmod 0640 /etc/partout/agent.env
fi

# ---- CA ---------------------------------------------------------------------
if [ -n "$CA_FILE" ] && [ "$DRY_RUN" -eq 0 ]; then
  step ca "$CA_FILE -> /etc/partout/ca.crt"
  install -m 0644 "$CA_FILE" /etc/partout/ca.crt
fi

# ---- elevation (optional) ----------------------------------------------------
if [ "$ELEVATE" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  step elevation "installing policy + sudoers"
  install -d -m 0755 /etc/partout/elevation.d
  install -m 0644 -o root -g root "$ELEVATION_POLICY" /etc/partout/elevation.d/10-policy.json
  PARTOUT_ELEVATION_POLICY=/etc/partout/elevation.d /usr/local/bin/partout ctl elevation install-sudoers || {
    fail "elevation: install-sudoers failed (bad policy?)"
  }
fi

# ---- systemd unit -----------------------------------------------------------
step unit "partout-agent.service (guard as ExecStart)"
if [ "$DRY_RUN" -eq 0 ]; then
  cat > /etc/systemd/system/partout-agent.service <<'EOF'
[Unit]
Description=Partout host agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=partout
EnvironmentFile=/etc/partout/agent.env
Environment=PARTOUT_AGENT_DATA_DIR=/var/lib/partout/agent
Environment=PARTOUT_GUARD_BIN=/var/lib/partout/bin/partout
ExecStart=/usr/local/sbin/partout-update-guard
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
fi

# ---- start ------------------------------------------------------------------
step start "daemon-reload + enable --now partout-agent"
if [ "$DRY_RUN" -eq 0 ]; then
  systemctl daemon-reload
  systemctl enable --now partout-agent
fi

step verify "waiting for the agent to connect (check the server's Fleet page)"
if [ "$DRY_RUN" -eq 0 ]; then
  healthy=0
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet partout-agent 2>/dev/null; then
      healthy=1; break
    fi
    sleep 1
  done
  [ "$healthy" -eq 1 ] || warn "agent service not active after 30s — check: journalctl -u partout-agent -n 50"
fi

echo
echo "──────────────────────────────────────────────────────────────────────"
echo " Partout agent $BIN_VERSION installed."
echo "   The host should appear on the server's Fleet page within ~10 s."
echo "   Logs: journalctl -u partout-agent -f"
echo "   Remove: partout uninstall (--purge also removes state)"
echo "──────────────────────────────────────────────────────────────────────"
