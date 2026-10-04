#!/usr/bin/env bash
# beta-gate — the one-command pre-release battery. Runs every quality leg
# that exists for this repo, in order cheap → expensive, continues on
# failure, and prints a verdict table. Exit 0 only when every leg that ran
# is green (skips don't fail the gate but are listed, loudly).
#
# Legs: unit tests + gofmt, license/config-doc lints, UI smoke (jsdom, real
# embedded server), install + update harnesses, backup-restore, offline
# dispatch, TLS rotation, real-systemd self-update, full `partout update`
# E2E. The fleet-provision E2E needs two real SSH hosts — opt in with
# PARTOUT_GATE_FLEET=1 (plus its own env).
#
# Usage: scripts/beta-gate.sh [leg-name-filter]
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
export PATH="$PATH:/usr/local/go/bin"

FILTER="${1:-}"

pass=0; fail=0; skip=0
declare -a ROWS

run_leg() {
  local name="$1" needs="$2" cmd="$3"
  if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then return; fi
  if [ -n "$needs" ] && ! command -v "$needs" >/dev/null 2>&1; then
    skip=$((skip+1)); ROWS+=("SKIP  $name (missing: $needs)")
    return
  fi
  local log; log="$(mktemp /tmp/partout-gate-XXXXXX.log)"
  local t0 t1; t0=$(date +%s)
  if bash -c "$cmd" >"$log" 2>&1; then
    t1=$(( $(date +%s) - t0 )); pass=$((pass+1))
    ROWS+=("PASS  $name (${t1}s)")
  else
    t1=$(( $(date +%s) - t0 )); fail=$((fail+1))
    ROWS+=("FAIL  $name (${t1}s) — log: $log")
    echo "==== $name FAILED (tail below; full log: $log) ====" >&2
    tail -25 "$log" >&2
    return
  fi
  rm -f "$log"
}

echo "partout beta gate — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "===================================================="

# --- static + unit ---
run_leg "go test"        "go"   "go test ./..."
run_leg "gofmt"          "go"   "test -z \"\$(gofmt -l internal cmd)\""
run_leg "check-licenses" ""     "bash scripts/check-licenses.sh"
run_leg "check-config-docs" ""  "bash scripts/check-config-docs.sh"

# --- UI + install/update harnesses (no root, no real systemd) ---
run_leg "ui-smoke"         "node" "bash scripts/ui-smoke.sh"
run_leg "install-server"    "go"   "bash scripts/install-server-test.sh"
run_leg "update-server"     "go"   "bash scripts/update-server-test.sh"

# --- functional E2Es (local processes) ---
run_leg "backup-restore"   "" "bash scripts/backup-restore-e2e.sh"
run_leg "offline-dispatch"  "" "bash scripts/offline-dispatch-e2e.sh"
run_leg "tls-rotation"      "" "bash scripts/tls-rotation-e2e.sh"

# --- RHEL-family real-install leg (skips on non-RHEL dev boxes; the CI
# rocky container job runs it on every push) ---
if command -v dnf >/dev/null 2>&1; then
  run_leg "rocky-e2e" "" "bash scripts/rocky-e2e.sh"
else
  skip=$((skip+1)); ROWS+=("SKIP  rocky-e2e (RHEL-family host or the CI container job)")
fi

# --- real-systemd legs (systemd as PID 1 + passwordless sudo) ---
if [ -d /run/systemd/system ] && sudo -n true >/dev/null 2>&1; then
  run_leg "systemd-e2e"    "" "bash scripts/systemd-e2e.sh"
  run_leg "update-e2e"     "" "bash scripts/update-e2e.sh"
else
  skip=$((skip+1)); ROWS+=("SKIP  systemd-e2e + update-e2e (need systemd as PID 1 + passwordless sudo)")
fi

# --- opt-in: needs two real SSH hosts (see scripts/fleet-provision-e2e.sh) ---
if [ "${PARTOUT_GATE_FLEET:-0}" = "1" ]; then
  run_leg "fleet-provision" "" "bash scripts/fleet-provision-e2e.sh"
else
  skip=$((skip+1)); ROWS+=("SKIP  fleet-provision (opt-in: PARTOUT_GATE_FLEET=1)")
fi

echo
echo "===================================================="
printf '%s\n' "${ROWS[@]}"
echo "===================================================="
if [ "$fail" -gt 0 ]; then
  echo "beta gate: $fail FAILED, $pass passed, $skip skipped — NOT ready"
  exit 1
fi
echo "beta gate: $pass passed, $skip skipped — ready"
exit 0
