#!/usr/bin/env bash
# Multi-machine fleet provisioning E2E (opt-in, real-environment).
#
# Provisions TWO distinct hosts over SSH in parallel (fresh mode — destructive
# wipe + reinstall + re-enroll), confirms the host-key gate for each, and waits
# until both reach "connected". This exercises the multi-run fleet
# orchestration (concurrent provision runs, per-run key-confirm gates, SSE).
#
# Requires 2+ real, reachable, systemd hosts the operator's SSH key can reach
# with NOPASSWD sudo. Loopback does NOT work: both "hosts" would be the same
# machine and collide on /usr/local/bin/partout + the partout-agent unit.
#
# Usage:
#   FLEET_HOST1='root@10.0.0.11' FLEET_HOST2='root@10.0.0.12' \
#     PARTOUT_SERVER_ADVERTISE=10.0.0.5:8443 \
#     bash scripts/fleet-provision-e2e.sh
#
#   FLEET_HOST1 / FLEET_HOST2   : SSH targets (user@host) for the two machines
#   PARTOUT_SERVER_ADVERTISE     : address the new agents use to reach the
#                                  server (PARTOUT_SERVER). Default 127.0.0.1:PORT
#                                  (only useful when the hosts are this box).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:/usr/local/go/bin"

HOST1="${FLEET_HOST1:?set FLEET_HOST1=user@host}"
HOST2="${FLEET_HOST2:?set FLEET_HOST2=user@host}"
if [ "$HOST1" = "$HOST2" ]; then
  echo "FLEET_HOST1 and FLEET_HOST2 must be different machines" >&2
  exit 2
fi

WORK=$(mktemp -d /tmp/partout-fleet-XXXXXX)
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
PORT=$((22000 + RANDOM % 15000))
ADMIN='fleet-e2e-token'
SERV_ADVERTISE="${PARTOUT_SERVER_ADVERTISE:-127.0.0.1:$PORT}"
go build -o "$WORK/partout" ./cmd/partout

# ---- server (plaintext) ----
env PARTOUT_MODE=server PARTOUT_PORT="$PORT" PARTOUT_DB_PATH="$WORK/p.db" \
  PARTOUT_ADMIN_PASSWORD='change-me-123' PARTOUT_TOKEN_ADMIN="$ADMIN" \
  "$WORK/partout" >"$WORK/srv.log" 2>&1 &
SRV_PID=$!
BASE="http://127.0.0.1:$PORT"
for i in $(seq 1 40); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
api() { curl -s -H "Authorization: Bearer $ADMIN" "$@"; }

# start_run <host> -> prints run id
start_run() {
  api -X POST -H 'Content-Type: application/json' \
    -d "{\"host\":\"$1\",\"mode\":\"fresh\"}" "$BASE/api/v1/provision-runs" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])'
}
# confirm_key <run_id>: wait for key_confirm, then confirm
confirm_key() {
  local rid="$1" st
  for i in $(seq 1 120); do
    st=$(api "$BASE/api/v1/provision-runs/$rid" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)
    case "$st" in
      key_confirm) api -X POST "$BASE/api/v1/provision-runs/$rid/key" >/dev/null; echo "  key confirmed"; return 0;;
      failed|cancelled|connected|handoff) echo "  run left key_confirm early (state=$st)"; return 1;;
    esac
    sleep 0.5
  done
  echo "  timeout waiting for key_confirm"; return 1
}
# wait_state <run_id> <want> : poll until the run reaches <want>
wait_state() {
  local rid="$1" want="$2" st
  for i in $(seq 1 240); do
    st=$(api "$BASE/api/v1/provision-runs/$rid" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true)
    [ "$st" = "$want" ] && { echo "  $rid -> $st"; return 0; }
    case "$st" in failed|cancelled|handoff) echo "  $rid ended $st (wanted $want)"; return 1;; esac
    sleep 1
  done
  echo "  timeout: $rid never reached $want (last=$st)"; return 1
}

echo "provisioning $HOST1 and $HOST2 in parallel (fresh mode)"
R1=$(start_run "$HOST1"); R2=$(start_run "$HOST2")
echo "run1=$R1 (for $HOST1)"; echo "run2=$R2 (for $HOST2)"

# Both key gates in parallel.
confirm_key "$R1" & C1=$!
confirm_key "$R2" & C2=$!
wait "$C1" || true; wait "$C2" || true

# Wait for both to connect.
wait_state "$R1" connected & W1=$!
wait_state "$R2" connected & W2=$!
ok1=0; ok2=0
wait "$W1" && ok1=1 || true
wait "$W2" && ok2=1 || true

# Assert both hosts show as connected in the fleet.
CONNECTED=$(api "$BASE/api/v1/hosts" | python3 -c 'import sys,json;print(len([x for x in json.load(sys.stdin)["items"] if x["state"]=="connected"]))')
echo "connected hosts in fleet: $CONNECTED"

if [ "$ok1" = 1 ] && [ "$ok2" = 1 ] && [ "$CONNECTED" -ge 2 ]; then
  echo "PASS: two-machine fleet provisioned to connected (run1=$R1 run2=$R2)"
else
  echo "FAIL: run1=$ok1 run2=$ok2 connected=$CONNECTED (want both connected + >=2 hosts)"
  echo "--- server log tail ---"; tail -40 "$WORK/srv.log" || true
  exit 1
fi
