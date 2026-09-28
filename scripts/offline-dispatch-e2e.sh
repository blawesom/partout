#!/usr/bin/env bash
# Functional E2E for dispatch-to-offline-agents: a command sent to a
# disconnected host is queued (run state queued_offline), then delivered and
# executed when the host reconnects.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:/usr/local/go/bin"

WORK=$(mktemp -d /tmp/partout-offline-XXXXXX)
SRV_PID=""; AG1_PID=""
cleanup() { [ -n "$AG1_PID" ] && kill "$AG1_PID" 2>/dev/null || true; [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
PORT=$((21000 + RANDOM % 20000))
ADMIN='offline-e2e-token'
go build -o "$WORK/partout" ./cmd/partout

# ---- server (plaintext) ----
env PARTOUT_MODE=server PARTOUT_PORT="$PORT" PARTOUT_DB_PATH="$WORK/p.db" \
  PARTOUT_ADMIN_PASSWORD='change-me-123' PARTOUT_TOKEN_ADMIN="$ADMIN" \
  "$WORK/partout" >"$WORK/srv.log" 2>&1 &
SRV_PID=$!
BASE="http://127.0.0.1:$PORT"
for i in $(seq 1 40); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.5; done

# ---- enroll + connect a separate agent ----
TOK=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/agents/enrollment-tokens" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
env PARTOUT_SERVER="127.0.0.1:$PORT" PARTOUT_TOKEN="$TOK" PARTOUT_DATA_DIR="$WORK/agent1" "$WORK/partout" --mode=agent >"$WORK/agent1.log" 2>&1 &
AG1_PID=$!
# wait for connected
HOST=""
for i in $(seq 1 40); do
  HOST=$(curl -s -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/hosts" | python3 -c 'import sys,json;h=json.load(sys.stdin)["items"];print([x["id"] for x in h if x["state"]=="connected"][0] if any(x["state"]=="connected" for x in h) else "")' 2>/dev/null || true)
  [ -n "$HOST" ] && break; sleep 0.5
done
[ -n "$HOST" ] || { echo "agent never connected"; cat "$WORK/agent1.log"; exit 1; }
echo "connected host: $HOST"

# ---- kill the agent -> offline ----
kill "$AG1_PID"; wait "$AG1_PID" 2>/dev/null || true
AG1_PID=""
sleep 2

# ---- dispatch to the now-offline host ----
EXEC=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"selector\":\"host:$HOST\",\"cmd\":\"echo offline-works\"}" "$BASE/api/v1/executions" | python3 -c 'import sys,json;print(json.load(sys.stdin)["execution_id"])')
echo "execution: $EXEC"
RUN_STATE=$(curl -s -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/executions/$EXEC" | python3 -c 'import sys,json;print(json.load(sys.stdin)["runs"][0]["state"])')
echo "run state while offline: $RUN_STATE"
if [ "$RUN_STATE" != "queued_offline" ]; then echo "FAIL: expected queued_offline, got $RUN_STATE"; exit 1; fi

# ---- restart the agent -> reconnect -> delivered + executed ----
env PARTOUT_SERVER="127.0.0.1:$PORT" PARTOUT_DATA_DIR="$WORK/agent1" "$WORK/partout" --mode=agent >"$WORK/agent1b.log" 2>&1 &
AG1_PID=$!
# wait for the run to leave queued_offline (delivered on reconnect)
FINAL=""
for i in $(seq 1 40); do
  FINAL=$(curl -s -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/executions/$EXEC" | python3 -c 'import sys,json;print(json.load(sys.stdin)["runs"][0]["state"])' 2>/dev/null || true)
  case "$FINAL" in queued_offline|queued) ;; succeeded|failed|delivered|running|timed_out|cancelled|expired|interrupted|not_delivered) break;; esac
  sleep 0.5
done
echo "run state after reconnect: $FINAL"
case "$FINAL" in
  succeeded|failed|delivered|running) echo "PASS: offline command delivered on reconnect (state=$FINAL)";;
  *) echo "FAIL: run did not leave queued_offline (state=$FINAL)"; exit 1;;
esac
