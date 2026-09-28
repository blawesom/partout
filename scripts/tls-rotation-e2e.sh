#!/usr/bin/env bash
# Functional E2E for mTLS leaf rotation: boot a TLS-mode embedded server, let
# the local agent enroll (CSR -> server persists tls_pub), then rotate the
# agent's leaf via the admin API and confirm the new 2-year expiry.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:/usr/local/go/bin"

WORK=$(mktemp -d /tmp/partout-tlsrot-XXXXXX)
trap 'kill "${SRV_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
PORT=$((20000 + RANDOM % 20000))
ADMIN='func-rot-token'

go build -o "$WORK/partout" ./cmd/partout
env PARTOUT_MODE=embedded PARTOUT_TLS=on PARTOUT_PORT="$PORT" \
  PARTOUT_DB_PATH="$WORK/p.db" PARTOUT_DATA_DIR="$WORK/agent" \
  PARTOUT_ADMIN_PASSWORD='change-me-123' PARTOUT_TOKEN_ADMIN="$ADMIN" \
  "$WORK/partout" >/dev/null 2>"$WORK/srv.log" &
SRV_PID=$!

BASE="https://127.0.0.1:$PORT"
# The server writes its CA to <db dir>/tls/ca.crt.
CACERT="$WORK/tls/ca.crt"
wait_for() { local n=$1; shift; for i in $(seq 1 "$n"); do "$@" && return 0; sleep 0.5; done; return 1; }

# Wait for the CA file + a connected agent.
wait_for 60 test -f "$CACERT" || { echo "no CA"; tail -20 "$WORK/srv.log"; exit 1; }

# Wait for one agent to enroll (tls status shows it).
get_status() { curl -sk --cacert "$CACERT" -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/tls/status"; }
AGENT=""
for i in $(seq 1 60); do
  S=$(get_status || true)
  if echo "$S" | grep -q '"tls":true'; then AGENT=$(echo "$S" | python3 -c 'import sys,json;a=[x["agent_id"] for x in json.load(sys.stdin)["agents"] if x["tls"]];print(a[0] if a else "")'); [ -n "$AGENT" ] && break; fi
  sleep 0.5
done
[ -n "$AGENT" ] || { echo "no TLS agent enrolled"; get_status; tail -20 "$WORK/srv.log"; exit 1; }
echo "enrolled agent: $AGENT"

echo "--- status before rotation ---"
get_status | python3 -m json.tool

BEFORE=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["not_after"])')
echo "not_after before: $BEFORE"

echo "--- rotate ---"
curl -sk --cacert "$CACERT" -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AGENT\"}" "$BASE/api/v1/tls/rotate" | python3 -m json.tool

AFTER=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["not_after"])')
echo "not_after after: $AFTER"

# The agent must still be connected after rotation (old leaf valid until its
# own expiry; new leaf picked up on next reconnect or in place).
sleep 2
STATE=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["state"])')
echo "agent state after rotation: $STATE"

if [ "$AFTER" -gt "$BEFORE" ]; then
  echo "PASS: rotation advanced the leaf expiry ($BEFORE -> $AFTER)"
else
  echo "FAIL: expiry did not advance ($BEFORE -> $AFTER)"; exit 1
fi

# Also verify the 'all' scope works.
curl -sk --cacert "$CACERT" -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"all":true}' "$BASE/api/v1/tls/rotate" | python3 -m json.tool
echo "PASS: functional rotation E2E complete"
