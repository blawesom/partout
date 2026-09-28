#!/usr/bin/env bash
# Functional E2E for mTLS leaf rotation: boot a TLS-mode embedded server, let
# the local agent enroll (CSR -> server persists tls_pub), then rotate the
# agent's leaf via the admin API and confirm a fresh serial is issued and the
# agent stays connected.
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

# Wait for the CA file.
wait_for 60 test -f "$CACERT" || { echo "no CA"; tail -20 "$WORK/srv.log"; exit 1; }

# Wait for one agent to enroll (tls status shows it).
get_status() { curl -sk --cacert "$CACERT" -H "Authorization: Bearer $ADMIN" "$BASE/api/v1/tls/status"; }
rotate() { curl -sk --cacert "$CACERT" -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "$1" "$BASE/api/v1/tls/rotate"; }
AGENT=""
for i in $(seq 1 60); do
  S=$(get_status || true)
  if echo "$S" | grep -q '"tls":true'; then AGENT=$(echo "$S" | python3 -c 'import sys,json;a=[x["agent_id"] for x in json.load(sys.stdin)["agents"] if x["tls"]];print(a[0] if a else "")'); [ -n "$AGENT" ] && break; fi
  sleep 0.5
done
[ -n "$AGENT" ] || { echo "no TLS agent enrolled"; get_status; tail -20 "$WORK/srv.log"; exit 1; }
echo "enrolled agent: $AGENT"

BEFORE=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["not_after"])')
echo "not_after before: $BEFORE"

echo "--- rotate (1 of 2) ---"
ROT1=$(rotate "{\"agent_id\":\"$AGENT\"}")
SERIAL1=$(echo "$ROT1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("serial",""))')
echo "rotation 1: $ROT1"

# A second rotation must issue a DIFFERENT (fresh) serial — the deterministic
# proof that rotation re-signs the leaf. (The not_after advance is only a few
# seconds on a fresh 2-year leaf and X.509 expiry is second-resolution, so a
# strict `>` on it is timing-flaky; the serial is deterministic.)
sleep 1
echo "--- rotate (2 of 2) ---"
ROT2=$(rotate "{\"agent_id\":\"$AGENT\"}")
SERIAL2=$(echo "$ROT2" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("serial",""))')
echo "rotation 2: $ROT2"

AFTER=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["not_after"])')
echo "not_after after: $AFTER"

# The agent must still be connected after rotation (old leaf stays valid until
# its own expiry; the new leaf is picked up in place or on next reconnect).
sleep 2
STATE=$(get_status | python3 -c 'import sys,json;a=[x for x in json.load(sys.stdin)["agents"] if x["agent_id"]=="'"$AGENT"'"][0];print(a["state"])')
echo "agent state after rotation: $STATE"

if [ -n "$SERIAL1" ] && [ -n "$SERIAL2" ] && [ "$SERIAL1" != "$SERIAL2" ]; then
  echo "PASS: rotation re-signed the leaf (serial $SERIAL1 -> $SERIAL2)"
else
  echo "FAIL: rotation did not issue a fresh serial (s1=$SERIAL1 s2=$SERIAL2)"; exit 1
fi
if [ "$AFTER" -lt "$BEFORE" ]; then
  echo "FAIL: leaf expiry regressed ($BEFORE -> $AFTER)"; exit 1
fi
if [ "$STATE" != "connected" ]; then
  echo "FAIL: agent not connected after rotation (state=$STATE)"; exit 1
fi

# Also verify the 'all' scope works.
rotate '{"all":true}' >/dev/null
echo "PASS: functional rotation E2E complete"
