#!/usr/bin/env bash
# End-to-end UI smoke test: boots a real embedded server (server + local agent),
# seeds representative data, then renders the actual SPA in a headless DOM
# (jsdom) logged in as admin and asserts that REAL data appears on every page.
#
# Why: the UI (internal/api/webui/app.js) has no compile-time link to the API.
# A handler-side rename or a loader reading the wrong response key blanks a page
# without failing any Go test. This harness is what catches that class of bug
# (it found: /secrets returning {secrets:[...]}, /files/list requiring agent_id,
# /hosts/{id}/facts not carrying overview fields, per-host /packages/updates).
#
# Requirements: node + npm (for jsdom), Go toolchain, openssl-free.
# Usage:   scripts/ui-smoke.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PARTOUT_UI_SMOKE_PORT:-18471}"
WORK="$(mktemp -d)"
BIN="$WORK/partout"
PASS="ui-smoke-pass"
ADMIN_TOKEN="ui-smoke-admin-token"

export PATH="$PATH:/usr/local/go/bin"

cleanup() {
  if [[ -n "${SRV_PID:-}" ]]; then kill "$SRV_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# A stale server on the same port would answer /healthz with a different admin
# token and make every seed below fail with 401. Refuse to run in that case.
if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  echo "error: something is already listening on :$PORT (set PARTOUT_UI_SMOKE_PORT)" >&2
  exit 1
fi

# seed <method> <path> <json> — request expecting 2xx, printing the body on failure.
seed() {
  local method="$1" path="$2" body="${3:-}"
  local out code
  local args=(-s -w '\n%{http_code}' -X "$method" "$B$path" -H "$H" -H "$C")
  if [[ -n "$body" ]]; then args+=(-d "$body"); fi
  out=$(curl "${args[@]}")
  code=$(printf '%s' "$out" | tail -n1)
  out=$(printf '%s' "$out" | sed '$d')
  if [[ "$code" != 2* ]]; then
    echo "seed $method $path failed: HTTP $code $out" >&2
    exit 1
  fi
  printf '%s' "$out"
}

echo "==> building partout"
(cd "$REPO" && go build -o "$BIN" ./cmd/partout)

echo "==> starting embedded server on :$PORT"
mkdir -p "$WORK/run"
(
  cd "$WORK/run"
  PARTOUT_ADMIN_PASSWORD="$PASS" \
  PARTOUT_TOKEN_ADMIN="$ADMIN_TOKEN" \
  PARTOUT_PORT="$PORT" \
  PARTOUT_DB_PATH="$WORK/run/p.db" \
  PARTOUT_DATA_DIR="$WORK/run/agent" \
  PARTOUT_MODE=embedded \
  PARTOUT_OBSERVE_FACTS_INTERVAL=2 \
  PARTOUT_SECRET_KEY=0123456789abcdef0123456789abcdef \
  "$BIN" > "$WORK/server.log" 2>&1
) &
SRV_PID=$!

# Wait for readiness.
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "server did not start"; tail -20 "$WORK/server.log"; exit 1; }

B="http://127.0.0.1:$PORT/api/v1"
H="Authorization: Bearer $ADMIN_TOKEN"
C="Content-Type: application/json"

echo "==> waiting for the local agent to connect"
for _ in $(seq 1 40); do
  n=$(curl -s "$B/hosts" -H "$H" | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("items") or []))' 2>/dev/null || echo 0)
  [[ "$n" -ge 1 ]] && break
  sleep 0.5
done

echo "==> seeding data"
AG=$(curl -s "$B/hosts" -H "$H" | python3 -c 'import sys,json;print(json.load(sys.stdin)["items"][0]["id"])')
seed POST /groups  '{"name":"web","selector":"all"}' >/dev/null
seed POST /policies '{"name":"deny-rm","effect":"deny","priority":10,"match":{"command_regex":"^rm"}}' >/dev/null
seed POST /users   '{"username":"alice","password":"alicepass123","role":"operator"}' >/dev/null
seed POST /secrets '{"name":"dbpass","value":"s3cr3t","selector":"all"}' >/dev/null
TID=$(seed POST /tasks '{"name":"check disk","description":"df -h","steps":[{"cmd":"df"}]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
seed POST /jobs "{\"name\":\"nightly df\",\"cron\":\"0 3 * * *\",\"task_id\":\"$TID\",\"selector\":\"all\"}" >/dev/null
echo "    host=$AG task=$TID"

echo "==> installing jsdom (if needed)"
HARNESS_DIR="$WORK/harness"
mkdir -p "$HARNESS_DIR"
if [[ ! -d "$REPO/node_modules/jsdom" ]]; then
  (cd "$HARNESS_DIR" && npm init -y >/dev/null 2>&1 && npm install jsdom@24 >/dev/null 2>&1)
  JSDOM_DIR="$HARNESS_DIR/node_modules"
else
  JSDOM_DIR="$REPO/node_modules"
fi

TOK=$(curl -s -X POST "$B/auth/login" -H "$C" -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

echo "==> rendering the SPA in a headless DOM"
NODE_PATH="$JSDOM_DIR" BASE="http://127.0.0.1:$PORT" TOK="$TOK" \
  node "$REPO/scripts/ui-smoke.js"
