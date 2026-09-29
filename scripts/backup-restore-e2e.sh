#!/usr/bin/env bash
# backup-restore-e2e — the disaster-recovery drill (1.0 prep).
#
# Proves the restore path end to end, not just the backup:
#   1. live server + a REAL separate agent process (its own identity),
#      tagged + release published
#   2. backup via `partout ctl db-backup` (VACUUM INTO)
#   3. backup PROVEN: sqlite magic, PRAGMA integrity_check, schema version,
#      row sanity (an unproven backup does not count)
#   4. server KILLED; the agent survives (reconnect backoff)
#   5. a NEW server instance boots from the restored backup on the same port
#   6. the same agent (same identity) reconnects; tags/roles/release intact;
#      schema version current
#   7. negative: a corrupted backup file is rejected by the integrity proof
#
# Nothing is touched outside a temp dir; the agent is a plain process.
set -uo pipefail

export PATH="$PATH:/usr/local/go/bin"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT=18498
T="$(mktemp -d /tmp/partout-bkrestore.XXXXXX)"
PASS=0; FAIL=0

ok()  { echo "  PASS $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1${2:+ <<< $2}"; FAIL=$((FAIL+1)); }
cleanup() {
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -f "$T/srv.pid" ] && kill "$(cat "$T/srv.pid")" 2>/dev/null || true
  rm -rf "$T"
}
trap cleanup EXIT

echo "==> building"
mkdir -p "$T/db" "$T/agent"
go build -trimpath -o "$T/partout" ./cmd/partout || { bad "build"; exit 1; }

api() { curl -s -m 5 -H "Authorization: Bearer bre2etok" "http://127.0.0.1:$PORT/api/v1$1"; }

start_server() { # dbpath
  PARTOUT_PORT=$PORT PARTOUT_DB_PATH="$1" PARTOUT_ADMIN_PASSWORD=brepw123 \
    PARTOUT_TOKEN_ADMIN=bre2etok "$T/partout" > "$T/srv.log" 2>&1 &
  echo $! > "$T/srv.pid"
  for i in $(seq 1 40); do
    curl -sf -m1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

echo "==> server A + real agent"
start_server "$T/db/a.db" || { bad "server A healthy" "$(tail -3 "$T/srv.log")"; exit 1; }
ok "server A healthy"
TOK="$(curl -s -X POST -H "Authorization: Bearer bre2etok" \
  "http://127.0.0.1:$PORT/api/v1/agents/enrollment-tokens" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
[ -n "$TOK" ] || { bad "enrollment token"; exit 1; }
PARTOUT_MODE=agent PARTOUT_SERVER="127.0.0.1:$PORT" PARTOUT_TOKEN="$TOK" \
  PARTOUT_DATA_DIR="$T/agent" "$T/partout" > "$T/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1
AG=""
for i in $(seq 1 30); do
  AG="$(api /hosts | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("id",""))' 2>/dev/null)"
  [ -n "$AG" ] && break
  sleep 1
done
[ -n "$AG" ] && ok "agent connected to server A ($AG)" || { bad "agent connected" "$(tail -3 "$T/agent.log")"; exit 1; }

echo "==> seeding data (tag, role, release)"
curl -s -X PUT -H "Authorization: Bearer bre2etok" -H "Content-Type: application/json" \
  -d '{"value":"prod"}' "http://127.0.0.1:$PORT/api/v1/hosts/$AG/tags/env" >/dev/null
curl -s -X PUT -H "Authorization: Bearer bre2etok" -H "Content-Type: application/json" \
  -d '{}' "http://127.0.0.1:$PORT/api/v1/hosts/$AG/roles/web" >/dev/null
python3 - > "$T/rel.json" <<'PY'
import base64, json
# Well-formed 64-byte Ed25519 signature (server validates format, not
# content; the drill does not verify signatures).
sig = base64.b64encode(bytes(range(64))).decode()
json.dump({"version": "1.0.0", "arch": "linux-amd64", "kind": "agent",
           "signature": sig, "artifact_b64": base64.b64encode(b"tiny").decode()},
          open("/dev/stdout", "w"))
PY
RELID="$(curl -s -X POST -H "Authorization: Bearer bre2etok" -H "Content-Type: application/json" \
  -d @"$T/rel.json" "http://127.0.0.1:$PORT/api/v1/updates/releases" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')"
[ -n "$RELID" ] && ok "seeded tag+role+release ($RELID)" || bad "seeded data"

echo "==> backup + prove it"
BK="$T/backup.db"
"$T/partout" ctl db-backup "$T/db/a.db" "$BK" >/dev/null 2>&1 && ok "db-backup produced $BK" || bad "db-backup"
[ -s "$BK" ] && ok "backup non-empty ($(stat -c%s "$BK") bytes)" || bad "backup non-empty"
python3 - "$BK" <<'PY' && ok "backup proven (magic + integrity_check + schema + rows)" \
  || bad "backup proven (magic + integrity + schema + rows)"
import sqlite3, sys
f = sys.argv[1]
magic = open(f, "rb").read(16)
assert magic.startswith(b"SQLite format 3"), "not a sqlite file"
con = sqlite3.connect(f"file:{f}?mode=ro", uri=True)
ic = con.execute("PRAGMA integrity_check").fetchone()[0]
assert ic == "ok", f"integrity_check: {ic}"
ver = con.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
assert ver >= 17, f"schema version {ver}"
hosts = con.execute("SELECT count(*) FROM agents").fetchone()[0]
tags = con.execute("SELECT count(*) FROM host_tags").fetchone()[0]
roles = con.execute("SELECT count(*) FROM host_roles").fetchone()[0]
releases = con.execute("SELECT count(*) FROM update_releases").fetchone()[0]
assert hosts >= 1 and tags >= 1 and roles >= 1 and releases >= 1, (hosts, tags, roles, releases)
PY

echo "==> killing server A (agent must survive)"
kill "$(cat "$T/srv.pid")" 2>/dev/null; rm -f "$T/srv.pid"
sleep 2
kill -0 "$AGENT_PID" 2>/dev/null && ok "agent process still alive after server death" \
  || bad "agent process still alive" "$(tail -3 "$T/agent.log")"

echo "==> restoring into a fresh server instance (same port)"
cp "$BK" "$T/db/restored.db"
start_server "$T/db/restored.db" && ok "server B healthy from restored backup" || { bad "server B healthy" "$(tail -3 "$T/srv.log")"; exit 1; }

echo "==> same agent reconnects; data intact"
AG2=""
for i in $(seq 1 30); do
  R="$(api /hosts)"
  AG2="$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("id",""))' 2>/dev/null)"
  [ "$AG2" = "$AG" ] && break
  sleep 1
done
[ "$AG2" = "$AG" ] && ok "same agent ($AG) reconnected to server B" \
  || bad "same agent reconnected" "saw=$AG2 want=$AG"
R="$(api /hosts/$AG)"
echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);assert d.get("tags",{}).get("env")=="prod";assert "web" in (d.get("roles") or [])' \
  && ok "tag + role survived the restore" || bad "tag + role survived" "$R"
RL="$(api /updates/releases)"
[ -n "$RELID" ] && echo "$RL" | grep -q "$RELID" && ok "release survived the restore" \
  || bad "release survived" "relID='$RELID' in-list=$RL"
VER="$(curl -s "http://127.0.0.1:$PORT/api/v1/version")"
echo "$VER" | grep -q "version" && ok "restored server serves /api/v1/version" || bad "version endpoint"

echo "==> negative: corrupted backup is rejected"
cp "$BK" "$T/corrupt.db"
printf 'XXXX' | dd of="$T/corrupt.db" bs=1 seek=100 conv=notrunc 2>/dev/null
if python3 - "$T/corrupt.db" <<'PY' 2>/dev/null
import sqlite3, sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
PY
then
  bad "corrupted backup rejected (integrity_check passed on a corrupt file)"
else
  ok "corrupted backup rejected"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
