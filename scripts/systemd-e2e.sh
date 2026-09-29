#!/usr/bin/env bash
# systemd-e2e — the real-systemd E2E for M8.1 agent self-update
# (the ops-checklist item that fake-systemctl tests cannot cover).
#
# Runs a THROWAWAY unit (partout-syse2e-agent.service) under the real
# systemd, with the real boot guard as ExecStart, and exercises:
#
#   A. live swap  : v1 agent -> signed v2 -> the agent downloads via a fresh
#                    grant, swaps, restarts via REAL systemctl, reconnects
#                    as v2 and reports verified (MainPID changes).
#   B. crashloop  : signed v3 is a broken binary -> the unit crashloops ->
#                    after the (shortened) health window the boot guard
#                    restores N-1, clears the marker, and the service comes
#                    back healthy. This also proves the unit survives
#                    systemd's start-rate limit (StartLimitIntervalSec=0).
#
# Requires: systemd running as PID 1, passwordless sudo, go, curl, python3.
# Never touches real partout units/binaries: everything lives in a temp dir
# under /tmp and is removed at the end (including the unit).
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$PATH:/usr/local/go/bin"

PORT=18495
UNIT=partout-syse2e-agent
T="$(mktemp -d /tmp/partout-syse2e.XXXXXX)"
PASS=0; FAIL=0

ok()  { echo "  PASS $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $1${2:+ <<< $2}"; FAIL=$((FAIL+1)); }
cleanup() {
  sudo systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  sudo rm -f "/etc/systemd/system/$UNIT.service" "$T/guard.sh"
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
  [ -f "$T/srv.pid" ] && kill "$(cat "$T/srv.pid")" 2>/dev/null || true
  # The unit runs as root: its files in $T (identity.json, ...) are root-owned.
  sudo rm -rf "$T"
}
trap cleanup EXIT

echo "==> building test binaries (real agent, stamped versions)"
mkdir -p "$T/server" "$T/bin" "$T/bin2" "$T/agent" "$T/srvdb"
VFLAGS="-s -w -X github.com/blawesom/partout/internal/agent/facts.Version="
CGO_ENABLED=0 go build -trimpath -ldflags "${VFLAGS}1.0.0-syse2e" -o "$T/bin/partout"  ./cmd/partout
CGO_ENABLED=0 go build -trimpath -ldflags "${VFLAGS}2.0.0-syse2e" -o "$T/bin2/partout" ./cmd/partout
CGO_ENABLED=0 go build -trimpath                     -o "$T/server/partout"        ./cmd/partout
[ -x "$T/bin/partout" ] && [ -x "$T/bin2/partout" ] && [ -x "$T/server/partout" ] \
  && ok "binaries built" || { bad "binaries built"; exit 1; }

echo "==> release key + signed artifacts"
KEYGEN="$("$T/server/partout" ctl update keygen 2>/dev/null)"
PUB="$(echo "$KEYGEN" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {print $1; exit}')"
PRIV="$(echo "$KEYGEN" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {c++; if (c==2) print $1}')"
[ -n "$PUB" ] && [ -n "$PRIV" ] && ok "keypair generated" || { bad "keypair generated" "$(echo "$KEYGEN" | head -4)"; exit 1; }
SIG2="$("$T/server/partout" ctl update sign --version 2.0.0-syse2e --arch linux-amd64 --kind agent --file "$T/bin2/partout" --key "$PRIV" 2>/dev/null | grep '^signature:' | awk '{print $2}')"
[ -n "$SIG2" ] && ok "v2 artifact signed" || { bad "v2 artifact signed"; exit 1; }

echo "==> starting the control plane (real binary, temp DB)"
(
  PARTOUT_PORT=$PORT PARTOUT_DB_PATH="$T/srvdb/p.db" \
  PARTOUT_ADMIN_PASSWORD=syse2epass PARTOUT_TOKEN_ADMIN=syse2etok \
  "$T/server/partout" > "$T/srv.log" 2>&1 &
  echo $! > "$T/srv.pid"
)
for i in $(seq 1 40); do
  curl -sf -m1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf -m1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 \
  && ok "server healthy" || { bad "server healthy" "$(tail -3 "$T/srv.log")"; exit 1; }

TOK="$(curl -s -X POST -H "Authorization: Bearer syse2etok" \
  "http://127.0.0.1:$PORT/api/v1/agents/enrollment-tokens" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')"
[ -n "$TOK" ] && ok "enrollment token minted" || { bad "enrollment token minted"; exit 1; }

echo "==> installing the throwaway agent unit (real guard as ExecStart)"
sudo cp "$REPO_DIR/deploy/systemd/partout-update-guard.sh" "$T/guard.sh"
sudo chmod 0755 "$T/guard.sh"
cat > "$T/agent.env" <<EOF
PARTOUT_MODE=agent
PARTOUT_SERVER=127.0.0.1:$PORT
PARTOUT_TOKEN=$TOK
PARTOUT_DATA_DIR=$T/agent
PARTOUT_RELEASE_KEY=$PUB
PARTOUT_UPDATE_HEALTH_S=3
PARTOUT_UPDATE_GUARD_GRACE_S=2
PARTOUT_UPDATE_RESTART_CMD=systemctl restart $UNIT
PARTOUT_GUARD_BIN=$T/bin/partout
PARTOUT_AGENT_DATA_DIR=$T/agent
EOF
sudo chmod 0644 "$T/agent.env"
cat > "$T/$UNIT.service" <<EOF
[Unit]
Description=partout syse2e throwaway agent
After=network-online.target
StartLimitIntervalSec=0

[Service]
EnvironmentFile=$T/agent.env
ExecStart=$T/guard.sh --mode=agent --data-dir=$T/agent
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
sudo cp "$T/$UNIT.service" "/etc/systemd/system/$UNIT.service"
sudo systemctl daemon-reload
sudo systemctl enable --now "$UNIT" >/dev/null 2>&1
sleep 1
sudo systemctl is-active "$UNIT" >/dev/null 2>&1 && ok "test unit active" || { bad "test unit active" "$(sudo systemctl status "$UNIT" --no-pager 2>&1 | head -5)"; exit 1; }

# Wait for the agent to enroll + connect at v1.
AG=""; V=""
for i in $(seq 1 60); do
  R="$(curl -s -H "Authorization: Bearer syse2etok" "http://127.0.0.1:$PORT/api/v1/hosts")"
  AG="$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("id",""))' 2>/dev/null)"
  V="$(echo "$R" | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("version",""))' 2>/dev/null)"
  [ -n "$AG" ] && [ "$V" = "1.0.0-syse2e" ] && break
  sleep 1
done
[ "$V" = "1.0.0-syse2e" ] && ok "agent enrolled + connected at v1 ($AG)" \
  || bad "agent enrolled + connected at v1" "version=$V (agent.log: $(sudo tail -3 "$T/agent/agent.log" 2>/dev/null | tr '\n' ' '))"
PID1="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null)"

upload_release() { # version sig file
  # Artifact is ~19 MB base64: write the body to a file, curl -d @file
  # (an inline -d argument exceeds the kernel's max single-argument size).
  python3 - "$1" "$2" "$3" > "$T/upload.json" <<'PY'
import base64, json, sys
with open(sys.argv[3], "rb") as f:
    body = {"version": sys.argv[1], "arch": "linux-amd64", "kind": "agent",
            "signature": sys.argv[2],
            "artifact_b64": base64.b64encode(f.read()).decode()}
with open("/dev/stdout", "w") as out:
    json.dump(body, out)
PY
  curl -s -X POST -H "Authorization: Bearer syse2etok" -H "Content-Type: application/json" \
    -d @"$T/upload.json" "http://127.0.0.1:$PORT/api/v1/updates/releases"
}

echo "==> scenario A: live supervised swap v1 -> v2"
REL2="$(upload_release 2.0.0-syse2e "$SIG2" "$T/bin2/partout" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)"
[ -n "$REL2" ] && ok "v2 release published ($REL2)" || { bad "v2 release published"; exit 1; }
APPLY="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer syse2etok" \
  -H "Content-Type: application/json" -d "{\"agent_id\":\"$AG\",\"release_id\":\"$REL2\"}" \
  "http://127.0.0.1:$PORT/api/v1/updates/apply")"
[ "$APPLY" = "200" ] || [ "$APPLY" = "201" ] && ok "update dispatched (HTTP $APPLY)" \
  || bad "update dispatched" "HTTP $APPLY"
V2=""
for i in $(seq 1 90); do
  V2="$(curl -s -H "Authorization: Bearer syse2etok" "http://127.0.0.1:$PORT/api/v1/hosts" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("version",""))' 2>/dev/null)"
  [ "$V2" = "2.0.0-syse2e" ] && break
  sleep 1
done
[ "$V2" = "2.0.0-syse2e" ] && ok "agent swapped + restarted into v2 via real systemd" \
  || bad "agent swapped + restarted into v2" "version=$V2 unit=$(sudo systemctl is-active "$UNIT") log=$(sudo tail -2 "$T/agent/agent.log" 2>/dev/null | tr '\n' ' ')"
PID2="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null)"
[ -n "$PID1" ] && [ -n "$PID2" ] && [ "$PID1" != "$PID2" ] \
  && ok "MainPID changed ($PID1 -> $PID2)" || bad "MainPID changed" "pid1=$PID1 pid2=$PID2"

echo "==> scenario B: crashlooping v3 -> guard rolls back to v2"
mkdir -p "$T/bin3"
cat > "$T/bin3/partout" <<'EOF'
#!/bin/sh
# Broken N+1: reports its version (so the guard sees "fresh + matching")
# but crashloops on every real start.
# NOTE: no "v" prefix — must match the release version string exactly,
# else the guard sees a version mismatch (rolls back immediately).
if [ "$1" = "--version" ]; then echo "partout 3.0.0-syse2e-broken"; exit 0; fi
exit 1
EOF
chmod 0755 "$T/bin3/partout"
SIG3="$("$T/server/partout" ctl update sign --version 3.0.0-syse2e-broken --arch linux-amd64 --kind agent --file "$T/bin3/partout" --key "$PRIV" 2>/dev/null | grep '^signature:' | awk '{print $2}')"
[ -n "$SIG3" ] && ok "broken v3 artifact signed" || { bad "broken v3 artifact signed"; exit 1; }
# The agent's CURRENT binary is v2 (scenario A); the v3 swap refreshes
# N-1 to v2, so the guard can restore it.
REL3="$(upload_release 3.0.0-syse2e-broken "$SIG3" "$T/bin3/partout" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))' 2>/dev/null)"
[ -n "$REL3" ] && ok "v3 release published ($REL3)" || { bad "v3 release published"; exit 1; }
APPLY3="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer syse2etok" \
  -H "Content-Type: application/json" -d "{\"agent_id\":\"$AG\",\"release_id\":\"$REL3\"}" \
  "http://127.0.0.1:$PORT/api/v1/updates/apply")"
[ "$APPLY3" = "200" ] || [ "$APPLY3" = "201" ] && ok "v3 dispatched (HTTP $APPLY3)" \
  || bad "v3 dispatched" "HTTP $APPLY3"
SINCE="$(date -d '2 seconds ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"

# Wait for the DEFINITIVE completion signal: the guard's rollback line.
# (Polling the host version is ambiguous here: the host row still shows v2
# while the v3 process crashloops, and the unit is "active" mid-crashloop.)
JOK=""
for i in $(seq 1 90); do
  if journalctl -u "$UNIT" --since "$SINCE" --no-pager 2>/dev/null | grep -q "rolled back failed update"; then
    JOK=1; break
  fi
  sleep 1
done
[ -n "$JOK" ] && ok "guard rolled back to v2 (journal: rollback after the health window)" \
  || bad "guard rolled back to v2" "$(journalctl -u "$UNIT" --since "$SINCE" --no-pager 2>/dev/null | tail -4)"
sleep 2
VB="$(curl -s -H "Authorization: Bearer syse2etok" "http://127.0.0.1:$PORT/api/v1/hosts" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("items") or [{}])[0].get("version",""))' 2>/dev/null)"
ACTIVE="$(sudo systemctl is-active "$UNIT" 2>/dev/null)"
[ "$VB" = "2.0.0-syse2e" ] && [ "$ACTIVE" = "active" ] \
  && ok "agent healthy on v2 after rollback" \
  || bad "agent healthy on v2 after rollback" "version=$VB unit=$ACTIVE"
J="$(journalctl -u "$UNIT" --since "$SINCE" --no-pager 2>/dev/null)"
echo "$J" | grep -q "update swapped to 3.0.0-syse2e-broken" \
  && ok "journal proves v3 was swapped in (crashloop was real)" \
  || bad "journal proves v3 was swapped in" "$(echo "$J" | tail -3)"
[ ! -f "$T/agent/update.json" ] && ok "boot marker cleared after rollback" \
  || bad "boot marker cleared" "marker still present"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
