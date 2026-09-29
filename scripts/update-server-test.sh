#!/usr/bin/env bash
# update-server-test.sh — exercises scripts/update-server.sh end to end:
# success + idempotent re-run, selftest gate, signature gate, and the
# full rollback path (postcheck failure -> previous binary restored).
#
# systemd is faked with a systemctl shim that (re)starts the test server
# process with the CURRENT binary at the swapped path; everything else
# (server, DB, API, health checks) is real.

set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$PATH:/usr/local/go/bin"

T="$(mktemp -d /tmp/upd-srv-test.XXXXXX)"
PORT=18492
PASS=0 FAILN=0

cleanup() {
  [ -f "$T/srv.pid" ] && kill "$(cat "$T/srv.pid")" 2>/dev/null || true
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$T"
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  PASS $1"; }
bad()  { FAILN=$((FAILN+1)); echo "  FAIL $1 <<< $2"; }

echo "==> building partout"
go build -o "$T/partout" ./cmd/partout

# ---- throwaway release key + a signed "new" binary --------------------------
KEYOUT="$("$T/partout" ctl update keygen 2>/dev/null)"
PUB="$(echo "$KEYOUT" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {print $1}' | sed -n 1p)"
PRIV="$(echo "$KEYOUT" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {print $1}' | sed -n 2p)"
ARCH="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
VER="v9.9.9-test"
SIGNOUT="$("$T/partout" ctl update sign --version "$VER" --arch "$ARCH" --kind server \
  --file "$T/partout" --key "$PRIV" 2>/dev/null)"
SIG="$(echo "$SIGNOUT" | grep '^signature:' | awk '{print $2}')"
SHA="$(sha256sum "$T/partout" | awk '{print $1}')"

# A decoy "new" binary (different bytes) with a VALID signature:
cp "$T/partout" "$T/new-partout"
printf '\n// decoy revision\n' >> "$T/new-partout"
NEW_SHA="$(sha256sum "$T/new-partout" | awk '{print $1}')"
SIGNOUT2="$("$T/partout" ctl update sign --version "$VER" --arch "$ARCH" --kind server \
  --file "$T/new-partout" --key "$PRIV" 2>/dev/null)"
SIG2="$(echo "$SIGNOUT2" | grep '^signature:' | awk '{print $2}')"

# ---- install layout: bin path the script will swap ---------------------------
BINPATH="$T/bin/partout"
mkdir -p "$T/bin" "$T/db"
install -m 755 "$T/partout" "$BINPATH"

# ---- fake systemctl: stop/start the test server with the CURRENT bin --------
mkdir -p "$T/fakebin"
cat > "$T/fakebin/systemctl" <<EOF
#!/bin/sh
case "\$1" in
  stop)
    [ -f "$T/srv.pid" ] && kill "\$(cat "$T/srv.pid")" 2>/dev/null || true
    rm -f "$T/srv.pid";;
  start)
    "$BINPATH" >> "$T/srv.log" 2>&1 &
    echo \$! > "$T/srv.pid";;
  *) exit 0;;
esac
EOF
chmod +x "$T/fakebin/systemctl"

# ---- env for the server (inherited by the shim) ------------------------------
export PARTOUT_PORT="$PORT"
export PARTOUT_DB_PATH="$T/db/p.db"
export PARTOUT_DATA_DIR="$T/db/agent"
export PARTOUT_MODE=embedded
export PARTOUT_ADMIN_PASSWORD=testpass123
export PARTOUT_TOKEN_ADMIN=restok
export PARTOUT_ADMIN_TOKEN=restok
export PARTOUT_RELEASE_KEY="$PUB"

start_server() {
  "$BINPATH" >> "$T/srv.log" 2>&1 &
  SRV_PID=$!
  echo "$SRV_PID" > "$T/srv.pid"
  for i in $(seq 1 40); do
    curl -sf -m1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "server never became healthy" >&2; return 1
}
wait_agent() { # wait until at least one host is connected
  for i in $(seq 1 30); do
    N=$(curl -s -H "Authorization: Bearer restok" "http://127.0.0.1:$PORT/api/v1/hosts" | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("items",[])))' 2>/dev/null || echo 0)
    [ "${N:-0}" -ge 1 ] && return 0
    sleep 1
  done
  return 1
}

ensure_server() { # server must be up with an agent before scenarios
  if ! curl -sf -m2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    start_server || return 1
  fi
  wait_agent || return 1
}

export -f ok bad start_server wait_agent ensure_server 2>/dev/null || true

run_update() { # run_update <new> <sha> <sig> <version> -> exit code
  PATH="$T/fakebin:$PATH" "$REPO/scripts/update-server.sh" \
    --new "$1" --sha256 "$2" --signature "$3" --version "$4" --key "$PUB" \
    --binary "$BINPATH" --db "$T/db/p.db" --health-url "http://127.0.0.1:$PORT" \
    --admin-token restok --post-timeout 45 2>&1
}

# =============================================================================
echo "==> scenario 1: signature gate (bad signature -> not installed)"
ensure_server
BADSIG="AAAA$(tail -c 88 <<< "$SIG2")"
if run_update "$T/new-partout" "$NEW_SHA" "$BADSIG" "$VER" > "$T/s1.log" 2>&1; then
  bad "signature gate blocks install" "script exited 0"
else
  grep -qi "signature" "$T/s1.log" && ok "signature gate blocks install" \
    || bad "signature gate blocks install" "$(tail -2 "$T/s1.log")"
fi
[ "$(sha256sum "$BINPATH" | awk '{print $1}')" = "$SHA" ] && ok "binary untouched after bad signature" \
  || bad "binary untouched after bad signature" "binary changed"

echo "==> scenario 2: selftest gate (new binary fails selftest -> not installed)"
cat > "$T/badselftest" <<'EOF2'
#!/bin/sh
if [ "$1" = "selftest" ]; then echo "selftest: simulated failure" >&2; exit 1; fi
exec /bin/true
EOF2
chmod +x "$T/badselftest"
BADSHA="$(sha256sum "$T/badselftest" | awk '{print $1}')"
SIGNOUT3="$("$T/partout" ctl update sign --version "$VER" --arch "$ARCH" --kind server \
  --file "$T/badselftest" --key "$PRIV" 2>/dev/null)"
SIG3="$(echo "$SIGNOUT3" | grep '^signature:' | awk '{print $2}')"
if run_update "$T/badselftest" "$BADSHA" "$SIG3" "$VER" > "$T/s2.log" 2>&1; then
  bad "selftest gate blocks install" "script exited 0"
else
  grep -q "selftest failed" "$T/s2.log" && ok "selftest gate blocks install" \
    || bad "selftest gate blocks install" "$(tail -2 "$T/s2.log")"
fi
[ "$(sha256sum "$BINPATH" | awk '{print $1}')" = "$SHA" ] && ok "binary untouched after selftest failure" \
  || bad "binary untouched after selftest failure" "binary changed"

echo "==> scenario 3: valid update (all gates pass, postcheck passes)"
ensure_server
if run_update "$T/new-partout" "$NEW_SHA" "$SIG2" "$VER" > "$T/s3.log" 2>&1; then
  ok "update succeeded"
else
  bad "update succeeded" "$(tail -2 "$T/s3.log")"
fi
NEWINSTALLED_SHA="$(sha256sum "$BINPATH" | awk '{print $1}')"
[ "$NEWINSTALLED_SHA" = "$NEW_SHA" ] && ok "installed binary is the new one" \
  || bad "installed binary is the new one" "sha=$NEWINSTALLED_SHA"
sleep 2
curl -sf -m2 "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "service healthy after update" \
  || bad "service healthy after update" "no healthz"

echo "==> scenario 4: idempotent re-run at target"
if run_update "$T/new-partout" "$NEW_SHA" "$SIG2" "$VER" > "$T/s4.log" 2>&1 \
   && grep -q "already at target" "$T/s4.log"; then
  ok "re-run reports already at target"
else
  bad "re-run reports already at target" "$(tail -2 "$T/s4.log")"
fi

echo "==> scenario 5: rollback (postcheck fails -> previous binary restored)"
# A "new" binary whose selftest passes but which never serves health.
cat > "$T/broken2" <<'EOF3'
#!/bin/sh
case "$1" in
  selftest) exit 0;;
esac
sleep 300
EOF3
chmod +x "$T/broken2"
BROKEN2_SHA="$(sha256sum "$T/broken2" | awk '{print $1}')"
SIGNOUT6="$("$T/partout" ctl update sign --version "$VER" --arch "$ARCH" --kind server \
  --file "$T/broken2" --key "$PRIV" 2>/dev/null)"
SIG6="$(echo "$SIGNOUT6" | grep '^signature:' | awk '{print $2}')"
PRE_SHA="$(sha256sum "$BINPATH" | awk '{print $1}')"
if run_update "$T/broken2" "$BROKEN2_SHA" "$SIG6" "$VER" > "$T/s5.log" 2>&1; then
  bad "postcheck failure triggers rollback" "script exited 0"
else
  grep -q "rolled back" "$T/s5.log" && ok "postcheck failure triggers rollback" \
    || bad "postcheck failure triggers rollback" "$(tail -3 "$T/s5.log")"
fi
POST_SHA="$(sha256sum "$BINPATH" | awk '{print $1}')"
[ "$POST_SHA" = "$PRE_SHA" ] && ok "previous binary restored" \
  || bad "previous binary restored" "sha=$POST_SHA want=$PRE_SHA"
sleep 3
curl -sf -m2 "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "service healthy after rollback" \
  || bad "service healthy after rollback" "no healthz"
ls "$T/db"/partout-backup-rollback-*.db >/dev/null 2>&1 && ok "pre-swap backup preserved on rollback" \
  || bad "pre-swap backup preserved on rollback" "no backup file"

echo ""
echo "RESULT: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ] || exit 1
