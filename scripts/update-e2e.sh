#!/usr/bin/env bash
# update-e2e.sh — full one-command E2E for `partout update`:
#   server v1 + fleet at v1  ->  `partout update`  ->  all at v2.
#
# The release "repo" is a local HTTP directory of signed artifacts. systemd
# is faked (as in update-server-test.sh); the server swap, the release
# store publish, the fleet rollout (convergence: the restarted embedded
# agent is already v2), and the final status line are all real.

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$PATH:/usr/local/go/bin"

T="$(mktemp -d /tmp/upd-e2e.XXXXXX)"
PORT=18491 REPO_PORT=18490
PASS=0 FAILN=0
cleanup() {
  [ -f "$T/srv.pid" ] && kill "$(cat "$T/srv.pid")" 2>/dev/null || true
  [ -n "${REPO_PID:-}" ] && kill "$REPO_PID" 2>/dev/null || true
  rm -rf "$T"
}
trap cleanup EXIT
ok()  { PASS=$((PASS+1)); echo "  PASS $1"; }
bad() { FAILN=$((FAILN+1)); echo "  FAIL $1 <<< $2"; }

echo "==> building v1 + v2 binaries"
go build -ldflags "-X github.com/blawesom/partout/internal/agent/facts.Version=v1.0.0-e2e" -o "$T/v1" ./cmd/partout
go build -ldflags "-X github.com/blawesom/partout/internal/agent/facts.Version=v2.0.0-e2e" -o "$T/v2" ./cmd/partout

# ---- release key + signed artifacts ----------------------------------------
KEYOUT="$("$T/v1" ctl update keygen 2>/dev/null)"
PUB="$(echo "$KEYOUT" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {print $1}' | sed -n 1p)"
PRIV="$(echo "$KEYOUT" | awk '/^    [A-Za-z0-9+\/=]{20,}$/ {print $1}' | sed -n 2p)"
ARCH="linux-$(go env GOARCH)"
VER=v2.0.0-e2e

# ---- local release repo ------------------------------------------------------
mkdir -p "$T/repo/$VER"
sign_and_publish() { # sign_and_publish <file> <kind>
  cp "$1" "$T/repo/$VER/partout-$VER-$ARCH-$2"
  SHA=$(sha256sum "$T/repo/$VER/partout-$VER-$ARCH-$2" | awk '{print $1}')
  "$T/v1" ctl update sign --version "$VER" --arch "$ARCH" --kind "$2" \
    --file "$T/repo/$VER/partout-$VER-$ARCH-$2" --key "$PRIV" 2>/dev/null \
    | grep '^signature:' | awk '{print $2}' > "$T/repo/$VER/partout-$VER-$ARCH-$2.sig"
}
sign_and_publish "$T/v2" server
sign_and_publish "$T/v2" agent
echo "$VER" > "$T/repo/latest"

cd "$T/repo"
python3 -m http.server "$REPO_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
REPO_PID=$!
cd "$REPO_DIR"
sleep 1

# ---- install layout + fake systemctl -----------------------------------------
mkdir -p "$T/bin" "$T/db"
install -m 755 "$T/v1" "$T/bin/partout"
mkdir -p "$T/fakebin"
cat > "$T/fakebin/systemctl" <<EOF
#!/bin/sh
case "\$1" in
  stop) [ -f "$T/srv.pid" ] && kill "\$(cat "$T/srv.pid")" 2>/dev/null || true; rm -f "$T/srv.pid";;
  start) "$T/bin/partout" >> "$T/srv.log" 2>&1 & echo \$! > "$T/srv.pid";;
  *) exit 0;;
esac
EOF
chmod +x "$T/fakebin/systemctl"

export PARTOUT_PORT="$PORT"
export PARTOUT_DB_PATH="$T/db/p.db"
export PARTOUT_DATA_DIR="$T/db/agent"
export PARTOUT_MODE=embedded
export PARTOUT_ADMIN_PASSWORD=testpass123
export PARTOUT_TOKEN_ADMIN=e2etok
export PARTOUT_ADMIN_TOKEN=e2etok
export PARTOUT_RELEASE_KEY="$PUB"

start_server() {
  "$T/bin/partout" >> "$T/srv.log" 2>&1 &
  echo $! > "$T/srv.pid"
  for i in $(seq 1 40); do
    curl -sf -m1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "server not healthy" >&2; return 1
}

echo "==> starting server at v1"
start_server
sleep 3
V1CUR="$(curl -s "http://127.0.0.1:$PORT/api/v1/version")"
echo "$V1CUR" | grep -q "v1.0.0-e2e" && ok "server reports v1.0.0-e2e" || bad "server reports v1.0.0-e2e" "$V1CUR"

echo "==> one-command: partout update (v1 -> v2, server + fleet)"
if PATH="$T/fakebin:$PATH" "$T/v1" update \
  --server "127.0.0.1:$PORT" --token e2etok \
  --repo "http://127.0.0.1:$REPO_PORT" \
  --script "$REPO_DIR/scripts/update-server.sh" \
  --server-bin "$T/bin/partout" --server-db "$T/db/p.db" --service test \
  --canary 1 --wave 50 > "$T/update.log" 2>&1; then
  ok "partout update exited 0"
else
  bad "partout update exited 0" "$(tail -4 "$T/update.log")"
fi
grep -q "both artifacts verified" "$T/update.log" && ok "artifacts verified against release key" \
  || bad "artifacts verified against release key" "$(head -4 "$T/update.log")"
grep -q "supervised, rollback-safe" "$T/update.log" && ok "supervised server swap reported" \
  || bad "supervised server swap reported" "$(grep -c '' "$T/update.log") lines"
grep -q "agent artifact in release store" "$T/update.log" && ok "agent artifact published to store" \
  || bad "agent artifact published to store" ""
grep -qE "DONE" "$T/update.log" && ok "final one-line status printed" \
  || bad "final one-line status printed" "$(tail -2 "$T/update.log")"

sleep 2
V2CUR="$(curl -s "http://127.0.0.1:$PORT/api/v1/version")"
echo "$V2CUR" | grep -q "v2.0.0-e2e" && ok "server now at v2.0.0-e2e" \
  || bad "server now at v2.0.0-e2e" "$V2CUR"
RUN=$(grep -oE "rollout run_[0-9a-fx_]+" "$T/update.log" | head -1 | awk '{print $2}')
[ -n "$RUN" ] && ok "rollout run created ($RUN)" || bad "rollout run created" "no run in log"

echo "==> re-run: converged (already at target)"
if PATH="$T/fakebin:$PATH" "$T/v2" update \
  --server "127.0.0.1:$PORT" --token e2etok \
  --repo "http://127.0.0.1:$REPO_PORT" \
  --script "$REPO_DIR/scripts/update-server.sh" \
  --server-bin "$T/bin/partout" --server-db "$T/db/p.db" --service test \
  > "$T/update2.log" 2>&1; then
  ok "re-run exited 0 (convergent)"
else
  bad "re-run exited 0 (convergent)" "$(tail -3 "$T/update2.log")"
fi
if grep -q "supervised, rollback-safe" "$T/update2.log"; then
  bad "re-run skips the server swap (already at target)" "server swap ran again"
else
  ok "re-run skips the server swap (already at target)"
fi
grep -qE "DONE" "$T/update2.log" && ok "re-run fleet converges to DONE" \
  || bad "re-run fleet converges to DONE" "$(tail -2 "$T/update2.log")"

echo "==> negative: tampered repo artifact is refused"
TAMPERED="$T/repo/$VER/partout-$VER-$ARCH-agent"
printf 'x' >> "$TAMPERED"
if PATH="$T/fakebin:$PATH" "$T/v2" update \
  --server "127.0.0.1:$PORT" --token e2etok \
  --repo "http://127.0.0.1:$REPO_PORT" \
  --version "$VER" --canary 1 \
  > "$T/update3.log" 2>&1; then
  bad "tampered artifact refused" "update exited 0"
else
  grep -qi "signature" "$T/update3.log" && ok "tampered artifact refused (signature)" \
    || bad "tampered artifact refused (signature)" "$(tail -2 "$T/update3.log")"
fi

echo ""
echo "RESULT: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ] || exit 1
