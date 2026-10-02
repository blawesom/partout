#!/usr/bin/env bash
# install-server.sh test harness — verifies the REAL install layout and a
# REAL server start from the installed artifacts, without root or systemd:
#
#   - builds the real partout binary, installs it via install-server.sh into
#     a test root (PARTOUT_INSTALL_TEST_ROOT), with a mock systemctl on PATH
#     that LOGS calls and, for `enable --now partout-server.service`, parses
#     the INSTALLED unit's ExecStart + EnvironmentFile and actually starts
#     the server from them (so the healthz verify, env file, and db path the
#     script installed are proven, not assumed)
#   - scenarios: fresh install (files, perms, env contents, live healthz,
#     generated admin password file from the REAL server), idempotent re-run
#     (no changes), env preservation across an uncleaned re-run, --port/--db
#     rewrites, version refusal while running (points at update-server.sh),
#     dry-run touches nothing
#
# Usage: bash scripts/install-server-test.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
ROOT="$WORK/root"     # the fake system root install-server.sh installs into
MOCKBIN="$WORK/bin"   # mock systemctl lives here
mkdir -p "$ROOT" "$MOCKBIN"
export PATH="$MOCKBIN:$PATH:/usr/local/go/bin"

PASS=0; FAIL=0
check() { # <name> <condition...>
  local name="$1"; shift
  if "$@"; then PASS=$((PASS+1)); echo "  PASS $name"
  else FAIL=$((FAIL+1)); echo "  FAIL $name  <<<"; fi
}
check_true() { # <name> <expr result>
  if [ "$2" = "1" ]; then PASS=$((PASS+1)); echo "  PASS $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1  <<< $3"; fi
}
check_grep() { # <name> <haystack> <pattern>
  if printf '%s' "$2" | grep -q "$3"; then PASS=$((PASS+1)); echo "  PASS $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1  <<< no match: $3"; fi
}

cleanup() {
  if [ -f "$WORK/server.pid" ]; then kill "$(cat "$WORK/server.pid")" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- pick a free port -------------------------------------------------------
PORT=$(python3 - <<'EOF'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
EOF
)
DB="$ROOT/var/lib/partout/partout.db"

# --- the mock systemctl ------------------------------------------------------
# Understands exactly what install-server.sh calls. For
# `enable --now partout-server.service` it parses the INSTALLED unit
# (EnvironmentFile + ExecStart, joining backslash continuations) and starts
# the real binary from it — the artifacts the script wrote are what runs.
cat > "$MOCKBIN/systemctl" <<EOF
#!/usr/bin/env bash
# mock systemctl (install-server-test)
LOG="$WORK/systemctl.log"
echo "\$*" >> "\$LOG"
cmd="\$1"; shift
case "\$cmd" in
  is-active)
    quiet=0
    [ "\$1" = "--quiet" ] && { quiet=1; shift; }
    if [ -f "$WORK/server.pid" ] && kill -0 "\$(cat "$WORK/server.pid")" 2>/dev/null; then
      [ "\$quiet" -eq 1 ] || echo active
      exit 0
    fi
    [ "\$quiet" -eq 1 ] || echo inactive
    exit 3
    ;;
  daemon-reload) exit 0;;
  enable)
    for u in "\$@"; do
      [ "\$u" = "--now" ] && continue
      if [ "\$u" = "partout-server.service" ]; then
        UNIT="$ROOT/etc/systemd/system/partout-server.service"
        ENVFILE="\$(grep -m1 '^EnvironmentFile=' "\$UNIT" | cut -d= -f2)"
        set -a; . "\$ENVFILE"; set +a
        CMDLINE="\$(awk '/^ExecStart=/{sub(/^ExecStart=/,""); printf "%s ", \$0; next} /^ /{printf "%s ", \$0} END{print ""}' "\$UNIT" | sed 's/\\\\//g')"
        nohup \$CMDLINE >> "$WORK/server.log" 2>&1 &
        echo \$! > "$WORK/server.pid"
      fi
    done
    exit 0;;
  stop|disable)
    [ -f "$WORK/server.pid" ] && kill "\$(cat "$WORK/server.pid")" 2>/dev/null || true
    rm -f "$WORK/server.pid"
    exit 0;;
  *) echo "mock systemctl: unsupported: \$cmd \$*" >&2; exit 1;;
esac
EOF
chmod +x "$MOCKBIN/systemctl"

tree_hash() { (cd "$ROOT" && find . -type f | sort | xargs sha256sum 2>/dev/null) | sha256sum | cut -d' ' -f1; }

echo "==> building the real binary"
(cd "$REPO" && go build -o "$WORK/partout" ./cmd/partout)
VERSION_NOW="$("$WORK/partout" --version | awk '{print $2}')"

run_install() {
  (cd "$REPO" && PARTOUT_INSTALL_TEST_ROOT="$ROOT" bash scripts/install-server.sh \
    --binary "$WORK/partout" --port "$PORT" "$@" 2>&1)
}

echo
echo "==> scenario 1: dry run touches nothing"
H0=$(tree_hash)
OUT=$(run_install --dry-run)
check_grep "dry-run: completes" "$OUT" "dry run complete"
H1=$(tree_hash)
check_true "dry-run: no file changes" "$([ "$H0" = "$H1" ] && echo 1 || echo 0)" "$OUT"

echo
echo "==> scenario 2: fresh install (real layout, real server start)"
OUT=$(run_install)
echo "$OUT" | sed 's/^/    | /'
check_grep "install: exits healthy" "$OUT" "installed and healthy"
check_grep "install: summary shows the UI URL" "$OUT" "http://.*:$PORT/"
check_grep "install: admin password file named" "$OUT" "admin_password.txt"
# The REAL server generated the first-run admin password next to the db.
sleep 1
check "server: admin_password.txt created by the real server" test -f "$ROOT/var/lib/partout/admin_password.txt"
# healthz via the script's own verify already passed; probe directly too.
check "server: /healthz answers" bash -c "curl -sf http://127.0.0.1:$PORT/healthz | grep -q status"
# Layout.
check "layout: binary installed" test -x "$ROOT/usr/local/bin/partout"
check "layout: env file 0600" test "$(stat -c %a "$ROOT/etc/partout/server.env")" = "600"
check "layout: env has generated admin token" grep -q "^PARTOUT_TOKEN_ADMIN=[0-9a-f]\{48\}$" "$ROOT/etc/partout/server.env"
check "layout: units installed" test -f "$ROOT/etc/systemd/system/partout-server.service" -a -f "$ROOT/etc/systemd/system/partout-backup.timer"
check "layout: backup script installed" test -x "$ROOT/usr/local/sbin/partout-backup.sh"
# The unit the script installed must reference the TEST-root paths (so the
# mock started the server from them) and carry the chosen port.
check "unit: ExecStart points at the test-root binary" grep -q "ExecStart=$ROOT/usr/local/bin/partout" "$ROOT/etc/systemd/system/partout-server.service"
check "unit: port rewritten" grep -q -- "--port=$PORT" "$ROOT/etc/systemd/system/partout-server.service"
check "unit: db points at the test root" grep -q -- "--db=$DB" "$ROOT/etc/systemd/system/partout-server.service"
check "unit: EnvironmentFile prefixed" grep -q "EnvironmentFile=$ROOT/etc/partout/server.env" "$ROOT/etc/systemd/system/partout-server.service"
check "systemctl: backup timer enabled" grep -q "enable --now partout-backup.timer" "$WORK/systemctl.log"
check_grep "summary: generated CLI token printed once" "$OUT" "PARTOUT_TOKEN_ADMIN="

echo
echo "==> scenario 3: idempotent re-run (healthy + same version)"
H_BEFORE=$(tree_hash)
OUT=$(run_install)
check_grep "re-run: early-out" "$OUT" "already active and healthy"
H_AFTER=$(tree_hash)
check_true "re-run: no file changes" "$([ "$H_BEFORE" = "$H_AFTER" ] && echo 1 || echo 0)" ""

echo
echo "==> scenario 4: env preserved on an uncleaned re-run"
echo "# operator edit $(date +%s)" >> "$ROOT/etc/partout/server.env"
kill "$(cat "$WORK/server.pid")" 2>/dev/null || true; rm -f "$WORK/server.pid"; sleep 1
OUT=$(run_install)
check "uncleaned re-run: env kept" grep -q "operator edit" "$ROOT/etc/partout/server.env"
check_grep "uncleaned re-run: installs + healthy again" "$OUT" "installed and healthy"

echo
echo "==> scenario 5: version refusal while the service runs"
(cd "$REPO" && go build -ldflags "-X github.com/blawesom/partout/internal/agent/facts.Version=v9.9.9-test" -o "$WORK/partout-v99" ./cmd/partout)
H_BEFORE=$(tree_hash)
set +e
OUT=$( (cd "$REPO" && PARTOUT_INSTALL_TEST_ROOT="$ROOT" bash scripts/install-server.sh --binary "$WORK/partout-v99" --port "$PORT") 2>&1 )
RC=$?
set -e
check_true "refusal: non-zero exit" "$([ $RC -ne 0 ] && echo 1 || echo 0)" "rc=$RC"
check_grep "refusal: points at update-server.sh" "$OUT" "update-server.sh"
H_AFTER=$(tree_hash)
check_true "refusal: binary not replaced" "$([ "$H_BEFORE" = "$H_AFTER" ] && echo 1 || echo 0)" ""
check "server: still the original version" test "$("$ROOT/usr/local/bin/partout" --version | awk '{print $2}')" = "$VERSION_NOW"

echo
echo "==> scenario 6: non-default --db rewrite"
kill "$(cat "$WORK/server.pid")" 2>/dev/null || true; rm -f "$WORK/server.pid"; sleep 1
OUT=$(run_install --db /var/lib/partout/custom.db)
check "custom db: unit rewritten" grep -q -- "--db=$ROOT/var/lib/partout/custom.db" "$ROOT/etc/systemd/system/partout-server.service"
check "custom db: server healthy on it" test -f "$ROOT/var/lib/partout/custom.db"

echo
echo "install-server-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
