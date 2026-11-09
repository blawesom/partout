#!/usr/bin/env bash
# check-readme — the anti-rot gate for docs, run in CI (see .github/workflows/ci.yml):
#
#   1. Link check: every relative markdown link (file.md, ./dir/, ../x) in
#      README.md, *.md at the repo root, and docs/**.md must resolve to an
#      existing file. Dead links fail the build.
#   2. Quickstart smoke: executes the README quickstart for real — builds the
#      binary, boots the embedded demo on a scratch port with a scratch DB,
#      waits for /healthz, then runs the README's CLI verification commands
#      (auth login, hosts, run --selector all -- hostname, audit verify).
#
# Usage: scripts/check-readme.sh [--links-only]   (no args = links + smoke)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

fail=0

# ---------- 1. relative link check ----------
link_check() {
  local files f raw t
  files="$( { ls README.md PRD.md CONTRIBUTING.md SECURITY.md partout.review.md 2>/dev/null || true
               find docs -name '*.md'; } )"
  while IFS= read -r f; do
    # markdown links: [text](target) — skip absolute URLs and pure anchors
    while IFS= read -r raw; do
      t="${raw%%#*}"; t="${t%% *}"
      [ -z "$t" ] && continue
      case "$t" in /*) continue;; esac
      if [ ! -e "$(dirname "$f")/$t" ]; then
        echo "DEAD LINK in $f -> $t"
        echo "$f" >> "$TMPDIR/deadlinks"
      fi
    done < <(grep -oE '\]\([^)#]+\)' "$f" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' | grep -vE '^[a-z]+://' || true)
  done <<< "$files"
  if [ -s "$TMPDIR/deadlinks" ]; then
    echo "check-readme: $(sort -u "$TMPDIR/deadlinks" | wc -l) file(s) with dead relative links"
    fail=1
  else
    echo "check-readme: all relative links in README/root/docs resolve"
  fi
}

TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
: > "$TMPDIR/deadlinks"

link_check

if [ "${1:-}" = "--links-only" ]; then
  [ "$fail" -eq 0 ] && echo "check-readme: OK (links only)" || { echo "check-readme: FAILED"; exit 1; }
  exit 0
fi

# ---------- 2. quickstart smoke (README quick start, executed) ----------
echo "check-readme: running the README quickstart for real (embedded mode)..."
command -v go >/dev/null || { echo "check-readme: go not found, skipping smoke"; exit $fail; }

go build -o "$TMPDIR/partout" ./cmd/partout

PORT="$(python3 - <<'EOF'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
EOF
)"
WORK="$TMPDIR/run"; mkdir -p "$WORK"
PW="smoke-test-pw-123"

( cd "$WORK" && PARTOUT_MODE=embedded PARTOUT_PORT="$PORT" \
    PARTOUT_ADMIN_PASSWORD="$PW" "$TMPDIR/partout" >server.log 2>&1 ) &
SRV=$!
# || true: under set -e a failing kill in the EXIT trap would override the
# script's real exit status with 1.
trap 'kill $SRV 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

# wait for /healthz (up to 30s)
up=0
for i in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 $SRV 2>/dev/null || { echo "check-readme: server died during boot"; tail -5 "$WORK/server.log"; exit 1; }
  sleep 0.5
done
[ "$up" = 1 ] || { echo "check-readme: /healthz never came up"; tail -5 "$WORK/server.log"; exit 1; }
echo "check-readme: server up on 127.0.0.1:$PORT"

SRVURL="127.0.0.1:$PORT"
# README verify block: auth login, hosts, run, audit verify
"$TMPDIR/partout" ctl --server "$SRVURL" auth login --username admin --password "$PW" 2>/dev/null

# The co-located embedded agent registers asynchronously after boot — poll
# `ctl hosts` (up to 20s) until the fleet shows 1 host before running against it.
HOSTS_OUT=""
host_up=0
for i in $(seq 1 40); do
  HOSTS_OUT="$("$TMPDIR/partout" ctl --server "$SRVURL" hosts 2>&1 || true)"
  if echo "$HOSTS_OUT" | grep -qE "1 host\(s\)"; then host_up=1; break; fi
  sleep 0.5
done
[ "$host_up" = 1 ] || { echo "check-readme: 'ctl hosts' did not show the co-located host:"; echo "$HOSTS_OUT"; fail=1; }

RUN_OUT="$("$TMPDIR/partout" ctl --server "$SRVURL" run --selector all -- hostname 2>&1)"
echo "$RUN_OUT" | grep -qE "ok|success|$(hostname)" \
  || { echo "check-readme: 'ctl run --selector all -- hostname' did not succeed:"; echo "$RUN_OUT"; fail=1; }

AUDIT_OUT="$("$TMPDIR/partout" ctl --server "$SRVURL" audit verify 2>&1)"
echo "$AUDIT_OUT" | grep -qiE "ok|valid|verified" \
  || { echo "check-readme: 'ctl audit verify' did not report OK:"; echo "$AUDIT_OUT"; fail=1; }

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null || true

if [ "$fail" -ne 0 ]; then
  echo "check-readme: FAILED"
  exit 1
fi
echo "check-readme: OK (links + quickstart smoke)"
