#!/usr/bin/env bash
# check-config-docs — every PARTOUT_* env var the code reads must be
# documented in the deployment config table (docs/deployment.md §4), so an
# operator can configure the product from the docs alone.
#
# Found real gaps on first run: PARTOUT_CADDY_CONF / HAPROXY_CONF /
# NGINX_CONF (observe collectors), PARTOUT_ADMIN_TOKEN / RELEASE_REPO /
# RELEASE_KEY_PRIV / PASSWORD (CLI + update tool) — seven knobs an operator
# could not have discovered from the docs.
#
# Usage: scripts/check-config-docs.sh   (no arguments; exits non-zero on gaps)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Test/harness-only variables, deliberately not operator config:
#   PARTOUT_LIVE_*, PARTOUT_UPDATE_*, PARTOUT_GUARD_BIN, PARTOUT_CAT,
#   PARTOUT_TEST_* — scripts/ and *_test.go plumbing.
HARNESS_RE='^PARTOUT_(LIVE_|UPDATE_|GUARD_BIN|CAT|TEST_)'

vars_code() {
  # Env vars read by non-test production code (internal/ + cmd/).
  grep -rlE 'PARTOUT_' "$REPO/internal" "$REPO/cmd" --include='*.go' 2>/dev/null \
    | grep -v '_test\.go$' \
    | xargs grep -hoE 'PARTOUT_[A-Z0-9_]+' 2>/dev/null \
    | sort -u \
    | grep -Ev "$HARNESS_RE" || true
}

vars_docs() {
  # Operator-facing documentation corpus (deployment table + operations).
  grep -hoE 'PARTOUT_[A-Z0-9_]+' "$REPO/docs/deployment.md" "$REPO/docs/operations.md" 2>/dev/null | sort -u
}

missing=0
while IFS= read -r v; do
  if ! grep -qxF "$v" <(vars_docs); then
    echo "FAIL  $v is read by the code but not documented in docs/deployment.md (or operations.md)"
    missing=$((missing + 1))
  fi
done < <(vars_code)

if [ "$missing" -gt 0 ]; then
  echo "check-config-docs: $missing undocumented variable(s)"
  exit 1
fi
echo "check-config-docs: every PARTOUT_* variable the code reads is documented"
