#!/usr/bin/env bash
# rocky-e2e.sh — the REAL-install CI leg on a RHEL-family host.
#
# Why this leg exists: every bootstrap bug from the v0.9.11 field run
# (FIELD-REPORT-v0.9.11-2026-10-04 §2) lived in a path no other rig
# exercises — install-server-test.sh runs under a test root with user
# creation skipped, and the provision e2e tests drive fake ssh binaries:
#
#   B1  elevation-policy sha mismatch (formatted JSON vs canonical hash)
#       → the provision fails at install                     [this leg: step 8]
#   B2  /etc/partout/elevation.d created 0700 by the install umask
#       → the agent cannot load its policy                   [this leg: step 9]
#   B3  dnf dry-run never elevated (dnf refuses to simulate
#       as non-root) → dry summary is an error text          [this leg: step 12]
#   F1  install-server.sh aborted on RHEL (useradd vs the pre-created
#       group)                                               [this leg: step 4]
#   F15 the backup timer raced the server boot (SQLITE_BUSY) [this leg: step 5]
#   F6  sudoers wildcard rendering (quoted = dead grants)   [this leg: step 10]
#
# plus the real target-side chain end to end: install-server.sh as root on
# real Rocky (useradd, visudo, dnf), the provisioner's install script
# over real ssh, the agent actually running, elevated and unprivileged
# dispatch, the packages dry-run, and a PTY session.
#
# Environment: a Rocky/Alma/RHEL-family container (or host) with network,
# running as root, WITHOUT systemd — a mock systemctl starts the units for
# real by parsing them (EnvironmentFile + ExecStart), same approach as
# install-server-test.sh. On a non-RHEL-family host this script prints a
# loud SKIP and exits 0 (it is wired into ci.yml's container job and
# beta-gate's leg list).
#
# Usage: bash scripts/rocky-e2e.sh
set -uo pipefail
export PATH="$PATH:/usr/local/go/bin:/root/go/bin"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT=18443
ADMIN_TOKEN="rocky-ci-admin-token"
PASS=0; FAIL=0

cleanup() {
  for pid in /run/partout-mock/*.pid; do
    [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n==> %s\n' "$*"; }
step() { printf '\n  ---- %s\n' "$*"; }
check() { # <name> <condition...>
  local name="$1"; shift
  if "$@"; then PASS=$((PASS+1)); echo "  PASS $name"
  else FAIL=$((FAIL+1)); echo "  FAIL $name  <<<"; fi
}
check_grep() { # <name> <haystack> <pattern>
  if printf '%s' "$2" | grep -q "$3"; then PASS=$((PASS+1)); echo "  PASS $1"
  else FAIL=$((FAIL+1)); echo "  FAIL $1  <<< no match: $3"; fi
}
check_not_grep() { # <name> <haystack> <pattern> — must NOT match
  if printf '%s' "$2" | grep -q "$3"; then FAIL=$((FAIL+1)); echo "  FAIL $1  <<< unexpected match: $3"
  else PASS=$((PASS+1)); echo "  PASS $1"; fi
}

# --- family gate -------------------------------------------------------------
if ! grep -qE 'rocky|rhel|almalinux|centos' /etc/os-release 2>/dev/null; then
  echo "SKIP rocky-e2e: not a RHEL-family host ($(grep PRETTY_NAME /etc/os-release 2>/dev/null || echo unknown))"
  exit 0
fi

# --- 1. container prerequisites (no systemd here; sshd runs directly) --------
say "prerequisites (openssh, sudo, a deploy user with NOPASSWD sudo)"
dnf install -y -q openssh-server openssh-clients sudo curl tar git python3 procps-ng >/dev/null 2>&1 || dnf install -y openssh-server openssh-clients sudo curl tar git python3 procps-ng
ssh-keygen -A
mkdir -p /run/sshd
useradd -m deploy 2>/dev/null || true
# A useradd'd account has no password hash = LOCKED, and sshd refuses
# locked accounts even for pubkey auth — set the "no password, not
# locked" marker so the pubkey-only flow works.
usermod -p '*' deploy
echo "deploy ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/deploy
chmod 0440 /etc/sudoers.d/deploy
/usr/sbin/sshd -o UsePAM=no
check "sshd is running" pgrep -x sshd

# --- mock systemctl: starts units FOR REAL by parsing them -------------------
say "mock systemctl (no systemd in the container; units start for real)"
mkdir -p /run/partout-mock /var/log/partout-mock
cat > /usr/local/bin/systemctl <<'EOF'
#!/usr/bin/env bash
# rocky-e2e mock systemctl: daemon-reload is a no-op; enable/start/restart
# parse the unit (EnvironmentFile + ExecStart, joining continuations) and
# run it for real under nohup, tracking the pid per unit.
set -u
mkdir -p /run/partout-mock /var/log/partout-mock
cmd="$1"; shift
unit_pidfile() {
  case "$1" in
    partout-server*) echo /run/partout-mock/server.pid;;
    partout-agent*) echo /run/partout-mock/agent.pid;;
    partout-backup*) echo /run/partout-mock/backup.pid;;
    *) echo "/run/partout-mock/$(echo "$1" | tr -c 'a-zA-Z0-9' '_').pid";;
  esac
}
start_unit() {
  local unit="$1" pf envfile cmdline
  # systemctl accepts bare names (enable partout-agent); the unit file
  # on disk carries the .service suffix.
  case "$unit" in *.service|*.timer|*.socket) ;; *) unit="$unit.service";; esac
  pf="$(unit_pidfile "$unit")"
  [ -f "/etc/systemd/system/$unit" ] || { echo "mock systemctl: no unit $unit" >&2; exit 1; }
  # stop a previous instance
  [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null
  unit="/etc/systemd/system/$unit"
  envfile="$(grep -m1 '^EnvironmentFile=' "$unit" | cut -d= -f2)"
  if [ -n "${envfile:-}" ] && [ -f "$envfile" ]; then set -a; . "$envfile"; set +a; fi
  cmdline="$(awk '/^ExecStart=/{sub(/^ExecStart=/,""); printf "%s ", $0; next} /^ /{printf "%s ", $0} END{print ""}' "$unit" | tr -d '\\')"
  # Honor User=/Group= (fidelity: the agent MUST run unprivileged or the
  # elevation assertions are meaningless). setpriv execs directly, so the
  # tracked pid is the service process itself.
  runas=""
  svcuser="$(grep -m1 '^User=' "$unit" | cut -d= -f2)"
  if [ -n "${svcuser:-}" ] && [ "$(id -u)" = "0" ] && [ "$svcuser" != "root" ]; then
    uid="$(id -u "$svcuser")"; gid="$(id -g "$svcuser")"
    # env HOME=... mirrors what systemd does for User= units (setpriv
    # alone would keep the caller's HOME — e.g. /root — and anything
    # resolving ~ from $HOME would look in the wrong place).
    runas="setpriv --reuid=$uid --regid=$gid --init-groups env HOME=$(eval echo ~"$svcuser")"
  fi
  nohup $runas $cmdline >> "/var/log/partout-mock/$(basename "$pf" .pid).log" 2>&1 &
  echo $! > "$pf"
  exit 0
}
case "$cmd" in
  daemon-reload) exit 0;;
  enable)
    for u in "$@"; do
      [ "$u" = "--now" ] && continue
      case "$u" in *.service|*.timer) ;; *) continue;; esac
      # timers: fire the service once (the backup timer's Persistent
      # behavior at enable is what the install relies on)
      if [ "${u%.timer}" != "$u" ]; then start_unit "${u%.timer}.service" || true; continue; fi
      start_unit "$u" || exit 1
    done
    exit 0;;
  start|restart)
    last=""
    for u in "$@"; do case "$u" in --*) ;; *) last="$u";; esac; done
    [ -n "$last" ] && start_unit "$last"
    exit 0;;
  stop|disable)
    for u in "$@"; do
      pf="$(unit_pidfile "$u")"
      [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null
      rm -f "$pf"
    done
    exit 0;;
  is-active)
    [ "$1" = "--quiet" ] && shift
    pf="$(unit_pidfile "$1")"
    if [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then echo active; exit 0; fi
    echo inactive; exit 3;;
  is-enabled) exit 0;;
  status) exit 0;;
  *) echo "mock systemctl: unsupported: $cmd $*" >&2; exit 1;;
esac
EOF
chmod +x /usr/local/bin/systemctl
# sudo's secure_path excludes /usr/local/bin — the provisioner's install
# script runs via `sudo -n bash`, so the mock must ALSO live inside
# secure_path or the REAL systemctl runs there ("System has not been
# booted with systemd" — caught on this rig).
install -m 0755 /usr/local/bin/systemctl /usr/sbin/systemctl
check "mock systemctl is on PATH" test -x /usr/sbin/systemctl

# --- 2. build -----------------------------------------------------------------
say "building the binary"
# PARTOUT_BIN: a prebuilt (static) binary may be supplied — the CI job
# builds on the runner (with the Go toolchain cache) and mounts it into
# the container; locally the script builds in-place.
if [ -n "${PARTOUT_BIN:-}" ] && [ -x "$PARTOUT_BIN" ]; then
  cp "$PARTOUT_BIN" "$WORK/partout"
else
  (cd "$REPO" && CGO_ENABLED=0 go build -o "$WORK/partout" ./cmd/partout)
fi
check "binary reports a version" "$WORK/partout" --version

# --- 3. real install-server.sh, as root, TLS on -------------------------------
say "install-server.sh (REAL system paths — no test root)"
OUT=$(cd "$REPO" && bash scripts/install-server.sh \
  --binary "$WORK/partout" --port "$PORT" --tls on --tls-names "localhost,127.0.0.1" \
  --admin-password 'rocky-ci-pass-123' --token-admin "$ADMIN_TOKEN" 2>&1) || true
echo "$OUT" | tail -20 | sed 's/^/    | /'
check_grep "install: completed healthy (F1: RHEL useradd)" "$OUT" "installed and healthy"
check "install: healthz answers over TLS" bash -c "curl -sk https://127.0.0.1:$PORT/healthz | grep -q status"
check "install: partout user created with the pre-made group (F1)" id partout
for i in $(seq 1 15); do
  ls /var/lib/partout/backups/partout.db.*.bak >/dev/null 2>&1 && test -s "$(ls -t /var/lib/partout/backups/partout.db.*.bak 2>/dev/null | head -1)" && break
  sleep 1
done
check "install: backup snapshot exists — no boot race (F15)" bash -c 'ls /var/lib/partout/backups/partout.db.*.bak >/dev/null 2>&1 && test -s "$(ls -t /var/lib/partout/backups/partout.db.*.bak 2>/dev/null | head -1)"'

# --- 4. doctor against the effective config, on the LIVE server ---------------
say "doctor --env-file on the live server"
DOCOUT=$(/usr/local/bin/partout doctor --env-file /etc/partout/server.env \
  --port "$PORT" --db /var/lib/partout/partout.db --tls on 2>&1) || true
echo "$DOCOUT" | tail -8 | sed 's/^/    | /'
check_grep "doctor: live port is a warning, not a FAIL (D5)" "$DOCOUT" "in use by a healthy Partout listener"
check_not_grep "doctor: no hard failures" "$DOCOUT" "NOT ready"

# --- 5. provisioning prerequisites: server host + the service user's ssh key ---
say "PARTOUT_SERVER_HOST + ssh trust (partout -> deploy@localhost)"
# 127.0.0.1, not localhost: the agent's gRPC dial resolves localhost to
# ::1 first and containers commonly have no IPv6 loopback listener — the
# connection is refused with no fallback (field-caught on this rig).
sed -i "/^PARTOUT_SERVER_HOST=/d" /etc/partout/server.env
echo "PARTOUT_SERVER_HOST=127.0.0.1:$PORT" >> /etc/partout/server.env
systemctl restart partout-server.service
for i in $(seq 1 20); do curl -sk "https://127.0.0.1:$PORT/healthz" | grep -q '"status"' && break; sleep 1; done
check "server restarted with PARTOUT_SERVER_HOST" bash -c "curl -sk https://127.0.0.1:$PORT/healthz | grep -q status"

install -d -m 0700 -o partout -g partout /var/lib/partout/.ssh
rm -f /var/lib/partout/.ssh/id_ed25519 /var/lib/partout/.ssh/id_ed25519.pub
sudo -u partout ssh-keygen -q -t ed25519 -N "" -f /var/lib/partout/.ssh/id_ed25519
# Hermetic re-runs: a previous run may leave a known_hosts entry (skips
# the key_confirm gate), a root-owned materialized config (the service
# user cannot read it), or stale agent state.
chown partout:partout /var/lib/partout/.ssh/config 2>/dev/null || true
rm -f /var/lib/partout/.ssh/known_hosts /var/lib/partout/.ssh/known_hosts.old
rm -rf /var/lib/partout/agent /etc/partout/agent.env /etc/partout/elevation.d /etc/sudoers.d/partout-agent
install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
cat /var/lib/partout/.ssh/id_ed25519.pub > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys && chmod 0600 /home/deploy/.ssh/authorized_keys
# NOTE: a separate known_hosts — the probe must not pre-trust the host
# for the provisioner (that would skip the key_confirm gate below).
check "ssh trust works (partout -> deploy@localhost)" sudo -u partout ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/rocky-e2e-trust-kh deploy@localhost true
rm -f /tmp/rocky-e2e-trust-kh

CTL="$WORK/ctl"
cat > "$CTL" <<EOF
#!/usr/bin/env bash
exec "$WORK/partout" ctl --server https://127.0.0.1:$PORT --ca-file /var/lib/partout/tls/ca.crt --token "$ADMIN_TOKEN" "\$@"
EOF
chmod +x "$CTL"

# --- 6. provision with --elevate (the D1 flow, over real ssh) ------------------
say "provision new --elevate (default-baseline policy, labels)"
PROVOUT=$("$CTL" provision new --host deploy@localhost --elevate --service-labels sshd 2>&1) || true
echo "$PROVOUT" | sed 's/^/    | /'
check_grep "provision: run started with the elevation bootstrap" "$PROVOUT" "elevation: bootstrap included"

# key_confirm gate: confirm the captured fingerprint (the TOFU pause)
RUN_ID=""
for i in $(seq 1 15); do
  RUN_ID=$("$CTL" provision list 2>/dev/null | awk '/prv_/{print $1; exit}')
  [ -n "$RUN_ID" ] && break
  sleep 1
done
# queued -> connecting -> key_confirm: wait for the pause (the keyscan can
# take a moment; confirming early is a 409).
STATE=""
for i in $(seq 1 30); do
  STATE=$("$CTL" provision get "$RUN_ID" 2>/dev/null | head -1)
  echo "$STATE" | grep -q "key_confirm" && break
  echo "$STATE" | grep -qE "\[(connected|failed)\]" && break
  sleep 1
done
check_grep "provision: paused at key_confirm (TOFU)" "$STATE" "key_confirm"
"$CTL" provision key "$RUN_ID" confirm >/dev/null 2>&1

# wait for the terminal state
FINAL=""
for i in $(seq 1 90); do
  FINAL=$("$CTL" provision get "$RUN_ID" 2>/dev/null | head -1)
  echo "$FINAL" | grep -qE "\[(connected|failed)\]" && break
  sleep 2
done
echo "$FINAL"
check_grep "provision: run connected (B1: policy sha verified)" "$FINAL" "\[connected\]"
check_grep "provision: agent enrolled at the build version" "$("$CTL" provision get "$RUN_ID" 2>/dev/null)" "agent:"

# --- 7. the D1 artifacts on the target ------------------------------------------
step "elevation bootstrap artifacts on the target"
check "elevation.d exists" test -d /etc/partout/elevation.d
MODE=$(stat -c %a /etc/partout/elevation.d)
check "elevation.d is 0755, not 0700 (B2: umask)" test "$MODE" = "755"
check "policy drop-in installed" test -f /etc/partout/elevation.d/10-default-baseline.json
check "PARTOUT_ELEVATE wired in agent.env" grep -q "^PARTOUT_ELEVATE=sudo" /etc/partout/agent.env
check "service labels wired" grep -q "^PARTOUT_SERVICE_LABELS=sshd" /etc/partout/agent.env
check "agent is running" systemctl is-active partout-agent.service
check_grep "agent: policy loaded (B2: readable)" "$(tail -50 /var/log/partout-mock/agent.log)" "elevation policy loaded"

# --- 8. the sudoers wall (F6: unquoted wildcards, F11: bare reboot) -------------
step "sudoers drop-in"
SUDOERS=$(cat /etc/sudoers.d/partout-agent 2>/dev/null)
check_grep "sudoers: unquoted wildcard grant (F6)" "$SUDOERS" "dnf -y install \*"
check_grep "sudoers: bare reboot renders as the no-args specifier (F11)" "$SUDOERS" 'reboot ""'
check_not_grep "sudoers: no quoted globs (F6)" "$SUDOERS" '"\*"'

# --- 8b. join-mode re-provision links the existing agent ------------------------
step "join-mode re-provision (existing agent, real identity.json)"
AGENT_ID=$("$CTL" hosts | awk '/ag_/{print $1; exit}')
JOINOUT=$("$CTL" provision new --host deploy@localhost --mode join --elevate --service-labels sshd 2>&1) || true
JRID=$(printf '%s' "$JOINOUT" | grep -o "prv_[a-z0-9]*" | head -1)
[ -z "$JRID" ] && JRID=$("$CTL" provision list 2>/dev/null | awk '/prv_/{print $1; exit}')
JFINAL=""
for i in $(seq 1 60); do
  JFINAL=$("$CTL" provision get "$JRID" 2>/dev/null | head -1)
  printf '%s' "$JFINAL" | grep -qE "\[(connected|failed)\]" && break
  sleep 2
done
echo "$JFINAL"
check_grep "join: run connected (no phantom wait-enroll)" "$JFINAL" "\[connected\]"
check_grep "join: linked to the EXISTING agent" "$("$CTL" provision get "$JRID" 2>/dev/null)" "agent: *$AGENT_ID"

# --- 9. fact hash matches the store (B1 chain + drift anchor) -------------------
step "elevation fact hash == store policy sha"
AGENT_ID=$("$CTL" hosts | awk '/ag_/{print $1; exit}')
HASH=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "https://localhost:$PORT/api/v1/hosts/$AGENT_ID/facts" | python3 -c 'import json,sys; f=json.load(sys.stdin); f=f.get("facts") or f; import json as j; print(j.loads(f["partout.elevation"]).get("hash",""))' 2>/dev/null || echo "")
STORE_SHA=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "https://localhost:$PORT/api/v1/elevation/policies/default-baseline" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("policy_sha256",""))' 2>/dev/null || echo "")
check "agent hash matches the store" test -n "$HASH" -a "$HASH" = "$STORE_SHA"

# --- 10. dispatch: elevated in-policy, unprivileged out-of-policy ----------------
step "dispatch through the elevation policy"
"$CTL" run --selector "host:$AGENT_ID" -- dnf -q makecache >/dev/null 2>&1
check "in-policy command elevates and succeeds" test "$?" -eq 0
IDOUT=$("$CTL" run --selector "host:$AGENT_ID" -- id 2>&1)
check_grep "out-of-policy command runs UNPRIVILEGED (F10)" "$IDOUT" "uid=.*partout"

# --- 11. packages dry-run (B3: elevated simulation) -------------------------------
step "packages dry-run"
DRY=$(curl -sk -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AGENT_ID\",\"dry_run\":true}" "https://localhost:$PORT/api/v1/packages/apply")
echo "$DRY" | python3 -m json.tool 2>/dev/null | head -8 | sed 's/^/    | /'
check_not_grep "dry-run: no superuser error (B3)" "$DRY" "superuser privileges"
check_grep "dry-run: succeeded" "$DRY" 'status.: *"succeeded"'

# --- 12. PTY session (F10) --------------------------------------------------------
step "PTY session under the policy"
"$CTL" sessions open --agent "$AGENT_ID" --cmd /bin/bash --record >/dev/null 2>&1
sleep 3
SID=$("$CTL" sessions list --agent "$AGENT_ID" | awk '/sess_/{print $1; exit}')
REPLAY=$("$CTL" sessions replay "$SID" 2>&1 || true)
check_grep "PTY: bash started (a prompt, not a sudo error)" "$REPLAY" '\$'
check_not_grep "PTY: no sudo failure under policy (F10)" "$REPLAY" "password is required"

# --- summary -----------------------------------------------------------------------
echo
echo "=================================================================="
if [ "$FAIL" -gt 0 ]; then
  echo "rocky-e2e: $PASS passed, $FAIL FAILED"
  echo "  agent log tail:"; tail -20 /var/log/partout-mock/agent.log 2>/dev/null | sed 's/^/    | /'
  echo "  server log tail:"; tail -10 /var/log/partout-mock/server.log 2>/dev/null | sed 's/^/    | /'
  exit 1
fi
echo "rocky-e2e: $PASS passed, 0 failed"
