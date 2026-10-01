#!/bin/sh
# partout-update-guard — M8.1 boot guard for the agent (PRD §11).
#
# The agent writes <data-dir>/update.json (plain key=value, no runtime
# dependency to parse) just before swapping its own binary and restarting.
# A successful new version removes the marker on its first stream connect.
# So when we start and the marker is STILL present:
#
#   - fresh (within the health window) and the on-disk binary matches the
#     target version → first boot right after a swap: run it. If it
#     crash-loops, systemd invokes us again; once the marker goes stale we
#     roll back (no human on the host).
#   - otherwise (stale marker, or binary/target mismatch) → the update did
#     not complete: restore the retained N-1 binary, clear the marker, and
#     start the old version.
#
# Dependencies: /bin/sh, sed, date, awk (all base-system).
set -u

BIN="${PARTOUT_GUARD_BIN:-/usr/local/bin/partout}"
DATA_DIR="${PARTOUT_AGENT_DATA_DIR:-/var/lib/partout/agent}"
HEALTH_S="${PARTOUT_UPDATE_HEALTH_S:-60}"
# Grace beyond the health window before a "fresh" marker is declared stale.
# 120 s covers a slow first boot of a big binary; tests shrink it.
GRACE_S="${PARTOUT_UPDATE_GUARD_GRACE_S:-120}"
MARKER="$DATA_DIR/update.json"

# No marker → nothing to supervise; run the real binary directly.
[ -f "$MARKER" ] || exec "$BIN" "$@"

get() { sed -n "s/^$1=//p" "$MARKER" | head -n 1; }
target="$(get target_version)"
started="$(get started_at)"
prev="$(get prev_binary)"

# Corrupt/empty marker: clear it and continue (the agent side re-checks).
[ -n "$target" ] || { rm -f "$MARKER"; exec "$BIN" "$@"; }

now="$(date +%s)"
age=$(( now - ${started:-$now} ))
curver="$("$BIN" --version 2>/dev/null | awk '{print $NF}')"

# Compare v-insensitively: the binary stamp never carries a leading "v"
# ("partout 0.9.4") while a registered release version may ("v0.9.4").
# Exact equality misread a healthy v-prefixed target as a failed update
# and rolled back; mirror internal/version.Equal (strip one leading v).
strip_v() { case "$1" in v*) printf '%s' "${1#v}" ;; *) printf '%s' "$1" ;; esac; }
curver="$(strip_v "$curver")"
target="$(strip_v "$target")"

if [ "$curver" = "$target" ] && [ "$age" -le $(( HEALTH_S + GRACE_S )) ]; then
	# New binary within the health window: first boot after the swap. The
	# agent clears the marker on its first successful connect.
	exec "$BIN" "$@"
fi

# The update did not complete (new binary crash-looping, or a partial swap):
# roll back to the retained N-1 binary, if any.
if [ -n "$prev" ] && [ -f "$prev" ]; then
	if ! mv -f "$prev" "$BIN"; then
		echo "partout-update-guard: FAILED to restore $prev over $BIN" >&2
	fi
fi
rm -f "$MARKER"
echo "partout-update-guard: rolled back failed update (target=$target, age=${age}s) to N-1" >&2
exec "$BIN" "$@"
