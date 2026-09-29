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

if [ "$curver" = "$target" ] && [ "$age" -le $(( HEALTH_S + 120 )) ]; then
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
