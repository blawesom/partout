#!/usr/bin/env bash
# release-github.sh — create a GitHub Release for a tag (v0.7.x pattern):
# binary tarballs per arch + SHA-256SUMS + a changelog from the git log.
#
# This is the DOWNLOADABLE release (manual installs, `partout selftest`
# preflight targets). It is distinct from release-publish.sh, which builds
# the SIGNED repository that `partout update` consumes — a GitHub Release
# is not a signed release; the fleet upgrade path signs separately.
#
# Usage:
#   bash scripts/release-github.sh v0.9.0              # after the tag exists
#   bash scripts/release-github.sh v1.0.0-rc.1 --prerelease
#   bash scripts/release-github.sh v0.9.0 --target <full-sha>   # detached tag
#   DRY_RUN=1 bash scripts/release-github.sh v0.9.0    # build assets, no gh call
#
# Requires: gh (authenticated), git, go.
set -euo pipefail
export PATH="$PATH:/usr/local/go/bin"

TAG=""
PRERELEASE=0
TARGET=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prerelease) PRERELEASE=1; shift ;;
    --target) TARGET="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) if [ -z "$TAG" ]; then TAG="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

[ -n "$TAG" ] || { echo "usage: release-github.sh <tag> [--prerelease] [--target SHA]" >&2; exit 2; }
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || { echo "tag $TAG does not exist" >&2; exit 1; }
VER="${TAG#v}"

T="$(mktemp -d /tmp/partout-ghrel.XXXXXX)"
trap 'rm -rf "$T"' EXIT

echo "==> building tarballs for $TAG"
for GOARCH in amd64 arm64; do
  mkdir -p "$T/dist/partout_linux_${GOARCH}"
  CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath \
    -ldflags "-s -w -X github.com/blawesom/partout/internal/agent/facts.Version=$VER" \
    -o "$T/dist/partout_linux_${GOARCH}/partout" ./cmd/partout
  ( cd "$T/dist" && tar czf "partout_${VER}_linux_${GOARCH}.tar.gz" "partout_linux_${GOARCH}" )
done
( cd "$T/dist" && sha256sum *.tar.gz > SHA-256SUMS )

# Guard: the version stamp must actually be in the binary (the UI sidebar
# and `partout update` both rely on it). Fail the release, don't publish it.
STAMPED_OUT="$("$T/dist/partout_linux_amd64/partout" --version)"
case "$STAMPED_OUT" in
  *"$VER"*) echo "  version stamp ok: $STAMPED_OUT" ;;
  *) echo "FATAL: binary reports '$STAMPED_OUT', want stamp '$VER' — refusing to release" >&2; exit 1 ;;
esac

echo "==> changelog"
PREV="$(git describe --tags --abbrev=0 "${TAG}^" 2>/dev/null || true)"
{
  echo "# $TAG"
  echo
  if [ -n "$PREV" ]; then
    echo "Changes since $PREV:"
    echo
    git log --no-decorate --pretty='  * %s' "${PREV}..${TAG}"
  else
    echo "Initial release."
  fi
} > "$T/notes.md"
wc -l < "$T/notes.md" | xargs echo "  notes lines:"

cp "$T/dist"/*.tar.gz "$T/"
cp "$T/dist/SHA-256SUMS" "$T/"

ASSETS=("$T"/partout_"${VER}"_linux_*.tar.gz "$T/SHA-256SUMS")

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo
  echo "DRY RUN — would execute:"
  ARGS=(release create "$TAG" --title "Partout $TAG" --notes-file "$T/notes.md" --repo blawesom/partout)
  [ "$PRERELEASE" = "1" ] && ARGS+=(--prerelease)
  [ -n "$TARGET" ] && ARGS+=(--target "$TARGET")
  ARGS+=("${ASSETS[@]}")
  echo "  gh ${ARGS[*]}"
  echo
  cat "$T/notes.md"
  exit 0
fi

ARGS=(release create "$TAG" --title "Partout $TAG" --notes-file "$T/notes.md" --repo blawesom/partout)
[ "$PRERELEASE" = "1" ] && ARGS+=(--prerelease)
[ -n "$TARGET" ] && ARGS+=(--target "$TARGET")
ARGS+=("${ASSETS[@]}")
echo "==> gh ${ARGS[*]}"
gh "${ARGS[@]}"
echo "GitHub release $TAG created."
