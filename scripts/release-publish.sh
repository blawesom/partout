#!/usr/bin/env bash
# release-publish.sh — build, sign, and lay out a SIGNED release repository.
#
# Produces exactly the layout `partout update` (and the agent) consume:
#   <out>/<version>/partout-<version>-<arch>-server      (+ .sig)
#   <out>/<version>/partout-<version>-<arch>-agent       (+ .sig)
#   <out>/<version>/partout-<version>-<arch>-server.sig
#   <out>/<version>/partout-<version>-<arch>-agent.sig
# and, only after EVERY artifact is built, signed, and independently
# re-verified against the public key, refreshes <out>/latest.
#
# Signatures are Ed25519 over "version|arch|kind|sha256" — the same
# canonical form every consumer verifies. The operator holds the private
# key ($PARTOUT_RELEASE_KEY_PRIV or --key); the public key
# ($PARTOUT_RELEASE_KEY or --pubkey) is what fleets trust.
#
# Publishing to the real repo (S3 bucket / rsync to the server's
# PARTOUT_RELEASE_REPO dir) is intentionally NOT done here — the operator
# copies <out> afterwards. This keeps the key on the build machine and the
# layout reproducible.
#
# Usage:
#   PARTOUT_RELEASE_KEY_PRIV=... bash scripts/release-publish.sh v1.0.0-rc.1
#   bash scripts/release-publish.sh v1.0.0-rc.1 --out /tmp/rel \
#        --archs linux-amd64 --skip build-only
set -euo pipefail
export PATH="$PATH:/usr/local/go/bin"

TAG=""
OUT=""
ARCHS="linux-amd64 linux-arm64"
KEY="${PARTOUT_RELEASE_KEY_PRIV:-}"
PUBKEY="${PARTOUT_RELEASE_KEY:-}"
SKIP_VERIFY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --archs) ARCHS="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) if [ -z "$TAG" ]; then TAG="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

[ -n "$TAG" ] || { echo "usage: release-publish.sh <version-tag> [--out DIR] [--archs ...] [--key B64] [--pubkey B64]" >&2; exit 2; }
[ -n "$KEY" ] || { echo "private key required: --key B64 or PARTOUT_RELEASE_KEY_PRIV" >&2; exit 2; }
[ -n "$PUBKEY" ] || { echo "public key required: --pubkey B64 or PARTOUT_RELEASE_KEY (the fleets' trust anchor)" >&2; exit 2; }
TAG="${TAG#v}"                      # release versions carry no leading v
OUT="${OUT:-$(pwd)/dist/release-repo}"
DEST="$OUT/$TAG"

echo "==> building operator binary"
T="$(mktemp -d /tmp/partout-rel.XXXXXX)"
trap 'rm -rf "$T"' EXIT
go build -trimpath -o "$T/partout-op" ./cmd/partout

sign() { # file version arch kind -> writes .sig next to the file
  local f="$1" v="$2" a="$3" k="$4"
  local sig
  sig="$("$T/partout-op" ctl update sign --version "$v" --arch "$a" --kind "$k" \
        --file "$f" --key "$KEY" | awk -F': ' '/^signature:/ {print $2}')"
  [ -n "$sig" ] || { echo "signing failed for $f" >&2; exit 1; }
  printf '%s' "$sig" > "$f.sig"
}

verify() { # file version arch kind
  local f="$1" v="$2" a="$3" k="$4"
  "$T/partout-op" ctl update verify --version "$v" --arch "$a" --kind "$k" \
    --file "$f" --signature "$(cat "$f.sig")" --pubkey "$PUBKEY" \
    || { echo "VERIFY FAILED: $f" >&2; exit 1; }
}

mkdir -p "$DEST"
for ARCH in $ARCHS; do
  GOARCH="${ARCH#linux-}"
  echo "==> building $TAG for $ARCH"
  mkdir -p "$T/build/$ARCH"
  CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath \
    -ldflags "-s -w -X github.com/blawesom/partout/internal/agent/facts.Version=$TAG" \
    -o "$T/build/$ARCH/partout" ./cmd/partout
  # One binary serves both roles (mode is runtime config); the release
  # layout signs them as distinct kinds.
  cp "$T/build/$ARCH/partout" "$DEST/partout-$TAG-$ARCH-server"
  cp "$T/build/$ARCH/partout" "$DEST/partout-$TAG-$ARCH-agent"
  chmod 0755 "$DEST/partout-$TAG-$ARCH-server" "$DEST/partout-$TAG-$ARCH-agent"
  sign "$DEST/partout-$TAG-$ARCH-server" "$TAG" "$ARCH" server
  sign "$DEST/partout-$TAG-$ARCH-agent"  "$TAG" "$ARCH" agent
  echo "    signed server+agent ($ARCH)"
done

if [ "$SKIP_VERIFY" = "1" ]; then
  echo "==> WARNING: skipping independent re-verification (--skip-verify)"
else
  echo "==> independent re-verification of every artifact (against $PUBKEY)"
  for ARCH in $ARCHS; do
    verify "$DEST/partout-$TAG-$ARCH-server" "$TAG" "$ARCH" server
    verify "$DEST/partout-$TAG-$ARCH-agent"  "$TAG" "$ARCH" agent
    echo "    OK $ARCH (server+agent)"
  done
fi

# Only after all artifacts are built, signed, and verified: move the
# pointer. A failed build must never leave 'latest' pointing at an
# incomplete version directory.
printf '%s' "$TAG" > "$OUT/latest"
echo
echo "DONE. Release repo at: $OUT"
echo "  latest -> $TAG"
ls -la "$DEST"
echo
echo "Publish (operator): copy $OUT to the release repository the server"
echo "  reads (PARTOUT_RELEASE_REPO dir or S3 bucket), e.g.:"
echo "    rsync -a $OUT/ <server>:/var/lib/partout/release-repo/"
echo "Fleets then upgrade with:  partout update"
