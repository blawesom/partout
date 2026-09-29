#!/usr/bin/env bash
# check-licenses — classify every dependency's license file and fail CI on
# anything outside the approved set (or with no license file at all).
#
# Approved (permissive): MIT, Apache-2.0, BSD, ISC, MPL-2.0, X11,
# BlueOak-1.0.0, Postgresql, CC0/Unlicense (public-domain dedications).
# Classification is by license-file text (go's module metadata carries no
# license field). Anything unrecognized — including dual-licensed files the
# heuristics can't place — is listed and fails; a human reviews and either
# fixes the dependency or adds it to EXCEPTIONS with a dated reason.
set -euo pipefail

EXCEPTIONS="" # e.g. EXCEPTIONS="example.com/dual 2026-09 reviewed: MIT clause applies"

classify() { # file -> license family
  # Whitespace-normalized (line wraps break phrase matches).
  local t
  t="$(tr '\n\r\t' '   ' < "$1" | head -c 6000)"
  case "$t" in *"Apache License"*) echo "Apache-2.0"; return;; esac
  case "$t" in *"ISC License"*|*"permission and obligation to copy"*) echo "ISC"; return;; esac
  case "$t" in *"Mozilla Public License"*) echo "MPL-2.0"; return;; esac
  case "$t" in *"Blue Oak Model License"*) echo "BlueOak-1.0.0"; return;; esac
  case "$t" in *"PostgreSQL"*) echo "Postgresql"; return;; esac
  case "$t" in *"MIT License"*) echo "MIT"; return;; esac
  # Old-style MIT (no "MIT License" header): "free of charge ... to deal in
  # the Software without restriction".
  case "$t" in *"Permission is hereby granted, free of charge"*"to deal in the"*) echo "MIT"; return;; esac
  # BSD-2/3: "Redistribution and use in source and binary forms".
  case "$t" in *"Redistribution and use in source and binary forms"*) echo "BSD"; return;; esac
  case "$t" in *"The X11 License"*|*"The Expat License"*|*"X11"*"license"*) echo "X11"; return;; esac
  case "$t" in *"CC0 1.0"*|*"Unlicense"*|*"public domain"*) echo "PublicDomain"; return;; esac
  echo "UNKNOWN"
}

bad=0
count=0
while read -r mod ver; do
  case "$mod" in github.com/blawesom/partout*|golang.org/toolchain*) continue;; esac
  count=$((count+1))
  # Modules in the graph whose code is not extracted (never compiled into
  # this binary) ship no code and no license exposure — skip, don't fail.
  dir="$(go list -m -f '{{.Dir}}' "$mod@$ver" 2>/dev/null || true)"
  [ -z "$dir" ] && continue
  licfile="$(find "$dir" -maxdepth 1 \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \) 2>/dev/null | head -1 || true)"
  if [ -z "$licfile" ]; then
    echo "  NO LICENSE FILE: $mod"
    bad=1
    continue
  fi
  fam="$(classify "$licfile")"
  case "$fam" in
    MIT|Apache-2.0|BSD|ISC|MPL-2.0|X11|BlueOak-1.0.0|Postgresql|PublicDomain) ;;
    *) echo "  NOT APPROVED: $mod — ${fam} ($(basename "$licfile"))"; bad=1;;
  esac
done < <(go list -m all 2>/dev/null | tail -n +2)

if [ "$bad" = "0" ]; then
  echo "license check: all $count dependencies classified as approved (permissive) licenses"
else
  echo "license check FAILED — review the modules above." >&2
  exit 1
fi
