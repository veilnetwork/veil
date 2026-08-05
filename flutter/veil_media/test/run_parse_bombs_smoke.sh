#!/usr/bin/env bash
# Feed the media containers what an attacker sends and check they refuse it.
#
# Links the real libveil_media.dylib, so it exercises the shipping parsers with
# the shipping flags (-fno-exceptions included, which is why a bad length is an
# abort() and not something a handler could catch). Build the dylib first:
#   macos/build_veil_media_dylib.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DYLIB="${VEIL_MEDIA_DYLIB:-$ROOT/macos/Frameworks/libveil_media.dylib}"
OUT="${TMPDIR:-/tmp}/veil_parse_bombs_smoke"

test -f "$DYLIB"
clang++ -std=c++20 -O1 -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/parse_bombs_smoke.cc" \
  "$DYLIB" -Wl,-rpath,"$(dirname "$DYLIB")" -o "$OUT"
"$OUT"
