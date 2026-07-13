#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DYLIB="$ROOT/macos/Frameworks/libveil_media.dylib"
OUT="${TMPDIR:-/tmp}/veil_group_audio_smoke"

test -f "$DYLIB"
clang++ -std=c++20 -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/group_audio_smoke.cc" \
  "$DYLIB" -Wl,-rpath,"$(dirname "$DYLIB")" -o "$OUT"
"$OUT"
