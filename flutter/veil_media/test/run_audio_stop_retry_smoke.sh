#!/usr/bin/env bash
# Exercises two actual 10-second scheduling timeouts per engine kind.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_audio_stop_retry.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
if [[ $# -eq 0 ]]; then
  VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
  DYLIB="$STAND_DIR/libveil_media.dylib"
else
  DYLIB="$1"
fi
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/audio_stop_retry_smoke.cc" \
  "$DYLIB" -Wl,-rpath,"$(dirname "$DYLIB")" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke"
