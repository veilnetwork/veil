#!/usr/bin/env bash
# Real Apple playout, silent PCM, with a simulated hardware-change notification.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_avf_configuration.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
unset VEIL_MEDIA_USE_PLATFORM_ADM
VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/avf_configuration_smoke.cc" \
  "$STAND_DIR/libveil_media.dylib" -Wl,-rpath,"$STAND_DIR" -o "$STAND_DIR/smoke"
VEIL_MEDIA_DIAG_PATH="$STAND_DIR/avf.log" "$STAND_DIR/smoke" || {
  cat "$STAND_DIR/avf.log"
  exit 1
}
