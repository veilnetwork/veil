#!/usr/bin/env bash
# Actual decoded PCM latency; synthetic ADM, no apps or physical audio devices.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_audio_playout.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/audio_playout_smoke.cc" \
  "$STAND_DIR/libveil_media.dylib" -Wl,-rpath,"$STAND_DIR" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke" --silence
"$STAND_DIR/smoke" --silence-after-jitter
"$STAND_DIR/smoke"
"$STAND_DIR/smoke" --recurring-jitter
"$STAND_DIR/smoke" --mature-jitter
"$STAND_DIR/smoke" --handover
"$STAND_DIR/smoke" --asymmetric-handover
"$STAND_DIR/smoke" --sender-restart
"$STAND_DIR/smoke" --delivery-stall
"$STAND_DIR/smoke" --delivery-loss
