#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBRTC_SRC="${WEBRTC_SRC:-$HOME/Projects/veilnetwork/webrtc-checkout/src}"
WEBRTC_OUT="${WEBRTC_OUT:-out/mac-arm64}"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_camera_lifetime.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
clang++ -std=c++20 -O1 -g -fsanitize=address -fno-omit-frame-pointer \
  -fobjc-arc -Wall -Wextra -Werror -Wno-unused-parameter \
  -I"$WEBRTC_SRC" -I"$WEBRTC_SRC/third_party/libyuv/include" -I"$ROOT/src" \
  "$ROOT/test/avf_camera_lifetime_smoke.mm" \
  "$WEBRTC_SRC/$WEBRTC_OUT/obj/libwebrtc.a" \
  -framework AVFoundation -framework CoreMedia -framework CoreVideo \
  -framework Foundation -o "$STAND_DIR/smoke"
for case in destroy-before-start stop-during-start replace-pending-session; do
  ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$STAND_DIR/smoke" "$case"
  echo "PASS: $case"
done
