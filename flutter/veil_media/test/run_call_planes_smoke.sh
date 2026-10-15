#!/usr/bin/env bash
# Real WebRTC Call/queues with a mocked plaintext Veil boundary. No phones or
# profiles are used. Test hooks exist only in the temporary stand library.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_call_planes.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/call_planes_smoke.cc" \
  "$STAND_DIR/libveil_media.dylib" -Wl,-rpath,"$STAND_DIR" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke" "$@"
if [ "$#" -eq 0 ]; then
  "$STAND_DIR/smoke" --rtcp-loss
fi
