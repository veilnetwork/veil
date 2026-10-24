#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_media_destroy_retry.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
if [[ $# -eq 0 ]]; then
  VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
  DYLIB="$STAND_DIR/libveil_media.dylib"
else
  DYLIB="$1"
  shift
fi
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/media_destroy_retry_smoke.cc" \
  "$DYLIB" -Wl,-rpath,"$(dirname "$DYLIB")" -o "$STAND_DIR/smoke"
python3 - "$STAND_DIR/smoke" "$@" <<'PY'
import subprocess, sys
cases = [sys.argv[2:]] if len(sys.argv) > 2 else [
    [kind, plane] for kind in ('direct', 'group') for plane in ('audio', 'video')
]
for case in cases:
    # A broken destructor must fail this test rather than hang the test host.
    subprocess.run([sys.argv[1], *case], check=True, timeout=30)
PY
