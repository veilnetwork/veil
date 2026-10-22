#!/usr/bin/env bash
# Real three-party Opus/mixing regression at a mocked Veil boundary.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_group_playout.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
if [[ $# -eq 0 ]]; then
  VEIL_MEDIA_TEST_HOOKS=1 "$ROOT/macos/build_veil_media_dylib.sh" "$STAND_DIR"
  DYLIB="$STAND_DIR/libveil_media.dylib"
else
  DYLIB="$1"
fi
clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
  -I"$ROOT/src" "$ROOT/test/group_playout_recovery_smoke.cc" \
  "$DYLIB" -Wl,-rpath,"$(dirname "$DYLIB")" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke" "$STAND_DIR/stats.json"
python3 - "$STAND_DIR/stats.json" <<'PYTEST'
import json, re, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    stats = json.load(stream)
peers = stats['video_delivery_peers']
expected = {prefix + '00' * 28 for prefix in ['02225cff', '03225cff']}
assert set(peers) == expected
assert all(re.fullmatch('[0-9a-f]{64}', key) for key in peers)
assert set(stats['audio_receivers']) == expected
for name in ['audio_latency_recovery_count', 'audio_latency_discarded_ms',
             'audio_latency_fallback_frames']:
    assert isinstance(stats[name], int)
print('group stats: valid UTF-8 JSON, hex peer keys and complete numeric counters')
PYTEST
