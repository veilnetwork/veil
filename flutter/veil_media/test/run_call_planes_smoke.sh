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
  "$STAND_DIR/smoke" --bwe-handover
  "$STAND_DIR/smoke" --rtcp-loss
  "$STAND_DIR/smoke" --video-loss-persistence
  bash "$ROOT/test/run_video_loss_persistence_smoke.sh"
  "$STAND_DIR/smoke" --group-rtcp-accounting
  "$STAND_DIR/smoke" --group-remb-cadence
  "$STAND_DIR/smoke" --frame-sizing
  "$STAND_DIR/smoke" --audio-source-pixels
  python3 "$ROOT/test/run_video_pacing_debt_smoke.py"
  bash "$ROOT/test/run_video_frame_budget_smoke.sh"
  "$ROOT/test/run_remb_cadence_smoke.sh"
  "$ROOT/test/run_rtcp_send_stats_smoke.sh"
  "$ROOT/test/run_video_loss_trace_smoke.sh"
  clang++ -std=c++20 -Wall -Wextra -Werror -Wl,-export_dynamic \
    -I"$ROOT/src" "$ROOT/test/group_video_repair_stats_smoke.cc" \
    "$STAND_DIR/libveil_media.dylib" -Wl,-rpath,"$STAND_DIR" -o "$STAND_DIR/repair-stats"
  "$STAND_DIR/repair-stats"
  python3 "$ROOT/test/run_playout_recovery_smoke.py"
  "$ROOT/test/run_group_playout_recovery_smoke.sh" "$STAND_DIR/libveil_media.dylib"
fi
