#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_frame_budget.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
clang++ -std=c++20 -Wall -Wextra -Werror -pthread -I"$ROOT/src" \
  "$ROOT/test/video_frame_budget_smoke.cc" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke" "$STAND_DIR/events.log"
