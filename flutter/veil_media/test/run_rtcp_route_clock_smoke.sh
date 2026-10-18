#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_rtcp_route_clock.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
clang++ -std=c++20 -O1 -Wall -Wextra -Werror \
  -I"$ROOT/src" "$ROOT/test/rtcp_route_clock_smoke.cc" -o "$STAND_DIR/smoke"
"$STAND_DIR/smoke"
