#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_inbound_queue.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

clang++ -std=c++20 -O1 -Wall -Wextra -Werror -pthread \
  -I"$ROOT/src" "$ROOT/test/inbound_packet_queue_smoke.cc" -o "$BUILD_DIR/smoke"
"$BUILD_DIR/smoke"
clang++ -std=c++20 -g -O1 -fsanitize=address,undefined -Wall -Wextra -Werror -pthread \
  -I"$ROOT/src" "$ROOT/test/inbound_packet_queue_smoke.cc" -o "$BUILD_DIR/smoke.asan"
"$BUILD_DIR/smoke.asan"
