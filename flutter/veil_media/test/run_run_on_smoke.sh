#!/usr/bin/env bash
# Lifetime contract of run_on (audit report8 H-07).
#
# Unlike the other smoke tests here, this one does NOT link the dylib: the
# rule under test is about object lifetime, and veil_run_on.h is deliberately
# free of WebRTC types so it can be checked without a media stack, on any
# host, in under a second. Assertions are left ON -- the gate-discipline
# guard inside the header is an assert, and compiling it out would silently
# retire half the coverage.
#
# The second pass runs the same checks under AddressSanitizer, which names
# the failure the way the audit did: stack-use-after-scope on the caller's
# closure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/veil_run_on_smoke"

clang++ -std=c++20 -O1 -Wall -Wextra \
  -I"$ROOT/src" "$ROOT/test/run_on_smoke.cc" -o "$OUT"
"$OUT"

echo
echo "--- same checks under AddressSanitizer ---"
clang++ -std=c++20 -g -fsanitize=address -Wall -Wextra \
  -I"$ROOT/src" "$ROOT/test/run_on_smoke.cc" -o "$OUT.asan"
"$OUT.asan"
