#!/usr/bin/env bash
# Phase 6.50.b-followup: Mutex poison-recovery policy enforcement.
#
# Workspace policy (existing since Epic 411.2):
#   All `std::sync::Mutex` and `std::sync::RwLock` acquisitions in production
#   code MUST go through the `lock!`/`rlock!`/`wlock!` macros defined in
#   `veilcore/src/lib.rs` and `crates/veil-util/src/lib.rs`.  Those
#   macros wrap `.lock()` / `.read()` / `.write()` with `unwrap_or_else(
#   |p| p.into_inner())` so panic-while-holding-mutex by some
#   prior holder does NOT cascade to a secondary panic on the next
#   `.lock().expect()` / `.lock().unwrap()` (which would silently
#   abort the holder task, or — at a FFI boundary — be UB).
#
# This script catches drift: any raw `.lock().expect(...)` or
# `.lock().unwrap()` site that lives OUTSIDE a `mod tests`/`tests.rs`
# context.  Test code is exempt because a poisoned mutex in a test =
# test failure (which is the desired outcome anyway).
#
# Anchor: see TASKS.md "Phase 6.50.b security & quality audit closeout"
# → "Production `.lock().expect()` audit (non-FFI sites)".
#
# Usage: ./scripts/check-mutex-poison-policy.sh
#   Exits 0 if clean, 1 if violations found.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PYEOF'
from __future__ import annotations

import os
import re
import sys

# Files we ignore wholesale (test fixtures / examples / build scripts).
IGNORE_PATH_FRAGMENTS = (
    "/tests/",          # workspace integration-test dirs
    "/target/",
    "/.git/",
    "/fuzz/",
    "/examples/",
    "build.rs",
)
# Filename patterns matching test-only files.
TEST_FILE_PATTERNS = (
    "_tests.rs",
    "/tests.rs",
    "/integration_tests.rs",
    "/integration_tests/",
    "_test.rs",
    # Audit 2026-05-29: catch `*_tests_<suffix>.rs` test-only files
    # included via `#[cfg(test)] #[path = "..."] mod tests;` (e.g.
    # veil-ipc/src/server_tests_unix.rs) — these have no inner
    # `mod tests {` block, so find_test_mod_start can't gate them.
    "_tests_",
)


def find_test_mod_start(path: str) -> int | None:
    """Return the 1-based line number where `mod tests {` (or similar) starts."""
    pattern = re.compile(r"^\s*mod\s+(tests?|integration_tests|.+_tests)\b.*\{?\s*$")
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f.readlines(), start=1):
            if pattern.match(line):
                return i
    return None


# Audit 2026-05-29: widened from single-line `.lock().unwrap()/expect()` to
# also catch (a) MULTILINE forms where `.lock()` and `.unwrap()/.expect(`
# sit on separate lines (the gap that let the mailbox/rendezvous
# rate-limiter poison-DoS sites slip through), and (b) RwLock guard
# acquisitions `.read()` / `.write()`.  The empty-parens match
# `\.(lock|read|write)\(\)` distinguishes Mutex/RwLock guard calls from
# `io::Read::read(&mut buf)` / `io::Write::write(buf)` which always take
# arguments, so file/socket I/O does not produce false positives.
_POISON_RE = re.compile(
    r"\.(?:lock|read|write)\(\)\s*\.\s*(?:unwrap\(\)|expect\()",
    re.DOTALL,
)


def find_violations(path: str):
    """Return list of (line_no, code) for raw Mutex/RwLock guard
    acquisitions that bypass the poison-recovering macros, outside the
    file's `mod tests` block.  Handles single-line AND multiline forms."""
    test_start = find_test_mod_start(path)
    is_test_file = any(p in path for p in TEST_FILE_PATTERNS)
    if is_test_file:
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    # Precompute line-start offsets so a match offset maps to a 1-based line.
    line_starts = [0]
    for ch_idx, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(ch_idx + 1)

    def offset_to_line(off: int) -> int:
        # Binary-search-free: line_starts is sorted; bisect.
        import bisect

        return bisect.bisect_right(line_starts, off)

    out = []
    for m in _POISON_RE.finditer(text):
        line_no = offset_to_line(m.start())
        if test_start is not None and line_no >= test_start:
            continue
        # Reconstruct the offending snippet (the matched span, single-lined).
        snippet = " ".join(text[m.start() : m.end()].split())
        out.append((line_no, snippet))
    return out


violations = []
for d in ("veilcore/src", "crates", "veilclient/src"):
    if not os.path.isdir(d):
        continue
    for root, _, files in os.walk(d):
        # Normalise to forward slashes so the IGNORE_PATH_FRAGMENTS /
        # TEST_FILE_PATTERNS (which are written with `/`) match on
        # Windows too — os.walk yields `\`-separated paths there, which
        # would otherwise let `/tests.rs` etc. miss and flag exempt files.
        root = root.replace(os.sep, "/")
        if any(frag in root for frag in IGNORE_PATH_FRAGMENTS):
            continue
        for fn in files:
            if not fn.endswith(".rs"):
                continue
            path = f"{root}/{fn}"
            if any(frag in path for frag in IGNORE_PATH_FRAGMENTS):
                continue
            for ln, src in find_violations(path):
                violations.append((path, ln, src.strip()))

if violations:
    print("VIOLATIONS — production sites must use lock!/rlock!/wlock! macro:")
    print("(see veilcore/src/lib.rs or veil-util/src/lib.rs for definitions)")
    print()
    for p, ln, src in violations:
        print(f"  {p}:{ln}")
        print(f"    {src}")
        print()
    print(f"Found {len(violations)} violation(s).")
    print("Fix: replace `mutex_expr.lock().unwrap()` with `lock!(mutex_expr)`,")
    print("OR move the site into a `mod tests` block if it's test-only.")
    sys.exit(1)

print("OK: zero production-path .lock().unwrap()/.lock().expect() sites.")
print("Policy enforced: workspace Mutex acquisitions go through lock!/rlock!/wlock!.")
PYEOF
