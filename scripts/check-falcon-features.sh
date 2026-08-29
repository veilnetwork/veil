#!/usr/bin/env bash
# One dependency line decides which C sources the whole workspace compiles.
#
# Cargo unifies features across the dependency graph. Six crates here take
# pqcrypto-falcon with `default-features = false, features = ["std"]`; one took
# the plain defaults, and that one line switched `avx2` and `neon` on for
# EVERY crate in the workspace, including the ones that carefully asked for
# neither.
#
# Harmless until a target appears where the optimised C does not compile. On
# aarch64-pc-windows-msvc it does not: pqclean's aarch64 sources are written
# against GCC/Clang NEON intrinsics and MSVC rejects them outright —
#
#   sampler.c(127): error C2440: 'type cast': cannot convert from
#                   '__n128' to 'uint32x4_t'
#
# — which is exactly what stopped the first native arm64 Windows build. The
# crate's own build.rs guards its avx2 path with a `target_env == "msvc"`
# check; its aarch64 path carries no such guard.
#
# THE RULE: a pqcrypto-falcon dependency either disables default features, or
# sits under a `[target.'cfg(...)'.dependencies]` table whose cfg excludes
# aarch64-msvc. A plain `pqcrypto-falcon = "0.4"` in a bare [dependencies]
# table is what this script exists to catch.
#
# Usage: invoke from the repo root. Exits non-zero on violations.

set -euo pipefail

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

CRATE = "pqcrypto-falcon"

sites = 0
violations = []

for manifest in sorted(Path(".").rglob("Cargo.toml")):
    if "target" in manifest.parts or "third_party" in manifest.parts:
        continue
    text = manifest.read_text(encoding="utf-8", errors="replace")
    if CRATE not in text:
        continue

    section = ""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if not re.match(rf"{re.escape(CRATE)}\s*=", line):
            continue
        sites += 1

        # A target table that cannot match aarch64-msvc is free to use the
        # optimised sources: that is the whole point of narrowing it there.
        narrowed = section.startswith("[target.") and "aarch64" in section
        disabled = "default-features" in line and "false" in line
        if not (narrowed or disabled):
            violations.append(f"{manifest}:{lineno}: {line}")

# Vacuity guard. Every check above passes on a tree where the dependency was
# renamed, moved, or dropped -- and then this script would report a clean bill
# of health for a rule it is no longer checking.
if sites < 6:
    print(
        f"found only {sites} {CRATE} dependency line(s) -- expected at least 6. "
        "Either the dependency moved somewhere this script cannot see it, or "
        "this guard is now checking nothing.",
        file=sys.stderr,
    )
    sys.exit(1)

if violations:
    print(f"{CRATE} taken with default features, unconditionally:", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    print(
        "\nCargo unifies features across the graph, so one such line turns "
        "`avx2` and `neon` on for the whole workspace -- and pqclean's aarch64 "
        "sources do not compile with MSVC, which is what stopped the first "
        "native arm64 Windows build. Either disable default features, or put "
        "the dependency under a target cfg that excludes aarch64-msvc.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"pqcrypto-falcon features: OK ({sites} dependency sites, none unconditional)")
PY
