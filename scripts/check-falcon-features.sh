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


DANGEROUS_TRIPLE = "aarch64-pc-windows-msvc"


def excludes_arm64_msvc(section: str) -> bool:
    """Can this `[target...]` header NOT match aarch64-pc-windows-msvc?

    Two shapes are provable, and nothing else is assumed safe:

      * an explicit triple that is not the dangerous one —
        `[target.x86_64-unknown-linux-gnu.dependencies]`;
      * a cfg that is a NOT over something naming both the architecture and
        the environment —
        `[target.'cfg(not(all(target_arch = "aarch64", target_env = "msvc")))'...]`.

    A bare `cfg(target_arch = "aarch64")` is neither: it MATCHES the dangerous
    target, which is the whole point.
    """
    if not section.startswith("[target."):
        return False
    inner = section[len("[target."):].rstrip("]")
    for suffix in (".dependencies", ".dev-dependencies", ".build-dependencies"):
        if inner.endswith(suffix):
            inner = inner[: -len(suffix)]
    inner = inner.strip().strip("'\"")
    if not inner.startswith("cfg("):
        # An explicit target triple.
        return inner != DANGEROUS_TRIPLE
    # Searched in the WHOLE header, not in a `cfg(...)` body carved out with
    # rstrip(")"): that strips the closing paren of the `not(...)` too, and the
    # pattern below then matches nothing — the self-test caught exactly that.
    negations = re.findall(r"not\s*\((.*)\)", inner, re.S)
    return any(
        "aarch64" in negated and "msvc" in negated for negated in negations
    )


def _self_test() -> int:
    """Fixtures, because a classifier nobody exercises is a guess."""
    cases = [
        ('[target.\'cfg(not(all(target_arch = "aarch64", target_env = "msvc")))\'.dependencies]', True),
        ('[target.\'cfg(all(target_arch = "aarch64", target_env = "msvc"))\'.dependencies]', False),
        ('[target.\'cfg(target_arch = "aarch64")\'.dependencies]', False),
        ('[target.\'cfg(windows)\'.dependencies]', False),
        ("[target.x86_64-unknown-linux-gnu.dependencies]", True),
        ("[target.aarch64-pc-windows-msvc.dependencies]", False),
        ("[dependencies]", False),
    ]
    bad = [
        (section, excludes_arm64_msvc(section), want)
        for section, want in cases
        if excludes_arm64_msvc(section) != want
    ]
    for section, got, want in bad:
        print(f"  {section} -> {got}, expected {want}", file=sys.stderr)
    if bad:
        print("the target-section classifier is wrong", file=sys.stderr)
        return 1
    print(f"target-section classifier: OK ({len(cases)} fixtures)")
    return 0


if "--self-test" in sys.argv:
    sys.exit(_self_test())


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

        # A target table is only an excuse if it CANNOT match the target that
        # breaks. `"aarch64" in section` said the opposite of what it meant:
        # `cfg(target_arch = "aarch64")` contains the word and matches
        # aarch64-pc-windows-msvc exactly, so the one section that must never
        # take the defaults was the one this called safe (report19 V19-L2).
        narrowed = excludes_arm64_msvc(section)
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
