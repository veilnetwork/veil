#!/usr/bin/env bash
#
# check-cyrillic-runtime-strings.sh
#
# Two scans, both failing on Cyrillic-block characters (U+0400–U+04FF):
#
#   1. RUNTIME-VISIBLE Rust strings — `expect(` / `panic!` / `assert*!` /
#      `format!` / `println!` / `eprintln!` / `write!` / `bail!` / `anyhow!` /
#      `.context(` / `with_context(`. A stray Cyrillic letter there both prints
#      garbled to operators on failure AND is a recognised review-obfuscation
#      vector (e.g. Cyrillic `с` is visually indistinguishable from Latin `c`).
#
#   2. CI TOOLING — every line of `scripts/` and `.github/`. These files are
#      build/release/policy infrastructure; they must be plain ASCII English so
#      a homoglyph (`а`/`с`/`к`) can't hide in a comment that no Rust-only lint
#      would ever scan. This detector script itself is exempt (it must contain
#      Cyrillic to define the pattern + example above).
#
# Scope notes:
#   * Scan 1 does NOT flag Cyrillic inside ordinary `//` / `///` Rust comments —
#     the codebase still carries a body of bilingual RU/EN comments whose
#     wholesale translation is tracked separately. This guard stops the
#     high-value (operator-visible) class from regressing.
#   * The generated C header (`include/veil_ffi.h`) is intentionally not checked:
#     its body mirrors `lib.rs` doc-comments (the deferred comment set) and its
#     own hygiene is enforced by the existing cbindgen-diff CI gate. The header
#     PREAMBLE (in `cbindgen.toml`) is plain ASCII.
#
# Exit 0 = clean, 1 = violations found.

set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import os, re, sys

CYR = re.compile(r'[Ѐ-ӿ]')
CTX = re.compile(
    r'(?:\bexpect\(|\.context\(|\bwith_context\(|\bpanic!|\bunreachable!|'
    r'\bassert!|\bassert_eq!|\bassert_ne!|\bformat!|\bprintln!|\beprintln!|'
    r'\bwrite!|\bwriteln!|\bbail!|\banyhow!|\.expect_err\()'
)

# This detector file legitimately contains Cyrillic (the pattern + example).
SELF = 'check-cyrillic-runtime-strings.sh'

runtime_violations = []
for root, _, files in os.walk('crates'):
    if '/target' in root:
        continue
    for f in files:
        if not f.endswith('.rs'):
            continue
        p = os.path.join(root, f)
        for i, line in enumerate(open(p, encoding='utf-8', errors='ignore'), 1):
            s = line.lstrip()
            if s.startswith(('//', '*')):
                continue
            if '"' in line and CTX.search(line) and CYR.search(line):
                runtime_violations.append((p, i, line.strip()))

tooling_violations = []
for base in ('scripts', '.github'):
    for root, _, files in os.walk(base):
        if '/target' in root:
            continue
        for f in files:
            if f == SELF:
                continue
            p = os.path.join(root, f)
            try:
                for i, line in enumerate(open(p, encoding='utf-8', errors='ignore'), 1):
                    if CYR.search(line):
                        tooling_violations.append((p, i, line.strip()))
            except (IsADirectoryError, UnicodeError):
                continue

rc = 0
if runtime_violations:
    print("Cyrillic found in operator-visible runtime strings:\n")
    for p, i, line in runtime_violations:
        print(f"  {p}:{i}: {line[:140]}")
    print(f"\n{len(runtime_violations)} violation(s). Use ASCII English in runtime "
          "strings (translate the meaning, do not transliterate letters).\n")
    rc = 1

if tooling_violations:
    print("Cyrillic found in CI tooling (scripts/ + .github/ must be ASCII English):\n")
    for p, i, line in tooling_violations:
        print(f"  {p}:{i}: {line[:140]}")
    print(f"\n{len(tooling_violations)} violation(s). Translate the meaning to "
          "English; watch for homoglyphs (а/с/к/в/о/е/р/у/х).\n")
    rc = 1

if rc == 0:
    print("OK: no Cyrillic in runtime strings or CI tooling.")
sys.exit(rc)
PY
