#!/usr/bin/env bash
#
# check-cyrillic-runtime-strings.sh
#
# Fails if Cyrillic-block characters (U+0400–U+04FF) appear inside a
# RUNTIME-VISIBLE Rust string context — `expect(` / `panic!` / `assert*!` /
# `format!` / `println!` / `eprintln!` / `write!` / `bail!` / `anyhow!` /
# `.context(` / `with_context(`. A stray Cyrillic letter there both prints
# garbled to operators on failure AND is a recognised review-obfuscation vector
# (e.g. Cyrillic `с` is visually indistinguishable from Latin `c`).
#
# Scope notes:
#   * It does NOT flag Cyrillic inside ordinary `//` / `///` comments — the
#     codebase still carries a large body of bilingual RU/EN comments whose
#     wholesale translation is tracked separately. This guard exists to stop the
#     high-value (operator-visible) class from regressing, not to enforce the
#     full comment cleanup.
#   * The generated C header (`include/veil_ffi.h`) is intentionally not checked
#     here: its body mirrors `lib.rs` doc-comments (the deferred comment set) and
#     its own hygiene is enforced by the existing cbindgen-diff CI gate. The
#     header PREAMBLE (in `cbindgen.toml`) is plain ASCII.
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

violations = []
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
                violations.append((p, i, line.strip()))

if violations:
    print("Cyrillic found in operator-visible runtime strings:\n")
    for p, i, line in violations:
        print(f"  {p}:{i}: {line[:140]}")
    print(f"\n{len(violations)} violation(s). Use ASCII English in runtime "
          "strings (translate the meaning, do not transliterate letters).")
    sys.exit(1)

print("OK: no Cyrillic in operator-visible runtime strings.")
PY
