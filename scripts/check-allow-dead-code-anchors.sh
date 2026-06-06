#!/usr/bin/env bash
# Phase 6.50.b dead_code policy enforcement (TASKS.md row closed
# 2026-05-10): every `#[allow(dead_code)]` in the workspace must
# have one of:
#   1. an immediately-preceding `///` doc comment explaining WHY
#      (typical: "field X is unused on platform Y but kept for
#      API symmetry with #[cfg(...)] variant Z"),
#   2. a `#[cfg(...)]` attribute on the same item OR within 2
#      lines above (typical: cross-platform stub helpers).
#
# Without this discipline, `dead_code` warnings pile up until
# someone adds a blanket allow at module scope, which then
# silently swallows future actual dead code.  The lint anchor
# forces the author to articulate the placeholder reason or
# delete the symbol.
#
# Usage: invoke from repo root.  Exits non-zero on violations.
# Suitable for CI invocation OR git pre-commit hook.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
violations=0
total=0

# `grep -rn` returns "path:line:content" — split on ':' once
# for path and line.  --include='*.rs' restricts to Rust files.
# Only match lines where `#[allow(dead_code)]` is the actual attribute
# (whitespace + #[) — skips `// ... #[allow(dead_code)] ...` references
# in comments / doc-strings.
while IFS= read -r match; do
    file="${match%%:*}"
    rest="${match#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    # Skip if the match is inside a `//` comment.  Test: trim leading
    # whitespace; require the attribute to start the line.
    trimmed="${content#"${content%%[![:space:]]*}"}"
    case "$trimmed" in
        '#[allow(dead_code)]'*) ;;        # actual attribute — keep
        *) continue ;;                     # inside comment / docstring
    esac
    total=$((total + 1))

    # Look at the 3 lines above the attribute for anchor markers.
    # awk's NR is 1-based; we want lines [line-3, line-1] inclusive.
    above=$(awk -v line="$line" 'NR >= line - 3 && NR < line { print }' "$file")
    if echo "$above" | grep -qE '^\s*///|^\s*#\[cfg\('; then
        continue
    fi

    echo "VIOLATION: $file:$line"
    echo "  '#[allow(dead_code)]' lacks anchor comment OR adjacent #[cfg(...)] attribute."
    echo "  Add either:"
    echo "    /// <reason field is dead but retained — Epic / TASKS anchor>"
    echo "    #[allow(dead_code)]"
    echo "  OR ensure the item already has #[cfg(...)] within 3 lines above."
    echo ""
    violations=$((violations + 1))
done < <(grep -rn '#\[allow(dead_code)\]' --include='*.rs' "$ROOT" 2>/dev/null || true)

if [ "$violations" -gt 0 ]; then
    echo "===================================================="
    echo "FAIL: $violations of $total #[allow(dead_code)] sites lack anchors."
    echo "Policy: TASKS.md 'dead_code policy' row (2026-05-10)."
    exit 1
fi

echo "OK: all $total #[allow(dead_code)] sites have anchors."
