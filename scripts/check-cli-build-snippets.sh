#!/usr/bin/env bash
# Stale-build-snippet policy (audit cycle-4).
#
# The CLI/daemon binary `veil-cli` lives in the `veil-cli` package
# (`crates/veil-cli`, `[[bin]] name = "veil-cli"`), NOT in `veilcore`.
# `cargo build -p veilcore --bin veil-cli` therefore fails with
# "no bin target named `veil-cli` in `veilcore` package" — which silently
# broke devnet / hot-standby / bootstrap / ansible deploy scripts after the
# CLI was extracted into its own crate.
#
# This gate fails if any script/doc/playbook still asks cargo to build the
# `veil-cli` binary out of the `veilcore` package. Legitimate veilcore *library*
# builds/tests (`-p veilcore --lib`, `-p veilcore --no-default-features`,
# `cargo test -p veilcore`, the veilcore bench bins) are NOT matched.
#
# Usage: invoke from repo root. Exits non-zero on violations. CI + pre-commit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The unambiguous broken form: building the veil-cli *bin* from the veilcore
# package. (Bare `-p veilcore` is intentionally NOT flagged — it is valid for
# lib-only compile-checks documented in the developer guide.)
pattern='-p[[:space:]]+veilcore[[:space:]]+--bin[[:space:]]+veil-cli'

# Search scripts, ansible, and docs; skip target/ and the git dir.
matches="$(grep -rnE --include='*.sh' --include='*.ps1' --include='*.yml' \
  --include='*.yaml' --include='*.md' "$pattern" scripts/ ansible/ docs/ 2>/dev/null || true)"

if [ -n "$matches" ]; then
  echo "ERROR: stale CLI build snippet — 'veil-cli' bin is in the 'veil-cli' package, not 'veilcore'." >&2
  echo "Replace '-p veilcore --bin veil-cli' with '-p veil-cli --bin veil-cli':" >&2
  echo "$matches" >&2
  exit 1
fi

echo "check-cli-build-snippets: OK (no stale '-p veilcore --bin veil-cli' snippets)"
