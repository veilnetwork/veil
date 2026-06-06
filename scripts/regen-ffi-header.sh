#!/usr/bin/env bash
# Phase 6.50.b-followup: regenerate `crates/veilclient-ffi/include/veil_ffi.h`
# from Rust source via cbindgen.
#
# Run locally before committing any change to the FFI surface (lib.rs);
# CI hygiene job runs the same command + `git diff --exit-code` to gate
# header drift.
#
# Install cbindgen one-time:
#     cargo install cbindgen
#
# Usage:
#     ./scripts/regen-ffi-header.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "error: cbindgen not installed" >&2
    echo "       run: cargo install cbindgen" >&2
    exit 1
fi

cbindgen \
    --config crates/veilclient-ffi/cbindgen.toml \
    --crate veilclient-ffi \
    --output crates/veilclient-ffi/include/veil_ffi.h

echo "OK: regenerated crates/veilclient-ffi/include/veil_ffi.h"
