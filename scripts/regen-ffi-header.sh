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

# Second pass, and it must stay second: everything that has to agree with the
# C ABI is derived from the header cbindgen just wrote — the contract hash both
# sides compare, and the numeric constants the Dart bindings expose. See
# scripts/gen-ffi-abi-contract.py for why a hash rather than a version counter.
python3 scripts/gen-ffi-abi-contract.py

# Third pass, and it is not cosmetic: the generated Rust is checked by
# `cargo fmt --all --check` like any other source file, while THIS script's
# output is checked by `git diff --exit-code`. Leave it unformatted and the
# two gates pull against each other -- rustfmt wraps the long hash constant,
# the next regeneration unwraps it, and whichever ran last fails the other.
#
# Formatting here rather than teaching the generator to emit pre-wrapped text:
# the wrapping rustfmt wants is a property of the rustfmt in use, and baking
# today's answer into a template is how the drift got in.
rustfmt --edition 2024 crates/veilclient-ffi/src/abi_contract.rs

echo "OK: formatted the generated ABI contract"
