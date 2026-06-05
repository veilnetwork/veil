#!/usr/bin/env bash
# Cross-compile a Linux x86_64 (static-musl) veil-cli FROM macOS.
#
# Usage:
#   scripts/cross-build-linux-musl.sh [extra cargo args...]
#
# Produces: target/x86_64-unknown-linux-musl/release/veil-cli
# (static-pie ELF, deployable via ansible/deploy-binary-only.yml).
#
# Prerequisites (macOS):
#   brew install FiloSottile/musl-cross/musl-cross   # x86_64-unknown-linux-musl-*
#   rustup target add x86_64-unknown-linux-musl
#
# WHY this wrapper exists — two macOS→linux-musl cross gotchas it handles:
#
# 1. tls-boring / BoringSSL (btls-sys, cmake-driven). cmake-rs otherwise injects
#    the HOST arch flag `-arch arm64` into the musl cross-compiler, which rejects
#    it ("unrecognized command-line option '-arch'"). Fix: a CMake toolchain
#    file that sets CMAKE_SYSTEM_NAME=Linux (disables macOS -arch logic), passed
#    via CMAKE_TOOLCHAIN_FILE_<triple>. NOTE: a stale CMakeCache.txt from a prior
#    (toolchain-less) configure pins the bad flags — this script wipes the
#    btls-sys build dir first so the toolchain file is honored on a clean
#    configure. With this, tls-boring (the fingerprint-rotation baseline) builds
#    cleanly cross-platform; no need to build on Linux just for boring.
#
# 2. librocksdb-sys bindgen needs an explicit --sysroot + --target so its clang
#    step finds stddef.h etc. for the musl target.
#
# Defaults match the production binary: rocksdb-cold + tls-boring +
# production-seeds. Override features by editing FEATURES below or passing
# `--no-default-features --features ...` as extra args.

set -euo pipefail

TRIPLE="x86_64-unknown-linux-musl"
FEATURES="rocksdb-cold,tls-boring,production-seeds"

command -v "${TRIPLE}-gcc" >/dev/null || {
  echo "error: ${TRIPLE}-gcc not found — brew install FiloSottile/musl-cross/musl-cross" >&2
  exit 1
}
SYSROOT="$(${TRIPLE}-gcc -print-sysroot)"
echo "musl sysroot: $SYSROOT"

# CMake toolchain file: the single thing that makes BoringSSL cross-compile.
TOOLCHAIN_FILE="$(mktemp -t musl-toolchain.XXXXXX.cmake)"
cat > "$TOOLCHAIN_FILE" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER ${TRIPLE}-gcc)
set(CMAKE_CXX_COMPILER ${TRIPLE}-g++)
set(CMAKE_AR ${TRIPLE}-ar)
set(CMAKE_RANLIB ${TRIPLE}-ranlib)
set(CMAKE_SYSROOT ${SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
trap 'rm -f "$TOOLCHAIN_FILE"' EXIT

# Wipe any stale btls-sys CMake configure that may pin host -arch flags.
rm -rf "target/${TRIPLE}"/*/build/btls-sys-* 2>/dev/null || true

export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${TRIPLE}-gcc"
export CC_x86_64_unknown_linux_musl="${TRIPLE}-gcc"
export CXX_x86_64_unknown_linux_musl="${TRIPLE}-g++"
export AR_x86_64_unknown_linux_musl="${TRIPLE}-ar"
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--sysroot=${SYSROOT} --target=${TRIPLE}"
export CMAKE_TOOLCHAIN_FILE_x86_64_unknown_linux_musl="$TOOLCHAIN_FILE"

echo "building veil-cli [$FEATURES] for $TRIPLE ..."
cargo build --release -p veil-cli \
  --no-default-features --features "$FEATURES" \
  --target "$TRIPLE" "$@"

OUT="target/${TRIPLE}/release/veil-cli"
echo "done: $OUT"
file "$OUT" || true
