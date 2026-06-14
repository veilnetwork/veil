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
# production-seeds. Override features via the FEATURES env var, e.g. a testnet
# build that takes bootstraps from node.toml instead of baked-in seeds:
#   FEATURES=rocksdb-cold,tls-boring,allow-empty-seeds scripts/cross-build-linux-musl.sh

set -euo pipefail

TRIPLE="${TRIPLE:-x86_64-unknown-linux-musl}"
FEATURES="${FEATURES:-rocksdb-cold,tls-boring,production-seeds}"

# Derive cargo/cc/cmake env-var name fragments from the triple so the script
# works for any linux-musl target (x86_64 via FiloSottile/musl-cross, aarch64
# via messense/macos-cross-toolchains, ...).
ARCH="${TRIPLE%%-*}"                       # x86_64 | aarch64
TRIPLE_US="${TRIPLE//-/_}"                  # lower underscore (CC_/CXX_/AR_/CMAKE_)
TRIPLE_UC="$(printf '%s' "$TRIPLE_US" | tr '[:lower:]' '[:upper:]')"  # CARGO_TARGET_

command -v "${TRIPLE}-gcc" >/dev/null || {
  echo "error: ${TRIPLE}-gcc not found — install the cross toolchain (x86_64: brew install FiloSottile/musl-cross/musl-cross; aarch64: brew install messense/macos-cross-toolchains/aarch64-unknown-linux-musl)" >&2
  exit 1
}
SYSROOT="$(${TRIPLE}-gcc -print-sysroot)"
echo "musl sysroot: $SYSROOT"

# CMake toolchain file: the single thing that makes BoringSSL cross-compile.
TOOLCHAIN_FILE="$(mktemp -t musl-toolchain.XXXXXX.cmake)"
cat > "$TOOLCHAIN_FILE" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${ARCH})
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

export "CARGO_TARGET_${TRIPLE_UC}_LINKER=${TRIPLE}-gcc"
export "CC_${TRIPLE_US}=${TRIPLE}-gcc"
export "CXX_${TRIPLE_US}=${TRIPLE}-g++"
export "AR_${TRIPLE_US}=${TRIPLE}-ar"
export "BINDGEN_EXTRA_CLANG_ARGS_${TRIPLE_US}=--sysroot=${SYSROOT} --target=${TRIPLE}"
export "CMAKE_TOOLCHAIN_FILE_${TRIPLE_US}=$TOOLCHAIN_FILE"

echo "building veil-cli [$FEATURES] for $TRIPLE ..."
cargo build --release -p veil-cli \
  --no-default-features --features "$FEATURES" \
  --target "$TRIPLE" "$@"

OUT="target/${TRIPLE}/release/veil-cli"
echo "done: $OUT"
file "$OUT" || true
