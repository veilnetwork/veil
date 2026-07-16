#!/usr/bin/env bash
# Cross-compile veilclient-ffi for Flutter / mobile hosts (Epic 489.2).
#
# Builds the C-ABI shared library for the Android + iOS + desktop
# targets that the Flutter plugin's pubspec.yaml supports.  Output goes
# under target/<triple>/release/ as both .so/.dylib (cdylib) and .a
# (staticlib).  Flutter Android plugin loads .so at runtime; iOS links
# the .a into the universal binary.
#
# Prerequisites:
#   rustup target add aarch64-linux-android x86_64-linux-android \
#                      aarch64-apple-ios x86_64-apple-ios          \
#                      aarch64-apple-darwin x86_64-apple-darwin
#
# For Android targets, cargo-ndk handles linker setup:
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
#
# For iOS / macOS targets you need Xcode + Xcode CLT installed (host = macOS).
#
# Pass `--target <triple>` to build a single target, otherwise all
# configured targets in MOBILE_TARGETS are built sequentially.  Pass
# `--release-features` to override the cargo --features flag (default:
# veil-bootstrap/allow-empty-seeds for testnet builds — production
# must drop this and provide BUILTIN_SEEDS).

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# cycle-7 (M3): default to `production-seeds` (compiles in BUILTIN_SEEDS — the
# safe posture for a release artifact). The dev/testnet escape hatch
# `allow-empty-seeds` (no builtin seeds; relies on runtime config) must be opted
# into explicitly AND requires VEIL_MOBILE_DEV=1 (see guard in main), so it
# can never land in a release build by accident.
#
# `node-embedded` bundles the in-process node runtime so the mobile lib can run
# a veil node WITHOUT a `veil-cli` subprocess — mandatory on iOS (Apple forbids
# spawning child processes) and the deniable posture on Android (nothing
# identity-bearing written to a config.toml). It pulls veil-node-runtime with
# NO default features, so the heavy C++ RocksDB cold store stays OFF mobile
# (in-memory DHT); add `node-embedded-rocksdb` only for desktop/server.
readonly DEFAULT_FEATURES="production-seeds,node-embedded"

# Targets supported by the Flutter plugin.  iOS / macOS targets require
# a macOS host toolchain — script just invokes cargo, no platform check
# (cargo errors clearly when the host can't reach a target).
readonly MOBILE_TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"   # 32-bit ARM Android (devices < 2017, low-RAM phones)
  "x86_64-linux-android"      # emulator
  "aarch64-apple-ios"
  "aarch64-apple-ios-sim"     # simulator on Apple Silicon Mac
  "x86_64-apple-ios"          # simulator on Intel Mac
  "aarch64-apple-darwin"      # Apple Silicon Mac (host for desktop Flutter)
  "x86_64-apple-darwin"       # Intel Mac (legacy)
  "x86_64-unknown-linux-gnu"  # Linux desktop
  "aarch64-unknown-linux-gnu" # Linux ARM64 (RPi etc)
)

usage() {
  cat <<EOF
Usage: $0 [--target <triple>] [--features '<features>'] [--all]

Options:
  --target <triple>     Build a single Rust target.  Defaults to all targets
                        in MOBILE_TARGETS when --all is passed.
  --features '<list>'   Cargo --features flag.  Default: '$DEFAULT_FEATURES'.
  --all                 Build every target in MOBILE_TARGETS.
  --list                Print MOBILE_TARGETS and exit.
  -h, --help            This message.

Examples:
  $0 --target aarch64-linux-android
  $0 --all
  $0 --target x86_64-unknown-linux-gnu --features ''
EOF
}

build_one() {
  local triple="$1"
  local features="$2"
  echo "==> cargo build --release -p veilclient-ffi --target $triple"

  local cargo_args=(--release -p veilclient-ffi --target "$triple")
  if [[ -n "$features" ]]; then
    cargo_args+=(--features "$features")
  fi

  if [[ "$triple" == *android* ]]; then
    if command -v cargo-ndk >/dev/null 2>&1; then
      # Keep the local helper aligned with mobile-build.yml.  In particular,
      # 32-bit armv7 needs bionic's fseeko/ftello declarations, which are only
      # exposed to RocksDB's C++ build at API 24 or newer.
      cargo ndk --target "$triple" --platform 24 -- build "${cargo_args[@]}"
    else
      echo "WARN: cargo-ndk not installed — falling back to plain cargo;" \
           "Android targets typically need 'cargo install cargo-ndk' to" \
           "wire up the NDK linker." >&2
      cd "$REPO_ROOT" && cargo build "${cargo_args[@]}"
    fi
  elif [[ "$triple" == *apple-ios* ]]; then
    # iOS distribution ships a staticlib through xcframework; Apple disallows
    # third-party dylibs in iOS apps.  Cargo's default cdylib emit fails on
    # native macOS hosts because zstd-sys emits `__chkstk_darwin` calls that
    # are not in iOS clang_rt under the default 10.0 deployment target.
    # `cargo rustc --crate-type staticlib` skips the cdylib link entirely.
    #
    # Bindgen workaround for iOS simulator triples: Rust shortens to `-sim`,
    # but clang expects the full `-simulator` suffix in the target triple.
    # Without this, librocksdb-sys' bindgen step dies with
    # `version 'sim' in target triple 'arm64-apple-ios-sim' is invalid`.
    case "$triple" in
      aarch64-apple-ios-sim)
        export BINDGEN_EXTRA_CLANG_ARGS_aarch64_apple_ios_sim="--target=arm64-apple-ios-simulator"
        ;;
      x86_64-apple-ios)
        export BINDGEN_EXTRA_CLANG_ARGS_x86_64_apple_ios="--target=x86_64-apple-ios-simulator"
        ;;
    esac
    cd "$REPO_ROOT" && cargo rustc "${cargo_args[@]}" --crate-type staticlib
  else
    cd "$REPO_ROOT" && cargo build "${cargo_args[@]}"
  fi

  echo "==> built target/$triple/release/{libveilclient_ffi.{so,a},liblibveilclient_ffi.dylib}"
  ls -la "$REPO_ROOT/target/$triple/release/" 2>/dev/null \
    | grep -E 'liblibveilclient|libveilclient_ffi' || true
}

main() {
  local target=""
  local features="$DEFAULT_FEATURES"
  local all=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target) target="$2"; shift 2 ;;
      --features) features="$2"; shift 2 ;;
      --all) all=true; shift ;;
      --list)
        printf '%s\n' "${MOBILE_TARGETS[@]}"
        exit 0
        ;;
      -h|--help) usage; exit 0 ;;
      *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
  done

  # cycle-7 (M3): `allow-empty-seeds` is dev/testnet-only (no builtin seeds).
  # Refuse to bake it into a (potentially release) artifact unless the operator
  # explicitly opts in with VEIL_MOBILE_DEV=1, so a release build can never
  # silently ship the bootstrap-less dev posture.
  if [[ "$features" == *allow-empty-seeds* && "${VEIL_MOBILE_DEV:-0}" != "1" ]]; then
    echo "ERROR: refusing to build with 'allow-empty-seeds' (dev/testnet only)." >&2
    echo "       Release builds use the default 'production-seeds'. For a dev/testnet" >&2
    echo "       build: VEIL_MOBILE_DEV=1 $0 ... --features allow-empty-seeds" >&2
    exit 2
  fi

  if [[ -z "$target" && "$all" != true ]]; then
    echo "ERROR: pass --target <triple> or --all" >&2
    usage >&2
    exit 2
  fi

  if [[ -n "$target" ]]; then
    build_one "$target" "$features"
  else
    for t in "${MOBILE_TARGETS[@]}"; do
      build_one "$t" "$features"
    done
  fi
}

main "$@"
