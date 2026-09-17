#!/usr/bin/env bash
# Type-check the WINDOWS half of veilclient-ffi.
#
# Why this exists
# ---------------
# `path_acl.rs` and `fs_beneath.rs` are `#[cfg(windows)]` in their entirety.
# Nothing in this repo's gates ever asked the compiler a Windows question, so
# the code in them was written, reviewed, tested on macOS and Linux — and never
# compiled at all. On 2026-09-17 that shipped a tag: `rules_json` returned its
# tail as `String` where the signature said `Result<String, String>`, a
# one-line type error that no local check could have seen, and it failed in
# xVeil's Windows bundle 57 minutes into the release run.
#
# `cargo check` rather than a build: the question is whether the code compiles,
# and a Windows LINK from here would need far more than a C toolchain.
#
# `x86_64-pc-windows-gnu` rather than `-msvc`: mingw-w64 exists on a Mac and a
# Linux runner, the MSVC linker does not. The two targets differ in linkage and
# ABI details, not in whether a `Result` is returned — which is the class of
# error this is here for.
#
# FEATURES. The Windows bundle builds `node-embedded` (see xVeil's builder.py)
# and NOT `packet-tunnel`, whose Unix-only `std::os::fd` and `OpenOptions::mode`
# are deliberately not cfg-gated because no Windows build reaches them. Asking
# for a feature set Windows never ships would fail on code Windows never
# compiles, and a gate that cries wolf is a gate people route around.
#
# `tls-boring` is off for the same reason it is not a Windows question here:
# BoringSSL's build script wants cmake and Go for the target, and CI's own
# Windows bundle builds it natively on a Windows runner where that works.
set -euo pipefail

target=x86_64-pc-windows-gnu

have_target() { rustup target list --installed 2>/dev/null | grep -qx "$target"; }
cc=x86_64-w64-mingw32-gcc

if ! have_target || ! command -v "$cc" >/dev/null 2>&1; then
  echo "NOT CHECKED: the Windows type-check needs a toolchain this host lacks."
  have_target || echo "  missing rust target: rustup target add $target"
  command -v "$cc" >/dev/null 2>&1 || echo "  missing C compiler: $cc (brew install mingw-w64 / apt-get install mingw-w64)"
  echo "  CI installs both, so the question is asked there on every run."
  exit 0
fi

# The workspace's .cargo/config.toml pins CC=clang for the host's C deps; clang
# cannot drive this target, so ring / aws-lc-sys / pqcrypto-internals need the
# per-target override. cc-rs reads these in preference to the global CC.
export CC_x86_64_pc_windows_gnu="$cc"
export CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++
export AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar

exec cargo check -p veilclient-ffi \
  --no-default-features --features node-embedded \
  --target "$target"
