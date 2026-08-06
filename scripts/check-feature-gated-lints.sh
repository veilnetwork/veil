#!/usr/bin/env bash
# Lint the code that lives behind OPT-IN cargo features.
#
# WHY THIS EXISTS
# ---------------
# `cargo clippy --workspace --all-targets` builds every workspace member with
# its DEFAULT feature set, unified across the workspace. Anything behind a
# non-default feature is therefore never fed to the compiler by the gate — it
# is not "untested", it is not compiled at all.
#
# On 2026-08-06 that cost five days. `crates/veilclient-ffi/src/anon_stream.rs`
# — the live streaming transport, ~4.5k lines — derived its rendezvous cookie
# from the node identity while the relay (768f8aa7) had moved to deriving it
# from the registration key. The two could never match, so the live delivery
# path was dead: calls did not arrive at all and text crawled through the
# mailbox. All 5052 tests stayed green, because `anon_stream.rs` sits behind
# `node-embedded` and no gate command enabled it.
#
# WHAT IS CHECKED
# ---------------
# The feature sets that are actually SHIPPED, so a break here is a break in a
# user's build:
#
#   node-embedded                 xVeil `builder.py` (desktop dylib)
#   node-embedded,packet-tunnel   `scripts/build-mobile.sh`, `build-native.sh`
#
# Both are checked, not just their union: the two differ in real lints. The
# `owned_runtime_dir` field is written only by `veil_vpn_upstream_start`, which
# is `packet-tunnel`-only — so under the union it has a writer and rustc is
# quiet, while under bare `node-embedded` it is dead. A gate that only checked
# the union would have shipped a warning to the narrower build.
#
# `node-embedded-rocksdb` is deliberately NOT a third pass: it adds no `cfg`
# site of its own (it only flips `veil-node-runtime/rocksdb-cold`, whose code
# the workspace gate already compiles through `veil-cli`'s defaults).
#
# WHAT IS NOT CHECKED, AND WHY
# ----------------------------
#   veil-dispatcher/relay-trace   ~10 log statements that print the rendezvous
#                                 cookie for debugging; opt-in by design and
#                                 never shipped. Verified clean 2026-08-06.
#   veil-fingerprint/pcap         Optional pcap parsing behind an extra crate;
#                                 no shipped binary enables it. Clean
#                                 2026-08-06.
#   veilcore/slow-sim-tests       Only toggles `#[ignore]`; the tests behind it
#                                 ARE compiled by the ordinary gate.
#   */production-seeds            A release-only `compile_error!` assertion on
#                                 the builtin seed list, and mutually exclusive
#                                 with the `allow-empty-seeds` the test gate
#                                 needs. Enforced by the release build instead.
#   */tls-boring, */rocksdb-cold  Default-on for `veil-cli`/`ogate`/`oproxy`/
#                                 `veilclient-ffi`, so the workspace gate
#                                 compiles the enabled side. The DISABLED side
#                                 (`cfg(not(...))` — the rustls and in-memory
#                                 fallbacks) is compiled by ci.yml's
#                                 `windows-check`, which excludes exactly the
#                                 tls-boring-default crates, and by the
#                                 `-p veilclient-ffi` passes below (they select
#                                 one crate, so `veil-cli`'s `rocksdb-cold`
#                                 does not unify into them).
#
# Test-only opt-in features are run by the test gate, not here — see
# `.github/workflows/ci.yml` ("Run feature-gated tests").
#
# HOST NOTE
# ---------
# `packet_tunnel/linux_helper.rs` (~900 lines, the pkexec-entered privileged
# VPN helper) is `#[cfg(target_os = "linux")]`, so a macOS run of this script
# does not compile it. Cross-checking it from macOS is not possible either —
# `--target x86_64-unknown-linux-musl` dies in `aws-lc-sys`' C build for want
# of a musl sysroot, not for anything in our source. The ubuntu CI runners are
# where that file gets a compiler; that is the reason this script is wired into
# both workflows and not only into the local gate.
#
# Usage: invoke from anywhere. Exits non-zero on the first failing pass.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run_pass() {
    local features="$1"
    echo "==> cargo clippy -p veilclient-ffi --all-targets --features ${features}"
    cargo clippy -p veilclient-ffi --all-targets --features "${features}" -- -D warnings
}

run_pass "node-embedded"
run_pass "node-embedded,packet-tunnel"

echo "OK: feature-gated code lints clean."
