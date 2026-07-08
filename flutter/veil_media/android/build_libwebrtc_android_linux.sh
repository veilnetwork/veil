#!/usr/bin/env bash
# Build a codec-stripped libwebrtc.a for android-arm64.
#
# ⚠️ MUST run on an x86_64 Linux host. WebRTC's gn asserts host_os=="linux" for
# Android targets (build/config/BUILDCONFIG.gn: "Android builds are only
# supported on Linux."), and the Android NDK toolchain it downloads is
# linux-x86_64 only. macOS and linux-arm64 hosts cannot build this.
#
# Pinned to the SAME WebRTC commit as the verified macOS build so the engine +
# transport-shim API signatures (std::span SendRtp, DeliverRtpPacket arity,
# CreateEnvironment, SignalChannelNetworkState, …) match exactly.
#
# Output: $WEBRTC_BUILD/src/out/android-arm64/obj/libwebrtc.a
set -uo pipefail

WEBRTC_PIN="4ef980bc2c70834276c791e71e7834b8809f24ad"  # matches mac-arm64 build
WEBRTC_BUILD="${WEBRTC_BUILD:-$HOME/webrtc-android}"
mkdir -p "$WEBRTC_BUILD"; cd "$WEBRTC_BUILD" || exit 1

if [ "$(uname -s)" != "Linux" ]; then
  echo "FATAL: WebRTC Android must be built on Linux (host is $(uname -s))." >&2
  exit 1
fi

if [ ! -d depot_tools ]; then
  git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git || exit 1
fi
export PATH="$WEBRTC_BUILD/depot_tools:$PATH"
export DEPOT_TOOLS_UPDATE=1

if [ ! -f .gclient ]; then
  fetch --nohooks webrtc || exit 1
  # Android target deps (NDK etc.).
  grep -q "target_os" .gclient || echo "target_os = ['android']" >> .gclient
fi

cd src || exit 1
git fetch origin "$WEBRTC_PIN" 2>/dev/null || true
git checkout "$WEBRTC_PIN" || { echo "checkout $WEBRTC_PIN failed" >&2; exit 1; }
# Retry sync on transient 429s (as the mac build needed).
ok=0
for a in 1 2 3 4 5 6; do
  echo "SYNC_ATTEMPT=$a $(date -u +%H:%M:%S)"
  gclient sync --jobs 4 --with_branch_heads --reset && { ok=1; break; }
  sleep $((a*20))
done
[ "$ok" = 1 ] || { echo "FATAL: gclient sync failed" >&2; exit 1; }

OUT="out/android-arm64"
ARGS='target_os="android" target_cpu="arm64" is_debug=false is_component_build=false symbol_level=0 rtc_include_tests=false rtc_build_examples=false rtc_build_tools=false rtc_enable_protobuf=false rtc_use_h264=false enable_libaom=false rtc_include_opus=true treat_warnings_as_errors=false'
gn gen "$OUT" --args="$ARGS" || exit 1
ninja -C "$OUT" webrtc || exit 1

echo "DONE: $WEBRTC_BUILD/src/$OUT/obj/libwebrtc.a"
ls -la "$OUT/obj/libwebrtc.a"
echo "compile_commands.json: $WEBRTC_BUILD/src/$OUT/compile_commands.json"
echo "Next: build_veil_media_so.sh (cross-compile the .so against this libwebrtc.a)."
