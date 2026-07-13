#!/usr/bin/env bash
# Build and stage the iOS arm64 veil media engine (device by default,
# Apple-Silicon simulator with --sim).
#
# The WebRTC checkout is pinned by the xVeil media integration notes. This
# script builds //:webrtc as a complete static library, compiles the veil
# control/capture TUs with call.cc's exact toolchain flags, then stages four
# CocoaPods archives:
#   libveil_media.a  — force-loaded ABI/shim/Apple capture objects
#   libwebrtc.a      — normally extracted reachable WebRTC graph
#   libwebrtc_cxx*.a — self-contained Chromium libc++/libc++abi runtimes
set -euo pipefail

SIM=false
if [[ "${1:-}" == "--sim" ]]; then
  SIM=true
  shift
fi

WEBRTC_ROOT="${WEBRTC_ROOT:-$HOME/Projects/veilnetwork/webrtc-checkout}"
WEBRTC_SRC="${WEBRTC_SRC:-$WEBRTC_ROOT/src}"
if $SIM; then
  WEBRTC_OUT="${WEBRTC_OUT:-out/ios-sim-arm64}"
  TARGET_ENVIRONMENT="simulator"
else
  WEBRTC_OUT="${WEBRTC_OUT:-out/ios-arm64}"
  TARGET_ENVIRONMENT="device"
fi
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Frameworks}"
DEPOT_TOOLS="${DEPOT_TOOLS:-$WEBRTC_ROOT/depot_tools}"
GN="$DEPOT_TOOLS/gn"
AUTONINJA="$DEPOT_TOOLS/autoninja"
CLANGXX="$WEBRTC_SRC/third_party/llvm-build/Release+Asserts/bin/clang++"
LLVM_BIN="$WEBRTC_SRC/third_party/llvm-build/Release+Asserts/bin"
CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
WEBRTC_A="$WEBRTC_SRC/$WEBRTC_OUT/obj/libwebrtc.a"
WEBRTC_CXX_A="$WEBRTC_SRC/$WEBRTC_OUT/obj/buildtools/third_party/libc++/libc++.a"
WEBRTC_CXXABI_A="$WEBRTC_SRC/$WEBRTC_OUT/obj/buildtools/third_party/libc++abi/libc++abi.a"
WEBRTC_CXX_OBJDIR="$WEBRTC_SRC/$WEBRTC_OUT/obj/buildtools/third_party/libc++/libc++"
WEBRTC_CXXABI_OBJDIR="$WEBRTC_SRC/$WEBRTC_OUT/obj/buildtools/third_party/libc++abi/libc++abi"

[ -x "$GN" ] || { echo "no gn at $GN" >&2; exit 1; }
[ -x "$AUTONINJA" ] || { echo "no autoninja at $AUTONINJA" >&2; exit 1; }
[ -x "$CLANGXX" ] || { echo "no bundled clang at $CLANGXX" >&2; exit 1; }

# Some Chromium clang packages omit the Mach-O inspection aliases expected by
# linker_driver.py. Xcode supplies the canonical tools; add stable aliases only
# when the bundled names are absent.
if [[ ! -e "$LLVM_BIN/llvm-otool" ]]; then
  ln -s "$(xcrun --find otool)" "$LLVM_BIN/llvm-otool"
fi
if [[ ! -e "$LLVM_BIN/llvm-nm" ]]; then
  ln -s "$(xcrun --find nm)" "$LLVM_BIN/llvm-nm"
fi

ARGS="target_os=\"ios\" target_environment=\"$TARGET_ENVIRONMENT\" target_cpu=\"arm64\" is_debug=false is_component_build=false symbol_level=0 rtc_include_tests=false rtc_build_examples=false rtc_build_tools=false rtc_enable_protobuf=false rtc_use_h264=false enable_libaom=false rtc_include_opus=true ios_enable_code_signing=false treat_warnings_as_errors=false"
(
  cd "$WEBRTC_SRC"
  "$GN" gen "$WEBRTC_OUT" --export-compile-commands --args="$ARGS"
  # The plain ninja target named "webrtc" is ambiguous on iOS and may select
  # sdk/WebRTC.framework. Request the complete root static archive explicitly.
  "$AUTONINJA" -C "$WEBRTC_OUT" obj/libwebrtc.a
)
[ -f "$CC_JSON" ] || { echo "missing $CC_JSON" >&2; exit 1; }
[ -f "$WEBRTC_A" ] || { echo "missing $WEBRTC_A" >&2; exit 1; }
[ -f "$WEBRTC_CXX_A" ] || { echo "missing $WEBRTC_CXX_A" >&2; exit 1; }
[ -f "$WEBRTC_CXXABI_A" ] || { echo "missing $WEBRTC_CXXABI_A" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

compile_tu() {
  python3 - "$CC_JSON" "$1" "$2" "$SRCDIR" <<'PY' > "$TMP/tu.sh"
import json,re,shlex,sys
cc=json.load(open(sys.argv[1])); src,out,shimdir=sys.argv[2:5]
entry=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
args=entry.get('arguments')
if not args:
    args=shlex.split(entry['command'])
source_index=next(i for i,a in enumerate(args) if a.endswith('call/call.cc'))
args[source_index]=src
out_index=args.index('-o') + 1
args[out_index]=out
args[1:1]=['-DVEIL_MEDIA_HAVE_WEBRTC=1', '-I'+shimdir]
if src.endswith('.mm'):
    args.insert(1, '-fobjc-arc')
print('cd '+shlex.quote(entry['directory']))
print(' '.join(shlex.quote(a) for a in args))
PY
  bash "$TMP/tu.sh"
}

echo "==> compiling iOS veil media objects"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"
compile_tu "$SRCDIR/veil_avf_adm.mm" "$TMP/avf_adm.o"
compile_tu "$SRCDIR/veil_avf_camera.mm" "$TMP/avf_camera.o"
compile_tu "$SRCDIR/veil_ios_screen_stub.cc" "$TMP/screen_stub.o"
compile_tu "$SRCDIR/veil_audio_record.cc" "$TMP/record.o"
compile_tu "$SRCDIR/veil_audio_play.cc" "$TMP/play.o"
compile_tu "$SRCDIR/veil_video_note.cc" "$TMP/vnote.o"

mkdir -p "$DEST"
xcrun libtool -static -o "$DEST/libveil_media.a" \
  "$TMP/engine.o" "$TMP/shim.o" "$TMP/avf_adm.o" \
  "$TMP/avf_camera.o" "$TMP/screen_stub.o" "$TMP/record.o" \
  "$TMP/play.o" "$TMP/vnote.o"
cp -f "$WEBRTC_A" "$DEST/libwebrtc.a"
# Chromium generates libc++ and libc++abi as thin archives. Copying those out
# of the GN tree leaves relative member references dangling (and ranlib then
# reduces each file to an empty 96-byte archive). Repack their object members
# into self-contained archives suitable for a CocoaPods vendored library.
CXX_OBJECTS=()
while IFS= read -r obj; do CXX_OBJECTS+=("$obj"); done \
  < <(find "$WEBRTC_CXX_OBJDIR" -type f -name '*.o' -print | sort)
CXXABI_OBJECTS=()
while IFS= read -r obj; do CXXABI_OBJECTS+=("$obj"); done \
  < <(find "$WEBRTC_CXXABI_OBJDIR" -type f -name '*.o' -print | sort)
[ "${#CXX_OBJECTS[@]}" -gt 0 ] || { echo "no libc++ objects in $WEBRTC_CXX_OBJDIR" >&2; exit 1; }
[ "${#CXXABI_OBJECTS[@]}" -gt 0 ] || { echo "no libc++abi objects in $WEBRTC_CXXABI_OBJDIR" >&2; exit 1; }
xcrun libtool -static -o "$DEST/libwebrtc_cxx.a" "${CXX_OBJECTS[@]}"
xcrun libtool -static -o "$DEST/libwebrtc_cxxabi.a" "${CXXABI_OBJECTS[@]}"
xcrun ranlib "$DEST/libveil_media.a" "$DEST/libwebrtc.a"

echo "==> staged iOS media archives"
ls -lh "$DEST/libveil_media.a" "$DEST/libwebrtc.a" \
  "$DEST/libwebrtc_cxx.a" "$DEST/libwebrtc_cxxabi.a"
nm -gU "$DEST/libveil_media.a" | grep -c ' T _veil_media_' | \
  xargs echo "exported veil_media_* symbols:"
