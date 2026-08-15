#!/usr/bin/env bash
# Build libveil_media.dylib for macOS (arm64) from a from-source WebRTC checkout.
#
# Produces a self-contained dylib: the veil call media engine (engine.cc) + the
# webrtc::Transport shim + a codec-stripped libwebrtc, all statically linked
# inside, exporting ONLY the `veil_media_*` extern-C ABI (the __Cr Chromium
# libc++ internals stay hidden). `veil_media_send_datagram` /
# `veil_media_set_recv_callback` are left undefined (dynamic_lookup) and resolve
# at runtime from libveilclient_ffi in the host process. ~4 MB (dead-stripped;
# libwebrtc.a is an archive so only the audio path is pulled).
#
# Bundle the result into the app the same way as libveilclient_ffi / the HV
# dylib (Contents/Frameworks + @rpath + re-sign); Dart finds the symbols via
# DynamicLibrary.process().
#
# Usage: WEBRTC_SRC=~/Projects/veilnetwork/webrtc-checkout/src \
#        WEBRTC_OUT=out/mac-arm64 ./build_veil_media_dylib.sh [dest_dir]
set -euo pipefail

WEBRTC_SRC="${WEBRTC_SRC:-$HOME/Projects/veilnetwork/webrtc-checkout/src}"
WEBRTC_OUT="${WEBRTC_OUT:-out/mac-arm64}"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Frameworks}"
mkdir -p "$DEST"

CLANGXX="$WEBRTC_SRC/third_party/llvm-build/Release+Asserts/bin/clang++"
CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
[ -x "$CLANGXX" ] || { echo "no bundled clang at $CLANGXX — build WebRTC first" >&2; exit 1; }
[ -f "$CC_JSON" ] || { echo "no $CC_JSON — run gn gen" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Compile one TU with call.cc's EXACT flags (bundled clang, __Cr libc++,
# -std=c++20, -nostdinc++, the WebRTC defines) — swapping only the source. This
# is the only reliable way to match WebRTC's compile environment.
compile_tu() {  # $1=src  $2=out.o
  python3 - "$CC_JSON" "$1" "$2" "$SRCDIR" <<'PY' > "$TMP/tu.sh"
import json,sys,re
cc=json.load(open(sys.argv[1])); src,out,shimdir=sys.argv[2],sys.argv[3],sys.argv[4]
e=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
cmd=e['command'] if e.get('command') else ' '.join(e['arguments'])
s=re.search(r'(\S*call/call\.cc)',cmd).group(1)
cmd=cmd.replace(s,src); cmd=re.sub(r'-o\s+\S+','-o '+out,cmd)
extra='-DVEIL_MEDIA_HAVE_WEBRTC=1 -I'+shimdir
if src.endswith('.mm'): extra+=' -fobjc-arc'  # Objective-C++ (AVAudioEngine ADM)
p=cmd.split(' ',1); cmd=p[0]+' '+extra+' '+p[1]
open('/dev/stdout','w').write('cd "'+e['directory']+'"\n'+cmd+'\n')
PY
  bash "$TMP/tu.sh"
}

echo "==> compiling engine + shim + avf_adm + avf_camera with the WebRTC toolchain"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"
compile_tu "$SRCDIR/veil_avf_adm.mm" "$TMP/avf_adm.o"
compile_tu "$SRCDIR/veil_avf_camera.mm" "$TMP/avf_camera.o"
compile_tu "$SRCDIR/veil_avf_screen.mm" "$TMP/avf_screen.o"
compile_tu "$SRCDIR/veil_audio_record.cc" "$TMP/record.o"
compile_tu "$SRCDIR/veil_audio_play.cc" "$TMP/play.o"
compile_tu "$SRCDIR/veil_video_note.cc" "$TMP/vnote.o"

# The export list must contain only symbols DEFINED here. A `_veil_media_*`
# wildcard also matches the two symbols this dylib IMPORTS via
# -undefined dynamic_lookup (veil_media_send_datagram /
# veil_media_set_recv_callback live in veilclient-ffi); listing an undefined
# symbol as exported makes ld64 record it as a re-export with the
# dynamic-lookup ordinal (-2), and modern dyld then rejects the whole image
# on dlopen ("re-export ordinal -2 out of range"), breaking the native
# voice/video players. ld64 refuses -unexported_symbols_list next to an
# export list, so the defined set is discovered with a first filterless link
# pass and fed to the final link explicitly (see below).

cd "$WEBRTC_SRC/$WEBRTC_OUT"
CXX_OBJS="$(find obj/buildtools/third_party/libc++ obj/buildtools/third_party/libc++abi -name '*.o')"
SDK="sdk/xcode_links/$(ls sdk/xcode_links | grep -iE 'MacOSX[0-9].*\.sdk$' | head -1)"

# dead_strip keeps the dylib ~4MB, but it can drop codec code that WebRTC's
# builtin factories reach only through internal function-pointer tables (the VP8
# video encoder factory crashed with a null call). Set VEIL_MEDIA_NO_DEADSTRIP=1
# to link the whole reachable graph while diagnosing that.
DEADSTRIP="-Wl,-dead_strip"
[ -n "${VEIL_MEDIA_NO_DEADSTRIP:-}" ] && DEADSTRIP=""

# WHICH MAC. The link target was written as arm64 because that is what this
# is built on, while the compile side takes its flags from the bundle's own
# compile_commands.json — so an x86_64 bundle compiled x86_64 objects and
# then asked the linker for arm64. Every member of libwebrtc.a was skipped
# with "found architecture 'x86_64', required architecture 'arm64'" and the
# link died on undefined symbols, which reads like a missing library.
#
# Derived from the same command the objects were compiled with, exactly as
# the Windows wrapper derives /MACHINE: the bundle knows what it is, and
# nothing else here should be guessing.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_TARGET="$(python3 "$SCRIPT_DIR/_mac_target.py" \
  "$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json")"
echo "==> linking for $MAC_TARGET"

link_dylib() {
  # $1 = output path, remaining args = extra linker flags
  local out="$1"; shift
  # shellcheck disable=SC2086
  "$CLANGXX" -dynamiclib -o "$out" \
    "$TMP/engine.o" "$TMP/shim.o" "$TMP/avf_adm.o" "$TMP/avf_camera.o" "$TMP/avf_screen.o" "$TMP/record.o" "$TMP/play.o" "$TMP/vnote.o" obj/libwebrtc.a $CXX_OBJS \
    $DEADSTRIP -Wl,-undefined,dynamic_lookup \
    "$@" \
    -install_name @rpath/libveil_media.dylib \
    --target="$MAC_TARGET" -isysroot "$SDK" \
    -framework Foundation -framework CoreFoundation -framework CoreAudio -framework AudioToolbox \
    -framework AudioUnit -framework CoreServices -framework IOKit -framework SystemConfiguration \
    -framework Security -framework CoreMedia -framework CoreVideo -framework AVFoundation -framework ApplicationServices \
    -framework CoreGraphics -weak_framework ScreenCaptureKit
}

echo "==> link pass 1: discover defined veil_media_* exports (sdk=$SDK)"
link_dylib "$TMP/probe.dylib"
nm -gU "$TMP/probe.dylib" | awk '{print $3}' | grep '^_veil_media_' > "$TMP/exported.txt"
echo "==> link pass 2: final dylib with $(wc -l < "$TMP/exported.txt" | xargs) defined exports (deadstrip='${DEADSTRIP}')"
link_dylib "$DEST/libveil_media.dylib" -Wl,-exported_symbols_list,"$TMP/exported.txt"

echo "==> done: $DEST/libveil_media.dylib ($(du -h "$DEST/libveil_media.dylib" | cut -f1))"
nm -gU "$DEST/libveil_media.dylib" | grep -c "T _veil_media_" | xargs echo "exported veil_media_* symbols:"
