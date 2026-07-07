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
p=cmd.split(' ',1); cmd=p[0]+' -DVEIL_MEDIA_HAVE_WEBRTC=1 -I'+shimdir+' '+p[1]
open('/dev/stdout','w').write('cd "'+e['directory']+'"\n'+cmd+'\n')
PY
  bash "$TMP/tu.sh"
}

echo "==> compiling engine + shim with the WebRTC toolchain"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"

printf '_veil_media_*\n' > "$TMP/exported.txt"

cd "$WEBRTC_SRC/$WEBRTC_OUT"
CXX_OBJS="$(find obj/buildtools/third_party/libc++ obj/buildtools/third_party/libc++abi -name '*.o')"
SDK="sdk/xcode_links/$(ls sdk/xcode_links | grep -iE 'MacOSX[0-9].*\.sdk$' | head -1)"

echo "==> linking libveil_media.dylib (sdk=$SDK)"
# shellcheck disable=SC2086
"$CLANGXX" -dynamiclib -o "$DEST/libveil_media.dylib" \
  "$TMP/engine.o" "$TMP/shim.o" obj/libwebrtc.a $CXX_OBJS \
  -Wl,-dead_strip -Wl,-undefined,dynamic_lookup \
  -Wl,-exported_symbols_list,"$TMP/exported.txt" \
  -install_name @rpath/libveil_media.dylib \
  --target=arm64-apple-macos -isysroot "$SDK" \
  -framework Foundation -framework CoreFoundation -framework CoreAudio -framework AudioToolbox \
  -framework AudioUnit -framework CoreServices -framework IOKit -framework SystemConfiguration \
  -framework Security -framework CoreMedia -framework ApplicationServices

echo "==> done: $DEST/libveil_media.dylib ($(du -h "$DEST/libveil_media.dylib" | cut -f1))"
nm -gU "$DEST/libveil_media.dylib" | grep -c "T _veil_media_" | xargs echo "exported veil_media_* symbols:"
