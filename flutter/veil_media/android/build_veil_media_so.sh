#!/usr/bin/env bash
# Build libveil_media.so for android-arm64 from a from-source WebRTC checkout.
# Runs on the SAME x86_64 Linux host as build_libwebrtc_android_linux.sh, after
# libwebrtc.a is built (so out/android-arm64/compile_commands.json exists).
#
# Produces a self-contained .so: the veil call media engine (engine.cc) + the
# webrtc::Transport shim + the AAudio ADM (veil_aaudio_adm.cc) + a codec-stripped
# libwebrtc, all statically linked, exporting ONLY the veil_media_* extern-C ABI.
# veil_media_send_datagram / veil_media_set_recv_callback stay undefined and
# resolve at runtime from libveilclient_ffi.so in the host process (both .so's
# live in the APK; see the Android integration notes in BUILD-INTEGRATION.md for
# the load-order / RTLD_GLOBAL requirement).
#
# Usage: WEBRTC_BUILD=~/webrtc-android ./build_veil_media_so.sh [dest_dir]
set -euo pipefail

WEBRTC_BUILD="${WEBRTC_BUILD:-$HOME/webrtc-android}"
WEBRTC_SRC="$WEBRTC_BUILD/src"
WEBRTC_OUT="out/android-arm64"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/jniLibs/arm64-v8a}"
mkdir -p "$DEST"

CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
[ -f "$CC_JSON" ] || { echo "no $CC_JSON — run build_libwebrtc_android_linux.sh first" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Compile one TU with call.cc's EXACT android flags (NDK clang, __Cr libc++,
# -std=c++20, android sysroot), swapping only the source.
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

echo "==> compiling engine + shim + aaudio_adm (android NDK toolchain)"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"
compile_tu "$SRCDIR/veil_aaudio_adm.cc"   "$TMP/aaudio_adm.o"

# ELF export control: only veil_media_* global.
cat > "$TMP/exports.map" <<'MAP'
{ global: veil_media_*; local: *; };
MAP

cd "$WEBRTC_SRC/$WEBRTC_OUT"
CXX_OBJS="$(find obj/buildtools/third_party/libc++ obj/buildtools/third_party/libc++abi -name '*.o')"
# NDK clang used for target compiles (from the android call.cc command).
CLANGXX="$(python3 - "$CC_JSON" <<'PY'
import json,sys,re
cc=json.load(open(sys.argv[1]))
e=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
cmd=e['command'] if e.get('command') else ' '.join(e['arguments'])
print(cmd.split(' ',1)[0])
PY
)"

echo "==> linking libveil_media.so"
# shellcheck disable=SC2086
"$CLANGXX" -shared -o "$DEST/libveil_media.so" \
  "$TMP/engine.o" "$TMP/shim.o" "$TMP/aaudio_adm.o" obj/libwebrtc.a $CXX_OBJS \
  --target=aarch64-linux-android21 \
  -Wl,--gc-sections -Wl,--version-script,"$TMP/exports.map" \
  -Wl,--allow-shlib-undefined -Wl,-soname,libveil_media.so \
  -static-libstdc++ -llog -laaudio -lOpenSLES -landroid

echo "==> done: $DEST/libveil_media.so ($(du -h "$DEST/libveil_media.so" | cut -f1))"
"${CLANGXX%clang++}llvm-nm" -D --defined-only "$DEST/libveil_media.so" 2>/dev/null | grep -c " T veil_media_" | xargs echo "exported veil_media_* symbols:"
