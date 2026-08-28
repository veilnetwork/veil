#!/usr/bin/env bash
# Build libveil_media.so for one Android ABI from a from-source WebRTC checkout.
# ANDROID_TARGET picks it: android-arm64 (default), android-arm, android-x64.
# Runs on the SAME x86_64 Linux host as build_libwebrtc_android_linux.sh, after
# libwebrtc.a is built (so out/android-arm64/compile_commands.json exists).
#
# Produces a self-contained .so: the veil call media engine (engine.cc) + the
# webrtc::Transport shim + the AAudio ADM (veil_aaudio_adm.cc) + a codec-stripped
# libwebrtc, all statically linked, exporting the veil_media_* extern-C ABI and
# the app-owned Camera2 JNI entry point.
# veil_media_send_datagram / veil_media_set_recv_callback stay undefined and
# resolve at runtime from libveilclient_ffi.so in the host process (both .so's
# live in the APK; see the Android integration notes in BUILD-INTEGRATION.md for
# the load-order / RTLD_GLOBAL requirement).
#
# Usage: WEBRTC_BUILD=~/webrtc-android [ANDROID_TARGET=android-arm] \
#          ./build_veil_media_so.sh [dest_dir]
set -euo pipefail

WEBRTC_BUILD="${WEBRTC_BUILD:-$HOME/webrtc-android}"
WEBRTC_SRC="$WEBRTC_BUILD/src"
# WHICH Android. An APK ships three ABIs and this built one of them, with the
# target spelled into the path — so a bundle for armeabi-v7a or x86_64 failed
# with "no out/android-arm64/compile_commands.json", which names a directory
# nobody asked for and reads like a missing build rather than a wrong guess.
#
# The out dir and the jniLibs dir have to move TOGETHER: they are the same
# choice written two ways, and letting one be overridden without the other is
# how an arm64 library ends up in the x86_64 folder, where nothing notices
# until an emulator refuses to start.
ANDROID_TARGET="${ANDROID_TARGET:-android-arm64}"
case "$ANDROID_TARGET" in
  android-arm64) ANDROID_ABI_DIR=arm64-v8a ;;
  android-arm)   ANDROID_ABI_DIR=armeabi-v7a ;;
  android-x64)   ANDROID_ABI_DIR=x86_64 ;;
  *) echo "unknown ANDROID_TARGET=$ANDROID_TARGET (android-arm64|android-arm|android-x64)" >&2; exit 2 ;;
esac
WEBRTC_OUT="${WEBRTC_OUT:-out/$ANDROID_TARGET}"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/jniLibs/$ANDROID_ABI_DIR}"
mkdir -p "$DEST"

CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
[ -f "$CC_JSON" ] || { echo "no $CC_JSON — run build_libwebrtc_android_linux.sh first, or set ANDROID_TARGET to the ABI this checkout actually built" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Compile one TU with call.cc's EXACT android flags (NDK clang, __Cr libc++,
# -std=c++20, android sysroot), swapping only the source.
compile_tu() {  # $1=src  $2=out.o
  python3 - "$CC_JSON" "$1" "$2" "$SRCDIR" <<'PY' > "$TMP/tu.sh"
import json,sys,re
cc=json.load(open(sys.argv[1])); src,out,shimdir=sys.argv[2],sys.argv[3],sys.argv[4]
e=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
cmd=(e['command'] if e.get('command') else ' '.join(e['arguments'])).strip()
s=re.search(r'(\S*call/call\.cc)',cmd).group(1)
cmd=cmd.replace(s,src); cmd=re.sub(r'-o\s+\S+','-o '+out,cmd)
# Retarget the veil TUs to android API 26: the AAudio ADM uses AAudio APIs
# introduced in 26, and libwebrtc is built at a lower min API (23) which makes
# those calls -Werror,-Wunguarded-availability. veil's AAudio path is API 26+
# by design (mirrors the old .so), so compile the veil TUs at 26.
#
# ANY android triple, not just arm64: this named `aarch64-linux-android` and so
# raised the API for exactly one of the three ABIs. On armeabi-v7a and x86_64
# the target stayed at 23 while `-D__ANDROID_API__` below moved to 26 — the
# header says the symbol exists, the target says it does not, and the two
# disagree about the same translation unit.
cmd=re.sub(r'(--target=\w+-linux-android(?:eabi)?)\d+', r'\g<1>26', cmd)
cmd=re.sub(r'-D__ANDROID_API__=\d+', '-D__ANDROID_API__=26', cmd)
# Keep deprecation warnings non-fatal when the Android WebRTC checkout exposes
# a legacy API that the macOS checkout still accepts.
p=cmd.split(' ',1); cmd=p[0]+' -DVEIL_MEDIA_HAVE_WEBRTC=1 -Wno-error=deprecated-declarations -I'+shimdir+' '+p[1]
open('/dev/stdout','w').write('cd "'+e['directory']+'"\n'+cmd+'\n')
PY
  bash "$TMP/tu.sh"
}

echo "==> compiling engine + shim + aaudio_adm (android NDK toolchain)"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"
compile_tu "$SRCDIR/veil_aaudio_adm.cc"   "$TMP/aaudio_adm.o"
compile_tu "$SRCDIR/veil_audio_record.cc" "$TMP/record.o"
compile_tu "$SRCDIR/veil_audio_play.cc"   "$TMP/play.o"
compile_tu "$SRCDIR/veil_video_note.cc"   "$TMP/vnote.o"

# ELF export control: public control ABI plus the direct Camera2 frame bridge.
cat > "$TMP/exports.map" <<'MAP'
{
  global:
    veil_media_*;
    Java_network_veil_xveil_NativeCallCamera_*;
    Java_network_veil_xveil_NativeCallVideoRenderer_*;
  local: *;
};
MAP

cd "$WEBRTC_SRC/$WEBRTC_OUT"
# Chromium __Cr libc++ + libc++abi + libunwind objects (webrtc builds all three;
# the NDK's own libc++/unwinder would clash with the __Cr namespace, so we bring
# our own and suppress the driver's C++/unwind defaults below).
CXX_OBJS="$(find obj/buildtools/third_party/libc++ obj/buildtools/third_party/libc++abi -name '*.o')"
UNWIND_OBJS="$(find obj/buildtools/third_party/libunwind -name '*.o')"
[ -n "$UNWIND_OBJS" ] || { echo "no libunwind objects — build libwebrtc first" >&2; exit 1; }
# Reuse the exact Chromium clang + android --target/--sysroot from the call.cc
# command (there is no NDK clang in this stripped toolchain).
read -r CLANGXX TGT SYSROOT <<EOF
$(python3 - "$CC_JSON" <<'PY'
import json,sys,re
cc=json.load(open(sys.argv[1]))
e=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
cmd=(e['command'] if e.get('command') else ' '.join(e['arguments'])).strip()
tgt=re.search(r'--target=\S+',cmd); sr=re.search(r'--sysroot=(\S+)',cmd)
print(cmd.split(' ',1)[0], tgt.group(0) if tgt else '', sr.group(1) if sr else '')
PY
)
EOF
# The sysroot's library directories are PER ABI: `usr/lib/<triple>/<api>`. The
# triple is the one clang was told to build for, so read it out of --target
# rather than naming one — this line said `aarch64-linux-android` for every
# ABI, and armeabi-v7a / x86_64 then linked against a directory belonging to
# another architecture (or, when it does not exist, against nothing at all).
#
# `--target=x86_64-linux-android23` → triple `x86_64-linux-android`, api `23`.
# The 32-bit ARM triple ends in `eabi` and clang spells the API level after it
# (`armv7a-linux-androideabi23`), which the same strip handles.
# Strip the TRAILING api digits only — every android arch name has digits in
# it (`aarch64`, `x86_64`, `armv7a`), so cutting at the first one leaves
# `aarch`, `x` and `armv`.
TARGET_TRIPLE="$(printf '%s' "${TGT#--target=}" | sed -E 's/[0-9]+$//')"
SYSROOT_LIBS="$SYSROOT/usr/lib/$TARGET_TRIPLE"
# AAudio's libaaudio.so lives only in the API 26+ lib dir; add it to the search path.
AAUDIO_L="$SYSROOT_LIBS/26"
echo "==> linking libveil_media.so ($TGT, sysroot=$SYSROOT, libs=$SYSROOT_LIBS)"
# The C runtime objects the driver adds implicitly come from the same per-ABI
# directory. When the toolchain does not carry this ABI the link fails deep in
# lld with `cannot open crtbegin_so.o: No such file or directory` — which names
# a file rather than the reason, and reads like a broken build instead of a
# toolchain that was never fetched for this architecture. Say it here, where
# the answer is one `ls` away, and list what the sysroot DOES carry.
if ! ls "$SYSROOT_LIBS"/*/crtbegin_so.o >/dev/null 2>&1; then
  echo "no C runtime for $TARGET_TRIPLE under $SYSROOT_LIBS —" >&2
  echo "this toolchain does not carry the $ANDROID_TARGET ABI. It has:" >&2
  find "$SYSROOT/usr/lib" -maxdepth 1 -mindepth 1 -exec basename {} \; 2>/dev/null | sed 's/^/  /' >&2
  exit 1
fi
if [ ! -d "$AAUDIO_L" ]; then
  echo "no API-26 lib dir at $AAUDIO_L — libaaudio.so will not resolve" >&2
  exit 1
fi
# shellcheck disable=SC2086
"$CLANGXX" -shared -o "$DEST/libveil_media.so" \
  $TGT --sysroot="$SYSROOT" -nostdlib++ -unwindlib=none \
  "$TMP/engine.o" "$TMP/shim.o" "$TMP/aaudio_adm.o" "$TMP/record.o" "$TMP/play.o" "$TMP/vnote.o" obj/libwebrtc.a $CXX_OBJS $UNWIND_OBJS \
  -L"$AAUDIO_L" \
  -Wl,--gc-sections -Wl,--version-script,"$TMP/exports.map" \
  -Wl,-soname,libveil_media.so \
  -llog -laaudio -lOpenSLES -landroid

# Strip debug info (the ELF ships with debug_info otherwise → ~5MB smaller).
# VEIL_MEDIA_NO_STRIP=1 keeps symbols for crash symbolication.
STRIP="$(dirname "$CLANGXX")/llvm-strip"
if [ -z "${VEIL_MEDIA_NO_STRIP:-}" ]; then
  [ -x "$STRIP" ] && "$STRIP" --strip-unneeded "$DEST/libveil_media.so" 2>/dev/null || true
fi

# DT_NEEDED on libveilclient_ffi.so: it defines the two undefined veil_media_*
# symbols (send_datagram / set_recv_callback). An explicit NEEDED makes the
# android linker resolve them when this .so is dlopen'd — a plain RTLD_GLOBAL
# preload from the Dart FFI side does NOT promote across bionic's namespaces.
if command -v patchelf >/dev/null 2>&1; then
  patchelf --add-needed libveilclient_ffi.so "$DEST/libveil_media.so" || true
else
  echo "WARN: patchelf missing — add DT_NEEDED libveilclient_ffi.so manually" >&2
fi

echo "==> done: $DEST/libveil_media.so ($(du -h "$DEST/libveil_media.so" | cut -f1))"
"${CLANGXX%clang++}llvm-nm" -D --defined-only "$DEST/libveil_media.so" 2>/dev/null | grep -c " T veil_media_" | xargs echo "exported veil_media_* symbols:"
