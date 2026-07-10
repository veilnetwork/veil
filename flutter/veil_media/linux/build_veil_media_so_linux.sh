#!/usr/bin/env bash
# Build libveil_media.so for linux-x64 from a from-source WebRTC checkout.
#
# Runs on an x86_64 Linux host (the same `wrtc` container / VM that built the
# linux-x64 libwebrtc.a, so out/linux-x64/compile_commands.json exists).
#
# Produces a self-contained .so: the veil call media engine (engine.cc) + the
# webrtc::Transport shim + the V4L2 camera capturer (veil_v4l2_camera.cc) + a
# codec-stripped libwebrtc, all statically linked, exporting ONLY the
# veil_media_* extern-C ABI. Audio uses WebRTC's built-in linux ADM
# (PulseAudio/ALSA, dlopen'd at runtime — no link dep).
# veil_media_send_datagram / veil_media_set_recv_callback stay undefined and
# resolve at runtime from libveilclient_ffi.so in the host process (a DT_NEEDED
# is added so the glibc loader resolves them; $ORIGIN rpath finds the sibling
# .so in the app bundle's lib/ dir).
#
# Usage: WEBRTC_SRC=/webrtc/src WEBRTC_OUT=out/linux-x64 \
#        ./build_veil_media_so_linux.sh [dest_dir]
set -euo pipefail

WEBRTC_SRC="${WEBRTC_SRC:-/webrtc/src}"
WEBRTC_OUT="${WEBRTC_OUT:-out/linux-x64}"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
DEST="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
mkdir -p "$DEST"

CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
[ -f "$CC_JSON" ] || { echo "no $CC_JSON — build linux-x64 libwebrtc first" >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Compile one TU with call.cc's EXACT flags (bundled clang, __Cr libc++,
# -std=c++20, linux sysroot), swapping only the source.
compile_tu() {  # $1=src  $2=out.o
  python3 - "$CC_JSON" "$1" "$2" "$SRCDIR" <<'PY' > "$TMP/tu.sh"
import json,sys,re
cc=json.load(open(sys.argv[1])); src,out,shimdir=sys.argv[2],sys.argv[3],sys.argv[4]
e=next(x for x in cc if x.get('file','').endswith('call/call.cc'))
cmd=(e['command'] if e.get('command') else ' '.join(e['arguments'])).strip()
s=re.search(r'(\S*call/call\.cc)',cmd).group(1)
cmd=cmd.replace(s,src); cmd=re.sub(r'-o\s+\S+','-o '+out,cmd)
p=cmd.split(' ',1); cmd=p[0]+' -DVEIL_MEDIA_HAVE_WEBRTC=1 -I'+shimdir+' '+p[1]
open('/dev/stdout','w').write('cd "'+e['directory']+'"\n'+cmd+'\n')
PY
  bash "$TMP/tu.sh"
}

echo "==> compiling engine + shim + v4l2_camera (linux toolchain)"
compile_tu "$SRCDIR/veil_media_engine.cc" "$TMP/engine.o"
compile_tu "$SRCDIR/veil_transport_shim.cc" "$TMP/shim.o"
compile_tu "$SRCDIR/veil_v4l2_camera.cc" "$TMP/v4l2.o"
compile_tu "$SRCDIR/veil_audio_record.cc" "$TMP/record.o"
compile_tu "$SRCDIR/veil_audio_play.cc" "$TMP/play.o"

# ELF export control: only veil_media_* global.
cat > "$TMP/exports.map" <<'MAP'
{ global: veil_media_*; local: *; };
MAP

cd "$WEBRTC_SRC/$WEBRTC_OUT"
# Chromium __Cr libc++ + libc++abi objects (webrtc builds its own; the sysroot's
# libstdc++ would clash with the __Cr namespace, so bring ours and suppress the
# driver's default C++ stdlib). No custom libunwind on the linux build → use the
# sysroot's libgcc/libgcc_s for the C++ unwinder + compiler builtins.
CXX_OBJS="$(find obj/buildtools/third_party/libc++ obj/buildtools/third_party/libc++abi -name '*.o')"
[ -n "$CXX_OBJS" ] || { echo "no libc++ objects — build libwebrtc first" >&2; exit 1; }

# Reuse the exact clang + --target + --sysroot from call.cc's command.
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

echo "==> linking libveil_media.so ($TGT, lld, sysroot libgcc unwinder)"
# -fuse-ld=lld: WebRTC objects carry chromium-format .eh_frame that the system
# GNU ld rejects ("no .eh_frame_hdr table"); the bundled lld (sibling of clang)
# is what chromium links with.
# shellcheck disable=SC2086
"$CLANGXX" -shared -o "$DEST/libveil_media.so" \
  $TGT --sysroot="$SYSROOT" -fuse-ld=lld -nostdlib++ -rtlib=libgcc -unwindlib=libgcc \
  "$TMP/engine.o" "$TMP/shim.o" "$TMP/v4l2.o" "$TMP/record.o" "$TMP/play.o" obj/libwebrtc.a $CXX_OBJS \
  -Wl,--gc-sections -Wl,--version-script,"$TMP/exports.map" \
  -Wl,-soname,libveil_media.so -Wl,-rpath,'$ORIGIN' \
  -lpthread -ldl -lrt -lm -lX11
# -lX11: WebRTC's linux desktop-capture code (unused — we drive V4L2) leaves
# XOpenDisplay/XCloseDisplay/XQueryKeymap referenced past --gc-sections. GTK3
# already hard-links libX11 so this adds no new runtime requirement; the
# explicit DT_NEEDED just avoids a lazy-binding surprise under RTLD_NOW.

# DT_NEEDED on libveilclient_ffi.so: it defines the two undefined veil_media_*
# symbols (send_datagram / set_recv_callback). Explicit NEEDED + $ORIGIN rpath
# make the loader resolve them from the sibling .so in the app bundle's lib/.
if command -v patchelf >/dev/null 2>&1; then
  patchelf --add-needed libveilclient_ffi.so "$DEST/libveil_media.so" || true
else
  echo "WARN: patchelf missing — add DT_NEEDED libveilclient_ffi.so manually" >&2
fi

# Strip debug info (VEIL_MEDIA_NO_STRIP=1 keeps symbols for crash symbolication).
STRIP="$(dirname "$CLANGXX")/llvm-strip"
if [ -z "${VEIL_MEDIA_NO_STRIP:-}" ] && [ -x "$STRIP" ]; then
  "$STRIP" --strip-unneeded "$DEST/libveil_media.so" 2>/dev/null || true
fi

NM="$(dirname "$CLANGXX")/llvm-nm"
echo "==> done: $DEST/libveil_media.so ($(du -h "$DEST/libveil_media.so" | cut -f1))"
"$NM" -D --defined-only "$DEST/libveil_media.so" 2>/dev/null | grep -c " T veil_media_" | xargs echo "exported veil_media_* symbols:"
echo "--- undefined veil_media_* (expect send_datagram + set_recv_callback) ---"
"$NM" -D -u "$DEST/libveil_media.so" 2>/dev/null | grep veil_media_ || true
