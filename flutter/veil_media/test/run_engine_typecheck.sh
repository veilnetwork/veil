#!/usr/bin/env bash
# Type-check the media engine TU without building the dylib.
#
# The engine is the one source here that cannot be compiled on its own: it
# needs WebRTC's exact compile environment (bundled clang, __Cr libc++,
# -nostdinc++, the full define set). Building the whole dylib to find a typo
# takes minutes, so in practice engine edits went out unchecked — and a native
# edit nobody compiled is how a fix becomes a defect.
#
# This compiles ONE translation unit with call.cc's exact flags, the same trick
# the dylib build uses, and throws the object away. It is a TYPE check: it says
# nothing about behaviour, and there is no runtime coverage of the engine on
# this host. Treat a pass as "this would build", nothing more.
#
# Needs the from-source WebRTC checkout the dylib build needs:
#   WEBRTC_SRC=~/Projects/veilnetwork/webrtc-checkout/src \
#   WEBRTC_OUT=out/mac-arm64 ./test/run_engine_typecheck.sh
set -euo pipefail

WEBRTC_SRC="${WEBRTC_SRC:-$HOME/Projects/veilnetwork/webrtc-checkout/src}"
WEBRTC_OUT="${WEBRTC_OUT:-out/mac-arm64}"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../src" && pwd)"
CC_JSON="$WEBRTC_SRC/$WEBRTC_OUT/compile_commands.json"
# Absolute, because the compile runs from WebRTC's build directory.
SRC_ARG="${1:-$SRCDIR/veil_media_engine.cc}"
SRC="$(cd "$(dirname "$SRC_ARG")" && pwd)/$(basename "$SRC_ARG")"
OUT="${TMPDIR:-/tmp}/veil_media_typecheck.o"

[ -f "$CC_JSON" ] || {
  echo "no $CC_JSON — build WebRTC and run gn gen first" >&2
  exit 1
}

python3 - "$CC_JSON" "$SRC" "$OUT" "$SRCDIR" <<'PY' > "${TMPDIR:-/tmp}/veil_media_typecheck.sh"
import json, re, sys
cc = json.load(open(sys.argv[1]))
src, out, shimdir = sys.argv[2], sys.argv[3], sys.argv[4]
# call.cc, because it is the TU whose flags the engine is compiled with in the
# real build — matching anything else would type-check under the wrong defines.
entry = next(x for x in cc if x.get('file', '').endswith('call/call.cc'))
cmd = entry['command'] if entry.get('command') else ' '.join(entry['arguments'])
cmd = cmd.replace(re.search(r'(\S*call/call\.cc)', cmd).group(1), src)
cmd = re.sub(r'-o\s+\S+', '-o ' + out, cmd)
print('cd ' + cc[0]['directory'])
print(cmd + ' -DVEIL_MEDIA_HAVE_WEBRTC=1 -I' + shimdir)
PY

bash "${TMPDIR:-/tmp}/veil_media_typecheck.sh"
rm -f "$OUT"
echo "ok  $(basename "$SRC") type-checks"
