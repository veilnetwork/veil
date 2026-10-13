#!/usr/bin/env bash
# Real bundled GCC controller; no devices, profiles or media playback.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$(mktemp -d "${TMPDIR:-/tmp}/veil_video_probe_budget.XXXXXX")"
trap 'rm -rf "$STAND_DIR"' EXIT
python3 - "$ROOT" "$STAND_DIR" <<'PY'
import json, os, shlex, subprocess, sys
from pathlib import Path
root, temporary = map(Path, sys.argv[1:])
webrtc = Path(os.environ.get('WEBRTC_SRC', str(Path.home()/'Projects/veilnetwork/webrtc-checkout/src')))
out = webrtc/os.environ.get('WEBRTC_OUT', 'out/mac-arm64')
commands = json.loads((out/'compile_commands.json').read_text())
entry = next(e for e in commands if e.get('file', '').endswith('call/call.cc'))
args = shlex.split(entry['command']) if 'command' in entry else entry['arguments']
source = root/'test/video_probe_budget_smoke.cc'
obj, exe = temporary/'probe.o', temporary/'smoke'
flags = []
skip = False
for a in args[1:]:
    if skip:
        skip = False
        continue
    if a in ('-o', '-MF', '-MT', '-MQ'):
        skip = True
        continue
    if a in ('-c', '-MMD', '-MD') or a.endswith('call/call.cc'):
        continue
    flags.append(a)
flags += ['-I'+str(root/'src')]
if '-DWEBRTC_ENABLE_PROTOBUF=1' in flags:
    flags += ['-I'+str(webrtc/'third_party/protobuf/src')]
subprocess.run([args[0], *flags, '-c', str(source), '-o', str(obj)], cwd=entry['directory'], check=True)
standard_objects = sorted(p for directory in [out/'obj/buildtools/third_party/libc++', out/'obj/buildtools/third_party/libc++abi'] for p in directory.rglob('*.o'))
subprocess.run([args[0], *flags, str(obj), str(out/'obj/libwebrtc.a'),
    *map(str, standard_objects), '-framework', 'Foundation', '-framework', 'CoreFoundation',
    '-o', str(exe)], cwd=entry['directory'], check=True)
subprocess.run([str(exe)], check=True)
PY
