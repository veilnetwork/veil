#!/usr/bin/env python3
"""Run against the same protobuf-enabled macOS WebRTC archive as the engine."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = Path(os.environ.get('WEBRTC_SRC', Path.home() / 'Projects/veilnetwork/webrtc-checkout/src'))
out = source / os.environ.get('WEBRTC_OUT', 'out/mac-arm64')
commands = json.loads((out / 'compile_commands.json').read_text())
entry = next(row for row in commands if row['file'].endswith('call/call.cc'))
command = shlex.split(entry['command']) if 'command' in entry else entry['arguments'][:]
if '-DWEBRTC_ENABLE_PROTOBUF=1' not in command:
    raise SystemExit('This regression requires a protobuf-enabled WebRTC archive')
with tempfile.TemporaryDirectory(prefix='veil-bounded-opus-', dir=os.environ.get('TMPDIR')) as tmp:
    temp = Path(tmp)
    command[command.index('-o') + 1] = str(temp / 'smoke.o')
    if '-MF' in command:
        command[command.index('-MF') + 1] = str(temp / 'smoke.d')
    command = [str(root / 'test/bounded_audio_encoder_smoke.cc')
               if token.endswith('call/call.cc') else token for token in command]
    command += ['-I' + str(root / 'src'), '-I' + str(source / 'third_party/protobuf/src')]
    subprocess.run(command, cwd=entry['directory'], check=True)
    clang = command[0]
    target = next(token for token in command if token.startswith('--target='))
    sdk = next((out / 'sdk/xcode_links').glob('MacOSX*.sdk'))
    objects = [str(obj) for name in ['libc++', 'libc++abi']
               for obj in (out / 'obj/buildtools/third_party' / name).rglob('*.o')]
    link = [clang, str(temp / 'smoke.o'), str(out / 'obj/libwebrtc.a'), *objects,
            '-Wl,-dead_strip', target, '-isysroot', str(sdk), '-o', str(temp / 'smoke')]
    for framework in ['Foundation', 'CoreFoundation', 'CoreAudio', 'AudioToolbox',
                      'AudioUnit', 'CoreServices', 'IOKit', 'SystemConfiguration',
                      'Security', 'CoreMedia', 'CoreVideo', 'AVFoundation']:
        link += ['-framework', framework]
    subprocess.run(link, cwd=entry['directory'], check=True)
    subprocess.run([str(temp / 'smoke')], check=True)
