#!/usr/bin/env python3
"""Exercise packet/yield coordination and real Opus without a device or profile."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='veil-packet-priority-', dir=os.environ.get('TMPDIR')) as tmp:
    binary = str(Path(tmp) / 'policy')
    subprocess.run(['clang++', '-std=c++20', '-pthread', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(root / 'src'), str(root / 'test/audio_packet_priority_smoke.cc'),
                    '-o', binary], check=True)
    subprocess.run([binary], check=True)
subprocess.run([sys.executable, str(root / 'test/run_bounded_audio_encoder_smoke.py')],
               env=dict(os.environ, VEIL_BOUNDED_AUDIO_SMOKE_SOURCE='audio_packet_priority_opus_smoke.cc'),
               check=True)
