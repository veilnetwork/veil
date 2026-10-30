#!/usr/bin/env python3
"""ABI smoke with a tiny test library; pass an existing package_config.json."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

test = Path(__file__).resolve().parent
packages = Path(sys.argv[1]).resolve()
if not packages.is_file():
    raise SystemExit('An existing Dart package_config.json is required.')
with tempfile.TemporaryDirectory(prefix='veil-mic-ffi-',
        dir='/private/tmp/' if sys.platform == 'darwin' else None) as temporary:
    library = Path(temporary) / ('stand.dylib' if sys.platform == 'darwin' else 'stand.so')
    subprocess.run(['cc', '-dynamiclib' if sys.platform == 'darwin' else '-shared',
        '-fPIC', str(test / 'microphone_control_ffi_fixture.c'), '-o', str(library)], check=True)
    environment = {**os.environ, 'VEIL_MEDIA_DYLIB': str(library)}
    if sys.platform == 'darwin':
        environment['TMPDIR'] = '/private/tmp/'
    environment.pop('VEIL_FFI_DYLIB', None)
    project = packages.parent.parent
    if not (project / 'pubspec.yaml').is_file():
        raise SystemExit('Pass a Flutter project .dart_tool/package_config.json.')
    subprocess.run(['flutter', 'test', '--no-pub',
        str(test / 'microphone_control_ffi_smoke.dart')],
        cwd=project, env=environment, check=True)
