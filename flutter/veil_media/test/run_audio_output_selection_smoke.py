#!/usr/bin/env python3
"""Exercise the production output-switch transaction without audio hardware."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="veil-audio-output-", dir=os.environ.get("TMPDIR")) as tmp:
    binary = Path(tmp) / "audio-output-selection"
    subprocess.run([
        *shlex.split(os.environ.get("CXX", "c++")),
        "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-I" + str(root / "src"),
        str(root / "test/audio_output_selection_smoke.cc"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
