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
    # Exercise the actual FFI branch too: helper-only coverage previously left
    # the non-Windows stop/set/init/start path outside the transaction.
    engine = (root / "src/veil_media_engine.cc").read_text()
    start = engine.index("int veil_media_engine_select_audio_output(")
    end = engine.index("\nchar* veil_media_engine_get_stats(", start)
    (Path(tmp) / "selected_output.inc").write_text(engine[start:end])
    binary = Path(tmp) / "audio-output-ffi-selection"
    subprocess.run([
        *shlex.split(os.environ.get("CXX", "c++")),
        "-std=c++17", "-Wall", "-Wextra", "-Werror",
        "-I" + str(root / "src"), "-I" + tmp,
        str(root / "test/audio_output_ffi_selection_smoke.cc"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
