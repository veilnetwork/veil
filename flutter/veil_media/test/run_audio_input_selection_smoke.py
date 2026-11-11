#!/usr/bin/env python3
"""Compile the exact production input-selection FFI with a controlled ADM."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "src/veil_media_engine.cc").read_text()
start = source.index("int veil_media_engine_select_audio_input(")
end = source.index("\nint veil_media_engine_select_audio_output(", start)
list_start = source.index("char* adm_devices_json(")
list_end = source.index("\n}  // namespace", list_start)
ffi_start = source.index("char* veil_media_engine_list_audio_inputs(")
ffi_end = source.index("\nchar* veil_media_engine_list_audio_outputs(", ffi_start)
with tempfile.TemporaryDirectory(prefix="veil-audio-input-", dir=os.environ.get("TMPDIR")) as tmp:
    (Path(tmp) / "selected_input.inc").write_text(source[start:end])
    (Path(tmp) / "listed_inputs.inc").write_text(source[list_start:list_end] + "\n" + source[ffi_start:ffi_end])
    failed = False
    for windows in (False, True):
        binary = Path(tmp) / ("input-windows" if windows else "input-nonwindows")
        command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-Wall", "-Wextra", "-Werror",
            "-I" + str(root / "src"), "-I" + tmp,
        ]
        if windows:
            command.append("-DINPUT_FIXTURE_WINDOWS=1")
        subprocess.run([
            *command, str(root / "test/audio_input_ffi_selection_smoke.cc"),
            "-o", str(binary),
        ], check=True)
        result = subprocess.run([str(binary)], check=False)
        failed |= result.returncode != 0
    raise SystemExit(1 if failed else 0)
