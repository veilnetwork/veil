#!/usr/bin/env python3
"""Check final-release thread and construction-failure/member lifetimes."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="veil-owner-ref-", dir=os.environ.get("TMPDIR")) as tmp:
    binary = Path(tmp) / "owner-thread-ref"
    subprocess.run([
        *shlex.split(os.environ.get("CXX", "c++")),
        "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I" + str(root / "src"),
        str(root / "test/owner_thread_ref_smoke.cc"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True)
