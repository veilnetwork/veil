"""Exercise the workspace release profile with a real Darwin proc-macro load."""
from __future__ import annotations

import ctypes
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ROOT = ROOT


def profile_tables(name, values):
    scalars = {key: value for key, value in values.items() if not isinstance(value, dict)}
    result = [f"[{name}]", *[f"{key} = {json.dumps(value)}" for key, value in scalars.items()]]
    for key, value in values.items():
        if isinstance(value, dict):
            result.extend(profile_tables(f"{name}.{key}", value))
    return result


@unittest.skipUnless(sys.platform == "darwin", "Requires the Darwin linker and loader")
class ReleaseProcMacroTest(unittest.TestCase):
    def test_release_derive_compiles_and_its_host_library_loads(self):
        manifest = tomllib.loads((PROFILE_ROOT / "Cargo.toml").read_text())
        channel = tomllib.loads((PROFILE_ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        host = subprocess.check_output(["rustc", f"+{channel}", "-vV"], text=True)
        host = next(line.removeprefix("host: ") for line in host.splitlines() if line.startswith("host: "))
        with tempfile.TemporaryDirectory(prefix="veil-release-macro-", dir="/private/tmp") as temporary:
            source = Path(temporary)
            (source / "src").mkdir()
            # This fixed dependency set has a LINKEDIT layout that triggers
            # the linker/strip defect. It is isolated from production's lock.
            fixture = ROOT / "scripts/fixtures/darwin-proc-macro"
            (source / "Cargo.toml").write_text((fixture / "Cargo.toml").read_text()
                + "\n".join(profile_tables("profile.release", manifest["profile"]["release"])) + "\n")
            (source / "Cargo.lock").write_bytes((fixture / "Cargo.lock").read_bytes())
            (source / "src/lib.rs").write_bytes((fixture / "src/lib.rs").read_bytes())
            env = dict(os.environ)
            # A caller's workaround must not hide a broken workspace profile.
            for key in list(env):
                if key.startswith("CARGO_PROFILE_RELEASE_") or key in (
                        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS"):
                    env.pop(key)
            env.update(TMPDIR="/private/tmp/", CARGO_TARGET_DIR=str(source / "target"),
                       MACOSX_DEPLOYMENT_TARGET="12.0",
                       CARGO_BUILD_RUSTFLAGS=(
                           f"--remap-path-prefix={Path.home() / '.cargo'}=/cargo "
                           f"--remap-path-prefix={source}=/xveil "
                           f"--remap-path-prefix={Path.home()}=/build"))
            for command in (
                    ["cargo", f"+{channel}", "build", "--locked", "--release", "--target", host],):
                result = subprocess.run(command, cwd=source, env=env,
                                        capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            libraries = list((source / "target/release/deps").glob("libzeroize_derive*.dylib"))
            self.assertEqual(len(libraries), 1)
            # codesign/nm can both succeed on the malformed LINKEDIT that dyld
            # rejects. Ask the loader too, after rustc has expanded the derive.
            ctypes.CDLL(str(libraries[0]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    options, remaining = parser.parse_known_args()
    PROFILE_ROOT = options.workspace.resolve(strict=True)
    unittest.main(argv=[sys.argv[0], *remaining])
