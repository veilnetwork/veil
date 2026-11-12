"""Build real tiny binaries to check Darwin staging with an external Cargo target."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin", "Requires Apple's strip/codesign and loader")
class ReleaseStagingTest(unittest.TestCase):
    def test_external_cargo_output_wins_over_stale_local_files(self):
        channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        host = subprocess.check_output(["rustc", f"+{channel}", "-vV"], text=True)
        host = next(row.removeprefix("host: ") for row in host.splitlines() if row.startswith("host: "))
        with tempfile.TemporaryDirectory(prefix="veil-release-stage-", dir="/private/tmp") as temporary:
            base = Path(temporary)
            source = base / "repository"
            (source / "scripts").mkdir(parents=True)
            (source / "src/bin").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/build-release.sh", source / "scripts/build-release.sh")
            (source / "Cargo.toml").write_text(
                '[package]\nname = "release-stage-fixture"\nversion = "0.0.0"\nedition = "2024"\n'
                '[profile.release]\nstrip = "debuginfo"\n')
            binaries = ("veil-cli", "ogate", "oproxy-client", "oproxy-server")
            stale = source / "target" / host / "release"
            stale.mkdir(parents=True)
            for name in binaries:
                (source / "src/bin" / (name + ".rs")).write_text('fn main() { println!("fresh"); }\n')
                file = stale / name
                file.write_text('#!/bin/sh\necho stale\n')
                file.chmod(0o700)
            env = {**os.environ, "TMPDIR": "/private/tmp/", "RUSTUP_TOOLCHAIN": channel,
                   "CARGO_TARGET_DIR": str(base / "actual cargo output")}
            for command in (
                    ["cargo", "generate-lockfile", "--offline"],
                    ["bash", "scripts/build-release.sh", "--target", host, "--features", ""]):
                result = subprocess.run(command, cwd=source, env=env,
                                        capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            staged = source / "target/release-artifacts" / host
            for name in binaries:
                self.assertEqual(subprocess.check_output([str(staged / name)], text=True).strip(), "fresh")
                self.assertEqual((stale / name).read_text(), '#!/bin/sh\necho stale\n')
                subprocess.run(["codesign", "--verify", str(staged / name)],
                               capture_output=True, check=True)


if __name__ == "__main__":
    unittest.main()
