"""Exercise the workflow shell with a build tool that records key visibility."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def signing_step():
    workflow = (ROOT / '.github/workflows/release.yml').read_text()
    names = ['Sign update manifest from staged host binary',
             'Sign manifest (host build only — has signing key)']
    for name in names:
        match = re.search(r'(?ms)^      - name: ' + re.escape(name)
                          + r'\n(.*?)(?=^      - (?:name|uses):|^  [a-z]|\Z)', workflow)
        if match:
            lines = match[1].splitlines()
            start = lines.index('        run: |') + 1
            script = []
            for line in lines[start:]:
                if line and not line.startswith('          '):
                    break
                script.append(line[10:])
            return workflow, match.start(), '\n'.join(script)
    raise AssertionError('release signing step was not found')


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux signing workflow')
class SigningWorkflowTests(unittest.TestCase):
    def fixture(self, *, signing_failure=False, corrupt_checksum=False):
        directory = tempfile.TemporaryDirectory(prefix='release-signing-')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        tools, runner = root / 'tools', root / 'runner'
        tools.mkdir()
        runner.mkdir()
        out = root / 'out'
        out.mkdir()
        cli = out / 'veil-cli-x86_64-unknown-linux-gnu'
        cli.write_text('''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
args = sys.argv[1:]
def value(flag): return args[args.index(flag) + 1]
key = pathlib.Path(value('--identity'))
assert key.read_text() == 'fixture signing material'
assert stat.S_IMODE(key.stat().st_mode) == 0o600
assert args[:2] == ['update', 'sign-manifest']
assert value('--version') == '1.2.3'
assert value('--min-compatible-version') == '1.2.0'
assert value('--release-unix') == '1731000000'
pathlib.Path(os.environ['SIGN_LOG']).write_text(json.dumps({'identity': str(key)}))
if os.environ['FAIL_SIGN'] == '1': sys.exit(17)
pathlib.Path(value('--output')).write_bytes(b'fixture manifest')
''')
        digest = '0' * 64 if corrupt_checksum else hashlib.sha256(cli.read_bytes()).hexdigest()
        (out / 'sha256-x86_64-unknown-linux-gnu.txt').write_text(digest + '  veil-cli\n')
        cargo = tools / 'cargo'
        cargo.write_text('''#!/usr/bin/env python3
import os, pathlib
pathlib.Path(os.environ['BUILD_LOG']).write_text(str(pathlib.Path(os.environ['LEGACY_KEY']).exists()))
raise SystemExit(71)
''')
        cargo.chmod(0o755)
        git = tools / 'git'
        git.write_text('#!/bin/sh\nprintf "%s\\n" 1731000000\n')
        git.chmod(0o755)
        (root / 'scripts').mkdir()
        shutil.copy2(ROOT / 'scripts/build-release.sh', root / 'scripts/build-release.sh')
        workflow, position, script = signing_step()
        legacy = root / 'legacy-key.toml'
        if '${{ steps.identity.outputs.path }}' in script:
            legacy.write_text('fixture signing material')
            legacy.chmod(0o600)
        replacements = {'${{ matrix.triple }}': 'x86_64-unknown-linux-gnu',
                        '${{ steps.epoch.outputs.value }}': '1731000000',
                        '${{ steps.identity.outputs.path }}': str(legacy)}
        for source, value in replacements.items():
            script = script.replace(source, value)
        self.assertNotIn('${{', script)
        env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'],
               'RUNNER_TEMP': str(runner), 'VERSION': 'v1.2.3', 'MIN_COMPAT': '',
               'RELEASE_TAG': 'v1.2.3', 'GITHUB_REPOSITORY': 'veilnetwork/veil',
               'IDENTITY_TOML': 'fixture signing material', 'LEGACY_KEY': str(legacy),
               'BUILD_LOG': str(root / 'build-log'), 'SIGN_LOG': str(root / 'sign-log'),
               'FAIL_SIGN': '1' if signing_failure else '0'}
        result = subprocess.run(['bash', '-c', script], cwd=root, env=env,
                                capture_output=True)
        return root, result

    def test_signing_runs_in_publish_job_without_dependency_builds(self):
        workflow, position, _ = signing_step()
        self.assertGreater(position, workflow.index('\n  publish:'))

    def test_success_signs_checked_artifact_and_removes_private_key(self):
        root, result = self.fixture()
        self.assertEqual(result.returncode, 0, 'signing fixture failed')
        self.assertFalse((root / 'build-log').exists(), 'Cargo ran with a staged identity')
        key = Path(json.loads((root / 'sign-log').read_text())['identity'])
        self.assertFalse(key.exists())
        self.assertEqual((root / 'out/manifest-x86_64-unknown-linux-gnu.bin').read_bytes(),
                         b'fixture manifest')

    def test_failed_signer_also_removes_private_key(self):
        root, result = self.fixture(signing_failure=True)
        self.assertEqual(result.returncode, 17)
        self.assertFalse((root / 'build-log').exists(), 'Cargo ran with a staged identity')
        key = Path(json.loads((root / 'sign-log').read_text())['identity'])
        self.assertFalse(key.exists())

    def test_changed_host_artifact_is_rejected_before_key_staging(self):
        root, result = self.fixture(corrupt_checksum=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((root / 'build-log').exists(), 'Cargo ran with a staged identity')
        self.assertFalse((root / 'sign-log').exists())
        self.assertEqual(list((root / 'runner').glob('veil-release-key.*')), [])


if __name__ == '__main__':
    unittest.main()
