import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

spec = importlib.util.spec_from_file_location(
    'vendor_audit', Path(__file__).with_name('audit-vendored-dependencies.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class VendoredAuditTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'workspace'
        self.root.mkdir()
        self.write_patch()

    def write_patch(self, *, override='fork', package='fork', version='1.2.3'):
        self.vendor = self.root / 'vendor'
        self.vendor.mkdir(exist_ok=True)
        (self.vendor / 'Cargo.toml').write_text(
            f'[package]\nname = "{package}"\nversion = "{version}"\n')
        (self.root / 'Cargo.toml').write_text(
            '[patch.crates-io]\n' + override + ' = {path = "vendor"}\n')

    def test_every_override_and_renamed_package_is_in_the_registry_inventory(self):
        second = self.root / 'second'
        second.mkdir()
        (second / 'Cargo.toml').write_text('[package]\nname = "other"\nversion = "2.0.0"\n')
        with (self.root / 'Cargo.toml').open('a') as stream:
            stream.write('alias = {path = "second", package = "other"}\n')
        packages = audit.inventory(self.root)
        self.assertEqual(packages, [('fork', '1.2.3'), ('other', '2.0.0')])
        data = tomllib.loads(audit.lock_text(packages))
        self.assertEqual(len(data['package']), 2)
        self.assertTrue(all(p['source'] == audit.REGISTRY for p in data['package']))

    def test_missing_or_empty_overrides_cannot_pass_vacuously(self):
        for manifest in ['', '[patch.crates-io]\n']:
            with self.subTest(manifest=manifest):
                (self.root / 'Cargo.toml').write_text(manifest)
                with self.assertRaises(ValueError):
                    audit.inventory(self.root)
        with self.assertRaises(ValueError):
            audit.lock_text([])

    def test_mismatched_identity_is_rejected(self):
        self.write_patch(package='different')
        with self.assertRaises(ValueError):
            audit.inventory(self.root)

    def test_unresolved_version_is_rejected(self):
        self.write_patch(version='workspace')
        with self.assertRaises(ValueError):
            audit.inventory(self.root)

    def test_remote_or_external_overrides_require_explicit_support(self):
        for entry in ['{git = "https://example.invalid/fork"}', '{path = "../external"}']:
            with self.subTest(entry=entry):
                (self.root / 'Cargo.toml').write_text('[patch.crates-io]\nfork = ' + entry)
                with self.assertRaises(ValueError):
                    audit.inventory(self.root)

    def test_real_lock_file_and_scanner_exit_status_survive_the_driver(self):
        observed = []
        def run(command, *, cwd, check):
            self.assertEqual(command[:5], ['cargo', 'audit', '--deny', 'warnings', '--file'])
            self.assertEqual(cwd, self.root)
            self.assertFalse(check)
            path = Path(command[-1])
            observed.append(path)
            data = tomllib.loads(path.read_text())
            self.assertEqual(data['package'], [dict(name='fork', version='1.2.3', source=audit.REGISTRY)])
            return subprocess.CompletedProcess(command, 17)
        self.assertEqual(audit.audit(self.root, runner=run), 17)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())


if __name__ == '__main__':
    unittest.main()
