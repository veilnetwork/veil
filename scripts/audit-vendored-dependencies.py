#!/usr/bin/env python3
"""Audit registry base versions even when Cargo.lock selects local path forks.

The temporary lock is an advisory-only package inventory, not a replacement
dependency graph or a claim that local sources are byte-identical to upstream.
Workspace auditing and fork provenance/regression checks remain separate gates.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'


def inventory(root: Path) -> list[tuple[str, str]]:
    root = root.resolve()
    manifest = tomllib.loads((root / 'Cargo.toml').read_text())
    patches = manifest.get('patch', {}).get('crates-io', {})
    if not patches:
        raise ValueError('no registry path overrides found; refusing an empty audit')
    packages = set()
    for alias, patch in patches.items():
        if not isinstance(patch, dict) or not isinstance(patch.get('path'), str):
            raise ValueError('registry override needs an auditable local manifest')
        path = (root / patch['path'] / 'Cargo.toml').resolve()
        if not path.is_relative_to(root):
            raise ValueError('vendored manifest must remain inside the repository')
        package = tomllib.loads(path.read_text())['package']
        name, version = package.get('name'), package.get('version')
        if name != patch.get('package', alias):
            raise ValueError('vendored package identity differs from its override')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name):
            raise ValueError('invalid vendored package name')
        if not isinstance(version, str) or not re.fullmatch(
                r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?', version):
            raise ValueError('vendored package needs an explicit release version')
        packages.add((name, version))
    return sorted(packages)


def lock_text(packages: list[tuple[str, str]]) -> str:
    if not packages:
        raise ValueError('refusing an empty vendored dependency audit')
    return 'version = 4\n\n' + '\n'.join(
        '[[package]]\nname = ' + json.dumps(name) + '\nversion = '
        + json.dumps(version) + '\nsource = ' + json.dumps(REGISTRY) + '\n'
        for name, version in packages)


def audit(root: Path, runner=subprocess.run, *, database=None, no_fetch=False) -> int:
    packages = inventory(root)
    with tempfile.TemporaryDirectory(prefix='veil-vendor-audit-') as temporary:
        path = Path(temporary) / 'Cargo.lock'
        path.write_text(lock_text(packages), encoding='utf-8')
        print(f'Auditing {len(packages)} vendored registry base versions', flush=True)
        command = ['cargo', 'audit', '--deny', 'warnings', '--file', str(path)]
        if database is not None:
            command.extend(['--db', str(database)])
        if no_fetch:
            command.append('--no-fetch')
        return runner(command,
                      cwd=root, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, help='explicit advisory DB for reproducible checks')
    parser.add_argument('--no-fetch', action='store_true')
    args = parser.parse_args()
    try:
        return audit(Path(__file__).resolve().parents[1], database=args.db, no_fetch=args.no_fetch)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'vendored dependency audit: {type(error).__name__}: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
