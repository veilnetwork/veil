#!/usr/bin/env python3
"""Verify vendored package versions against their provenance manifest."""
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

NAMES = {'quinn', 'quinn-proto', 'quinn-udp'}


def validate(records, packages):
    errors = []
    if len(records) != len(NAMES) or {r.get('name') for r in records} != NAMES:
        errors.append('manifest must name each vendored Quinn package exactly once')
    for record in records:
        name = record.get('name')
        package = packages.get(name, {})
        if package.get('name') != name or package.get('version') != record.get('version'):
            errors.append(f'{name}: vendored Cargo.toml version differs from provenance')
        if not re.fullmatch('[a-f0-9]{64}', record.get('registry_archive_sha256', '')):
            errors.append(f'{name}: missing registry SHA-256')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        records = [dict(name=n, version='1.0', registry_archive_sha256='a'*64) for n in sorted(NAMES)]
        packages = {n: dict(name=n, version='1.0') for n in NAMES}
        assert not validate(records, packages)
        packages['quinn-proto']['version'] = '2.0'
        assert validate(records, packages)
        packages['quinn-proto']['version'] = '1.0'
        assert validate(records[:-1], packages)
        records[0]['registry_archive_sha256'] = ''
        assert validate(records, packages)
        print('Quinn provenance self-tests passed')
        return 0
    root = Path(__file__).resolve().parent.parent
    try:
        records = json.loads((root / 'third_party/quinn/UPSTREAM.json').read_text())
        packages = {n: tomllib.loads((root / 'third_party' / n / 'Cargo.toml').read_text())['package'] for n in NAMES}
        errors = validate(records, packages)
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors = [f'cannot validate provenance: {error}']
    for error in errors:
        print(f'error: {error}', file=sys.stderr)
    if not errors:
        print('vendored Quinn versions match provenance manifest')
    return int(bool(errors))

if __name__ == '__main__':
    sys.exit(main())
