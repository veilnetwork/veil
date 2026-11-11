"""Canonical native-media source digest and local build record (stdlib only)."""
import argparse
import hashlib
import os
from pathlib import Path
import tempfile


def source_digest(source: Path) -> str:
    files = sorted((p for p in source.rglob('*') if p.is_file()),
                   key=lambda p: p.relative_to(source).as_posix())
    if not files:
        raise ValueError('native media source tree is empty')
    digest = hashlib.sha256(b'xveil-media-source-v1\0')
    for path in files:
        if path.is_symlink():
            raise ValueError('native media source must not contain symlinks')
        name = path.relative_to(source).as_posix().encode('utf-8')
        data = path.read_bytes().replace(b'\r\n', b'\n')
        digest.update(len(name).to_bytes(8, 'big'))
        digest.update(name)
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    return digest.hexdigest()


def record_build(source: Path, binary: Path, expected_source: str) -> None:
    digest = source_digest(source)
    if digest != expected_source:
        raise ValueError('native media source changed during the build')
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    destination = binary.with_name(binary.name + '.provenance')
    fd, name = tempfile.mkstemp(prefix='.media-provenance-', dir=binary.parent)
    try:
        with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
            stream.write('sha256: ' + binary_sha + '\n')
            stream.write('media-source-sha256: ' + digest + '\n')
        os.replace(name, destination)
    finally:
        Path(name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--expected-source')
    args = parser.parse_args()
    if args.binary:
        if not args.expected_source:
            parser.error('--binary requires --expected-source captured before compiling')
        record_build(args.source, args.binary, args.expected_source)
    else:
        print(source_digest(args.source))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
