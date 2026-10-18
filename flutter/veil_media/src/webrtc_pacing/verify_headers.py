#!/usr/bin/env python3
"""Refuse a pacing override compiled against a different private WebRTC ABI."""
import hashlib
import json
from pathlib import Path
import sys

manifest = json.loads((Path(__file__).parent / 'abi.json').read_text())
root = Path(sys.argv[1])
for name, expected in manifest['headers'].items():
    path = root / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f'Unsupported WebRTC pacing ABI: {name}. Use the pinned SDK or update and qualify the pacing override with that SDK.')
