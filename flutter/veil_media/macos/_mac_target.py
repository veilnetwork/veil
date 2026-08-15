"""Read the clang target the bundle's own objects were compiled with.

The wrapper compiles its sources with call.cc's exact command, taken from
compile_commands.json, and then links. Writing the link target by hand is how
those two disagree: an x86_64 bundle compiled x86_64 objects and asked for an
arm64 link, every member of libwebrtc.a was skipped as the wrong architecture,
and the failure surfaced as undefined symbols — which reads like a missing
library rather than a wrong flag.

Falls back to the host default only when the command carries no --target at
all, which is the case where guessing is all anyone could do.
"""

import json
import re
import subprocess
import sys


def main() -> int:
    with open(sys.argv[1]) as fh:
        entries = json.load(fh)
    entry = next(e for e in entries if e.get("file", "").endswith("call/call.cc"))
    command = entry.get("command") or " ".join(entry["arguments"])
    found = re.search(r"--target=(\S+)", command)
    if found:
        print(found.group(1))
        return 0
    machine = subprocess.run(
        ["uname", "-m"], capture_output=True, text=True, check=True
    ).stdout.strip()
    print(f"{'arm64' if machine == 'arm64' else 'x86_64'}-apple-macos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
