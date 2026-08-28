#!/usr/bin/env bash
# A COM apartment belongs to the thread, and the thread has an owner.
#
# `CoInitializeEx` does not configure a library, it configures THE CALLING
# THREAD, permanently, for everything that thread will ever do afterwards. So
# calling it on a thread we were merely handed — an FFI call arriving from
# Dart, a host callback, a task queue we do not own — reaches out of this
# library and changes somebody else's world.
#
# That is not a theoretical objection. veil_mf_camera.cc held its Media
# Foundation platform in a function-local static, so the FIRST caller to touch
# a camera was moved to MTA and left there. WebRTC's Windows audio device
# module then asks for STA on that same thread, and its ScopedCOMInitializer
# treats the mismatch as fatal rather than as an error to report:
#
#   Fatal error in ..\..\rtc_base\win\scoped_com_initializer.cc, line 43
#   Check failed: ((HRESULT)0x80010106L) != hr_
#   Invalid COM thread model change (MTA->STA)
#
# Measured on Windows 11 with 0.13.4: the answering side accepted a call and
# the process died before a frame arrived. Whoever ran first won the apartment,
# which is why the caller survived and the answerer did not.
#
# THE RULE: inside flutter/veil_media, `CoInitializeEx` may appear only in the
# body of a thread this code starts. This script checks it structurally — it
# finds the `std::thread(...)` bodies, and the functions named as such a body,
# and requires every call to sit inside one of them.
#
# Usage: invoke from repo root. Exits non-zero on violations.

set -euo pipefail

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path("flutter/veil_media")
if not ROOT.is_dir():
    print(f"run from the repo root: {ROOT} not found", file=sys.stderr)
    sys.exit(2)


def strip_comments(text: str) -> str:
    """Blank out comments and string literals, preserving every offset.

    Offsets have to survive: the scope walk below indexes back into this same
    buffer. And comments have to go, or a guard that looks for a call ends up
    matching the prose that explains the call — including the prose in this
    file's own header.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            for k in range(i + 1, j - 1):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def brace_block(src: str, open_at: int):
    """(start, end) of the {...} block whose '{' is at or after open_at."""
    start = src.find("{", open_at)
    if start < 0:
        return None
    depth, i, n = 0, start, len(src)
    while i < n:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return (start, i)
        i += 1
    return None


def owned_regions(src: str):
    """Byte ranges that run on a thread this file starts.

    Two shapes, both present in the camera backend:
      * an inline lambda:  std::thread([...] { ...body... })
      * a named body:      std::thread([this] { Serve(); })  -> Serve()'s body
    """
    regions = []
    named = set()
    for m in re.finditer(r"std::thread\s*\(", src):
        block = brace_block(src, m.end())
        if block is None:
            continue
        regions.append(block)
        body = src[block[0]:block[1]]
        for call in re.finditer(r"\b([A-Za-z_]\w*)\s*\(\s*\)\s*;", body):
            named.add(call.group(1))
    for name in named:
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*\([^;{)]*\)\s*(?:const\s*)?\{", src):
            block = brace_block(src, m.end() - 1)
            if block is not None:
                regions.append(block)
    return regions


violations = []
call_sites = 0
for path in sorted(ROOT.rglob("*")):
    if path.suffix not in (".cc", ".cpp", ".mm", ".h") or not path.is_file():
        continue
    raw = path.read_text(encoding="utf-8", errors="replace")
    src = strip_comments(raw)
    if "CoInitializeEx" not in src:
        continue
    regions = owned_regions(src)
    for m in re.finditer(r"\bCoInitializeEx\s*\(", src):
        call_sites += 1
        at = m.start()
        if not any(lo < at < hi for lo, hi in regions):
            line = raw.count("\n", 0, at) + 1
            violations.append(f"{path}:{line}")

# Vacuity guard. Everything above passes trivially on a tree where the calls
# have been renamed, moved behind a macro, or deleted — and then this script
# would report a clean bill of health for a rule it is no longer checking.
if call_sites < 2:
    print(
        f"found only {call_sites} CoInitializeEx call site(s) under {ROOT} — "
        "expected at least 2 (the MF platform thread and the capture thread). "
        "Either the apartment handling moved somewhere this script cannot see "
        "it, or this guard is now checking nothing.",
        file=sys.stderr,
    )
    sys.exit(1)

if violations:
    print("CoInitializeEx on a thread this library does not own:", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    print(
        "\nA COM apartment is per-thread and permanent. Initialising it on a "
        "borrowed thread changes that thread for every later caller — which is "
        "how a Windows call took the whole app down with WebRTC's "
        "'Invalid COM thread model change (MTA->STA)'. Move the work onto a "
        "thread started here.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"COM apartment ownership: OK ({call_sites} call sites, all on owned threads)")
PY
