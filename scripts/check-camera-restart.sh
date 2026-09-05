#!/usr/bin/env bash
# A capturer that exists is not a camera that is capturing.
#
# `CameraCapturer` outlives its device. The Media Foundation loop returns when
# the device is invalidated — measured on a Windows 11 ARM64 stand 2026-09-05,
# `MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED` (0xc00d3ea2) from the pending
# synchronous read 292 ms after the camera was disabled — and v4l2's returns on
# a failed `select` or a `VIDIOC_DQBUF` that is not EAGAIN. The object stays
# behind holding nothing.
#
# `veil_media_engine.cc` used to answer `VEIL_MEDIA_OK` on the pointer alone:
#
#     if (ws->camera) return VEIL_MEDIA_OK;  // "already capturing"
#
# so after an unplug every `start_camera` reported success and no frame ever
# came again for the rest of the call. Driven end to end against the shipped
# DLL: as shipped "STILL NOTHING", fixed "VIDEO IS BACK".
#
# THE RULE, in two halves:
#   1. every `if (ws->camera)`-shaped early return out of a camera entry point
#      must ask `Capturing()`, not merely test the pointer;
#   2. every CameraCapturer backend must define `Capturing()`.
#
# CI cannot compile this engine — it needs a WebRTC checkout — so the fact is
# guarded at the source instead. `--self-test` runs it against fixtures first,
# because a guard nobody has watched fail is a guard nobody has tested.
#
# Usage: invoke from the repo root. `--self-test` checks the checker.

set -euo pipefail

python3 - "$@" <<'PY'
import re
import sys
from pathlib import Path

ROOT = Path("flutter/veil_media")


def bad_guards(engine_src: str) -> list[str]:
    """Early returns that decide 'already capturing' from the pointer alone."""
    out = []
    for m in re.finditer(
        r"if\s*\(\s*(ws|engine->ws)->camera\s*\)\s*return\s+VEIL_MEDIA_OK", engine_src
    ):
        out.append(engine_src[m.start() : m.end()])
    return out


def asks_capturing(engine_src: str) -> int:
    return len(re.findall(r"->camera->Capturing\s*\(\s*\)", engine_src))


def backends_missing_capturing(root: Path) -> tuple[list[str], int]:
    missing, found = [], 0
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".cc", ".cpp", ".mm") or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not re.search(r"class\s+\w+\s*:\s*public\s+CameraCapturer", text):
            continue
        found += 1
        if not re.search(r"bool\s+Capturing\s*\(\s*\)\s*const\s+override", text):
            missing.append(str(path))
    return missing, found


if "--self-test" in sys.argv:
    # The checker, against what it must catch and what it must not.
    bad = 'if (ws->camera) return VEIL_MEDIA_OK;  // already capturing'
    good = 'if (ws->camera && ws->camera->Capturing()) return VEIL_MEDIA_OK;'
    assert bad_guards(bad), "the checker does not catch the pointer-only guard"
    assert not bad_guards(good), "the checker rejects the correct guard"
    assert asks_capturing(good) == 1, "the checker does not see Capturing()"
    assert asks_capturing(bad) == 0
    # And the backend half, on a fixture tree rather than on the real one.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.cc").write_text(
            "class XCapturer : public CameraCapturer {\n"
            "  bool Capturing() const override { return true; }\n};\n"
        )
        (d / "b.cc").write_text("class YCapturer : public CameraCapturer {\n};\n")
        miss, n = backends_missing_capturing(d)
        assert n == 2, f"the fixture backends were not found: {n}"
        assert len(miss) == 1 and miss[0].endswith("b.cc"), miss
    print("check-camera-restart self-test: OK")
    sys.exit(0)

if not ROOT.is_dir():
    print(f"run from the repo root: {ROOT} not found", file=sys.stderr)
    sys.exit(2)

engine = ROOT / "src" / "veil_media_engine.cc"
if not engine.is_file():
    print(f"{engine} is missing — this guard cannot see its subject", file=sys.stderr)
    sys.exit(1)
src = engine.read_text(encoding="utf-8", errors="replace")

failures = []
for guard in bad_guards(src):
    failures.append(f"{engine}: {guard.strip()}")

# Vacuity guard: the checks above pass on an engine that has no camera entry
# points left at all, which would be a guard reporting health for a rule it can
# no longer see.
asked = asks_capturing(src)
if asked < 2:
    failures.append(
        f"{engine}: only {asked} camera entry point(s) ask Capturing() — "
        "expected at least 2 (the 1-1 engine and the group engine). Either "
        "they moved, or this guard is checking nothing."
    )

missing, backends = backends_missing_capturing(ROOT)
for path in missing:
    failures.append(f"{path}: a CameraCapturer backend without Capturing()")
if backends < 3:
    failures.append(
        f"found only {backends} CameraCapturer backend(s) under {ROOT} — "
        "expected at least 3 (Media Foundation, v4l2, AVFoundation)."
    )

if failures:
    print("a capturer that exists is not a camera that is capturing:", file=sys.stderr)
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    print(
        "\nThe capture loop ends on its own when the device goes away and the "
        "object stays behind. Deciding 'already capturing' from the pointer "
        "means a camera that was unplugged can never be started again: the "
        "retry reports success and no frame ever comes. Ask Capturing().",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"camera restart: OK ({asked} entry points ask Capturing(), "
    f"{backends} backends answer it)"
)
PY
