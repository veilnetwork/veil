#!/usr/bin/env python3
"""Run CI's `hygiene` job on this machine, reading the steps FROM the workflow.

Why this exists
---------------
The job is eighteen steps. Every time somebody reconstructs a subset of it by
hand, the subset is the part that was green. On 2026-08-31 that cost three CI
cycles in a row: first `clippy` was not run at all, then it was run but not
`check-feature-gated-lints.sh` (which compiles code the default-feature clippy
never sees), then ten more steps were missing and a stale `fuzz/Cargo.lock`
went out.

So this does not keep its own list. It parses the `hygiene` job out of
`.github/workflows/ci.yml` and runs what is written there, which is the only
way a local mirror cannot drift from the thing it mirrors.

Usage:
    scripts/run-ci-hygiene.py            run every step, print a result table
    scripts/run-ci-hygiene.py --list     print the steps without running them

`cargo install` steps are skipped and their tools checked for instead: CI
installs them into a fresh runner, a developer already has them or is told
which are missing. Logs land in a temp directory named at the end.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
JOB = "hygiene"


def steps_of_job(text, job):
    """Every (name, script) of `job`, in order. Hand-rolled: pulling in a YAML
    dependency for one file is a worse trade than forty lines that fail loudly."""
    lines = text.split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if l == f"  {job}:")
    except StopIteration:
        sys.exit(f"no `{job}` job in {WORKFLOW}")
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(r"^  [a-z][a-z0-9-]*:\s*$", lines[i])),
        len(lines),
    )

    out, name = [], None
    i = start
    while i < end:
        line = lines[i]
        m = re.match(r"^      - name: (.+)$", line)
        if m:
            name = m.group(1).strip()
        m = re.match(r"^        run: (.+)$", line)
        if m and m.group(1).strip() != "|":
            out.append((name or line, m.group(1)))
        elif re.match(r"^        run: \|", line):
            body = []
            j = i + 1
            while j < end and (lines[j].startswith("          ") or not lines[j].strip()):
                body.append(lines[j][10:] if lines[j].startswith("          ") else "")
                j += 1
            out.append((name or line, "\n".join(body).strip()))
            i = j - 1
        i += 1
    if not out:
        sys.exit(f"parsed no steps out of `{job}` — the workflow's shape changed")
    return out


SELF_TEST_WORKFLOW = """\
jobs:
  hygiene:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: one liner
        run: cargo fmt --all --check
      - name: a block
        # a comment inside the step
        run: |
          ./scripts/a.sh --self-test
          ./scripts/a.sh
      - name: an install
        run: cargo install cbindgen --version "^0.29" --locked
  other:
    steps:
      - name: not ours
        run: echo no
"""


def self_test():
    """Prove the parser reads what it claims, and shouts when it reads nothing.

    A runner that quietly parses zero steps reports every step green, which is
    the failure this whole script exists to stop — so that case is checked
    first."""
    steps = steps_of_job(SELF_TEST_WORKFLOW, "hygiene")
    names = [n for n, _ in steps]
    assert names == ["one liner", "a block", "an install"], names
    assert steps[0][1] == "cargo fmt --all --check", steps[0]
    assert steps[1][1] == "./scripts/a.sh --self-test\n./scripts/a.sh", repr(steps[1][1])
    assert steps[2][1].startswith("cargo install "), steps[2]

    # A job that is not there, and a job with no steps, must both exit rather
    # than return an empty list that reads as success.
    for text, job in ((SELF_TEST_WORKFLOW, "nosuchjob"), ("jobs:\n  hygiene:\n    x: y\n", "hygiene")):
        try:
            steps_of_job(text, job)
        except SystemExit:
            continue
        raise AssertionError(f"parsing {job!r} returned quietly instead of exiting")

    # And the real workflow still parses, or this script is mirroring nothing.
    real = steps_of_job(WORKFLOW.read_text(), JOB)
    assert len(real) >= 10, f"only {len(real)} steps parsed from the real workflow"
    print(f"self-test OK ({len(real)} steps in the real `{JOB}` job)")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    steps = steps_of_job(WORKFLOW.read_text(), JOB)

    runnable, installs = [], []
    for name, script in steps:
        (installs if script.startswith("cargo install ") else runnable).append((name, script))

    if "--list" in sys.argv:
        for name, script in runnable:
            print(f"  {name}\n      {script.splitlines()[0]}")
        if installs:
            print("\n  skipped (CI installs these; you need them on PATH):")
            for name, script in installs:
                print(f"    {script}")
        return 0

    missing = [t for t in ("cargo-audit", "cargo-deny", "cbindgen") if shutil.which(t) is None]
    if missing:
        print(f"!! not on PATH: {', '.join(missing)} — the steps that use them will fail")

    logs = Path(tempfile.mkdtemp(prefix="veil-hygiene-"))
    env = dict(os.environ, RUNNER_TEMP=str(logs), CARGO_TERM_COLOR="always")
    failed = []
    for n, (name, script) in enumerate(runnable, 1):
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
        with open(logs / f"{n:02d}-{slug}.out", "w") as out, \
             open(logs / f"{n:02d}-{slug}.err", "w") as err:
            rc = subprocess.call(["bash", "-e", "-c", script], cwd=ROOT,
                                 stdout=out, stderr=err, env=env)
        print(f"{rc:4}  {name}", flush=True)
        if rc != 0:
            failed.append((name, slug, n))

    print(f"\nlogs: {logs}")
    if failed:
        print(f"FAILED {len(failed)} of {len(runnable)}:")
        for name, slug, n in failed:
            print(f"  {name}  →  {logs}/{n:02d}-{slug}.err")
        return 1
    print(f"OK: all {len(runnable)} steps green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
