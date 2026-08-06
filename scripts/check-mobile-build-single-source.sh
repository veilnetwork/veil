#!/usr/bin/env bash
#
# One definition of how a veilclient-ffi mobile/desktop artifact is built.
#
# `.github/workflows/mobile-build.yml` used to spell out its own cargo
# invocations beside `scripts/build-mobile.sh`, and the two drifted: the script
# built with `production-seeds,node-embedded,packet-tunnel`, the workflow with
# `production-seeds` alone. Every artifact that matrix uploaded therefore had
# NO in-process node — mandatory on iOS, and the deniable posture on Android —
# while both files looked perfectly reasonable on their own. The iOS legs had
# drifted further: the script emits a staticlib and fixes the simulator bindgen
# triple; the workflow did neither.
#
# Nothing catches that class of defect by reading either file alone. So the
# rule is structural: the workflow calls the script, and does not build
# veilclient-ffi by itself.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

WORKFLOW=".github/workflows/mobile-build.yml"
SCRIPT="scripts/build-mobile.sh"

[[ -f "$WORKFLOW" ]] || { echo "error: $WORKFLOW is missing" >&2; exit 1; }
[[ -f "$SCRIPT" ]] || { echo "error: $SCRIPT is missing" >&2; exit 1; }

fail=0

# Any cargo line that builds the ffi crate is the drift this exists to stop.
# `cargo install cargo-ndk` and `rustup target add` are tooling, not builds.
if offenders=$(grep -nE '(cargo (ndk .* -- )?build|cargo rustc)[^|]*veilclient-ffi' \
      "$WORKFLOW"); then
  echo "error: $WORKFLOW builds veilclient-ffi directly instead of calling" >&2
  echo "       $SCRIPT — that is how the feature sets drifted apart before." >&2
  echo "$offenders" >&2
  fail=1
fi

# And it must actually call the script, or the rule above is satisfied by a
# workflow that builds nothing at all.
legs=$(grep -c "$SCRIPT --target" "$WORKFLOW" || true)
if [[ "$legs" -lt 3 ]]; then
  echo "error: $WORKFLOW calls '$SCRIPT --target' only $legs time(s);" >&2
  echo "       expected one per matrix leg (android, apple, linux)." >&2
  fail=1
fi

# The script is the single place the feature set is stated. If that line moves,
# whoever moves it should see this check and decide, rather than discover it
# from a release artifact.
if ! grep -q '^readonly DEFAULT_FEATURES="production-seeds,node-embedded,packet-tunnel"$' \
      "$SCRIPT"; then
  echo "error: $SCRIPT no longer states the expected DEFAULT_FEATURES." >&2
  echo "       If the change is deliberate, update this check with it — the" >&2
  echo "       point is that the feature set is decided in one place." >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "OK: mobile-build.yml builds through $SCRIPT (single definition)."
