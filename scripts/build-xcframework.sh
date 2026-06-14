#!/usr/bin/env bash
# Pack the per-arch iOS staticlibs produced by build-mobile.sh into a
# single `.xcframework` consumable by Xcode (Epic 489.2 follow-up).
#
# An xcframework holds per-platform "slices" so the same dependency
# entry resolves to the right binary depending on whether the consumer
# is building for a physical device, an Apple Silicon simulator, or an
# Intel-Mac simulator.  Without the bundling, an iOS app build picks
# whichever slice happens to be available and trips on the runtime
# arch mismatch ("undefined symbol _objc_msgSend@i386" etc).
#
# Strategy:
#   * Device slice  = aarch64-apple-ios staticlib
#   * Simulator slice = lipo(aarch64-apple-ios-sim, x86_64-apple-ios) so
#     it works on BOTH Apple-Silicon and Intel-Mac Xcode hosts.
#
# Run AFTER `scripts/build-mobile.sh --target aarch64-apple-ios`,
# `--target aarch64-apple-ios-sim`, and `--target x86_64-apple-ios`
# have populated `target/<triple>/release/libveilclient_ffi.a`.
#
# Output: `target/xcframework/VeilClientFFI.xcframework/` ready to
# vendor in the Flutter plugin's iOS Podspec (`ios/Frameworks/`).
#
# Requires: macOS host with Xcode 11+ (xcodebuild -create-xcframework).
# The script no-ops with a clear error on non-macOS hosts (Linux CI can
# still upload the per-arch artifacts; xcframework packaging happens
# on the macOS leg of the matrix).

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LIB_NAME="libveilclient_ffi.a"
readonly FRAMEWORK_NAME="VeilClientFFI"
readonly OUTPUT_DIR="$REPO_ROOT/target/xcframework"
readonly OUTPUT_FRAMEWORK="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
readonly HEADER_DIR="$REPO_ROOT/crates/veilclient-ffi/include"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: xcframework packaging requires macOS (xcodebuild)." >&2
  echo "Run scripts/build-mobile.sh on Linux to produce per-arch staticlibs," >&2
  echo "then run this script on the macOS CI runner." >&2
  exit 2
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "ERROR: xcodebuild not found.  Install Xcode + run xcode-select --install." >&2
  exit 2
fi

device_lib="$REPO_ROOT/target/aarch64-apple-ios/release/$LIB_NAME"
sim_arm64_lib="$REPO_ROOT/target/aarch64-apple-ios-sim/release/$LIB_NAME"
sim_x86_64_lib="$REPO_ROOT/target/x86_64-apple-ios/release/$LIB_NAME"

for f in "$device_lib" "$sim_arm64_lib" "$sim_x86_64_lib"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: missing $f" >&2
    echo "Build first: scripts/build-mobile.sh --target <ios-triple>" >&2
    exit 1
  fi
done

if [[ ! -d "$HEADER_DIR" ]]; then
  echo "ERROR: header dir $HEADER_DIR missing" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -rf "$OUTPUT_FRAMEWORK"

# Combine the two simulator slices (Apple Silicon ARM + Intel x86_64)
# into a single fat staticlib.  An xcframework slice MUST be platform-
# native — and "iOS Simulator on Apple Silicon" is a separate platform
# from "iOS Simulator on Intel" only at the triple level; both slices
# are valid for the simulator destination, so lipo merges them.
sim_fat_dir="$(mktemp -d)"
trap 'rm -rf "$sim_fat_dir"' EXIT
sim_fat_lib="$sim_fat_dir/$LIB_NAME"
echo "==> lipo merge simulator slices → $sim_fat_lib"
lipo -create "$sim_arm64_lib" "$sim_x86_64_lib" -output "$sim_fat_lib"

echo "==> xcodebuild -create-xcframework"
xcodebuild -create-xcframework \
  -library "$device_lib"   -headers "$HEADER_DIR" \
  -library "$sim_fat_lib"  -headers "$HEADER_DIR" \
  -output "$OUTPUT_FRAMEWORK"

echo
echo "==> built $OUTPUT_FRAMEWORK"
ls -la "$OUTPUT_FRAMEWORK"
echo
echo "Vendor with the Flutter plugin's iOS Podspec:"
echo "  cp -R $OUTPUT_FRAMEWORK flutter/veil_flutter/ios/Frameworks/"
