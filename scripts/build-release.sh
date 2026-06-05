#!/usr/bin/env bash
# Deterministic release build (Epic 484.1).
#
# Goals:
#   1. Same input source tree → same SHA-256 of output binary on
#      EVERY machine that supports the target.  Lets independent
#      verifiers rebuild from source and confirm "the binary I
#      downloaded is what the source says it is".
#   2. Single signed `UpdateManifest` blob ready для distribution.
#
# Determinism is enforced by:
#   * `--remap-path-prefix=$PWD=.` — strips host path prefixes from
#     panics / debug info, so identical sources on different
#     machines produce byte-identical binaries.
#   * `SOURCE_DATE_EPOCH` — pinned timestamp anywhere any tool would
#     embed `time(0)` (rust embeds none directly, but transitive
#     deps occasionally do — pin defensively).
#   * `--locked` — uses Cargo.lock verbatim, no resolver drift.
#   * `RUSTFLAGS` static across invocations.
#   * No CARGO_INCREMENTAL (incremental builds inject per-machine state).
#
# Targets supported (one per invocation; CI matrix runs them in parallel):
#   linux-x86_64    aarch64-linux-android
#   linux-aarch64   aarch64-apple-darwin
#   macos-arm64     aarch64-apple-ios
#   windows-x86_64
#
# Binaries built per invocation: `veil-cli`, `ogate`, `oproxy`.
# veil-cli is the user-facing CLI + auto-update entry point;
# ogate / oproxy are operator-side service binaries що ship alongside
# so a release tag carries the full daemon set.
#
# Output paths (per-target):
#   target/<triple>/release/{veil-cli,ogate,oproxy}[.exe]
#   target/release-artifacts/<triple>/{<bin>,<bin>.sha256,manifest.bin}
#   manifest.bin is generated only for veil-cli (auto-update target);
#   ogate / oproxy are deployed via systemd / package managers и do not
#   currently consume signed manifests.
#
# Pass `--sign --identity <path> --version X.Y.Z --binary-url URL[ URL...]`
# to ALSO produce a signed manifest from the freshly-built veil-cli
# binary.

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ARTIFACT_ROOT="$REPO_ROOT/target/release-artifacts"

# Pinned epoch keeps reproducibility narrative honest — operators
# building from the same git commit on different days still produce
# byte-identical binaries when this is set.  CI overrides via
# `--source-date-epoch <unix>` to reflect the tag's commit timestamp.
DEFAULT_SOURCE_DATE_EPOCH=1700000000  # 2023-11-14 — frozen mid-epoch

usage() {
  cat <<EOF
Usage: $0 --target <triple> [options]

Required:
  --target <triple>           Rust target triple to build for.

Options:
  --features <list>           Cargo --features.  Default:
                              'veil-bootstrap/allow-empty-seeds'.
  --source-date-epoch <unix>  Pin embedded build timestamps.
                              Default: $DEFAULT_SOURCE_DATE_EPOCH.
  --sign                      Also produce a signed UpdateManifest from
                              the freshly-built binary (requires
                              --identity, --version, --binary-url).
  --identity <path>           Issuer identity TOML (used with --sign).
  --version <ver>             Semver string (used with --sign).
  --min-compatible-version <ver>
                              Minimum installed version that may apply
                              this update.  Default: same as --version.
  --binary-url <url>          Repeatable.  Where binary is hosted (≥ 1).
  -h, --help

Examples:
  # Just build (no signing):
  $0 --target x86_64-unknown-linux-gnu

  # Build + sign:
  $0 --target x86_64-unknown-linux-gnu \\
     --sign \\
     --identity \$HOME/.veil-release/release-key.toml \\
     --version 1.2.3 \\
     --binary-url https://github.com/foo/bar/releases/download/v1.2.3/veil-cli-x86_64-unknown-linux-gnu \\
     --binary-url https://veil-mirror.example/releases/v1.2.3/veil-cli-x86_64-unknown-linux-gnu
EOF
}

target=""
# Phase 6.50.b audit fix: default to `production-seeds`.  Pre-fix the
# default was `allow-empty-seeds`, which produced а binary that won't
# bootstrap без operator-supplied peers — а production-deploy footgun
# for а CI artifact that LOOKS production-ready.  Override с
# `--features veil-bootstrap/allow-empty-seeds` для testnet builds.
# When `--sign` is also set, allow-empty-seeds is rejected (см. policy
# block below).
features="veil-bootstrap/production-seeds"
source_date_epoch="$DEFAULT_SOURCE_DATE_EPOCH"
sign=false
identity=""
version=""
min_compatible_version=""
binary_urls=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --features) features="$2"; shift 2 ;;
    --source-date-epoch) source_date_epoch="$2"; shift 2 ;;
    --sign) sign=true; shift ;;
    --identity) identity="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --min-compatible-version) min_compatible_version="$2"; shift 2 ;;
    --binary-url) binary_urls+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown arg $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$target" ]]; then
  echo "ERROR: --target is required" >&2
  usage >&2
  exit 2
fi

if "$sign"; then
  for required in identity version; do
    if [[ -z "${!required}" ]]; then
      echo "ERROR: --$required is required when --sign" >&2
      exit 2
    fi
  done
  if [[ ${#binary_urls[@]} -eq 0 ]]; then
    echo "ERROR: at least one --binary-url required when --sign" >&2
    exit 2
  fi
  # Phase 6.50.b audit fix: signed releases MUST NOT bundle
  # `allow-empty-seeds` — that flag produces а binary that won't
  # bootstrap без operator-supplied peers и is а production-deploy
  # footgun.  Pre-fix nothing prevented а CI/operator от signing
  # such an artifact.  Now the build script refuses к sign.
  if [[ "$features" == *"allow-empty-seeds"* ]]; then
    echo "ERROR: --sign incompatible с features='$features'" >&2
    echo "       allow-empty-seeds builds will not bootstrap on their own;" >&2
    echo "       signing such а binary creates а production-deploy footgun." >&2
    echo "       Use --features veil-bootstrap/production-seeds for signed releases," >&2
    echo "       OR drop --sign for а testnet build." >&2
    exit 2
  fi
fi

[[ -z "$min_compatible_version" ]] && min_compatible_version="$version"

# ── Build environment — deterministic flags ─────────────────────────────────

export SOURCE_DATE_EPOCH="$source_date_epoch"
# --remap-path-prefix strips host paths from binary debug info so
# the binary built на /home/alice/veil matches /Users/bob/proj/veil.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$REPO_ROOT=. --remap-path-prefix=$HOME=/HOME"
# Disable incremental compilation — incremental injects per-machine
# fingerprints into intermediate artifacts.
export CARGO_INCREMENTAL=0
# Lock the resolver to the committed Cargo.lock.
# Binary set: veil-cli (user CLI / auto-update) + ogate / oproxy-client /
# oproxy-server (operator-side service daemons). Listed explicitly so the
# script fails loud если а bin target is renamed upstream.
bins=(veil-cli ogate oproxy-client oproxy-server)
cargo_args=(--release --target "$target" --locked)
for b in "${bins[@]}"; do
  cargo_args+=(--bin "$b")
done
if [[ -n "$features" ]]; then
  cargo_args+=(--features "$features")
fi

echo "==> deterministic build for $target"
echo "    SOURCE_DATE_EPOCH=$source_date_epoch"
echo "    features=$features"
echo "    bins=${bins[*]}"
cd "$REPO_ROOT"
cargo build "${cargo_args[@]}"

# ── Stage artifact directory + per-bin SHA-256 ─────────────────────────────

stage="$ARTIFACT_ROOT/$target"
mkdir -p "$stage"
: > "$stage/sha256.txt"
veil_cli_bin_name=""
veil_cli_stage_path=""
for b in "${bins[@]}"; do
  bin_name="$b"
  if [[ "$target" == *windows* ]]; then
    bin_name="$b.exe"
  fi
  src_path="$REPO_ROOT/target/$target/release/$bin_name"
  if [[ ! -f "$src_path" ]]; then
    echo "ERROR: build did not produce $src_path" >&2
    exit 1
  fi
  cp "$src_path" "$stage/$bin_name"
  # Strip whitespace/path from sha256sum output to keep it parseable.
  sha=$(sha256sum "$stage/$bin_name" | awk '{print $1}')
  echo "$sha  $bin_name" >> "$stage/sha256.txt"
  echo "==> artifact: $stage/$bin_name"
  echo "    sha256:   $sha"
  if [[ "$b" == "veil-cli" ]]; then
    veil_cli_bin_name="$bin_name"
    veil_cli_stage_path="$stage/$bin_name"
  fi
done

# ── Optionally produce signed manifest ──────────────────────────────────────

if "$sign"; then
  echo "==> signing UpdateManifest (veil-cli only)"
  # Build the host veil-cli first so we can call its
  # `update sign-manifest` subcommand.  Cached after first run.
  cargo build --release --bin veil-cli --locked \
    --features "$features" >/dev/null
  host_cli="$REPO_ROOT/target/release/veil-cli"

  binary_url_args=()
  for url in "${binary_urls[@]}"; do
    binary_url_args+=("--binary-url" "$url")
  done

  # Signed manifest covers only veil-cli — the only binary с the
  # auto-update entry point (`veil-cli update apply`). ogate /
  # oproxy-* ship as system services (systemd, package managers) and
  # do not currently consume signed manifests.
  "$host_cli" update sign-manifest \
    --binary "$veil_cli_stage_path" \
    --version "$version" \
    --min-compatible-version "$min_compatible_version" \
    --platform-target "$target" \
    --identity "$identity" \
    --release-unix "$source_date_epoch" \
    --output "$stage/manifest.bin" \
    "${binary_url_args[@]}"

  echo "==> manifest written: $stage/manifest.bin"
  echo "    Distribute alongside $veil_cli_bin_name at one of:"
  for url in "${binary_urls[@]}"; do
    echo "      $url"
  done
fi

echo "==> done"
