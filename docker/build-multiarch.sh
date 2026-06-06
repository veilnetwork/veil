#!/bin/bash
# build-multiarch.sh — build & push veil images for one or more architectures.
#
# Subcommands:
#   build   (default) Build + push image for the current platform
#   manifest         Create a multi-arch manifest from already-pushed arch images
#
# Usage — build on each machine natively, then combine:
#
#   # Machine 1 (arm64):
#   REPO=veilnetwork/veil ./docker/build-multiarch.sh build v0.1.0
#
#   # Machine 2 (amd64):
#   REPO=veilnetwork/veil ./docker/build-multiarch.sh build v0.1.0
#
#   # Either machine — combine into one multi-arch tag:
#   REPO=veilnetwork/veil ./docker/build-multiarch.sh manifest v0.1.0
#
#   # Single-machine shortcut (if buildx + QEMU work):
#   PLATFORMS=linux/amd64,linux/arm64 REPO=veilnetwork/veil ./docker/build-multiarch.sh build v0.1.0
#
# Env vars:
#   REPO              Docker Hub repo (default: veilnetwork/veil)
#   TAG / $2          Image tag (default: latest)
#   PLATFORMS         Comma-separated platforms (default: auto-detected native)
#   CARGO_FEATURES    Rust feature flags (default: production-seeds,quic-session).
#                     Override to "allow-empty-seeds,quic-session" ONLY for
#                     explicit testnet/devnet builds; the production default
#                     refuses to compile without populated bootstrap seeds, which
#                     prevents shipping a "production-looking" artefact that
#                     cannot bootstrap (Phase 6.50.b safe-default policy).
#   PUSH              1=push (default), 0=local only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTEXT_DIR="$(dirname "$SCRIPT_DIR")"

REPO="${REPO:-veilnetwork/veil}"
CARGO_FEATURES="${CARGO_FEATURES:-production-seeds,quic-session}"
PUSH="${PUSH:-1}"

CMD="${1:-build}"
case "$CMD" in
    build|manifest) TAG="${2:-latest}" ;;
    *)              TAG="${CMD}"; CMD="build" ;;  # bare "./script v0.1.0"
esac

detect_platform() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "linux/amd64" ;;
        aarch64|arm64) echo "linux/arm64" ;;
        *)             echo "linux/$arch" ;;
    esac
}

PLATFORMS="${PLATFORMS:-$(detect_platform)}"
IFS=',' read -ra PLATFORM_LIST <<< "$PLATFORMS"

# ── manifest: combine arch-specific images into one tag ──────────────────
do_manifest() {
    local ARCH_IMAGES=()
    for PLATFORM in "${PLATFORM_LIST[@]}"; do
        ARCH_IMAGES+=("${REPO}:${TAG}-${PLATFORM//\//-}")
    done

    echo "Creating manifest ${REPO}:${TAG} from:"
    for IMG in "${ARCH_IMAGES[@]}"; do
        echo "  - $IMG"
    done

    docker manifest rm "${REPO}:${TAG}" 2>/dev/null || true
    docker manifest create "${REPO}:${TAG}" "${ARCH_IMAGES[@]}"
    docker manifest push "${REPO}:${TAG}"
    echo ""
    echo "Pushed manifest ${REPO}:${TAG}"
    echo "  docker pull ${REPO}:${TAG}  # auto-selects arch"
}

# ── build: build + push for specified platforms ──────────────────────────
do_build() {
    echo "Building ${REPO}:${TAG}"
    echo "  platforms: ${PLATFORMS}"
    echo "  features:  ${CARGO_FEATURES}"
    echo "  push:      ${PUSH}"
    echo ""

    ARCH_IMAGES=()
    for PLATFORM in "${PLATFORM_LIST[@]}"; do
        ARCH_SUFFIX="${PLATFORM//\//-}"
        ARCH_TAG="${REPO}:${TAG}-${ARCH_SUFFIX}"
        echo ""
        echo "=== Building ${ARCH_TAG} (platform: ${PLATFORM}) ==="
        docker build \
            --build-arg "CARGO_FEATURES=${CARGO_FEATURES}" \
            -t "$ARCH_TAG" \
            -f "$SCRIPT_DIR/Dockerfile" \
            "$CONTEXT_DIR"
        ARCH_IMAGES+=("$ARCH_TAG")
    done

    if [ "$PUSH" = "1" ]; then
        echo ""
        echo "=== Pushing ==="
        for IMG in "${ARCH_IMAGES[@]}"; do
            docker push "$IMG"
        done

        if [ "${#ARCH_IMAGES[@]}" -eq 1 ]; then
            docker tag "${ARCH_IMAGES[0]}" "${REPO}:${TAG}"
            docker push "${REPO}:${TAG}"
            echo ""
            echo "Pushed ${REPO}:${TAG} (${PLATFORMS})"
        else
            echo ""
            echo "Pushed arch images. Run 'manifest' to combine:"
            echo "  REPO=${REPO} $0 manifest ${TAG}"
        fi
    else
        echo ""
        echo "Built locally:"
        for IMG in "${ARCH_IMAGES[@]}"; do
            echo "  $IMG"
        done
    fi
}

# ── dispatch ─────────────────────────────────────────────────────────────
case "$CMD" in
    build)    do_build ;;
    manifest) do_manifest ;;
esac
