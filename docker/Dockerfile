# ── Stage 1: build veil-cli ───────────────────────────────────────────────
FROM rust:1-bookworm AS build

# Phase 6.50.b audit fix: production default.  Pre-fix the Dockerfile
# baked in `allow-empty-seeds`, producing a container image that won't
# bootstrap without operator-supplied peers.  Now defaults to
# `production-seeds`.  Override at build time for testnet:
#     docker build --build-arg CARGO_FEATURES="allow-empty-seeds" .
# (audit M-6: dropped the non-existent `quic-session` feature that failed
# every build; the default features rocksdb-cold + tls-boring are applied
# automatically when building `-p veil-cli`.)
ARG CARGO_FEATURES="production-seeds"

# Build deps. rocksdb-cold: cmake + clang + liblzma. tls-boring (BoringSSL via
# the `boring` crate — a DEFAULT feature): cmake + a C/C++ toolchain + go + nasm
# + ninja. (audit M-6: go/nasm/ninja/liblzma were missing, so the
# default-feature build failed.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev liblzma-dev cmake clang golang nasm ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# audit M-6: the workspace members (incl. the veil-cli binary) live under
# crates/* — they were NOT copied, so the build could not resolve a single path
# dependency. Copy the whole source tree the workspace references.
COPY crates ./crates
COPY veilcore ./veilcore
COPY veilclient ./veilclient
COPY fuzz ./fuzz
COPY specification.md ./specification.md

# audit M-6: build the veil-cli BINARY package (was `-p veilcore`, a lib
# crate that produced no `veil-cli` binary for the strip/copy below).
RUN cargo build --release --features "${CARGO_FEATURES}" -p veil-cli \
    && strip target/release/veil-cli

# ── Stage 2: minimal runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system veil \
    && useradd --system --gid veil --home-dir /var/lib/veil \
        --no-create-home --shell /usr/sbin/nologin veil \
    && install -d -m 0700 -o veil -g veil /var/lib/veil

COPY --from=build /src/target/release/veil-cli /usr/local/bin/veil-cli
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Ports — default values; docker-compose publishes these.
EXPOSE 5555/tcp 9906/tcp 8443/tcp 8443/udp 6666/udp

USER veil
WORKDIR /var/lib/veil

# tini as PID 1 so Ctrl-C propagates to veil-cli and it performs a graceful
# shutdown (flush persist snapshots, close sessions) before the container exits.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["run"]
