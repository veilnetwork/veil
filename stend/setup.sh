#!/usr/bin/env bash
# Generate per-node identity material for the local 5-node test
# stand.  Idempotent: re-running skips nodes that already have
# a populated `veil/` dir.
#
# Phase 6.49 audit follow-up (2026-05-08): replaces previously-
# committed secrets with reproducible local generation.  See
# `stend/SETUP.md` for context.

set -euo pipefail

cd "$(dirname "$0")"

CLI="../target/release/veil-cli"
if [[ ! -x "$CLI" ]]; then
    if [[ -x "./veil-cli" ]]; then
        CLI="./veil-cli"
    else
        echo "error: veil-cli not found." >&2
        echo "Build first: cargo build --release -p veilcore --bin veil-cli --features veil-bootstrap/allow-empty-seeds" >&2
        exit 1
    fi
fi

# Per-node TCP port assignment (matches existing config.toml convention).
declare -A PORTS=( [1]=17201 [2]=17202 [3]=17203 [4]=17204 [5]=17205 )

for n in 1 2 3 4 5; do
    NODE_DIR="node$n"
    VEIL_DIR="$NODE_DIR/veil"
    CONFIG="$NODE_DIR/config.toml"
    PORT="${PORTS[$n]}"

    if [[ -d "$VEIL_DIR" && -f "$CONFIG" ]]; then
        echo "node$n: already provisioned, skipping (delete $NODE_DIR/veil/ to force regenerate)"
        continue
    fi

    mkdir -p "$NODE_DIR"
    echo "node$n: provisioning..."

    # Reference the external veil_dir.  This is a deliberate move
    # away from inline `[Identity] private_key = "..."` (which leaked
    # SK material into the repo previously).  The daemon writes
    # device_identity_sk.bin into veil_dir on first start.
    cat > "$CONFIG" <<EOF
listen = [{ id = "0x00000001", transport = "tcp://127.0.0.1:${PORT}" }]
[global]
runtime_flavor = "multi_thread"
admin_socket = "unix://$(pwd)/$NODE_DIR/config.sock"
logs = "stderr"
log_level = "info"
log_format = "text"

[identity]
veil_dir = "$(pwd)/$VEIL_DIR"

[ipc]
enabled = true
socket_uri = "unix://$(pwd)/$NODE_DIR/app.sock"

[metrics]
listen = "tcp://127.0.0.1:$((19000 + n))"
path = "/metrics"
EOF

    # Pre-create the veil dir with the right perms — daemon writes
    # SK/PK material here on first start.
    mkdir -p "$VEIL_DIR"
    chmod 700 "$VEIL_DIR"

    echo "node$n: provisioned (port=$PORT, veil_dir=$VEIL_DIR)"
done

cat <<EOF

stend setup complete.  Each node generates its own identity material
on first start (inside its veil_dir).  Start individual nodes with:

  ($CLI --config node1/config.toml node run --foreground &)
  ($CLI --config node2/config.toml node run --foreground &)
  ...

NOTE: The legacy topology-*.sh scripts grep for \`^node_id\` in
config.toml.  Since identity is now external (veil_dir), those
scripts need updating to read node_id from each daemon's admin
socket after first start.  Open issue if you actually use them.
EOF
