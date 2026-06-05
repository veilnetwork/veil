#!/usr/bin/env bash
# install-bootstrap.sh — build veil-cli, provision a bootstrap Core
# node, and install a systemd unit for it.
#
# Run as root on a fresh Linux host (Debian/Ubuntu/RHEL family).  Re-runnable:
# each step checks for existing state before making changes.
#
# What it does:
#   1. Installs build-essential + rustup (if absent).
#   2. Builds veil-cli with --features allow-empty-seeds (testnet build)
#      and installs it to /usr/local/bin/veil-cli.
#   3. Creates the system user `veil` + data dir /var/lib/veil
#      (mode 0700, owned by veil:veil).
#   4. Generates a fresh identity, configures role = core, binds
#      tcp://0.0.0.0:${LISTEN_PORT}, and sets up persist paths.
#   5. Writes /etc/systemd/system/veil-bootstrap.service.
#   6. Prints the public advertisement blob other nodes need to join.

set -euo pipefail

# ── Tunables ─────────────────────────────────────────────────────────────────
PUBLIC_IP="${PUBLIC_IP:-}"                        # required, no default
LISTEN_PORT="${LISTEN_PORT:-9000}"
ROLE="${ROLE:-core}"                              # core | leaf
DIFFICULTY="${DIFFICULTY:-24}"                    # ≥24 for core
VEIL_USER="${VEIL_USER:-veil}"
DATA_DIR="${DATA_DIR:-/var/lib/veil}"
CONFIG_PATH="${CONFIG_PATH:-${DATA_DIR}/node.toml}"
CARGO_FEATURES="${CARGO_FEATURES:-allow-empty-seeds}"
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
BINARY_PATH="/usr/local/bin/veil-cli"
UNIT_PATH="/etc/systemd/system/veil-bootstrap.service"

say()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || fail "run as root (needs systemd + /usr/local/bin + useradd)"
[[ -n "${PUBLIC_IP}" ]] || fail "set PUBLIC_IP=<your advertised IP> before running"
case "${ROLE}" in core|leaf) ;; *) fail "ROLE must be core or leaf";; esac

# Whitelist-validate every env var that ends up in shell / sed / systemd /
# CLI-arg position, so a typo or hostile env can't break config or escalate
# privileges. Patterns chosen permissively but reject quotes, slashes-in-host,
# and shell metacharacters.
[[ "${PUBLIC_IP}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || fail "PUBLIC_IP must be a plain IP/hostname (got '${PUBLIC_IP}')"
[[ "${LISTEN_PORT}" =~ ^[0-9]+$ ]] && [[ "${LISTEN_PORT}" -ge 1 ]] && [[ "${LISTEN_PORT}" -le 65535 ]] \
    || fail "LISTEN_PORT must be 1..65535 (got '${LISTEN_PORT}')"
[[ "${DIFFICULTY}" =~ ^[0-9]+$ ]] && [[ "${DIFFICULTY}" -ge 0 ]] && [[ "${DIFFICULTY}" -le 32 ]] \
    || fail "DIFFICULTY must be 0..32 bits (got '${DIFFICULTY}')"
[[ "${VEIL_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]] \
    || fail "VEIL_USER must match POSIX username (got '${VEIL_USER}')"
[[ "${DATA_DIR}" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    || fail "DATA_DIR must be an absolute path with safe chars (got '${DATA_DIR}')"
[[ "${CONFIG_PATH}" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    || fail "CONFIG_PATH must be an absolute path with safe chars (got '${CONFIG_PATH}')"

# ── 1. Toolchain ─────────────────────────────────────────────────────────────
ensure_toolchain() {
    if command -v cargo >/dev/null 2>&1; then
        say "cargo present: $(cargo --version)"
        return
    fi
    say "installing rustup + stable toolchain"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y build-essential pkg-config libssl-dev curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y gcc gcc-c++ make pkgconfig openssl-devel curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y gcc gcc-c++ make pkgconfig openssl-devel curl
    else
        fail "unsupported distro — install build-essential + pkg-config + openssl-dev manually"
    fi
    # Supply-chain note (audit U15): this bootstraps the Rust toolchain via the
    # upstream rustup installer, pinned to HTTPS + TLS>=1.2. For high-assurance
    # / production builds, prefer a pre-provisioned toolchain (or verify the
    # rustup installer against a known SHA-256) rather than piping curl→sh — a
    # compromised install transport could otherwise substitute the toolchain.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
}

# ── 2. Build + install binary ────────────────────────────────────────────────
build_and_install_binary() {
    say "building veil-cli (features=${CARGO_FEATURES}) from ${SRC_DIR}"
    (
        cd "${SRC_DIR}"
        # shellcheck disable=SC1091
        [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
        cargo build --release --features "${CARGO_FEATURES}" -p veilcore
    )
    install -m 0755 "${SRC_DIR}/target/release/veil-cli" "${BINARY_PATH}"
    say "installed ${BINARY_PATH} ($(${BINARY_PATH} --version 2>/dev/null || echo unknown version))"
}

# ── 3. System user + data dir ────────────────────────────────────────────────
ensure_system_user() {
    if id "${VEIL_USER}" >/dev/null 2>&1; then
        say "user ${VEIL_USER} already exists"
    else
        say "creating system user ${VEIL_USER}"
        useradd --system --no-create-home --shell /usr/sbin/nologin \
            --home-dir "${DATA_DIR}" "${VEIL_USER}"
    fi
    install -d -m 0700 -o "${VEIL_USER}" -g "${VEIL_USER}" "${DATA_DIR}"
}

# ── 4. Config ────────────────────────────────────────────────────────────────
# `veil-cli config init` lays down a default Config; role / listen /
# persist are not reachable via `config set`, so we patch the TOML directly
# after generation.  Idempotent: the patch is a no-op on subsequent runs.
generate_config() {
    if [[ -f "${CONFIG_PATH}" ]]; then
        say "config ${CONFIG_PATH} already exists — leaving as-is"
        return
    fi

    say "generating identity + default config at ${CONFIG_PATH}"
    sudo -u "${VEIL_USER}" "${BINARY_PATH}" \
        --config "${CONFIG_PATH}" \
        config init --difficulty "${DIFFICULTY}"

    say "patching role=${ROLE} and persist paths"
    # 1. role — appended under [identity] if not already explicitly set.
    if ! grep -qE '^\s*role\s*=' "${CONFIG_PATH}"; then
        sudo -u "${VEIL_USER}" tee -a "${CONFIG_PATH}" >/dev/null <<EOF

# Bootstrap node role — DHT participant.  Set by install-bootstrap.sh.
EOF
    fi
    # Replace or append role under [identity].  sed targets the first
    # identity section; falls back to appending under [identity] when absent.
    if grep -qE '^\s*role\s*=' "${CONFIG_PATH}"; then
        sudo -u "${VEIL_USER}" sed -i -E \
            "s|^(\s*role\s*=\s*)\"[^\"]*\"|\1\"${ROLE}\"|" "${CONFIG_PATH}"
    else
        # Insert `role = "..."` right after the `[identity]` header line.
        sudo -u "${VEIL_USER}" sed -i -E \
            "/^\[identity\]/a role = \"${ROLE}\"" "${CONFIG_PATH}"
    fi

    # 2. persist_enabled + persist paths + a snapshot of ephemeral defaults.
    # We append a block guarded by a marker so re-runs don't duplicate it.
    if ! grep -q '# >>> install-bootstrap.sh managed block >>>' "${CONFIG_PATH}"; then
        sudo -u "${VEIL_USER}" tee -a "${CONFIG_PATH}" >/dev/null <<'EOF'

# >>> install-bootstrap.sh managed block >>>
# Persist DHT routing + route cache across restarts so this node retains its
# view of the network after reboots.
persist_enabled = true

[routing]
cache_persist_path        = "/var/lib/veil/route_cache.json"
rtt_persist_path          = "/var/lib/veil/rtt.json"
vivaldi_persist_path      = "/var/lib/veil/vivaldi.json"
gateway_persist_path      = "/var/lib/veil/gateway_list.json"
peer_pubkeys_persist_path = "/var/lib/veil/peer_pubkeys.json"

[dht]
routing_persist_path = "/var/lib/veil/dht_routing.json"
values_persist_path  = "/var/lib/veil/dht_values.json"
# <<< install-bootstrap.sh managed block <<<
EOF
    fi

    # 3. Listener — added via the CLI so the [[listen]] array-of-tables
    # format matches what the parser expects.
    if "${BINARY_PATH}" --config "${CONFIG_PATH}" listen list 2>/dev/null \
        | grep -q "tcp://0.0.0.0:${LISTEN_PORT}"; then
        say "listener tcp://0.0.0.0:${LISTEN_PORT} already configured"
    else
        sudo -u "${VEIL_USER}" "${BINARY_PATH}" \
            --config "${CONFIG_PATH}" \
            listen add "tcp://0.0.0.0:${LISTEN_PORT}" \
            --advertise "tcp://${PUBLIC_IP}:${LISTEN_PORT}"
    fi

    say "validating config"
    "${BINARY_PATH}" --config "${CONFIG_PATH}" config validate
}

# ── 5. systemd unit ──────────────────────────────────────────────────────────
write_systemd_unit() {
    say "writing ${UNIT_PATH}"
    cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Veil bootstrap node (${ROLE})
Documentation=https://github.com/veilnetwork/veil
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${VEIL_USER}
Group=${VEIL_USER}
ExecStart=${BINARY_PATH} --config ${CONFIG_PATH} node run --foreground
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ReadWritePaths=${DATA_DIR}

# Resource limits for a dedicated bootstrap host.  Raise fd limit since this
# node may hold many concurrent sessions; the runtime itself caps at
# max_concurrent + max_per_ip / max_per_subnet from the config.
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

start_service() {
    say "enabling + starting veil-bootstrap.service"
    systemctl enable veil-bootstrap.service
    systemctl restart veil-bootstrap.service
    sleep 2
    systemctl --no-pager --full status veil-bootstrap.service || true
}

print_advertisement() {
    say "node advertisement (share this with other nodes' bootstrap_peers)"
    sudo -u "${VEIL_USER}" "${BINARY_PATH}" \
        --config "${CONFIG_PATH}" node show
    echo
    cat <<EOF

╭───────────────────────────────────────────────────────────────╮
│  TOML snippet to paste into other nodes' config.toml:         │
╰───────────────────────────────────────────────────────────────╯
EOF
    PUB_KEY=$(grep -E '^\s*public_key\s*=' "${CONFIG_PATH}" | head -1 | sed -E 's/^\s*public_key\s*=\s*"([^"]*)"/\1/')
    NONCE=$(grep -E '^\s*nonce\s*=' "${CONFIG_PATH}" | head -1 | sed -E 's/^\s*nonce\s*=\s*"([^"]*)"/\1/')
    cat <<EOF
[[bootstrap_peers]]
transport  = "tcp://${PUBLIC_IP}:${LISTEN_PORT}"
public_key = "${PUB_KEY}"
nonce      = "${NONCE}"
algo       = "ed25519"

EOF
}

# ── Run ──────────────────────────────────────────────────────────────────────
ensure_toolchain
build_and_install_binary
ensure_system_user
generate_config
write_systemd_unit
start_service
print_advertisement

say "done"
