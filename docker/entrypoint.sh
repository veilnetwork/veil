#!/bin/sh
# entrypoint.sh — runs inside the veil-bootstrap container.
#
# Responsibilities:
#   1. Wait for the Let's Encrypt live directory to exist (certbot sibling
#      container drops fullchain.pem + privkey.pem there).
#   2. On first boot, generate identity + patch config.toml with:
#      - identity.role = core
#      - [[listen]] entries for tcp / tls / quic / wss (all sharing the
#        same fullchain/privkey)
#      - mesh UDP beacon bind
#      - persist_enabled + persist paths
#   3. Exec veil-cli node run --foreground.
#
# All subsequent boots reuse the existing config.
set -eu

: "${HOST:?HOST env variable is required (DNS name the cert was issued for)}"
# F8: HOST is interpolated into filesystem paths (/etc/letsencrypt/live/$HOST)
# and into the advertised transport URI, so a value containing path separators,
# shell metacharacters, or control chars could traverse paths or inject. Accept
# only a conservative DNS hostname charset (letters, digits, dot, hyphen).
case "$HOST" in
    *[!a-zA-Z0-9.-]* | "" | -* | *..*)
        echo "invalid HOST '$HOST' — expected a DNS hostname (a-z 0-9 . -)" >&2
        exit 1 ;;
esac
: "${EMAIL:=admin@${HOST}}"
: "${ROLE:=core}"
: "${DIFFICULTY:=24}"

: "${TCP_PORT:=5555}"
: "${TLS_PORT:=9906}"
: "${QUIC_PORT:=8443}"
: "${WSS_PORT:=8443}"
: "${MESH_UDP_PORT:=6666}"
: "${METRICS_PORT:=}"

CONFIG="/var/lib/veil/node.toml"
CERT_DIR="/etc/letsencrypt/live/${HOST}"
FULLCHAIN="${CERT_DIR}/fullchain.pem"
PRIVKEY="${CERT_DIR}/privkey.pem"

log() { printf '\033[1;36m[entrypoint %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }

# ── 1. Wait for Let's Encrypt certs ──────────────────────────────────────────
wait_for_certs() {
    log "waiting for ${FULLCHAIN}"
    i=0
    while [ ! -s "${FULLCHAIN}" ] || [ ! -s "${PRIVKEY}" ]; do
        i=$((i + 1))
        if [ "$i" -gt 300 ]; then
            echo "timeout waiting for Let's Encrypt cert at ${FULLCHAIN}" >&2
            exit 1
        fi
        sleep 2
    done
    log "certs ready"
}

# ── 2. Generate / enrich config (idempotent) ─────────────────────────────────
# Each step checks whether its artefact is already present; redeploys never
# skip `listen add` just because `node.toml` exists (previous bug: container
# restart during PoW mining left config with identity but no listeners —
# entrypoint saw existing file, early-return-ed, node booted without any
# ports bound).  Now identity generation is the only step gated on
# "node.toml missing"; everything else is re-checked by content.
generate_config() {
    if [ ! -f "${CONFIG}" ]; then
        log "generating identity (difficulty=${DIFFICULTY}) + default config"
        veil-cli config init "${CONFIG}" --difficulty "${DIFFICULTY}"
    else
        log "config already present at ${CONFIG} — re-validating listeners / managed block"
    fi

    # identity.role is a first-class config key (cfg/keys.rs); no sed hacks.
    # Runs every boot so config drift is auto-corrected.
    veil-cli --config "${CONFIG}" config set identity.role "${ROLE}"

    # Listeners — tcp (plain), tls (wrapped), quic (QUIC+TLS), wss (WebSocket
    # over TLS).  All three TLS-bearing listeners share the same Let's Encrypt
    # cert.  `advertise` uses the host's DNS name so other nodes learn the
    # canonical endpoint rather than the container-internal bind address.
    # Gated on "no listen entries yet" — matches both `[[listen]]` headers
    # and the inline-array `listen = [...]` form that `listen add` produces.
    if ! grep -qE '^\s*listen\s*=|^\[\[listen\]\]' "${CONFIG}"; then
        log "adding listeners"
        veil-cli --config "${CONFIG}" listen add \
            "tcp://0.0.0.0:${TCP_PORT}" \
            --advertise "tcp://${HOST}:${TCP_PORT}"
        veil-cli --config "${CONFIG}" listen add \
            "tls://0.0.0.0:${TLS_PORT}" \
            --advertise "tls://${HOST}:${TLS_PORT}" \
            --tls-cert "${FULLCHAIN}" --tls-key "${PRIVKEY}"
        veil-cli --config "${CONFIG}" listen add \
            "quic://0.0.0.0:${QUIC_PORT}" \
            --advertise "quic://${HOST}:${QUIC_PORT}" \
            --tls-cert "${FULLCHAIN}" --tls-key "${PRIVKEY}"
        veil-cli --config "${CONFIG}" listen add \
            "wss://0.0.0.0:${WSS_PORT}/veil" \
            --advertise "wss://${HOST}:${WSS_PORT}/veil" \
            --tls-cert "${FULLCHAIN}" --tls-key "${PRIVKEY}"
    fi

    # Mesh UDP beacon + persist paths.  Appended as a managed block guarded
    # by markers so subsequent patches are idempotent.
    if ! grep -q '# >>> entrypoint.sh managed block >>>' "${CONFIG}"; then
        cat >> "${CONFIG}" <<EOF

# >>> entrypoint.sh managed block >>>
EOF

        # Metrics block (only if METRICS_PORT is set).
        #
        # Safe-default policy (Phase 6.50.b): generate a random
        # `auth_token` if the operator opted into a non-loopback bind.
        # Otherwise the metrics endpoint would expose role / session /
        # mailbox / DHT telemetry to anyone who can route to the port.
        # Loopback-only deploys (most production setups behind a reverse
        # proxy) skip the token.  Operator can override by setting
        # METRICS_BIND=127.0.0.1 / ::1 OR pre-populating METRICS_TOKEN.
        if [ -n "${METRICS_PORT}" ]; then
            METRICS_BIND="${METRICS_BIND:-0.0.0.0}"
            METRICS_TOKEN_LINE=""
            case "${METRICS_BIND}" in
                127.0.0.1|::1|localhost)
                    : # loopback — no token needed
                    ;;
                *)
                    if [ -z "${METRICS_TOKEN:-}" ]; then
                        METRICS_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 43)"
                        log "generated random METRICS_TOKEN for non-loopback bind ${METRICS_BIND}"
                    fi
                    METRICS_TOKEN_LINE="auth_token = \"${METRICS_TOKEN}\""
                    ;;
            esac
            cat >> "${CONFIG}" <<EOF

[metrics]
listen = "tcp://${METRICS_BIND}:${METRICS_PORT}"
path = "/metrics"
${METRICS_TOKEN_LINE}
EOF
        fi

        cat >> "${CONFIG}" <<EOF

[routing]
cache_persist_path        = "/var/lib/veil/route_cache.json"
rtt_persist_path          = "/var/lib/veil/rtt.json"
vivaldi_persist_path      = "/var/lib/veil/vivaldi.json"
gateway_persist_path      = "/var/lib/veil/gateway_list.json"
peer_pubkeys_persist_path = "/var/lib/veil/peer_pubkeys.json"

[dht]
routing_persist_path = "/var/lib/veil/dht_routing.json"
values_persist_path  = "/var/lib/veil/dht_values.json"
# <<< entrypoint.sh managed block <<<
EOF
    fi

    log "validating config"
    veil-cli --config "${CONFIG}" config validate

    # Print the advertisement blob other operators paste into their
    # bootstrap_peers array.
    log "node identity:"
    veil-cli --config "${CONFIG}" node show || true
    log "bootstrap_peers snippet for other nodes:"
    # Scope to the [Identity] section — a naive first-match grep would pick up
    # the first [[bootstrap_peers]].public_key entry instead of our own.
    PUB_KEY=$(sed -n '/^\[[Ii]dentity\]/,$ p' "${CONFIG}" | \
        sed -nE 's/^\s*public_key\s*=\s*"([^"]*)".*/\1/p' | head -1)
    NONCE=$(sed -n '/^\[[Ii]dentity\]/,$ p' "${CONFIG}" | \
        sed -nE 's/^\s*nonce\s*=\s*"([^"]*)".*/\1/p' | head -1)
    cat <<EOF

╭───────────────────────────────────────────────────────────────╮
│  Paste ONE of these into other nodes' config.toml             │
╰───────────────────────────────────────────────────────────────╯

[[bootstrap_peers]]
transport  = "tls://${HOST}:${TLS_PORT}"
public_key = "${PUB_KEY}"
nonce      = "${NONCE}"
algo       = "ed25519"

# Or QUIC:
# transport  = "quic://${HOST}:${QUIC_PORT}"
# Or plain TCP:
# transport  = "tcp://${HOST}:${TCP_PORT}"
# Or WSS:
# transport  = "wss://${HOST}:${WSS_PORT}/veil"

EOF
}

# ── 3. Dispatch ──────────────────────────────────────────────────────────────
cmd="${1:-run}"
case "${cmd}" in
    run)
        wait_for_certs
        generate_config
        log "starting veil-cli node run"
        exec veil-cli --config "${CONFIG}" node run --foreground
        ;;
    show)
        exec veil-cli --config "${CONFIG}" node show
        ;;
    cli)
        shift
        exec veil-cli --config "${CONFIG}" "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
