#!/usr/bin/env bash
# iperf-veil-bench.sh — integration bench for veil throughput.
#
# Two-part test:
#   1. baseline = iperf3 over kernel loopback (127.0.0.1)
#   2. veil  = 2 daemons + 2 ogates in network namespaces, iperf3 between
#                 the virtual ogate IPs
#
# Compares (2) to (1) and fails if veil throughput drops below a
# configurable percentage of the loopback baseline.
#
# Environment knobs:
#   MIN_VEIL_PCT    pass threshold (default 1)   — veil must achieve
#                       ≥ this percent of loopback Mbps
#   DURATION           iperf3 run duration in s (default 10)
#   OGATE_MTU          ogate TUN MTU (default 16000)
#   OGATE_WORKERS      tokio worker_threads (default 1; low value tames
#                       scheduler thrashing on single-host bench rigs)
#   DEVNET_DIR         working dir for devnet state (default
#                       /tmp/iperf-veil-bench)
#   KEEP               if "1", skip cleanup on exit (debug)
#
# Exit codes:
#   0 — pass
#   1 — fail (veil below threshold)
#   2 — setup error
#
# Requires:  sudo (TUN + netns + iptables), iperf3, veil-cli and ogate
# release binaries (defaults: ./target/release/{veil-cli,ogate}).

set -e
set -u
set -o pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

# Threshold sized to catch catastrophic regressions (e.g. the Phase E27
# batching bug that dropped veil throughput from 4-5 % to 0.001 % of
# loopback), not minor variance.  Local single-host runs naturally see
# 2-5 % ratio depending on contention; production-grade architectural
# regression brings it to < 1 %.  Default 1 % leaves comfortable headroom
# for the noisy single-host case.
MIN_VEIL_PCT="${MIN_VEIL_PCT:-1}"
DURATION="${DURATION:-15}"
WARMUP="${WARMUP:-3}"
# Number of veil-measurement trials; the best ratio is reported and used
# for the pass/fail decision.  Single-host benches are noisy enough that
# a single sample can spuriously dip below the threshold even on a healthy
# veil; 3 samples tames the false-positive rate.
TRIALS="${TRIALS:-3}"
OGATE_MTU="${OGATE_MTU:-16000}"
OGATE_WORKERS="${OGATE_WORKERS:-1}"
DEVNET_DIR="${DEVNET_DIR:-/tmp/iperf-veil-bench}"
KEEP="${KEEP:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VEIL_CLI="${VEIL_CLI:-${REPO_ROOT}/target/release/veil-cli}"
OGATE_BIN="${OGATE_BIN:-${REPO_ROOT}/target/release/ogate}"

# Virtual IPs assigned to the two ogate TUN devices.
N0_IP="10.99.0.1"
N1_IP="10.99.0.2"

# Loopback bind for phase-1 iperf3 — keep on a high port to avoid
# privileged-port collisions on shared CI runners.
LOOPBACK_PORT=15201

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[bench] $*" >&2; }
warn() { echo "[bench:WARN] $*" >&2; }
err()  { echo "[bench:ERR] $*" >&2; }

# Locate the actual mbps number from the iperf3 sender-summary line. iperf3 prints
# units in the same column (Mbits/Gbits/Kbits/sec). Returns Mbps as integer.
parse_mbps() {
    local logfile=$1
    # Sender-summary line shape:
    #   [  5]   0.00-10.00  sec  4.30 GBytes  3.69 Gbits/sec    0   sender
    # Picks the bitrate (second-to-last numeric field before "sender").
    local line val unit
    line=$(grep -E '^\[(  5|SUM)\]' "$logfile" | grep -E 'sender' | tail -1) || return 1
    val=$(awk '/sender/ { for (i=1;i<=NF;i++) if ($i ~ /^(Gbits|Mbits|Kbits)\/sec$/) { print $(i-1), $i; exit } }' <<< "$line")
    [[ -z "$val" ]] && return 1
    local num="${val%% *}"
    unit="${val##* }"
    case "$unit" in
        Gbits/sec) python3 -c "print(int(${num} * 1000))" ;;
        Mbits/sec) python3 -c "print(int(${num}))" ;;
        Kbits/sec) python3 -c "print(int(${num} / 1000))" ;;
        *) return 1 ;;
    esac
}

# ── Cleanup on exit ───────────────────────────────────────────────────────────

cleanup() {
    local rc=$?
    if [[ "$KEEP" == "1" ]]; then
        log "KEEP=1 set; leaving devnet state in $DEVNET_DIR"
        return $rc
    fi
    log "cleanup: stopping processes + netns"
    sudo pkill -f "ogate up" >/dev/null 2>&1 || true
    pkill -f "${VEIL_CLI##*/}.*node run" >/dev/null 2>&1 || true
    pkill -f "iperf3" >/dev/null 2>&1 || true
    sudo ip netns del ovns0 >/dev/null 2>&1 || true
    sudo ip netns del ovns1 >/dev/null 2>&1 || true
    sleep 1
    if [[ -d "$DEVNET_DIR" ]]; then
        rm -rf "$DEVNET_DIR" || true
    fi
    return $rc
}
trap cleanup EXIT INT TERM

# ── Pre-flight ────────────────────────────────────────────────────────────────

log "iperf-veil-bench start (DURATION=${DURATION}s, threshold=${MIN_VEIL_PCT}%)"

for cmd in iperf3 sudo ip awk python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        err "missing required tool: $cmd"
        exit 2
    fi
done

if [[ ! -x "$VEIL_CLI" ]]; then
    err "veil-cli not found at $VEIL_CLI"
    err "build first:  cargo build --release -p veil-cli --features veilcore/allow-empty-seeds"
    exit 2
fi
if [[ ! -x "$OGATE_BIN" ]]; then
    err "ogate not found at $OGATE_BIN"
    err "build first:  cargo build --release -p ogate --features allow-empty-seeds"
    exit 2
fi

if ! sudo -n true 2>/dev/null; then
    err "sudo with NOPASSWD required for TUN/netns ops"
    exit 2
fi

# ── Phase 1: loopback baseline ────────────────────────────────────────────────

log "phase 1/2: loopback iperf3 baseline"

pkill -f "iperf3" >/dev/null 2>&1 || true
sleep 1

iperf3 -s -1 -B 127.0.0.1 -p $LOOPBACK_PORT > /dev/null 2>&1 &
sleep 1
iperf3 -c 127.0.0.1 -p $LOOPBACK_PORT -t "$DURATION" > /tmp/iperf-loopback.log 2>&1

LOOPBACK_MBPS=$(parse_mbps /tmp/iperf-loopback.log) || {
    err "failed to parse loopback iperf3 output"
    cat /tmp/iperf-loopback.log >&2
    exit 2
}
log "  loopback: ${LOOPBACK_MBPS} Mbps"

# ── Phase 2: veil (2 daemons + 2 ogates) ───────────────────────────────────

log "phase 2/2: veil (2 daemons + 2 ogates through netns)"

mkdir -p "$DEVNET_DIR"
chmod 700 "$DEVNET_DIR"
mkdir -p "$DEVNET_DIR/node-0" "$DEVNET_DIR/node-1"
chmod 700 "$DEVNET_DIR/node-0" "$DEVNET_DIR/node-1"

# Generate fresh configs each run — avoids any leftover state from prior runs.
# PoW difficulty 24 matches production builds' runtime check; each `config
# init` runs a short search (typically 1-30 s on modern hardware).
log "  generating fresh configs (PoW search may take 1-30 s per node)"
for n in 0 1; do
    cfg="$DEVNET_DIR/node-${n}/config.toml"
    port=$((9200 + n))
    "$VEIL_CLI" config init "$cfg" --difficulty 24 >/dev/null 2>&1 || {
        err "config init failed for node-${n}"
        exit 2
    }
    "$VEIL_CLI" identity standalone --veil-dir "$DEVNET_DIR/node-${n}" --force >/dev/null 2>&1 || true
    "$VEIL_CLI" --config "$cfg" listen add "tcp://127.0.0.1:${port}" >/dev/null 2>&1
    "$VEIL_CLI" --config "$cfg" config set ipc.enabled true >/dev/null
    "$VEIL_CLI" --config "$cfg" config set ipc.socket_uri "unix://${DEVNET_DIR}/node-${n}/app.sock" >/dev/null
    # Lazy mining wastes CPU on this short-running bench.
    sed -i 's/^lazy_mining = true/lazy_mining = false/' "$cfg" 2>/dev/null || true
    # Multi-thread is the default for production; under-saturate workers
    # on a single-host bench to avoid scheduler thrashing.
    if grep -q '^worker_threads' "$cfg"; then
        sed -i "s/^worker_threads = .*/worker_threads = ${OGATE_WORKERS}/" "$cfg"
    else
        sed -i "/^runtime_flavor = /a worker_threads = ${OGATE_WORKERS}\\nmax_blocking_threads = ${OGATE_WORKERS}" "$cfg"
    fi
done

# Symmetric peering: node-0 dials node-1 AND vice-versa (lex-dedup picks
# the canonical direction).  Without symmetric configuration, lex-dedup
# rejects the unidirectional inbound session.
N0_PK=$(awk -F'"' '/^public_key /{print $2}' "$DEVNET_DIR/node-0/config.toml" | head -1)
N0_NONCE=$(awk -F'"' '/^nonce /{print $2}' "$DEVNET_DIR/node-0/config.toml" | head -1)
N1_PK=$(awk -F'"' '/^public_key /{print $2}' "$DEVNET_DIR/node-1/config.toml" | head -1)
N1_NONCE=$(awk -F'"' '/^nonce /{print $2}' "$DEVNET_DIR/node-1/config.toml" | head -1)
"$VEIL_CLI" --config "$DEVNET_DIR/node-0/config.toml" peers add \
    "$N1_PK" "$N1_NONCE" "tcp://127.0.0.1:9201" >/dev/null 2>&1
"$VEIL_CLI" --config "$DEVNET_DIR/node-1/config.toml" peers add \
    "$N0_PK" "$N0_NONCE" "tcp://127.0.0.1:9200" >/dev/null 2>&1

# Start daemons.
"$VEIL_CLI" --config "$DEVNET_DIR/node-0/config.toml" node run --foreground \
    >"$DEVNET_DIR/node-0/veil.log" 2>&1 &
N0_PID=$!
"$VEIL_CLI" --config "$DEVNET_DIR/node-1/config.toml" node run --foreground \
    >"$DEVNET_DIR/node-1/veil.log" 2>&1 &
N1_PID=$!

# Wait for daemons to bind admin + ipc sockets and handshake their peer session.
for _ in {1..15}; do
    if [[ -S "$DEVNET_DIR/node-0/app.sock" ]] && [[ -S "$DEVNET_DIR/node-1/app.sock" ]]; then
        break
    fi
    sleep 1
done
[[ -S "$DEVNET_DIR/node-0/app.sock" ]] || { err "node-0 app.sock not bound"; exit 2; }
[[ -S "$DEVNET_DIR/node-1/app.sock" ]] || { err "node-1 app.sock not bound"; exit 2; }

# Wait for session establishment.
for _ in {1..10}; do
    sessions=$("$VEIL_CLI" --config "$DEVNET_DIR/node-0/config.toml" \
        sessions list 2>/dev/null | grep -c "active" || true)
    [[ "$sessions" -ge 1 ]] && break
    sleep 1
done
[[ "$sessions" -ge 1 ]] || { err "no active peer session"; exit 2; }

# Get node_ids for ogate configs.
N0_ID=$("$VEIL_CLI" --config "$DEVNET_DIR/node-0/config.toml" \
    node show 2>/dev/null | awk -F': ' '/^node_id/{print $2}')
N1_ID=$("$VEIL_CLI" --config "$DEVNET_DIR/node-1/config.toml" \
    node show 2>/dev/null | awk -F': ' '/^node_id/{print $2}')

# Generate ogate configs.
for n in 0 1; do
    cfg="$DEVNET_DIR/ogate-${n}.toml"
    if [[ "$n" == "0" ]]; then
        peer_id="$N1_ID"; peer_ip="$N1_IP"; iface=ogate0; local_ip="$N0_IP"
    else
        peer_id="$N0_ID"; peer_ip="$N0_IP"; iface=ogate1; local_ip="$N1_IP"
    fi
    cat > "$cfg" <<EOF
network       = "bench"
app           = "ogate"
mode          = "authorized"
socket_path   = "${DEVNET_DIR}/node-${n}/app.sock"
iface_name    = "${iface}"
mtu           = ${OGATE_MTU}
local_addr_v4 = "${local_ip}"
prefix_v4     = 24
endpoint_id   = 1

[[peers]]
node_id = "${peer_id}"
addr_v4 = "${peer_ip}"
name    = "peer"
EOF
done

# Setup netns.
sudo ip netns add ovns0
sudo ip netns add ovns1
sudo ip netns exec ovns0 ip link set lo up
sudo ip netns exec ovns1 ip link set lo up

# Start ogate.  `OGATE_WORKERS=1` keeps the tokio runtime small enough to
# coexist with another ogate + 2 daemons + iperf3 endpoints on one host.
sudo env OGATE_WORKERS="${OGATE_WORKERS}" OGATE_MAX_BLOCKING_THREADS="${OGATE_WORKERS}" \
    ip netns exec ovns0 "$OGATE_BIN" up --config "$DEVNET_DIR/ogate-0.toml" \
    >"$DEVNET_DIR/ogate-0.log" 2>&1 &
sudo env OGATE_WORKERS="${OGATE_WORKERS}" OGATE_MAX_BLOCKING_THREADS="${OGATE_WORKERS}" \
    ip netns exec ovns1 "$OGATE_BIN" up --config "$DEVNET_DIR/ogate-1.toml" \
    >"$DEVNET_DIR/ogate-1.log" 2>&1 &
sleep 3

# Smoke: ping must succeed.
if ! sudo ip netns exec ovns0 ping -c 1 -W 3 "$N1_IP" >/dev/null 2>&1; then
    err "smoke ping ${N0_IP} → ${N1_IP} failed"
    tail -10 "$DEVNET_DIR/ogate-0.log" >&2 || true
    tail -10 "$DEVNET_DIR/ogate-1.log" >&2 || true
    exit 2
fi

# Warm-up: short iperf3 burst to prime TCP windows + populate the
# session-runner's TX queue.  Fresh-process cold-start with TCP slow-start
# + first-frame ChaCha20 keystream init add ~1-3 s of below-steady-state
# throughput, which would skew the headline number on a short bench.
# Discarded run; logfile to /dev/null.
if [[ "$WARMUP" -gt 0 ]]; then
    sudo ip netns exec ovns1 iperf3 -s -1 -B "$N1_IP" > /dev/null 2>&1 &
    sleep 1
    sudo ip netns exec ovns0 iperf3 -c "$N1_IP" -t "$WARMUP" >/dev/null 2>&1 || true
    sleep 1
fi

# iperf3 over veil — repeat TRIALS times and keep the best.  Single-host
# benches naturally vary ±30 % due to kernel scheduler + iperf3 own thread
# placement; taking max(N) gives a stable indicator of the architectural
# ceiling, not the worst-case scheduler luck.
VEIL_MBPS=0
TRIAL_RESULTS=()
for i in $(seq 1 "$TRIALS"); do
    sudo ip netns exec ovns1 pkill iperf3 >/dev/null 2>&1 || true
    sleep 1
    sudo ip netns exec ovns1 iperf3 -s -1 -B "$N1_IP" > /dev/null 2>&1 &
    sleep 1
    sudo ip netns exec ovns0 iperf3 -c "$N1_IP" -t "$DURATION" \
        > "/tmp/iperf-veil-trial-$i.log" 2>&1
    mbps=$(parse_mbps "/tmp/iperf-veil-trial-$i.log") || {
        err "trial $i failed to parse iperf3 output"
        cat "/tmp/iperf-veil-trial-$i.log" >&2
        continue
    }
    TRIAL_RESULTS+=("$mbps")
    if (( mbps > VEIL_MBPS )); then
        VEIL_MBPS=$mbps
    fi
    log "  veil trial $i: ${mbps} Mbps"
done
[[ "$VEIL_MBPS" -eq 0 ]] && { err "all veil trials failed"; exit 2; }
log "  veil best:    ${VEIL_MBPS} Mbps (of ${TRIALS} trials)"

# ── Comparison ────────────────────────────────────────────────────────────────

PCT=$(python3 -c "print(round(${VEIL_MBPS} * 100 / ${LOOPBACK_MBPS}, 2))")
DROP=$(python3 -c "print(round(100 - ${VEIL_MBPS} * 100 / ${LOOPBACK_MBPS}, 2))")

echo
echo "=========================================="
echo "loopback baseline : ${LOOPBACK_MBPS} Mbps"
echo "veil measured  : ${VEIL_MBPS} Mbps"
echo "veil ratio     : ${PCT}% of loopback"
echo "drop              : ${DROP}%"
echo "threshold         : >= ${MIN_VEIL_PCT}% of loopback"
echo "=========================================="

PASS=$(python3 -c "print(1 if ${PCT} >= ${MIN_VEIL_PCT} else 0)")
if [[ "$PASS" == "1" ]]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL (veil ${PCT}% < threshold ${MIN_VEIL_PCT}%)"
    exit 1
fi
