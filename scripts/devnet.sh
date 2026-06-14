#!/usr/bin/env bash
# devnet.sh — local multi-node veil devnet manager.
#
# Usage:
#   devnet.sh start [--nodes N]   Build + start N veil nodes (default: 3)
#   devnet.sh stop                Stop all running devnet nodes
#   devnet.sh status              Show which nodes are running
#   devnet.sh smoke               Run a quick smoke test against the devnet
#   devnet.sh replication-smoke   Prove K-closest DHT replication on PUT
#   devnet.sh throughput          iperf3 over an ogate TUN bridge (needs ROOT;
#                                 run `start --nodes 2` first, then
#                                 `sudo devnet.sh throughput`)
#   devnet.sh logs [N]            Tail logs for node N (default: 0)
#
# Nodes each listen on 127.0.0.1:920{N} for peer connections.
# The admin socket for node N is at /tmp/veil-devnet/node-N/config.sock
# (derived automatically by veil-cli from the config file path).

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DEVNET_DIR="${DEVNET_DIR:-/tmp/veil-devnet}"
DEFAULT_NODES=3
BASE_PEER_PORT=9200   # node-0 listens on 9200, node-1 on 9201, ...
# Allow callers to point at a pre-built release binary (production-grade
# smoke under `--features test-low-difficulty,allow-empty-seeds`) by
# exporting BINARY=… before invoking the script.  Default: debug binary
# from a workspace `cargo build`.
BINARY="${BINARY:-${REPO_ROOT}/target/debug/veil-cli}"
# Sovereign name node-0 claims on devnet startup — used by the
# cross-node name-resolve smoke check.
DEVNET_NAME="${DEVNET_NAME:-devnet0}"

# ── Helpers ───────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[devnet] $*"; }

require_binary() {
    if [[ ! -x "$BINARY" ]]; then
        info "Building veil-cli binary..."
        (cd "$REPO_ROOT" && cargo build -q -p veil-cli --bin veil-cli) || die "Build failed"
    fi
}

node_dir()   { echo "${DEVNET_DIR}/node-${1}"; }
config_file(){ echo "$(node_dir "$1")/config.toml"; }
pid_file()   { echo "$(node_dir "$1")/veil.pid"; }
log_file()   { echo "$(node_dir "$1")/veil.log"; }
# The CLI derives the admin socket from the config path by replacing the
# .toml extension with .sock (see handlers.rs default_admin_socket_uri).
admin_sock() { echo "$(node_dir "$1")/config.sock"; }

is_running() {
    local pid_f
    pid_f="$(pid_file "$1")"
    [[ -f "$pid_f" ]] && kill -0 "$(cat "$pid_f")" 2>/dev/null
}

# ── generate_config ───────────────────────────────────────────────────────────

generate_config() {
    local n="$1"
    local dir
    dir="$(node_dir "$n")"
    mkdir -p "$dir"
    # Epic 451 admin-socket security gate: refuse to bind on a parent
    # whose mode lets group/other write without the sticky bit set.
    # Dev runs default to umask 022 (775) → restrict to 700 explicitly.
    chmod 700 "$dir"

    local config
    config="$(config_file "$n")"
    local peer_port=$(( BASE_PEER_PORT + n ))

    # Generate a fresh config with identity + PoW nonce + admin socket.
    # The admin socket path is set automatically to config.sock alongside config.toml.
    # ${DEVNET_POW_DIFFICULTY:-24} lets a caller override default 24-bit PoW
    # for a faster startup (e.g. Phase 6.27 production-build smoke validates
    # adaptive proximity gate, but doesn't need full production PoW work).
    "$BINARY" config init "$config" --difficulty "${DEVNET_POW_DIFFICULTY:-24}" \
        || die "config init failed for node-${n}"

    # Provision a standalone sovereign identity (device key IS master).
    # Without this, the daemon would build a degenerate one on first
    # start, but claim-name needs it to exist BEFORE we sign the
    # name claim — same as a fresh phone install.
    "$BINARY" identity standalone --veil-dir "$dir" --force >/dev/null \
        || die "identity standalone failed for node-${n}"

    # Add a TCP listener on this node's dedicated port.
    "$BINARY" --config "$config" listen add "tcp://127.0.0.1:${peer_port}" \
        || die "listen add failed for node-${n}"

    # Enable the app-IPC socket so SDK clients (oproxy, ogate) can bind app
    # endpoints + open/accept streams. Disabled by default in production
    # (IpcConfig.enabled = false); the devnet enables it for the `throughput`
    # data-plane test (and it is harmless for the control-plane smokes, which
    # only use the admin socket). The app socket lives alongside config.toml.
    cat >> "$config" <<EOF

[ipc]
enabled = true
socket_uri = "unix://${dir}/app.sock"
EOF

    info "Generated config for node-${n} (listener tcp://127.0.0.1:${peer_port}, app-ipc on)"
}

# Path to the app-IPC socket for node N (enabled by generate_config).
app_sock() { echo "$(node_dir "$1")/app.sock"; }

# ── start ─────────────────────────────────────────────────────────────────────

cmd_start() {
    local num_nodes=$DEFAULT_NODES
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --nodes|-n) num_nodes="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    require_binary
    mkdir -p "$DEVNET_DIR"
    chmod 700 "$DEVNET_DIR"

    for n in $(seq 0 $(( num_nodes - 1 ))); do
        generate_config "$n"
    done

    # Wire bidirectional peer knowledge:  node-0 ↔ node-N for each N>0.
    # node-0 acts as the seed; everyone else PEX-walks from there.
    #
    # **Bidirectional is required** under the Phase E20 directional dedup
    # policy (veil-node-runtime/outbound_connector.rs:176):  for pair
    # (A, B), the **smaller-hex** side dials, the larger-hex side waits for
    # inbound.  If only one side knows the peer and that side happens to be
    # the larger-hex one, no connection ever forms (observed node-1's
    # hex `89c2…` > node-0's `29c1…` → node-1 sits in gateway.failover
    # waiting on a dial from node-0, which does not know about node-1).  Adding
    # the peer entry in both directions ensures whichever side has the lower
    # hex is the one that actually dials.
    if (( num_nodes > 1 )); then
        # Capture each node's IDENTITY pubkey + PoW nonce BEFORE any `peers add`
        # mutates a config.  `peers add` appends a `[[peers]]` block carrying its
        # OWN unindented `public_key`/`nonce` fields, which the `/^public_key /`
        # awk would then match in addition to the identity line — yielding a
        # two-line value that fails base64 decode ("Invalid symbol 61, offset
        # 43").  Pre-capturing from pristine configs (and `exit` on first match)
        # keeps each value the single identity key.
        local -a node_pubkeys node_nonces
        for n in $(seq 0 $(( num_nodes - 1 ))); do
            node_pubkeys[n]=$( awk -F'"' '/^public_key /{print $2; exit}' "$(config_file "$n")" )
            node_nonces[n]=$(  awk -F'"' '/^nonce /{print $2; exit}'       "$(config_file "$n")" )
        done
        for n in $(seq 1 $(( num_nodes - 1 ))); do
            # node-N learns node-0 (the seed).
            "$BINARY" --config "$(config_file "$n")" peers add \
                "${node_pubkeys[0]}" "${node_nonces[0]}" "tcp://127.0.0.1:${BASE_PEER_PORT}" \
                >/dev/null \
                || die "peers add failed for node-${n}"
            # node-0 learns node-N (so node-0 can dial out if it's the
            # lower-hex side for this pair — required by the directional
            # dedup policy described above).
            "$BINARY" --config "$(config_file 0)" peers add \
                "${node_pubkeys[n]}" "${node_nonces[n]}" "tcp://127.0.0.1:$(( BASE_PEER_PORT + n ))" \
                >/dev/null \
                || die "peers add failed for node-0 ↔ node-${n}"
            info "node-${n} ↔ node-0: bidirectional peer config wired"
        done
    fi

    # Claim a fixed devnet-test name on node-0 BEFORE the daemon starts.
    # On the daemon's first boot (or any restart) it scans
    # `<veil_dir>/name_claims/*.bin` and publishes each signed
    # NameClaim to its local DHT under
    # `blake3("veil.name_claim_dht.v1" || len_be_u16 || normalized)`.
    # Lets the smoke test verify cross-node sovereign-name resolution
    # without an out-of-band 6-hour republish-tick wait.
    if "$BINARY" identity claim-name "$DEVNET_NAME" --veil-dir "$(node_dir 0)" \
        >/dev/null 2>&1; then
        info "node-0: claimed sovereign name '${DEVNET_NAME}'"
    else
        info "node-0: ⚠ identity claim-name '${DEVNET_NAME}' failed (will skip name-resolve smoke)"
    fi

    for n in $(seq 0 $(( num_nodes - 1 ))); do
        if is_running "$n"; then
            info "node-${n} already running (pid $(cat "$(pid_file "$n")"))"
            continue
        fi
        # Run in the foreground (backgrounded via &) so the process is a direct
        # child of this shell and its PID is reliably captured in $!.
        "$BINARY" --config "$(config_file "$n")" node run --foreground \
            >"$(log_file "$n")" 2>&1 &
        echo $! > "$(pid_file "$n")"
        info "Started node-${n} (pid $!)"
    done

    info "Devnet started (${num_nodes} nodes). Run 'devnet.sh status' to check."
}

# ── stop ──────────────────────────────────────────────────────────────────────

cmd_stop() {
    if [[ ! -d "$DEVNET_DIR" ]]; then
        info "No devnet directory found at ${DEVNET_DIR}"
        return
    fi
    local stopped=0
    for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
        [[ -f "$pid_f" ]] || continue
        local pid
        pid="$(cat "$pid_f")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            info "Stopped pid ${pid}"
            (( stopped++ )) || true
        fi
        rm -f "$pid_f"
    done
    [[ $stopped -gt 0 ]] && info "Stopped ${stopped} node(s)." || info "No running nodes found."
}

# ── status ────────────────────────────────────────────────────────────────────

cmd_status() {
    if [[ ! -d "$DEVNET_DIR" ]]; then
        info "No devnet directory found."; return
    fi
    local running=0
    for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
        [[ -f "$pid_f" ]] || continue
        local node pid
        node="$(basename "$(dirname "$pid_f")")"
        pid="$(cat "$pid_f")"
        if kill -0 "$pid" 2>/dev/null; then
            info "${node}: running (pid ${pid})"
            (( running++ )) || true
        else
            info "${node}: STOPPED (stale pid ${pid})"
        fi
    done
    [[ $running -eq 0 ]] && info "No nodes running."
}

# ── logs ──────────────────────────────────────────────────────────────────────

cmd_logs() {
    local n="${1:-0}"
    local log
    log="$(log_file "$n")"
    [[ -f "$log" ]] || die "No log file for node-${n} at ${log}"
    tail -f "$log"
}

# ── smoke ─────────────────────────────────────────────────────────────────────

cmd_smoke() {
    info "Running smoke test..."

    # Check that at least node-0 is running.
    is_running 0 || die "node-0 is not running. Start the devnet first with: devnet.sh start"

    local admin0
    admin0="$(admin_sock 0)"
    # Nodes bind their admin socket a short time after process start — the
    # config.sock file may not exist immediately even once $!/pid is set.
    # Poll for up to 30s instead of failing on the first miss.  This matches
    # the retry window we use below for each node's `admin show`, so slow
    # CI runners (GitHub's shared ubuntu-latest) don't flake.
    local waited=0
    while [[ ! -S "$admin0" && $waited -lt 30 ]]; do
        sleep 1
        waited=$(( waited + 1 ))
    done
    [[ -S "$admin0" ]] || die "Admin socket not found after ${waited}s: ${admin0}"

    # Query the admin API to verify node-0 is healthy.
    local result
    result="$("$BINARY" --config "$(config_file 0)" node show 2>&1)" \
        || die "Admin query failed: ${result}"
    info "node-0 responded to admin query."

    # Check all configured nodes are reachable.  Retry up to 90s per node so
    # a node whose admin socket came up slightly later doesn't flake the
    # test — observed 30s+ to first-`node show`-success on GitHub
    # ubuntu-latest under debug-mode PoW init (audit 2026-05-27 phase Q.4).
    local ok=0 fail=0
    for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
        [[ -f "$pid_f" ]] || continue
        local node n
        node="$(basename "$(dirname "$pid_f")")"
        n="${node#node-}"
        local attempt=0
        local reachable=0
        while [[ $attempt -lt 90 ]]; do
            if "$BINARY" --config "$(config_file "$n")" node show >/dev/null 2>&1; then
                reachable=1
                break
            fi
            sleep 1
            attempt=$(( attempt + 1 ))
        done
        if [[ $reachable -eq 1 ]]; then
            info "  ${node}: OK"
            (( ok++ )) || true
        else
            info "  ${node}: FAIL (after ${attempt}s)"
            (( fail++ )) || true
        fi
    done

    # Short-circuit: if any node is unreachable, downstream topology /
    # DHT / identity / name-resolve checks would all try to talk to the
    # dead node and spam the log with pipeline failures.  Surface the actual
    # root cause now instead of cascading.
    if (( fail > 0 )); then
        local total=$(( ok + fail ))
        die "Smoke test FAILED: ${fail}/${total} node(s) unreachable; aborting topology+DHT checks."
    fi

    # ── Topology check (Epic devnet smoke +): each non-zero node should
    # have ≥1 active session (its bootstrap to node-0); node-0 itself
    # should have ≥(num_nodes-1) inbound sessions.  This catches the
    # bootstrap-wired-but-handshake-broken regression that the simple
    # "admin responds" check above cannot.
    #
    # Poll up to 90s for sessions to come up — bootstrap + handshake on
    # cold GitHub runners can take 30-60s even under `--test-low-difficulty`
    # (observed sessions_active=0 after a 30s poll even when the DHT local
    # round-trip already works, audit 2026-05-27 phase Q.5).  Bumped from 30s
    # because debug-mode handshakes plus shared-CPU jitter push the
    # convergence window past one minute on ubuntu-latest.
    info "Topology check (sessions_active across nodes):"
    local topology_ok=0
    local topo_attempt=0
    # Read sessions_active without letting a failing `node show` (dead node)
    # propagate out of the pipeline and trigger `set -euo pipefail`.  The
    # `if ... ; then ... else echo 0` pattern keeps the function exit
    # code 0 even when the binary itself returns non-zero (e.g. admin
    # socket gone, node crashed).
    read_sessions_active() {
        local cfg="$1"
        local out
        if out=$("$BINARY" --config "$cfg" node show 2>/dev/null); then
            local n
            n=$(printf "%s" "$out" | awk -F': ' '/^sessions_active/{print $2}')
            printf "%s" "${n:-0}"
        else
            printf "0"
        fi
    }
    while [[ $topo_attempt -lt 90 ]]; do
        topology_ok=1
        local pending_log=""
        for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
            [[ -f "$pid_f" ]] || continue
            local node n
            node="$(basename "$(dirname "$pid_f")")"
            n="${node#node-}"
            local sessions
            sessions=$(read_sessions_active "$(config_file "$n")")
            pending_log+="  ${node}: sessions_active=${sessions}\n"
            if [[ "$n" == "0" ]]; then
                if (( sessions < ok - 1 )); then
                    pending_log+="    (node-0 needs ≥$(( ok - 1 )) inbound sessions)\n"
                    topology_ok=0
                fi
            else
                if (( sessions < 1 )); then
                    pending_log+="    (${node} bootstrap to node-0 not yet handshaked)\n"
                    topology_ok=0
                fi
            fi
        done
        if [[ $topology_ok -eq 1 ]]; then
            printf "%b" "$pending_log"
            break
        fi
        sleep 1
        topo_attempt=$(( topo_attempt + 1 ))
    done
    if [[ $topology_ok -eq 0 ]]; then
        info "Topology not healthy after ${topo_attempt}s:"
        for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
            [[ -f "$pid_f" ]] || continue
            local node n
            node="$(basename "$(dirname "$pid_f")")"
            n="${node#node-}"
            local sessions
            sessions=$(read_sessions_active "$(config_file "$n")")
            info "  ${node}: sessions_active=${sessions}"
        done
    fi

    # ── DHT round-trip check: put a pseudo-random key/value on node-0,
    # confirm the LOCAL store on node-0 reads it back.  (Cross-node
    # recursive lookup is not exposed via the admin CLI; admin `node dht
    # get` is local-only by design.  A future smoke step will exercise
    # cross-node lookup via an IPC client once one is bundled.)
    info "DHT local round-trip check on node-0:"
    local rand_key rand_val
    rand_key=$(openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | xxd -p -c 64)
    rand_val=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 32)
    "$BINARY" --config "$(config_file 0)" node dht put "$rand_key" "$rand_val" >/dev/null 2>&1 \
        || { info "  ⚠ node-0 dht put failed"; topology_ok=0; }
    local dht_value
    dht_value=$("$BINARY" --config "$(config_file 0)" node dht get "$rand_key" 2>/dev/null \
        | awk '/^value:/{print $2}')
    if [[ "$dht_value" == "$rand_val" ]]; then
        info "  node-0 dht round-trip: OK (value matches)"
    else
        info "  ⚠ node-0 dht round-trip: FAIL (got=${dht_value} expected=${rand_val})"
        topology_ok=0
    fi

    # ── Cross-node DHT recursive lookup smoke (Epic devnet smoke +): the
    # last node in the topology asks `node dht recursive-get` for the key
    # we just stored on node-0.  This validates the FIND_VALUE recursive
    # query path end-to-end across processes — the responder-proximity
    # gate is relaxed under `test-low-difficulty`, so a random-key smoke
    # actually completes (production builds keep the 16-bit prefix gate).
    if (( ok > 1 )); then
        local last_n=$(( ok - 1 ))
        info "Cross-node DHT recursive-get smoke (node-${last_n} → node-0):"
        local rec_value
        rec_value=$("$BINARY" --config "$(config_file "$last_n")" node dht recursive-get \
            "$rand_key" --timeout-ms 5000 2>/dev/null \
            | awk '/^value:/{print $2}')
        if [[ "$rec_value" == "$rand_val" ]]; then
            info "  node-${last_n} recursive-get: OK (value matches the put on node-0)"
        else
            info "  ⚠ node-${last_n} recursive-get: FAIL (got=${rec_value} expected=${rand_val})"
            topology_ok=0
        fi

        # ── Cross-node IdentityDocument resolve smoke (Epic 490) ──────────
        # node-0 publishes its signed IdentityDocument to its local DHT
        # at startup (see veilcore::node::identity::publisher_dht).
        # From node-${last_n}, run the **verified** resolve verb — this
        # walks the recursive DHT, decodes IdentityDocument, and runs the
        # full crypto chain (master sig, expiry, sig_key_idx bounds,
        # node_id ↔ master_pubkey binding, substitution check).  Distinct
        # from the older `node dht recursive-get` smoke that asserted
        # only payload length and would happily accept a forged blob.
        info "Cross-node identity resolve smoke (node-${last_n} → node-0):"
        # Read node-0's *sovereign* node_id (from the standalone identity
        # we provisioned, NOT the network-PoW identity in `[Identity]`
        # config that `node show` reports — those are intentionally
        # distinct in the protocol).  Grep the daemon's startup log.
        local n0_node_id
        n0_node_id=$(grep -oE 'node.sovereign_identity.published node_id=[a-f0-9]{64}' \
            "$(log_file 0)" 2>/dev/null \
            | head -1 \
            | awk -F'node_id=' '{print $2}')
        if [[ -z "$n0_node_id" ]]; then
            info "  ⚠ could not read node-0 node_id from `node show`"
            topology_ok=0
        else
            local resolve_id_out
            # `|| true`: under `set -euo pipefail` a non-zero exit from the
            # command substitution would abort the whole smoke BEFORE the
            # graceful FAIL branch below — capture the failure instead.
            resolve_id_out=$("$BINARY" --config "$(config_file "$last_n")" \
                node resolve-identity "$n0_node_id" --timeout-ms 5000 \
                2>&1 || true)
            if echo "$resolve_id_out" | grep -q "resolved + verified" \
               && echo "$resolve_id_out" | grep -qF "node_id: $n0_node_id"; then
                info "  node-${last_n} identity-resolve: OK (signature chain verified for $n0_node_id)"
            else
                info "  ⚠ node-${last_n} identity-resolve: FAIL"
                info "    output: $(echo "$resolve_id_out" | head -3)"
                topology_ok=0
            fi
        fi

        # ── Cross-node sovereign-name resolve smoke (Epic 490) ────────────
        # node-0 had `identity claim-name $DEVNET_NAME` baked in before
        # boot.  From node-${last_n}, run the **verified** name-resolve
        # verb — this walks NameClaim → IdentityDocument and asserts
        # PoW difficulty, freshness-hour skew, signature against the
        # active subkey, AND that the resolved node_id matches what the
        # name binding promised.  Closes the entire @name → identity
        # security path the network actually relies on.
        info "Cross-node name resolve smoke (node-${last_n} → node-0, name='${DEVNET_NAME}'):"
        # NON-FATAL (best-effort). A NameClaim is NON-self-certifying (a forged
        # self-consistent claim passes any crypto self-check), so the resolver
        # requires a ≥2-replica anti-sybil quorum (cycle-9 hardening:
        # `allow_single_replica = false`). This devnet is a STAR — each leaf is
        # wired only to node-0 (the seed) — so a leaf reaches exactly ONE
        # replica-holder for a name it did not publish and CANNOT satisfy the
        # quorum, unlike resolve-identity above (an IdentityDocument is
        # self-certifying → a single replica is accepted). That is a topology
        # limitation of the 3-node star, NOT a resolver regression: the
        # quorum → @name → identity path is gated by the sim test
        # `epic490_resolve_name_verified_round_trip`. Retry a few times (so a
        # fuller topology / completed replication still PASSES this check), then
        # WARN — do not fail the smoke. `|| true` keeps `set -e` from aborting.
        local resolve_name_out="" rn_try
        for rn_try in 1 2 3; do
            resolve_name_out=$("$BINARY" --config "$(config_file "$last_n")" \
                node resolve-name "$DEVNET_NAME" --timeout-ms 5000 2>&1 || true)
            echo "$resolve_name_out" | grep -q "resolved + verified" && break
            sleep 2
        done
        if echo "$resolve_name_out" | grep -q "resolved + verified"; then
            info "  node-${last_n} name-resolve: OK (full crypto chain verified for @${DEVNET_NAME})"
        else
            info "  ⚠ node-${last_n} name-resolve: best-effort FAIL (3-node star can't meet the"
            info "    ≥2-replica anti-sybil quorum from a leaf) — NOT fatal; quorum path is"
            info "    covered by sim test epic490_resolve_name_verified_round_trip."
            info "    output: $(echo "$resolve_name_out" | grep -ivE '^progress' | head -2 | tr '\n' ' ')"
        fi
    fi

    if [[ $fail -eq 0 && $topology_ok -eq 1 ]]; then
        info "Smoke test PASSED (${ok} nodes healthy, topology connected, DHT round-trip OK)."
    elif [[ $fail -gt 0 ]]; then
        die "Smoke test FAILED: ${fail} node(s) unreachable."
    else
        die "Smoke test FAILED: topology / DHT check failed (${ok} nodes responsive but not all linked)."
    fi
}

# ── replication-smoke ────────────────────────────────────────────────────────
#
# Epic 489.2 cross-node smoke: prove that K-closest replication on PUT works
# by killing the publisher and resolving from another peer.  Flow:
#   1. Read node-0's sovereign node_id from its log (log-grep, same as
#      the main smoke).
#   2. Touch node-0's identity_document.bin so the on-change republish
#      tick fires (`SOVEREIGN_ON_CHANGE_POLL_INTERVAL` = 2 s under
#      test-low-difficulty), forcing the daemon to fan IdentityDocument
#      out to K-closest replicas via with_replication publisher.
#   3. Wait ~5 s for the tick to propagate STORE messages.
#   4. STOP node-0.
#   5. Recursive-get N0's identity dht_key from the LAST node — must
#      come back from a replica (N1 or peer) since N0 is offline.
cmd_replication_smoke() {
    is_running 0 || die "node-0 is not running. Start the devnet first."
    info "Replication smoke: K-closest replication on PUT (Epic 489.2)..."

    local n0_node_id n0_identity_key last_n
    n0_node_id=$(grep -oE 'node.sovereign_identity.published node_id=[a-f0-9]{64}' \
        "$(log_file 0)" 2>/dev/null \
        | head -1 \
        | awk -F'node_id=' '{print $2}')
    [[ -n "$n0_node_id" ]] || die "could not read node-0 sovereign node_id"
    n0_identity_key=$("$BINARY" identity dht-key "$n0_node_id" 2>/dev/null | head -1)
    [[ -n "$n0_identity_key" ]] || die "could not compute identity dht-key for node-0"

    # Find the last live node.
    local count=0
    for pid_f in "${DEVNET_DIR}"/node-*/veil.pid; do
        [[ -f "$pid_f" ]] || continue
        ((count++)) || true
    done
    last_n=$(( count - 1 ))
    (( last_n > 0 )) || die "need ≥2 nodes for replication smoke"

    info "  Touching node-0 identity_document.bin to force on-change republish tick..."
    touch "$(node_dir 0)/identity_document.bin"
    info "  Waiting 5 s for STORE replication to fan out to K-closest peers..."
    sleep 5

    info "  Stopping node-0 to take its local DHT shard offline..."
    local n0_pid
    n0_pid="$(cat "$(pid_file 0)")"
    if kill -0 "$n0_pid" 2>/dev/null; then
        kill "$n0_pid"
        # Wait up to 10 s for the process to actually exit.
        local waited=0
        while kill -0 "$n0_pid" 2>/dev/null && (( waited < 10 )); do
            sleep 1
            ((waited++)) || true
        done
        rm -f "$(pid_file 0)"
        info "  node-0 stopped."
    fi
    sleep 1

    info "  Resolving node-0's IdentityDocument from node-${last_n} (N0 OFFLINE)..."
    # Epic 490: use the verified resolve verb instead of raw recursive-get
    # — proves the replica's bytes pass the full crypto chain too, not
    # just that some bytes came back.
    local resolve_out
    resolve_out=$("$BINARY" --config "$(config_file "$last_n")" \
        node resolve-identity "$n0_node_id" --timeout-ms 10000 \
        2>&1)
    if echo "$resolve_out" | grep -q "resolved + verified" \
       && echo "$resolve_out" | grep -qF "node_id: $n0_node_id"; then
        info "  ✅ node-${last_n} resolved + verified node-0's IdentityDocument FROM A REPLICA — N0 is offline"
        info "Replication smoke PASSED (Epic 489.2 K-closest replication + Epic 490 verified resolve work end-to-end)."
    else
        die "Replication smoke FAILED: node-${last_n} could not verify-resolve node-0's IdentityDocument with N0 offline (output: $resolve_out)"
    fi
}

# ── throughput ────────────────────────────────────────────────────────────────
#
# Data-plane throughput test: bring up an `ogate` TUN bridge on node-0 and
# node-1 so the two nodes share a virtual /24 (10.99.0.1 ↔ 10.99.0.2) over the
# veil, then run iperf3 across it. This exercises the REAL cross-node stream
# data-plane (veil app-streams via VeilConnector) end-to-end — the path
# that previously had no integration test.
#
# Topology:
#   iperf3 -s  ←TUN(10.99.0.1)← veil app-stream ←TUN(10.99.0.2)← iperf3 -c
#       node-0 + `ogate up`                              node-1 + `ogate up`
#
# REQUIRES ROOT: TUN device creation (utun on macOS, /dev/net/tun on Linux)
# needs root. Run as:  sudo scripts/devnet.sh throughput
# (Start the devnet FIRST as your normal user: scripts/devnet.sh start --nodes 2)
#
# REQUIRES iperf3 (resolved by absolute path, since `sudo` on macOS resets PATH
# to /usr/bin:/bin:/usr/sbin:/sbin and drops /opt/homebrew/bin).
cmd_throughput() {
    [[ "$(id -u)" -eq 0 ]] || die "throughput needs root for TUN. Run: sudo $0 throughput  (after: $0 start --nodes 2)"

    # Resolve iperf3 by absolute path: under `sudo` the homebrew/local bindir is
    # not on PATH, so a bare `command -v iperf3` fails even when it is installed.
    # Honour an explicit IPERF3 override, then probe the common locations.
    local iperf3_bin="${IPERF3:-}"
    if [[ -z "$iperf3_bin" ]]; then
        for cand in /opt/homebrew/bin/iperf3 /usr/local/bin/iperf3 /usr/bin/iperf3 "$(command -v iperf3 2>/dev/null || true)"; do
            [[ -n "$cand" && -x "$cand" ]] && { iperf3_bin="$cand"; break; }
        done
    fi
    [[ -n "$iperf3_bin" && -x "$iperf3_bin" ]] \
        || die "iperf3 not found (looked in /opt/homebrew/bin, /usr/local/bin, /usr/bin). Install it or pass IPERF3=/path: sudo IPERF3=\$(command -v iperf3) $0 throughput"
    info "Using iperf3: $iperf3_bin"

    local ogate_bin="${REPO_ROOT}/target/debug/ogate"
    if [[ ! -x "$ogate_bin" ]]; then
        info "Building ogate…"
        ( cd "$REPO_ROOT" && cargo build -p ogate --bin ogate ) || die "ogate build failed"
    fi

    # Both nodes must be running with app-IPC enabled (generate_config does this).
    for n in 0 1; do
        [[ -S "$(app_sock "$n")" ]] || die "node-${n} app socket missing ($(app_sock "$n")). Run '$0 start --nodes 2' first (as your normal user)."
    done

    # node_ids for the peer tables.
    local nid0 nid1
    nid0="$("$BINARY" --config "$(config_file 0)" node show 2>/dev/null | awk '/^node_id:/{print $2}')"
    nid1="$("$BINARY" --config "$(config_file 1)" node show 2>/dev/null | awk '/^node_id:/{print $2}')"
    [[ -n "$nid0" && -n "$nid1" ]] || die "could not read node_ids via 'node show'"
    info "node-0 id=${nid0:0:16}…  node-1 id=${nid1:0:16}…"

    # ── write ogate configs (node-0 ↔ node-1) ──────────────────────────────
    local og0="${DEVNET_DIR}/ogate-0.toml" og1="${DEVNET_DIR}/ogate-1.toml"
    write_ogate_config 0 "$og0" "$(app_sock 0)" "ogate-d0" "10.99.0.1" "$nid1" "10.99.0.2"
    write_ogate_config 1 "$og1" "$(app_sock 1)" "ogate-d1" "10.99.0.2" "$nid0" "10.99.0.1"
    chmod 600 "$og0" "$og1"

    # ── bring up both TUN bridges ───────────────────────────────────────────
    info "Bringing up ogate TUN bridges (needs root)…"
    "$ogate_bin" up --config "$og0" >"${DEVNET_DIR}/ogate-0.log" 2>&1 &
    local og0_pid=$!
    "$ogate_bin" up --config "$og1" >"${DEVNET_DIR}/ogate-1.log" 2>&1 &
    local og1_pid=$!

    # RAII-ish cleanup: always tear the bridges down on exit.
    # shellcheck disable=SC2064
    trap "kill ${og0_pid} ${og1_pid} 2>/dev/null; wait ${og0_pid} ${og1_pid} 2>/dev/null" EXIT

    # Wait for both TUN ifaces to be up + the veil app-stream to settle.
    info "Waiting for bridges to settle (≤15s)…"
    local up0=0 up1=0 waited=0
    while (( waited < 15 )); do
        kill -0 "$og0_pid" 2>/dev/null || { info "node-0 ogate exited early — see ${DEVNET_DIR}/ogate-0.log"; sed -n '1,20p' "${DEVNET_DIR}/ogate-0.log"; die "ogate-0 failed"; }
        kill -0 "$og1_pid" 2>/dev/null || { info "node-1 ogate exited early — see ${DEVNET_DIR}/ogate-1.log"; sed -n '1,20p' "${DEVNET_DIR}/ogate-1.log"; die "ogate-1 failed"; }
        grep -qiE "bridge up|tun .* up|interface ready|listening" "${DEVNET_DIR}/ogate-0.log" 2>/dev/null && up0=1
        grep -qiE "bridge up|tun .* up|interface ready|listening" "${DEVNET_DIR}/ogate-1.log" 2>/dev/null && up1=1
        (( up0 && up1 )) && break
        sleep 1; waited=$(( waited + 1 ))
    done

    # ── probe veil reachability across the TUN, then iperf3 ──────────────
    info "Pinging 10.99.0.1 from the virtual LAN…"
    if ping -c 3 -t 5 10.99.0.1 >/dev/null 2>&1; then
        info "  veil TUN ping OK"
    else
        info "  ⚠ ping did not return (continuing to iperf3 anyway; some setups block ICMP)"
    fi

    info "Starting iperf3 server behind node-0's TUN (10.99.0.1)…"
    "$iperf3_bin" -s -1 -B 10.99.0.1 >"${DEVNET_DIR}/iperf3-server.log" 2>&1 &
    local iperf_srv_pid=$!
    sleep 1

    info "Running iperf3 client → 10.99.0.1 (10s)…"
    if "$iperf3_bin" -c 10.99.0.1 -t 10 -i 1 2>&1 | tee "${DEVNET_DIR}/iperf3-client.log"; then
        info "Throughput test PASSED — see summary above (veil app-stream data-plane via ogate TUN)."
    else
        kill "$iperf_srv_pid" 2>/dev/null
        info "iperf3 server log:"; sed -n '1,20p' "${DEVNET_DIR}/iperf3-server.log"
        die "iperf3 client failed — veil data-plane did not carry TCP across the TUN"
    fi
    kill "$iperf_srv_pid" 2>/dev/null
    # bridges torn down by the EXIT trap.
}

# write_ogate_config <n> <out> <socket> <iface> <local_v4> <peer_nid> <peer_v4>
write_ogate_config() {
    local out="$2" socket="$3" iface="$4" local_v4="$5" peer_nid="$6" peer_v4="$7"
    cat > "$out" <<EOF
# devnet throughput test — ogate bridge config (generated by devnet.sh)
network       = "devnet-iperf"
app           = "ogate"
mode          = "authorized"
socket_path   = "${socket}"
endpoint_id   = 0
iface_name    = "${iface}"
mtu           = 1280
local_addr_v4 = "${local_v4}"
prefix_v4     = 24

[[peers]]
node_id = "${peer_nid}"
addr_v4 = "${peer_v4}"
EOF
}

# ── dispatch ──────────────────────────────────────────────────────────────────

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    start)  cmd_start "$@" ;;
    stop)   cmd_stop "$@" ;;
    status) cmd_status "$@" ;;
    logs)   cmd_logs "$@" ;;
    smoke)  cmd_smoke "$@" ;;
    throughput) cmd_throughput "$@" ;;
    replication-smoke) cmd_replication_smoke "$@" ;;
    help|--help|-h)
        grep '^#' "$0" | sed 's/^# \{0,2\}//' | head -12
        ;;
    *)
        die "Unknown command: ${COMMAND}. Use: start | stop | status | logs | smoke | replication-smoke | throughput"
        ;;
esac
