#!/usr/bin/env bash
# test-hot-standby.sh — Epic 459 hot-standby transport swap verification.
#
# Usage:
#   test-hot-standby.sh run      Build, start 2 nodes, run all verifications, stop.
#   test-hot-standby.sh start    Just bring up the two-node fixture.
#   test-hot-standby.sh stop     Tear down the fixture.
#   test-hot-standby.sh verify   Run verifications against an already-running fixture.
#   test-hot-standby.sh logs N   Tail node N's log (0 or 1).
#
# ── What this script proves (today, stage (a) only) ───────────────────────────
#   1. The SessionRunner swap-point mechanism is correct in isolation
#      (via `cargo test swap_` — unit tests using tokio::io::duplex
#      streams with real SessionCipher).
#   2. Adding the swap infrastructure did not break the normal session
#      path on a real two-node devnet (TLS / WSS listeners bound, OVL1
#      handshake completes, frames flow).
#
# ── What is not yet testable ──────────────────────────────────────────────────
#   End-to-end swap against a running peer requires Epic 459 follow-ups:
#     (b) warm-probe task that pre-opens the alternate transport,
#     (c) trigger logic / admin command that pushes the warm stream into
#         the runner's `swap_rx`,
#     (d) wire-format `HandoffInit` / `HandoffAck` frames so both sides
#         swap synchronously (today the peer has no way to recognise a
#         bare socket as the continuation of an existing session).
#   Once (b)+(c)+(d) land, this script grows a `swap` phase that invokes
#   the admin command and asserts `session_id` is stable across the swap
#   and a post-swap chat message round-trips on the NEW transport.
#
# See: docs/hot-standby.md, docs/hot-standby-test-plan-windows.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURE_DIR="${HS_FIXTURE_DIR:-/tmp/veil-hot-standby}"
BINARY="${REPO_ROOT}/target/debug/veil-cli"

# Two nodes, each with two TCP listeners on distinct ports.
# Scheme is TCP for both — the point of the fixture is to have two
# reachable transport endpoints per peer.  Real-world swap crosses
# schemes (e.g. tls → wss); that uses the same swap mechanism.
NODE_A_TRANSPORT_1_PORT=9310
NODE_A_TRANSPORT_2_PORT=9311
NODE_B_TRANSPORT_1_PORT=9320
NODE_B_TRANSPORT_2_PORT=9321

# ── Helpers ───────────────────────────────────────────────────────────────────

c_red()    { printf '\033[1;31m%s\033[0m' "$*"; }
c_green()  { printf '\033[1;32m%s\033[0m' "$*"; }
c_yellow() { printf '\033[1;33m%s\033[0m' "$*"; }
c_blue()   { printf '\033[1;36m%s\033[0m' "$*"; }

info()  { echo "$(c_blue '[hot-standby]') $*"; }
pass()  { echo "  $(c_green '✓') $*"; }
fail()  { echo "  $(c_red   '✗') $*" >&2; }
warn()  { echo "  $(c_yellow '!') $*"; }
die()   { fail "$*"; exit 1; }

node_dir()    { echo "${FIXTURE_DIR}/node-${1}"; }
config_file() { echo "$(node_dir "$1")/config.toml"; }
pid_file()    { echo "$(node_dir "$1")/veil.pid"; }
log_file()    { echo "$(node_dir "$1")/veil.log"; }

node_ports() {
    case "$1" in
        0|A|a) echo "${NODE_A_TRANSPORT_1_PORT} ${NODE_A_TRANSPORT_2_PORT}" ;;
        1|B|b) echo "${NODE_B_TRANSPORT_1_PORT} ${NODE_B_TRANSPORT_2_PORT}" ;;
        *)     die "unknown node index: $1" ;;
    esac
}

is_running() {
    local pf; pf="$(pid_file "$1")"
    [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

require_binary() {
    if [[ ! -x "$BINARY" ]]; then
        info "building veil-cli"
        (cd "$REPO_ROOT" && cargo build -q -p veilcore --bin veil-cli) \
            || die "build failed"
    fi
}

# ── generate_config ───────────────────────────────────────────────────────────
#
# Creates a fresh config for node N with identity + 2 TCP listeners.  Peer
# wiring is patched in afterwards by `wire_peers` once both configs exist
# and the node_ids are known.

generate_config() {
    local n="$1"
    local dir; dir="$(node_dir "$n")"
    mkdir -p "$dir"

    local cfg; cfg="$(config_file "$n")"
    local ports; ports="$(node_ports "$n")"
    local p1 p2; read -r p1 p2 <<< "$ports"

    if [[ -f "$cfg" ]]; then
        info "reusing existing config for node-${n}"
        return
    fi

    # Runtime config validator locks identity PoW at difficulty=24 — the
    # `veil-cli node run` startup path rejects weaker identities with
    # `identity.nonce: must produce at least 24 leading zero bits`, so we
    # cannot reduce this knob for the fixture.  First-run cost is minutes
    # per `config init`; subsequent runs reuse the cached config above.
    info "minting identity for node-${n} (PoW=24, may take several minutes on first run)"
    "$BINARY" config init "$cfg" >/dev/null \
        || die "config init failed for node-${n}"
    # Primary transport.
    "$BINARY" --config "$cfg" listen add "tcp://127.0.0.1:${p1}" >/dev/null \
        --advertise "tcp://127.0.0.1:${p1}" \
        || die "listen add (primary) failed for node-${n}"
    # Alternate transport (the "warm standby" target for Epic 459 b/c/d).
    "$BINARY" --config "$cfg" listen add "tcp://127.0.0.1:${p2}" >/dev/null \
        --advertise "tcp://127.0.0.1:${p2}" \
        || die "listen add (alternate) failed for node-${n}"

    info "generated node-${n} config (transports tcp://127.0.0.1:${p1}, tcp://127.0.0.1:${p2})"
}

# ── identity_triplet ──────────────────────────────────────────────────────────
#
# Extracts (node_id, public_key, nonce) from a config.  We read them directly
# from the [Identity] / [identity] section of config.toml — same pattern the
# ansible entrypoint uses to print bootstrap snippets.

identity_triplet() {
    local cfg="$1"
    local pk; pk="$(sed -n '/^\[[Ii]dentity\]/,$ p' "$cfg" \
        | sed -nE 's/^\s*public_key\s*=\s*"([^"]*)".*/\1/p' | head -1)"
    local nonce; nonce="$(sed -n '/^\[[Ii]dentity\]/,$ p' "$cfg" \
        | sed -nE 's/^\s*nonce\s*=\s*"([^"]*)".*/\1/p' | head -1)"
    local nid; nid="$(sed -n '/^\[[Ii]dentity\]/,$ p' "$cfg" \
        | sed -nE 's/^\s*node_id\s*=\s*"([^"]*)".*/\1/p' | head -1)"
    echo "${nid}|${pk}|${nonce}"
}

# ── wire_peers ────────────────────────────────────────────────────────────────
#
# Appends [[bootstrap_peers]] entries to each node's config so they know how
# to reach each other on the PRIMARY transport.  The alternate port is left
# un-advertised-as-bootstrap — real stage-(b) warm-probe will discover it
# via PEX.  For this fixture we point only at the primary so we can later
# observe "session established on port PRIMARY" unambiguously.

wire_peers() {
    local cfg_a cfg_b
    cfg_a="$(config_file 0)"; cfg_b="$(config_file 1)"

    local id_a id_b; id_a="$(identity_triplet "$cfg_a")"; id_b="$(identity_triplet "$cfg_b")"
    local _nid_a pk_a nonce_a; IFS='|' read -r _nid_a pk_a nonce_a <<< "$id_a"
    local _nid_b pk_b nonce_b; IFS='|' read -r _nid_b pk_b nonce_b <<< "$id_b"

    [[ -n "$pk_a" && -n "$pk_b" ]] \
        || die "could not parse public_key from configs — regenerate via 'stop + start'"

    # Idempotent: only append if there isn't already a [[bootstrap_peers]]
    # block that mentions the other node's pubkey.
    if ! grep -qF "public_key = \"${pk_b}\"" "$cfg_a"; then
        cat >> "$cfg_a" <<EOF

[[bootstrap_peers]]
transport  = "tcp://127.0.0.1:${NODE_B_TRANSPORT_1_PORT}"
public_key = "${pk_b}"
nonce      = "${nonce_b}"
algo       = "ed25519"
EOF
        info "wired node-0 → node-1 (tcp://127.0.0.1:${NODE_B_TRANSPORT_1_PORT})"
    fi
    if ! grep -qF "public_key = \"${pk_a}\"" "$cfg_b"; then
        cat >> "$cfg_b" <<EOF

[[bootstrap_peers]]
transport  = "tcp://127.0.0.1:${NODE_A_TRANSPORT_1_PORT}"
public_key = "${pk_a}"
nonce      = "${nonce_a}"
algo       = "ed25519"
EOF
        info "wired node-1 → node-0 (tcp://127.0.0.1:${NODE_A_TRANSPORT_1_PORT})"
    fi
}

# ── cmd_start ─────────────────────────────────────────────────────────────────

cmd_start() {
    require_binary
    mkdir -p "$FIXTURE_DIR"

    generate_config 0
    generate_config 1
    wire_peers

    for n in 0 1; do
        if is_running "$n"; then
            info "node-${n} already running (pid $(cat "$(pid_file "$n")"))"
            continue
        fi
        "$BINARY" --config "$(config_file "$n")" node run --foreground \
            >"$(log_file "$n")" 2>&1 &
        echo $! > "$(pid_file "$n")"
        info "started node-${n} (pid $!)"
    done

    # Wait for sessions to form.  With two bootstrap peers directly wired to
    # each other, both outbound connectors race to the same OVL1 handshake;
    # one wins, the other closes.  `sessions_active` should reach 1 on each
    # side within a few seconds of admin-socket being bound.  60s budget
    # covers slow dev boxes and lets the admin socket come up first.
    info "waiting for session to establish (up to 60s)…"
    local waited=0
    while [[ $waited -lt 60 ]]; do
        local a b
        a="$("$BINARY" --config "$(config_file 0)" node show 2>/dev/null \
            | sed -nE 's/^sessions_active:\s*([0-9]+)$/\1/p')" || a=""
        b="$("$BINARY" --config "$(config_file 1)" node show 2>/dev/null \
            | sed -nE 's/^sessions_active:\s*([0-9]+)$/\1/p')" || b=""
        if [[ "${a:-0}" -ge 1 && "${b:-0}" -ge 1 ]]; then
            info "session established (node-0=${a}, node-1=${b})"
            return 0
        fi
        sleep 1
        waited=$(( waited + 1 ))
    done
    die "session did not establish within 60s (see logs via: $0 logs 0|1)"
}

# ── cmd_stop ──────────────────────────────────────────────────────────────────

cmd_stop() {
    local stopped=0
    if [[ -d "$FIXTURE_DIR" ]]; then
        for pf in "$FIXTURE_DIR"/node-*/veil.pid; do
            [[ -f "$pf" ]] || continue
            local pid; pid="$(cat "$pf")"
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" && info "stopped pid ${pid}"
                (( stopped++ )) || true
            fi
            rm -f "$pf"
        done
    fi
    [[ $stopped -eq 0 ]] && info "no running nodes found"
}

# ── cmd_logs ──────────────────────────────────────────────────────────────────

cmd_logs() {
    local n="${1:-0}"
    local f; f="$(log_file "$n")"
    [[ -f "$f" ]] || die "no log file: ${f}"
    tail -f "$f"
}

# ── verify_phase ──────────────────────────────────────────────────────────────

VERIFY_FAILED=0
record_fail() { VERIFY_FAILED=$(( VERIFY_FAILED + 1 )); fail "$@"; }

phase_session_health() {
    info "── phase 1: session health ──────────────────────────────────────"
    for n in 0 1; do
        is_running "$n" || { record_fail "node-${n} is not running"; continue; }
        local out; out="$("$BINARY" --config "$(config_file "$n")" node show 2>&1)" \
            || { record_fail "admin query failed for node-${n}: ${out}"; continue; }
        local sessions listens
        sessions="$(echo "$out" | sed -nE 's/^sessions_active:\s*([0-9]+)$/\1/p')"
        listens="$(echo   "$out" | sed -nE 's/^listens_active:\s*([0-9]+)$/\1/p')"
        if [[ "${sessions:-0}" -ge 1 ]]; then
            pass "node-${n}: ${sessions} session(s), ${listens} listener(s)"
        else
            record_fail "node-${n}: 0 active sessions (expected ≥1)"
        fi
    done
}

phase_transport_inventory() {
    info "── phase 2: transport inventory (baseline) ──────────────────────"
    # Dump `sessions list` on both nodes and record the primary transport.
    # Output is TSV with columns: link_id / node_id / source / transport /
    # state / loss_pct / samples.  A data row contains `active` in the
    # state column; the header line doesn't.  When stage (b)/(c)/(d)
    # lands, phase 4 will re-dump and assert the primary changed.
    for n in 0 1; do
        local out
        out="$("$BINARY" --config "$(config_file "$n")" sessions list 2>&1)" \
            || { record_fail "sessions list failed for node-${n}"; continue; }
        # Count data rows (those with state == active).
        local rows
        rows="$(echo "$out" | awk -F'\t' '$5=="active"{c++} END{print c+0}')"
        if [[ "$rows" -ge 1 ]]; then
            pass "node-${n}: ${rows} active session(s)"
            # Show just the primary transport column for brevity.
            echo "$out" | awk -F'\t' '$5=="active"{printf "    primary transport: %s (link=%s)\n", $4, $1}'
        else
            record_fail "node-${n}: sessions list has no active rows"
            echo "$out" | sed 's/^/    /'
        fi
    done
}

phase_unit_tests() {
    info "── phase 3: hot-standby unit tests (stage (a) correctness) ─────"
    # The runner-level swap-point is proved by these two tests; they use
    # tokio::io::duplex so they do not touch the running fixture.  A
    # passing result is the strongest assertion we have today that
    # `NextInput::SwapStream` + `self.stream = new_stream` preserves
    # AEAD state across a mid-session transport handover.
    local test_out
    if test_out="$(cd "$REPO_ROOT" && cargo test -q -p veilcore --lib \
            node::session::runner::tests::swap 2>&1)"; then
        pass "swap_redirects_runner_to_new_stream_without_reset"
        pass "swap_preserves_aead_counter_across_transports"
    else
        record_fail "hot-standby unit tests failed — swap mechanism regression"
        echo "$test_out" | tail -20 | sed 's/^/    /'
    fi
}

phase_swap_end_to_end() {
    info "── phase 4: end-to-end swap via admin command ───────────────────"
    if ! "$BINARY" --config "$(config_file 0)" node --help 2>&1 | grep -q 'swap-transport'; then
        warn "'node swap-transport' admin command not present — hot-standby B5 integration missing"
        warn "expected command shape: veil-cli node swap-transport --peer <hex> --alt-uri <uri>"
        return
    fi

    # Extract node-1's node_id so node-0 can address it in the admin command.
    local peer_id
    peer_id="$("$BINARY" --config "$(config_file 1)" node show 2>/dev/null \
        | sed -nE 's/^node_id:\s*([0-9a-f]+)$/\1/p')"
    if [[ -z "$peer_id" ]]; then
        record_fail "couldn't read node-1's node_id from 'node show'"
        return
    fi

    # Count 'session.transport_swapped' and 'handshake.success' log events
    # on both sides BEFORE the swap.  The swap must raise the former by
    # exactly 1 on each side and must NOT raise the latter (no re-handshake).
    local a_swap_before a_hs_before b_swap_before b_hs_before
    a_swap_before="$(grep -c 'session.transport_swapped' "$(log_file 0)" 2>/dev/null | tr -d ' \n' || echo 0)"
    b_swap_before="$(grep -c 'session.transport_swapped' "$(log_file 1)" 2>/dev/null | tr -d ' \n' || echo 0)"
    a_hs_before="$(grep -c 'handshake.success' "$(log_file 0)" 2>/dev/null | tr -d ' \n' || echo 0)"
    b_hs_before="$(grep -c 'handshake.success' "$(log_file 1)" 2>/dev/null | tr -d ' \n' || echo 0)"

    # Drive the swap: node-0 side initiates, dialling node-1's alternate
    # transport (the "second" listener we configured at startup).
    local alt_uri="tcp://127.0.0.1:${NODE_B_TRANSPORT_2_PORT}"
    info "invoking: node swap-transport --peer ${peer_id:0:12}… --alt-uri ${alt_uri}"
    local cmd_out
    if ! cmd_out="$("$BINARY" --config "$(config_file 0)" node swap-transport \
                --peer "$peer_id" --alt-uri "$alt_uri" 2>&1)"; then
        record_fail "swap-transport admin command failed: ${cmd_out}"
        return
    fi
    pass "swap-transport command returned successfully"

    # Give both sides a moment to emit their log events.  The runner's
    # `await_next_input` tick is sub-ms but log flushing can lag.
    sleep 1

    # Verify 'session.transport_swapped' appears on BOTH sides (node-0 via
    # warm-probe-push into own swap_rx; node-1 via peek_and_dispatch push
    # into its own runner's swap_rx).
    local a_swap_after b_swap_after
    a_swap_after="$(grep -c 'session.transport_swapped' "$(log_file 0)" 2>/dev/null | tr -d ' \n' || echo 0)"
    b_swap_after="$(grep -c 'session.transport_swapped' "$(log_file 1)" 2>/dev/null | tr -d ' \n' || echo 0)"
    if [[ "$a_swap_after" -gt "$a_swap_before" && "$b_swap_after" -gt "$b_swap_before" ]]; then
        pass "both sides logged session.transport_swapped (node-0: ${a_swap_before}→${a_swap_after}, node-1: ${b_swap_before}→${b_swap_after})"
    else
        record_fail "session.transport_swapped not observed on both sides \
(node-0: ${a_swap_before}→${a_swap_after}, node-1: ${b_swap_before}→${b_swap_after})"
    fi

    # Verify NO new handshake happened — the swap must preserve the session.
    local a_hs_after b_hs_after
    a_hs_after="$(grep -c 'handshake.success' "$(log_file 0)" 2>/dev/null | tr -d ' \n' || echo 0)"
    b_hs_after="$(grep -c 'handshake.success' "$(log_file 1)" 2>/dev/null | tr -d ' \n' || echo 0)"
    if [[ "$a_hs_after" -eq "$a_hs_before" && "$b_hs_after" -eq "$b_hs_before" ]]; then
        pass "no new handshake.success events — session preserved across transport"
    else
        record_fail "unexpected re-handshake during swap \
(node-0: ${a_hs_before}→${a_hs_after}, node-1: ${b_hs_before}→${b_hs_after})"
    fi

    # Show the new transport inventory — session should now report the
    # alternate port (or whatever the peer advertised for the new transport).
    local out_after
    out_after="$("$BINARY" --config "$(config_file 0)" sessions list 2>&1)"
    info "post-swap sessions on node-0:"
    echo "$out_after" | awk -F'\t' '$5=="active"{printf "    transport: %s (link=%s)\n", $4, $1}'
}

phase_auto_trigger() {
    info "── phase 5: auto-trigger unit test (stage (c) correctness) ─────"
    # Stage (c)'s hard guarantee — that consecutive primary-transport
    # write errors advance an internal counter which, at threshold,
    # fires HotStandbyController::try_auto_trigger — is proved by
    # unit tests using a WriteAlwaysFailsStream fixture.  Inducing
    # real write errors on a live two-node devnet requires either
    # root-level iptables or killing the peer mid-session; doing so
    # cleanly would need more orchestration than this smoke script
    # aims to provide.  So we run the hard-guarantee test here and
    # note that real-deployment verification belongs in the Windows
    # multi-host test plan (docs/hot-standby-test-plan-windows.md).
    local test_out
    if test_out="$(cd "$REPO_ROOT" && cargo test -q -p veilcore --lib \
            auto_trigger_fires_on_primary_write_error 2>&1)"; then
        pass "auto_trigger_fires_on_primary_write_error"
    else
        record_fail "stage (c) auto-trigger unit test failed — regression"
        echo "$test_out" | tail -20 | sed 's/^/    /'
    fi

    info "  live-fixture auto-trigger induction requires either root"
    info "  (iptables on the primary TCP port) or a separate Windows"
    info "  multi-host fixture (docs/hot-standby-test-plan-windows.md"
    info "  scenario 2).  The unit test above covers the hard contract."
}

cmd_verify() {
    VERIFY_FAILED=0
    phase_session_health
    phase_transport_inventory
    phase_unit_tests
    phase_swap_end_to_end
    phase_auto_trigger

    echo
    if [[ "$VERIFY_FAILED" -eq 0 ]]; then
        info "$(c_green 'ALL PHASES PASSED') (with stage (a) scope noted)"
        return 0
    else
        info "$(c_red 'FAILED') — ${VERIFY_FAILED} check(s) did not pass"
        return 1
    fi
}

# ── cmd_run ───────────────────────────────────────────────────────────────────

cmd_run() {
    local clean_up=1
    # If --no-stop is passed, leave the fixture up for interactive inspection.
    [[ "${1:-}" == "--no-stop" ]] && clean_up=0

    # Auto-cleanup on any exit path (including `die` from cmd_start) so
    # failed runs don't leave orphaned node processes behind.  `trap - EXIT`
    # at the end cancels when we want `--no-stop`.
    if [[ $clean_up -eq 1 ]]; then
        trap 'cmd_stop >/dev/null 2>&1 || true' EXIT
    fi

    if ! is_running 0 || ! is_running 1; then
        cmd_start
    else
        info "reusing running fixture"
    fi

    local rc=0
    cmd_verify || rc=$?

    if [[ $clean_up -eq 0 ]]; then
        info "fixture left running; stop with: $0 stop"
    fi
    # EXIT trap will run cmd_stop when clean_up=1; otherwise it was never set.
    return $rc
}

# ── dispatch ──────────────────────────────────────────────────────────────────

COMMAND="${1:-help}"; shift || true

case "$COMMAND" in
    run)    cmd_run "$@" ;;
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    verify) cmd_verify ;;
    logs)   cmd_logs "$@" ;;
    help|--help|-h)
        grep '^#' "$0" | sed 's/^# \{0,2\}//' | head -40 ;;
    *)
        die "unknown command: ${COMMAND} (try 'help')" ;;
esac
