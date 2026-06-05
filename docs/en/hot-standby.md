# Hot-standby transport handover

Adjacent to [adaptive-failover.md](adaptive-failover.md), which scores and
switches **routes** (`next_hop → dst` entries in `RouteCache`), this document
covers **transports** on a single already-established session: if the peer
we're talking to is still reachable but the socket we're using starts
failing — TCP RST from a middlebox, TLS record corruption, QUIC congestion
collapse — we want to *keep the session* (same `session_id`, same AEAD
ciphers, same negotiated capabilities) and only change the byte pipe
underneath it.

The alternative, a fresh OVL1 handshake on a different socket, is expensive
(PoW-bound identity exchange, kex, cipher derivation) and burns the
session's pending request IDs, peer aliases, and any outstanding rekey
state.  Hot-standby avoids all of that.

---

## Status

The feature ships in stages.  The table below tracks what is in-tree
and what is deferred behind the version gate.

| Stage | Scope | Status |
|-------|-------|--------|
| **(a) Runner swap-point** | `SessionRunner.swap_rx: Option<Receiver<BoxIoStream>>` + `NextInput::SwapStream(..)` handled between frames in `run()` so `self.stream` is replaced atomically without touching AEAD state. | ✅ in-tree (2026-04-24) |
| **(b) Warm-probe task** | Per-session one-shot `WarmProbe` that dials the alt URI and runs the challenge-response handoff (T1): `HandoffInit`/`HandoffAck` over the primary, then a bare `HandoffAttach` announce + `HandoffChallenge(24)` + `HandoffResponse(25)` on the warm socket.  Operator-driven via `node swap-transport` admin command, or auto-dispatched by (c). | ✅ in-tree (2026-04-24) |
| **(c) Trigger logic** | Consecutive write errors + `rx_stall` (idle_timeout × 2/3 without RX) + `primary_closed` (peer FIN/RST).  All three funnel through `HotStandbyController::try_auto_trigger` with per-peer flap damping. | ✅ in-tree (2026-04-24); see limitations below |
| **(c.3) Peer capability auto-discovery** | AttachPayload TLV `ADVERTISED_TRANSPORTS_TLV_TAG=0x0012` conveys each side's active `[[listen]]` URIs.  Controller auto-populates `alt_uri_for` from any advertised URI that differs from the primary. | ✅ in-tree (2026-04-24) |
| **(d) Cross-peer handoff protocol** | `SessionMsg::HandoffInit` + `HandoffAck` over the AEAD session, then `HandoffAttach` + `HandoffChallenge(24)` + `HandoffResponse(25)` on the warm socket; `peek_and_dispatch` on every inbound socket `peek`s (does not consume) the pending entry, sends a fresh `HandoffChallenge`, and binds the socket to an existing runner's `swap_rx` only after the `HandoffResponse` HMAC verifies. | ✅ in-tree (2026-04-24) |

### Stage (c.2.2) — keepalive-probe timeout

On a Windows Firewall half-block (outbound from A → B dropped, B → A
still flowing), neither `rx_stall` nor `write_error_threshold` fires
reliably.  `rx_stall` doesn't fire because B's own keepalives and
frames keep reaching A, bumping `last_rx`.  `write_error_threshold`
doesn't fire because Windows TCP silently buffers A's writes in
SNDBUF for the full ~30s retransmission quota before returning an
error — by which point B's TCP has given up and closed the socket,
sending A's runner into the `primary_closed` path instead.

Fix: track acks to A's own keepalives.  OVL1 has
`ControlMsg::KeepaliveAck` in the protocol; stage (c.2.2) wires
it to the hot-standby trigger.  Flow:

1. Runner sends `ControlMsg::Keepalive`; if `pending_keepalive_ack_since`
   is `None`, records the current time.  (Preserving the oldest unacked
   timestamp gives the widest possible window for legitimate latency.)
2. Peer's dispatcher replies with `ControlMsg::KeepaliveAck` — this
   was already in the protocol, just never gated anything.
3. Runner intercepts `KeepaliveAck` before the general dispatcher call,
   clears `pending_keepalive_ack_since`, and resets the trigger-fired
   flag.
4. Timer tick: if `pending_keepalive_ack_since.is_some() && now - t >=
   keepalive_probe_timeout`, `fire_hot_standby_trigger("keepalive_probe_timeout")`.
   Default `keepalive_probe_timeout = 1 × keepalive_interval`.  (Shipped
   as 2 × initially; two-host validation on a Windows LAN showed
   station's TCP issuing RST at ~25-30s after the firewall block,
   which beat a 2 × 10s = 20s probe by a few seconds.  1 × interval
   fires the probe comfortably before the OS-level RST so `HandoffInit`
   can still travel over the live primary.)

#### Tuning for synthetic firewall-block tests

On a LAN with Windows Firewall injecting an outbound-block rule, the
peer's TCP gives up in **~9 seconds** (not the 25-30s we see when the
rule is ineffective due to DNS mismatch).  To watch c.2.2 fire in
this synthetic scenario, shorten `keepalive_interval_secs` so the
probe deadline lands inside that 9 s window:

    [session]
    keepalive_interval_secs = 3
    idle_timeout_secs       = 20

With `keepalive_interval = 3 s`, the first keepalive jitters in
[1.5, 4.5]; probe_timeout is also 3 s, so the probe fires at
approximately `T = 4.5 + 3 = 7.5 s`, comfortably before the OS-level
RST at `~9 s`.

In production (`keepalive_interval_secs = 30`, default), the primary
does **not** die that fast — TCP retransmission runs the full quota,
giving ~60 s of half-broken state for the probe to fire in.  No
tuning required.

The runner's `sleep_until` now includes the probe deadline so the
check actually wakes.  `keepalive_enabled` was also fixed to treat
sub-second intervals as enabled (previously `as_secs() > 0` rounded
50 ms down to 0, leaving the probe dormant).

Covered by unit test `keepalive_probe_timeout_fires_trigger_when_no_ack`:
fixture accepts writes but never delivers any byte (no ack), runner
fires trigger within 2 × keepalive_interval.

### Previous gap on Windows firewall half-block — closed

Before c.2.2, the runner exited silently on `NextInput::Closed` with
no hot-standby signal; the session re-established via full OVL1
handshake instead of a warm-probe handoff.  `NextInput::Closed` now
also logs `session.primary_closed` and fires the trigger one last
time as a defence-in-depth, even though by that point `HandoffInit`
can no longer go out on the dead primary.  c.2.2's keepalive-probe
timeout fires MUCH earlier than `primary_closed`, so this path is
only hit when both rx_stall AND keepalive-probe somehow miss the
degradation (full network partition on the receive side, where no
keepalives arrive at all).

The stage-(a) swap-point is the contract the other stages depend on.  Its
correctness is proved by two unit tests in
[crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs):

- `swap_redirects_runner_to_new_stream_without_reset` — a runner serving
  Ping→Pong on duplex A is handed duplex B via `swap_tx.send`; the next
  Ping on B receives a Pong without the runner re-entering handshake or
  dropping the session.
- `swap_preserves_aead_counter_across_transports` — same flow with real
  `SessionCipher` instances.  If the runner had re-initialised `rx_cipher`
  on swap, the round-2 Ping on B would sail past `rx_cipher.open()` at
  counter=2 while the runner expected counter=1, silently dropping the
  frame.  The test's 2-second timeout enforces the negative case.

---

## Swap safety — why "between frames" is enough

Every byte of wire traffic belongs to exactly one `FrameHeader + body`.
The runner consumes frames in a two-phase loop:

1. `await_next_input` blocks until **one** of {first-byte-of-next-frame,
   outbox-frame, rpc-request, swap-stream, timer} is ready.
2. If `Byte(b)` wins, it reads the rest of the header with
   `read_exact`, decrypts+dispatches the body, loops back.

A `SwapStream` result can only win at step 1.  Swap therefore happens
with the wire in a clean state: zero bytes of an in-progress frame have
been consumed on the old stream.  On the write side, the priority-queue
flush at the top of each iteration has already completed before
`await_next_input` is entered, so no partial write is in flight either.

The **peer** of course doesn't see our scheduler; it may still be
mid-frame on the old transport when our side drops it.  That's why
follow-up (d) introduces the synchronous challenge-response handoff
protocol (T1) — the warm socket sends a bare `HandoffAttach { session_id }`,
the receiver issues a fresh per-socket `HandoffChallenge` (32 bytes of
`OsRng`), and the initiator must prove session-key ownership by answering
`HandoffResponse` with `hmac = BLAKE3::keyed(tx_key)(session_id || challenge)`.
Frames only start flowing on the NEW transport once the receiver
recomputes the HMAC with `rx_key` and confirms a constant-time match
(a replayed attach gets a different challenge it cannot answer without
the session key).  Bytes still on the old wire after that point are
discarded by the TCP/TLS close on both sides.

---

## Why this is distinct from session resumption

Session resumption (`SESSION_TICKET`) is the *cold* path — the
current session is already torn down and the client re-dials, skipping
PoW/kex by replaying the ticket.  It still rebuilds ciphers and
request-id state from scratch; RTT is dial + handshake + 1 RTT.

Hot-standby is the *hot* path — the session is never torn down.  RTT is
a single round-trip of `HandoffInit` / `HandoffAck` over the already-
active encrypted session plus however long it takes the warm probe to
stop being idle and start carrying real frames.  In the limit (probe
kept fresh via L2 / QUIC 0-RTT to the same advertised address), swap
RTT is zero above the new transport's connect latency.

Both mechanisms coexist: hot-standby is always preferred; resumption
is the fallback when the session actually died (both transports
failed simultaneously, or the peer rebooted).

---

## Configuration (planned for stage b/c)

Proposed knobs in `[session.hot_standby]`:

    [session.hot_standby]
    enabled              = false        # opt-in; privacy impact is nil on a
                                        # per-peer basis but enabling per-peer
                                        # warm probes doubles socket count
    alt_scheme_order     = ["quic", "wss", "tls"]
                                        # tried after the primary in this order
    probe_keepalive_secs = 15           # warm-probe keepalive cadence
    swap_on_write_errors = 3            # consecutive wire-level write errors
                                        # on the primary → trigger swap
    swap_on_rtt_multiplier = 4.0        # if keepalive RTT > 4× median → swap
    max_swaps_per_minute = 4            # flap-damping ceiling

These don't exist yet; stage (b) introduces `enabled` + `alt_scheme_order`;
stage (c) introduces the trigger thresholds.
