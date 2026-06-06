# Hot-standby transport handover

Its sibling [adaptive-failover.md](adaptive-failover.md) scores and switches
**routes** — the `next_hop → dst` entries in `RouteCache`. This document is
about **transports** (the actual byte pipe: TCP, TLS, QUIC, and friends) on a
single session that is *already* established. The case we care about: the peer
is still reachable, but the socket we're using starts failing. A middlebox
sends a TCP RST, TLS records get corrupted, QUIC congestion collapses. We want
to *keep the session* — same `session_id`, same AEAD ciphers, same negotiated
capabilities — and swap only the pipe underneath it.

The obvious alternative is a fresh OVL1 handshake on a different socket. That
is expensive: it re-runs the PoW-bound identity exchange, the key exchange
(kex), and cipher derivation. Worse, it burns the session's pending request
IDs, its peer aliases, and any outstanding rekey state. Hot-standby avoids all
of that.

---

## Status

The feature ships in stages. The table below tracks what is already in-tree
and what is deferred behind the version gate.

| Stage | Scope | Status |
|-------|-------|--------|
| **(a) Runner swap-point** | `SessionRunner.swap_rx: Option<Receiver<BoxIoStream>>` + `NextInput::SwapStream(..)` handled between frames in `run()` so `self.stream` is replaced atomically without touching AEAD state. | ✅ in-tree (2026-04-24) |
| **(b) Warm-probe task** | A per-session one-shot `WarmProbe`. It dials the alt URI and runs the challenge-response handoff (T1): `HandoffInit`/`HandoffAck` over the primary, then a bare `HandoffAttach` announce + `HandoffChallenge(24)` + `HandoffResponse(25)` on the warm socket. Started by an operator via the `node swap-transport` admin command, or auto-dispatched by (c). | ✅ in-tree (2026-04-24) |
| **(c) Trigger logic** | Consecutive write errors + `rx_stall` (idle_timeout × 2/3 without RX) + `primary_closed` (peer FIN/RST).  All three funnel through `HotStandbyController::try_auto_trigger` with per-peer flap damping. | ✅ in-tree (2026-04-24); see limitations below |
| **(c.3) Peer capability auto-discovery** | AttachPayload TLV `ADVERTISED_TRANSPORTS_TLV_TAG=0x0012` conveys each side's active `[[listen]]` URIs.  Controller auto-populates `alt_uri_for` from any advertised URI that differs from the primary. | ✅ in-tree (2026-04-24) |
| **(d) Cross-peer handoff protocol** | `SessionMsg::HandoffInit` + `HandoffAck` over the AEAD session, then `HandoffAttach` + `HandoffChallenge(24)` + `HandoffResponse(25)` on the warm socket. On every inbound socket, `peek_and_dispatch` `peek`s the pending entry (without consuming it), sends a fresh `HandoffChallenge`, and binds the socket to an existing runner's `swap_rx` only once the `HandoffResponse` HMAC verifies. | ✅ in-tree (2026-04-24) |

### Stage (c.2.2) — keepalive-probe timeout

Consider a Windows Firewall *half-block*: outbound traffic from A → B is
dropped, but B → A still flows. Here neither `rx_stall` nor
`write_error_threshold` fires reliably. `rx_stall` stays quiet because B's own
keepalives and frames keep reaching A, which bumps `last_rx`.
`write_error_threshold` stays quiet because Windows TCP silently buffers A's
writes in SNDBUF for the full ~30s retransmission quota before it returns an
error. By then B's TCP has already given up and closed the socket, which sends
A's runner down the `primary_closed` path instead.

The fix is to track acks for A's own keepalives. OVL1 already carries
`ControlMsg::KeepaliveAck`; stage (c.2.2) wires it to the hot-standby trigger.
The flow:

1. The runner sends `ControlMsg::Keepalive`. If `pending_keepalive_ack_since`
   is `None`, it records the current time. (Keeping the *oldest* unacked
   timestamp gives the widest window for legitimate latency.)
2. The peer's dispatcher replies with `ControlMsg::KeepaliveAck`. This message
   was already in the protocol; it just never gated anything before.
3. The runner intercepts `KeepaliveAck` ahead of the general dispatcher call,
   clears `pending_keepalive_ack_since`, and resets the trigger-fired flag.
4. On a timer tick: if `pending_keepalive_ack_since.is_some() && now - t >=
   keepalive_probe_timeout`, it calls
   `fire_hot_standby_trigger("keepalive_probe_timeout")`. The default is
   `keepalive_probe_timeout = 1 × keepalive_interval`. (It shipped as 2 ×
   initially. Two-host validation on a Windows LAN showed the station's TCP
   issuing an RST ~25-30s after the firewall block, which beat a 2 × 10s = 20s
   probe by a few seconds. At 1 × interval the probe fires comfortably before
   the OS-level RST, so `HandoffInit` can still travel over the live primary.)

#### Tuning for synthetic firewall-block tests

On a LAN where Windows Firewall injects an outbound-block rule, the peer's TCP
gives up in **~9 seconds** — not the 25-30s we saw when the rule was
ineffective because of a DNS mismatch. To watch c.2.2 fire in this synthetic
scenario, shorten `keepalive_interval_secs` so the probe deadline lands inside
that 9 s window:

    [session]
    keepalive_interval_secs = 3
    idle_timeout_secs       = 20

With `keepalive_interval = 3 s`, the first keepalive jitters within
[1.5, 4.5]. probe_timeout is also 3 s, so the probe fires at roughly
`T = 4.5 + 3 = 7.5 s` — comfortably before the OS-level RST at `~9 s`.

In production (the default `keepalive_interval_secs = 30`), the primary does
**not** die that fast. TCP retransmission runs the full quota, which leaves
~60 s of half-broken state for the probe to fire in. No tuning required.

Two supporting fixes landed with this. The runner's `sleep_until` now includes
the probe deadline, so the check actually wakes on time. And `keepalive_enabled`
now treats sub-second intervals as enabled — previously `as_secs() > 0` rounded
50 ms down to 0, which left the probe dormant.

A unit test covers it: `keepalive_probe_timeout_fires_trigger_when_no_ack`. The
fixture accepts writes but never delivers a single byte (so no ack ever
arrives), and the runner fires the trigger within 2 × keepalive_interval.

### Previous gap on Windows firewall half-block — closed

Before c.2.2, the runner exited silently on `NextInput::Closed` with no
hot-standby signal. The session then re-established via a full OVL1 handshake
instead of a warm-probe handoff. Now `NextInput::Closed` also logs
`session.primary_closed` and fires the trigger one last time, as
defence-in-depth — even though by that point `HandoffInit` can no longer go out
on the dead primary. The c.2.2 keepalive-probe timeout fires MUCH earlier than
`primary_closed`, so this path is hit only when both rx_stall AND the
keepalive-probe somehow miss the degradation. That means a full network
partition on the receive side, where no keepalives arrive at all.

The stage-(a) swap-point is the contract every other stage depends on. Two
unit tests in
[crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs)
prove it correct:

- `swap_redirects_runner_to_new_stream_without_reset` — a runner serving
  Ping→Pong on duplex A is handed duplex B via `swap_tx.send`. The next Ping on
  B receives a Pong, and the runner neither re-enters the handshake nor drops
  the session.
- `swap_preserves_aead_counter_across_transports` — the same flow, but with real
  `SessionCipher` instances. If the runner had re-initialised `rx_cipher` on
  swap, the round-2 Ping on B would sail past `rx_cipher.open()` at counter=2
  while the runner expected counter=1, silently dropping the frame. The test's
  2-second timeout enforces this negative case.

---

## Swap safety — why "between frames" is enough

Every byte of wire traffic belongs to exactly one `FrameHeader + body`. The
runner consumes frames in a two-phase loop:

1. `await_next_input` blocks until **one** of these is ready:
   first-byte-of-next-frame, outbox-frame, rpc-request, swap-stream, or timer.
2. If `Byte(b)` wins, the runner reads the rest of the header with
   `read_exact`, decrypts and dispatches the body, then loops back.

A `SwapStream` result can only win at step 1. So a swap always happens with the
wire in a clean state: not a single byte of an in-progress frame has been
consumed on the old stream. The write side is clean too — the priority-queue
flush at the top of each iteration has already completed before
`await_next_input` is entered, so no partial write is in flight.

The **peer**, of course, can't see our scheduler. It may still be mid-frame on
the old transport when our side drops it. That is why follow-up (d) adds the
synchronous challenge-response handoff protocol (T1). The warm socket sends a
bare `HandoffAttach { session_id }`. The receiver issues a fresh per-socket
`HandoffChallenge` (32 bytes from `OsRng`). The initiator must then prove it
owns the session key by answering `HandoffResponse` with
`hmac = BLAKE3::keyed(tx_key)(session_id || challenge)`. Frames start flowing on
the NEW transport only after the receiver recomputes the HMAC with `rx_key` and
confirms a constant-time match. A replayed attach gets a different challenge,
which it cannot answer without the session key. Any bytes still on the old wire
past that point are discarded by the TCP/TLS close on both sides.

---

## Why this is distinct from session resumption

Session resumption (`SESSION_TICKET`) is the *cold* path. The current session
is already torn down, so the client re-dials and replays the ticket to skip
PoW and kex. It still rebuilds the ciphers and request-id state from scratch,
and its cost is dial + handshake + 1 RTT.

Hot-standby is the *hot* path. The session is never torn down. Its cost is a
single round-trip of `HandoffInit` / `HandoffAck` over the still-active
encrypted session, plus however long the warm probe takes to stop being idle
and start carrying real frames. In the best case — a probe kept fresh via L2 or
QUIC 0-RTT to the same advertised address — the swap RTT is zero on top of the
new transport's connect latency.

The two mechanisms coexist. Hot-standby is always preferred; resumption is the
fallback for when the session actually died — both transports failed at once, or
the peer rebooted.

---

## Configuration (planned for stage b/c)

The proposed knobs live under `[session.hot_standby]`:

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

None of these exist yet. Stage (b) introduces `enabled` and `alt_scheme_order`;
stage (c) introduces the trigger thresholds.
