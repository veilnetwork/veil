# Hot-standby manual test plan — Windows multi-host

This is the hardware regression suite for stages (b) / (c) / (d) of
hot-standby — see [hot-standby.md](hot-standby.md). Hot-standby keeps a
second transport warm so a session can move to it without dropping.
Stage (a) — the swap-point inside the runner — is covered by unit tests
and needs no Windows hardware. Stages (b), (c), and (d) already shipped
(2026-04-24). So the scenarios below are not a wait-for-ship plan: they
are the live regression suite, and they drive a real handover at the
socket level across two machines.

Why Windows, and why two machines? Three reasons. First, we run an
end-to-end Windows Service mode that only exists here. Second, in
production we saw a middlebox send an RST (a TCP reset that kills the
connection) on WSS sessions from Windows hosts — and our Linux
simulation never reproduces it. Third, the native Windows TCP stack
hits partial-write edge cases during a swap that Linux
`tokio::io::duplex` simply cannot surface.

---

## Topology

Two Windows hosts:

- **Alice** — `veil-cli service install --config C:\veil\alice.toml`
  + `Start-Service VeilNode`.  Configured with two listen endpoints:

      [[listen]]
      transport = "tls://0.0.0.0:9906"
      advertise = "tls://alice.test:9906"
      tls-cert  = "C:\\veil\\alice-fullchain.pem"
      tls-key   = "C:\\veil\\alice-privkey.pem"

      [[listen]]
      transport = "wss://0.0.0.0:8443/veil"
      advertise = "wss://alice.test:8443/veil"
      tls-cert  = "C:\\veil\\alice-fullchain.pem"
      tls-key   = "C:\\veil\\alice-privkey.pem"

- **Bob** — same pattern; `bob.test` on both ports.

The two hosts find each other through `[[bootstrap_peers]]`. You can
wire them directly to each other over `tls://`, or point both at the
same third-party bootstrap seed and let gossip do the rest.

Both sides also need a top-level `[hot_standby]` table with
`enabled = true`. The old `alt_scheme_order` key is gone. The alt
transport — the warm backup each peer can fail over to — is now
discovered automatically from each peer's advertised `[[listen]]` URIs
(stage (c.3), `auto_set_alt_uri_from_transports`). If a manual test
needs a specific alt, pin it on the swap command itself with
`node swap-transport --alt-uri ...`.

---

## Scenario 1 — manual swap, the happy path

**Goal:** confirm the stage (a)+(d) handoff works end to end over real
TCP.

1. On Alice, start a long-running chat session to Bob:

       python examples\chat_client.py --to <bob_node_id> --say "hello"

   Leave the Python client in interactive mode.

2. On Alice, check the primary transport:

       veil-cli --config C:\veil\alice.toml sessions list

   Note the `transport` column for Bob's session — should be `tls://`.

3. On Alice, fire an admin command that fakes the degradation signal.
   Stage (c) raises this signal on its own through
   `AdminCommand::SwapTransport`; here we send it by hand so the test
   stays deterministic. Both `--peer` and `--alt-uri` are required:

       veil-cli --config C:\veil\alice.toml node swap-transport --peer <bob_node_id> --alt-uri wss://bob.test:8443/veil

4. Check Alice's logs for:

       session.transport_swapped peer_id=<bob> session preserved across transport handover

   then re-run `sessions list`. The `transport` for Bob should now read
   `wss://`, and `session_id` must be **unchanged**.

5. In the Python client, type another message. It must arrive on Bob's
   side with no visible hiccup, and neither side may log a "session
   reset".

**Pass criteria.** `session_id` stays the same across steps 2 and 4.
The post-swap message is delivered without re-establishing the session.
No `handshake.*` events appear on either host between step 3 and
step 5.

---

## Scenario 2 — the primary dies unexpectedly

**Goal:** confirm that stage (c)'s trigger fires on the real-world
failure modes the Linux simulation can't reproduce.

1. Same starting setup as scenario 1.

2. On Alice, block the primary transport with Windows Firewall:

       New-NetFirewallRule -DisplayName "veil-hotstandby-test" `
           -Direction Outbound -Action Block `
           -Protocol TCP -RemotePort 9906 -RemoteAddress <bob_ip>

3. Send another chat message. Alice's runner should now see write
   errors pile up on the TLS socket. Stage (c) counts them and swaps
   over to the warm WSS probe within roughly
   `swap_on_write_errors × send_cadence` — about 1-3 s for a 1 Hz chat
   client at the default 3-error threshold.

4. Remove the firewall rule and confirm the session is still on WSS.
   The primary does not swap back on its own; that is a separate
   policy and out of scope here.

       Remove-NetFirewallRule -DisplayName "veil-hotstandby-test"

**Pass criteria.** The chat message from step 3 is delivered, possibly
with a visible delay. Both hosts log `session.transport_swapped`. And
neither side brackets the swap with a `session.handshake_start`,
`session.idle_timeout`, or `peer.reconnect` event.

---

## Scenario 3 — flap damping

A "flap" is a link that keeps dropping and recovering. This scenario
checks that we don't chase it forever.

**Goal:** confirm `max_swaps_per_minute` caps runaway swap loops when
both transports go bad on and off.

1. Same starting setup.

2. Toggle the firewall rule from scenario 2 every 5 s in a PowerShell
   loop, for 2 minutes. This blocks and unblocks the primary in turn.

3. Inspect the log. The `session.transport_swapped` events should cap
   at `max_swaps_per_minute` (default 4). Once the cap is hit, the
   runner should log `session.swap_rate_limited` and hold off on
   further swaps until the window rolls over.

**Pass criteria.** The swap count in the log stays ≤ 4 per rolling
minute. The session survives the flap window with no re-handshake. And
across the 2 minutes, at least *some* frames get through on whichever
transport was live at the time.

---

## Scenario 4 — handoff attach replay resistance

**Goal:** confirm that an off-path observer cannot replay the
warm-socket `HandoffAttach` announce to hijack a session. ("Replay"
means capturing valid bytes off the wire and sending them again;
"off-path" means the attacker can see and inject packets but isn't one
of the real endpoints.) Since audit cycle-6 (T1) the proof is no longer
a static token. `HandoffAttach` now carries only the bare `session_id`,
and the receiver answers with a fresh per-socket challenge
(`SessionMsg::HandoffChallenge = 24`, 32-byte `OsRng`). The initiator
must answer that with `SessionMsg::HandoffResponse = 25`, where
`hmac = BLAKE3::keyed(tx_key)(session_id || challenge)`, keyed by the
session AEAD `tx_key`. A replayed attach draws a *different* challenge,
and it cannot answer that without the session key.

1. On Bob, capture packets on the primary transport during scenario 1:

       netsh trace start capture=yes tracefile=C:\swap.etl

2. Run scenario 1 to completion; stop the trace:

       netsh trace stop

3. Open the trace in Microsoft Message Analyzer, or convert it with
   `etl2pcapng` and inspect it in Wireshark. Find the warm-socket
   handoff frames. The `HandoffAttach` announce on the warm socket is
   plaintext (pre-OVL1), but it carries only the 32-byte `session_id`.
   The `HandoffResponse` HMAC depends on the per-socket challenge, so
   nothing on the wire is a reusable token.

4. From a third host — call it Eve, spoofing Bob's IP — try to connect
   to Alice's advertised WSS port and replay the captured
   `HandoffAttach` bytes (the bare `session_id`). Alice answers Eve's
   socket with a *fresh* `HandoffChallenge`. Eve can't produce the
   matching `HandoffResponse` HMAC without the session's `tx_key`, and
   that key never left the legitimate primary session's AEAD. The
   resistance comes from the session AEAD keys, **not** from Bob's
   identity private key. Alice never binds Eve's socket to `swap_rx`.

**Pass criteria.** Eve's replayed attach is challenged but never binds.
The warm socket is dropped, because the `HandoffResponse` HMAC does not
verify against Alice's `rx_key`. Alice's real session with Bob is
untouched, and its `session_id` does not change. (The exact log and
reason strings are an implementation detail — treat the description
above as the expected behaviour, not as literal event names.)

---

## Reporting

For each scenario, capture three things:

- the `veil-cli node show` and `sessions list` output, both before and
  after the swap;
- the full log span, from `session.transport_swapped` on one host to
  the next application frame delivered on the other;
- the `netsh trace` output, trimmed down to the swap window.

File them under `reports/459-hot-standby-YYYY-MM-DD/scenario-N/`
in the operations repo.

---

## What Linux can and cannot cover

The unit tests in [crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs)
use `tokio::io::duplex` streams. Those streams have zero latency, lose
nothing, and stay perfectly in sync. They prove the swap *mechanism*
works in isolation. But some real-world failure modes only show up on
Windows, and only across two machines:

- **Partial writes that straddle the swap.** Windows TCP can return
  `WSAEWOULDBLOCK` mid-frame on the old transport while the runner is
  busy with the swap. Linux duplex streams either finish a write or
  don't. The "between frames" guarantee in stage (a) handles this, but
  only hardware testing confirms that no partial bytes leak onto the
  new transport.
- **Firewall, Windows Defender, and AV heuristics** flagging the swap
  traffic as suspicious — a fast open, close, and reopen of a socket on
  the same IP. That can add latency or block the swap outright, which in
  turn throws off the trigger-threshold calibration.
- **Windows Service mode**, where veil runs as the LocalSystem user.
  Its socket credentials differ from a user-mode `veil-cli node run`,
  and TLS trust-chain loading and per-user cert stores diverge.

Stages (b), (c), and (d) shipped on 2026-04-24, so these scenarios are
the standing regression suite. Re-run them before any release that
touches `node/session/runner.rs` or the handshake path. The one item
still genuinely deferred is the proactive, RTT-based trigger.
