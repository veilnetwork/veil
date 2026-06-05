# Hot-standby manual test plan — Windows multi-host

Hardware regression suite for stages (b) / (c) / (d) of hot-standby —
[hot-standby.md](hot-standby.md).  Stage (a) (the in-tree runner
swap-point) is verified by unit tests and does not need Windows hardware.
Stages (b)/(c)/(d) are in-tree (2026-04-24), so the scenarios below are
the live regression suite — they exercise real socket-level handover
across two machines, not a wait-for-ship plan.

Why Windows specifically: "Windows multi-host" matters here
because (i) we have end-to-end Windows Service mode, (ii) production
observations showed middlebox RST on WSS sessions from Windows hosts
that our Linux sim doesn't reproduce, and (iii) native Windows TCP
stack surfaces a different set of partial-write edge cases during
swap than Linux `tokio::io::duplex` can.

---

## Topology

Two Windows hosts:

- **Alice** — `veil-cli service install --config C:\veil\alice.toml`
  + `Start-Service veil-node`.  Configured with two listen endpoints:

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

Both hosts know each other via `[[bootstrap_peers]]` — either hand-wired
to each other over `tls://`, or both pointing at the same third-party
bootstrap seed and letting gossip converge.

Top-level `[hot_standby]` table with `enabled = true` on both sides.
There is no `alt_scheme_order` key any more: the alt transport is
auto-discovered from each peer's advertised `[[listen]]` URIs (stage
(c.3), `auto_set_alt_uri_from_transports`).  If a specific alt is
needed for the manual test, pin it on the swap command itself with
`node swap-transport --alt-uri ...`.

---

## Scenario 1 — manual swap, happy path

**Goal:** confirm stage (a)+(d) handoff works end-to-end on real TCP.

1. On Alice, start a long-running chat session to Bob:

       python examples\chat_client.py --to <bob_node_id> --say "hello"

   Leave the Python client in interactive mode.

2. On Alice, check the primary transport:

       veil-cli --config C:\veil\alice.toml sessions list

   Note the `transport` column for Bob's session — should be `tls://`.

3. On Alice, fire an admin command that simulates the degradation
   signal (stage (c) drives this automatically via
   `AdminCommand::SwapTransport`; for a deterministic manual test we
   dial it ourselves).  Both `--peer` and `--alt-uri` are required:

       veil-cli --config C:\veil\alice.toml node swap-transport --peer <bob_node_id> --alt-uri wss://bob.test:8443/veil

4. Check Alice's logs for:

       session.transport_swapped peer_id=<bob> session preserved across transport handover

   and re-run `sessions list` — `transport` for Bob should now be
   `wss://`.  `session_id` must be **unchanged**.

5. In the Python client, type another message.  It must arrive on
   Bob's side with no visible hiccup and no "session reset" log entry
   on either side.

**Pass criteria.** `session_id` stable across steps 2 and 4; post-swap
message delivered without re-establishing the session; no
`handshake.*` events between step 3 and step 5 on either host.

---

## Scenario 2 — primary dies unexpectedly

**Goal:** confirm stage (c)'s in-tree trigger fires on real-world
failure modes Linux sim can't reproduce.

1. Same starting setup as scenario 1.

2. On Alice, block the primary transport with Windows Firewall:

       New-NetFirewallRule -DisplayName "veil-hotstandby-test" `
           -Direction Outbound -Action Block `
           -Protocol TCP -RemotePort 9906 -RemoteAddress <bob_ip>

3. Send another chat message.  Alice's runner should observe
   consecutive write errors on the TLS socket; stage (c) counts them
   and drives a swap to the warm WSS probe within roughly
   `swap_on_write_errors × send_cadence` (~1-3 s for a 1 Hz chat
   client at default 3-error threshold).

4. Remove the firewall rule and confirm the session still on WSS —
   primary does not auto-swap-back (that's a separate policy, not in
   scope here).

       Remove-NetFirewallRule -DisplayName "veil-hotstandby-test"

**Pass criteria.** Chat message sent at step 3 is delivered (possibly
with visible delay); `session.transport_swapped` log on both hosts;
no `session.handshake_start` / `session.idle_timeout` / `peer.reconnect`
events bracketing the swap on either side.

---

## Scenario 3 — flap damping

**Goal:** confirm `max_swaps_per_minute` limits runaway swap loops
when both transports are intermittently bad.

1. Same starting setup.

2. Toggle the firewall rule from scenario 2 every 5 s (PowerShell
   loop) for 2 minutes.  This alternately blocks and unblocks primary.

3. Inspect the log: `session.transport_swapped` events should cap at
   `max_swaps_per_minute` (default 4).  After the cap is hit, the
   runner should log `session.swap_rate_limited` and defer further
   swaps for the remainder of the window.

**Pass criteria.** Swap count in the log stays ≤ 4 per rolling
minute; session survives the flap window (no re-handshake); in the
2-minute window, at least *some* frames are delivered on whichever
transport was live at the time.

---

## Scenario 4 — handoff attach replay resistance

**Goal:** confirm the warm-socket `HandoffAttach` announce cannot be
replayed by an off-path observer to hijack a session.  Since audit
cycle-6 (T1) the proof is no longer a static token: `HandoffAttach`
carries only the bare `session_id`, and the receiver answers with a
fresh per-socket challenge (`SessionMsg::HandoffChallenge = 24`,
32-byte `OsRng`) that the initiator must answer with
`SessionMsg::HandoffResponse = 25` — `hmac =
BLAKE3::keyed(tx_key)(session_id || challenge)`, keyed by the session
AEAD `tx_key`.  A replayed attach gets a *different* challenge it
cannot answer without the session key.

1. On Bob, capture packets on the primary transport during scenario 1:

       netsh trace start capture=yes tracefile=C:\swap.etl

2. Run scenario 1 to completion; stop the trace:

       netsh trace stop

3. Open the trace in Microsoft Message Analyzer (or convert via
   `etl2pcapng` and inspect in Wireshark).  Find the warm-socket
   handoff frames.  The `HandoffAttach` announce on the warm socket
   is plaintext (pre-OVL1) but carries only the 32-byte `session_id`;
   the `HandoffResponse` HMAC depends on the per-socket challenge, so
   nothing on the wire is a reusable token.

4. From a third host (Eve, spoofing Bob's IP), attempt to connect to
   Alice's advertised WSS port and replay the captured `HandoffAttach`
   bytes (the bare `session_id`).  Alice answers Eve's socket with a
   *fresh* `HandoffChallenge`; Eve cannot produce the matching
   `HandoffResponse` HMAC without the session's `tx_key`, which never
   left the legitimate primary session's AEAD.  Resistance derives
   from the session AEAD keys, **not** from Bob's identity private
   key.  Alice never binds Eve's socket to `swap_rx`.

**Pass criteria.** Eve's replayed attach is challenged but never
binds — the warm socket is dropped because the `HandoffResponse` HMAC
does not verify against Alice's `rx_key`; Alice's legitimate session
with Bob is unaffected, `session_id` unchanged.  (The exact log/reason
strings are implementation detail; treat the above as the expected
behaviour, not literal event names.)

---

## Reporting

For each scenario, capture:

- `veil-cli node show` and `sessions list` output before + after
  the swap;
- the full log span from `session.transport_swapped` on one host to
  the next delivered application frame on the other;
- `netsh trace` output sized down to the swap window.

File them under `reports/459-hot-standby-YYYY-MM-DD/scenario-N/`
in the operations repo.

---

## What Linux can and cannot cover

Unit tests in [crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs)
use `tokio::io::duplex` streams — zero-latency, lossless, always in
sync.  They prove the swap *mechanism* works in isolation.  Real-world
failure modes that only surface on Windows + across two machines:

- **Partial writes straddling swap** — Windows TCP can return
  `WSAEWOULDBLOCK` mid-frame on the old transport while the runner
  is processing the swap.  Linux duplex streams either complete or
  don't.  The "between frames" guarantee in stage (a) handles this,
  but only hardware testing confirms no partial bytes leak to the
  new transport.
- **Firewall + Windows Defender + AV heuristics** marking the swap
  traffic as suspicious (rapid socket open + close + open on the same
  IP).  This can add latency or outright block the swap, which
  changes the trigger-threshold calibration.
- **Windows Service mode** running the veil as the
  LocalSystem user — different socket credentials than a user-mode
  `veil-cli node run`.  TLS trust chain loading and per-user
  cert stores diverge.

Stages (b)+(c)+(d) are in-tree (2026-04-24), so these scenarios are
the standing regression suite — re-run them before each release that
touches `node/session/runner.rs` or the handshake path.  The only
genuinely-deferred item is the proactive RTT-based trigger.
