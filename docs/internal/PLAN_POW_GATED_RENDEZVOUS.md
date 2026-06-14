# PoW-Gated Rendezvous — on-demand listener provisioning

> Status: **IMPLEMENTED** — Slices 1–7 shipped. The design contract below is now
> live: wire frames + PoW primitives in `crates/veil-proto/src/rendezvous.rs`
> (`RequestEphemeralEndpointPayload`, `EphemeralEndpointResponsePayload`,
> `mine_pow_nonce*`, `verify_ephemeral_endpoint_response`; `SessionMsg::`
> `{RequestEphemeralEndpoint=22, EphemeralEndpointResponse=23}`), the on-demand
> listener controller (`crates/veil-transport/src/on_demand.rs`), the
> `RendezvousController` (`crates/veil-session/src/rendezvous.rs` + runner
> dispatch + `veil-dispatcher` recursive routing), the initiator client
> (`veil-node-runtime`), mediator-relay recursive routing, and metrics. The
> threat-model / wire-format / slice sections below are retained as the design
> record.
>
> This is the successor to Phase 5 (per-listener visibility and ephemeral
> rotation, commits `bdbf256`..`08b3f57`). Phase 5 made listener ports
> **rotate**, but they were still **persistently bound**. This plan goes
> further: a listener binds **only on demand**, for peers that prove
> proof-of-work, and shuts down automatically after a short TTL or one
> accepted session. (Proof-of-work, or PoW, is a small CPU puzzle the caller
> must solve before the node will act, which raises the cost of flooding it.)

## Threat model

### What we want to defend against

| Threat | Current state with Phase 5f | After this epic |
|---|---|---|
| Internet-wide port scanning (Shodan / nmap / Censys) finds the node | Listener bound on a rotating port in the configured range, so a scanner does find it within the range/TTL | Listener bound **only when a vetted peer asks**, so nmap sees zero open ports unless a PoW-gated request landed recently |
| Censor block-listing a reachable node-IP | IP discoverable through a scan even with Phase 5f rotation | IP undiscoverable from passive observation |
| DPI-based identification of veil traffic | Phase 1+5 obfs4 already disguises the wire bytes | Same |
| DDoS amplification (cheap-to-issue requests trigger expensive operations) | Open listener accepts everything; handshake CPU is the only gate | PoW gate shifts the cost to the requester (X CPU-seconds per dial attempt) |
| Sybil flooding the rendezvous mechanism | N/A (Phase 5 trusts an allowlist OR a public broadcast) | Per-requester rate limit plus adaptive PoW difficulty |

### Out of scope

- **Sender-side anonymity.** The requesting peer's IP is still visible to the
  rendezvous mediator (a DHT or PEX node). The existing `veil-anonymity`
  circuits (Epic 482) provide that layer separately and compose with this work.
- **Defeating active probing by a compromised mediator.** A mediator that
  accepts a forged rendezvous request can leak the target's ephemeral URI.
  The PoW gate raises the cost; it does not eliminate the attack. Future
  work: zero-knowledge PoW, where the verifier cannot forge requests it
  didn't relay.
- **Bandwidth amplification.** Out of scope; the existing
  `veil-abuse::BandwidthGate` covers it.

### Non-goals

- This is **NOT a replacement** for Phase 5 visibility levels. Public,
  Trusted, Hidden, and Ephemeral all stay valid choices for their use cases.
  PoW-gated rendezvous is a NEW level, "Stealth" or similar.
- It is **NOT a Tor onion-service clone.** veil's identity model and DHT
  routing have different invariants than Tor's HSDir / intro-circuit /
  rendezvous-circuit chain. We reuse veil's existing pieces rather than
  transplant Tor's.

## Architecture

### Components

```
                        ┌─────────────────────────────────┐
                        │  Initiator (wants to dial Bob)  │
                        └───────────┬─────────────────────┘
                                    │ 1. RequestEphemeralEndpoint
                                    │    {target=bob, requester=alice_pk,
                                    │     timestamp, pow_nonce}
                                    │
                                    │  via DHT-resolved control session OR
                                    │  PEX-walk piggyback
                                    │
                                    ▼
                        ┌─────────────────────────────────┐
                        │  Mediator (any veil node        │
                        │  with a session to Bob)         │
                        │  - relays the request to Bob    │
                        │    via the existing OVL1 session│
                        │  - takes a small fee in PoW     │
                        │    work-units (anti-flood)      │
                        └───────────┬─────────────────────┘
                                    │ 2. relayed inside OVL1
                                    ▼
                        ┌─────────────────────────────────┐
                        │  Target Bob (stealth listener)  │
                        │  ┌───────────────────────────┐  │
                        │  │ OnDemandRendezvous module │  │
                        │  │ - verify PoW              │  │
                        │  │ - rate-limit per requester│  │
                        │  │ - bind_random_port        │  │
                        │  │ - sign EphemeralEndpoint  │  │
                        │  │ - arm accept-once timer   │  │
                        │  └───────────┬───────────────┘  │
                        └──────────────┼──────────────────┘
                                       │ 3. EphemeralEndpointResponse
                                       │    {transport_uri, psk,
                                       │     valid_until, sig}
                                       │
                                       │  via the relay reverse path
                                       │
                                       ▼
                        ┌─────────────────────────────────┐
                        │  Initiator dials transport_uri  │
                        │  with psk; obfs4 handshake      │
                        │  proceeds normally              │
                        └─────────────────────────────────┘
                                       │
                                       │ 4. OVL1 session established
                                       │
                                       ▼
                        ┌─────────────────────────────────┐
                        │  Bob's accept-once timer drops  │
                        │  the listener after the one     │
                        │  accepted session (or TTL       │
                        │  expires).  Port is freed.      │
                        └─────────────────────────────────┘
```

### Why route the request through a mediator

There are two alternatives, and here is why we pick the relay model:

1. **Direct: the initiator connects to Bob's transport URI first, then
   sends the request on the OVL1 plane.** This cannot work — Bob has no
   listener bound, so there is nothing to connect to.

2. **Relay-mediated** (chosen): the initiator's existing connectivity —
   bootstrap peers, PEX-discovered relays — carries the request. Bob
   receives it over his ALREADY-OPEN sessions with relay nodes. No new
   bootstrap mechanism is needed.

3. **DHT publication**: Bob publishes an "ask-the-mediator" record under
   his node_id. The initiator does a DHT lookup, finds the mediator
   addresses, then routes the request. This adds overhead, so it is
   deferred to a follow-up slice; the initial implementation uses (2)
   directly.

### Wire formats

A new session-level message family, `Rendezvous` (or reuse `Session` with
fresh msg_types). Two frames:

```
// SessionMsg = 22 (next after Phase 5b TransportMigrationNotify = 21)

RequestEphemeralEndpointPayload {
    target_node_id:    [u8; 32],  // who the initiator wants to dial
    requester_pubkey:  [u8; 32],  // initiator's Ed25519 identity
    timestamp_unix:    u64,       // anti-replay window anchor
    pow_difficulty:    u32,       // claimed (verifier re-checks)
    pow_nonce:         u64,       // such that BLAKE3(canonical) has
                                  //   >= pow_difficulty leading zero bits
    requester_sig:     [u8; 64],  // Ed25519 sig over (target||requester||
                                  //   timestamp||difficulty||nonce)
                                  //   under requester_pubkey
}

// signable_bytes() = target_node_id || requester_pubkey || timestamp_be ||
//                    difficulty_be || nonce_be
// pow input = SIG_DOMAIN_REQUEST || signable_bytes()
//                    (separate domain from migration-notify to prevent
//                     cross-purpose replay)
// Wire size: 32 + 32 + 8 + 4 + 8 + 64 = 148 bytes

// SessionMsg = 23

EphemeralEndpointResponsePayload {
    target_node_id:    [u8; 32],  // who answered (== Bob's node_id)
    requester_pubkey:  [u8; 32],  // echo (anti-replay for another peer)
    transport_uri:     String,    // utf8 ≤ 240 bytes (matches Phase 5b cap)
    psk:               [u8; 32],  // one-shot PSK for this endpoint
    valid_until_unix:  u64,       // exp_unix
    sig:               [u8; 64],  // Ed25519 sig over canonical form
                                  //   under target's identity_pk
}

// signable_bytes() = target_node_id || requester_pubkey ||
//                    transport_len_be || transport_utf8 || psk ||
//                    valid_until_be
// Wire size: 32 + 32 + 2 + ≤240 + 32 + 8 + 64 = ≤410 bytes
```

The PoW canonical form **MUST** include `requester_pubkey`, so that a PoW
solution can't be transferred to a different requester. Difficulty sits
inside the signable surface too, so a stripping mediator can't downgrade an
adaptive bump.

### PoW design

- Function: BLAKE3 (matches the existing `IdentityConfig.nonce` PoW
  primitive).
- Difficulty unit: leading-zero **bits** in `BLAKE3(SIG_DOMAIN || canonical)`.
- Initial deployment difficulty: **24 bits** (~16M tries, about 0.5 CPU-sec
  on a typical 2-vCPU VPS). Tuneable per target node via config.
- Adaptive: the target node measures its incoming request rate and bumps the
  exposed `min_pow_difficulty` field on its rendezvous-config record (a
  separate DHT/PEX advertisement) when the rate crosses a threshold.
- Mining: a simple incremental loop over the `pow_nonce` field.

### On-demand listener controller

This extends Phase 5f's `EphemeralPortBinder` plus the accept-loop swap channel:

```rust
// crates/veil-transport/src/on_demand.rs (new module)

pub enum OnDemandTrigger {
    /// Request to bind a listener for exactly one accepted session.
    /// Listener drops after the first OVL1 handshake completes OR after
    /// `ttl` elapses, whichever first.
    BindOnce {
        ttl: Duration,
        psk: [u8; 32],
        port_range: RangeInclusive<u16>,
        bind_retries: u32,
    },
}

pub async fn bind_on_demand(
    trigger: OnDemandTrigger,
    swap_tx: mpsc::Sender<Box<dyn TransportListener>>,
    drop_signal_tx: mpsc::Sender<()>,  // accept-loop notifies on first session
) -> Result<u16> { ... }
```

How the drop_signal path works: after the accept-loop hands the connection
to spawn_inbound_session, it fires `drop_signal_tx`. The on-demand
controller's TTL timer and that drop signal race each other; whichever
completes first wins, and the controller then pushes a **null listener** (or
signals close some other way) to unbind.

### Anti-abuse infrastructure

- `OnDemandRendezvous::request_limiter: HashMap<NodeIdBytes, RateState>` —
  a per-requester rate limit, e.g. **3 requests per hour per pubkey**.
- Replay window: the timestamp must be within ±5 minutes of `now_unix()`.
- Forged-sig rejection: the requester's sig must verify under their declared
  pubkey, and that pubkey must not be banned.
- A quota on concurrent ephemeral listeners (e.g. 16 max in-flight) so a
  PoW-funded burst can't exhaust file descriptors.

## Slice plan

Estimated 6-10 implementation sessions. The slices are independent enough
that abandoning mid-stack still leaves a working tree.

### Slice 1 — Wire frames + PoW primitives (~300 LoC)

- A new `veil-proto::rendezvous` module with two payload structs
  (`RequestEphemeralEndpointPayload`, `EphemeralEndpointResponsePayload`),
  plus signable_bytes/encode/decode and sign/verify helpers.
- `pow_score` and `mine_pow_nonce` helpers — separate from identity-PoW,
  but reusing the BLAKE3 primitive.
- New `SessionMsg::RequestEphemeralEndpoint = 22` and
  `SessionMsg::EphemeralEndpointResponse = 23`, plus family.rs entries.
- Tests: 10-15 unit tests covering the wire round-trip, sig verify, the
  PoW difficulty boundary, the replay window, and domain separation.

### Slice 2 — On-demand listener controller (~500 LoC)

- A new `veil-transport::on_demand` module.
- A `bind_on_demand` async fn that combines `bind_random_port` (Phase 5a)
  with a per-request TTL timer and an accept-once drop signal.
- Test fixture: ScriptedBinder, a 1-session limit, and a drop-signal check.
- Integration with the swap-channel mechanism shipped in Phase 5f Step 3.

### Slice 3 — Rendezvous controller (server-side) (~400 LoC)

- A new `veilcore::node::rendezvous` module.
- An `OnDemandRendezvous` struct holding a per-requester rate limiter, a
  PoW verifier, a concurrent-listener semaphore, and an in-flight pubkey
  table.
- A dispatcher arm for `SessionMsg::RequestEphemeralEndpoint` in the session
  runner (the same pattern as the Phase 5e migration-notify arm).
- On a valid request: call `bind_on_demand`, sign the response, and push it
  back to the requester via session_tx_registry.
- Tests: 8-10 covering the happy path, replay rejection, bad-sig rejection,
  the rate-limit boundary, and the concurrent-listener quota.

### Slice 4 — Initiator client (~300 LoC)

- A `veilclient::rendezvous` module: `request_ephemeral_endpoint(target,
  difficulty_hint) -> Result<TransportUri + PSK>`.
- Mines the PoW (with a progress callback so the UI can show a spinner),
  signs the request, sends it via the existing OVL1 outbox, awaits the
  matching response, and validates the signature and timestamp.
- Tests: a mock target server that replies with a canned response; verify
  the client's PoW solution decodes correctly.

### Slice 5 — Config + spawn integration (~250 LoC)

- New `[listen.on_demand]` config block:
  ```toml
  [[listen]]
  id = "0x00000004"
  # `transport` not strictly needed — only port range + range matter
  visibility = "stealth"          # new variant

  [listen.on_demand]
  range          = [50000, 60000]
  pow_difficulty = 24             # leading-zero bits required
  ttl            = "5m"           # listener TTL after bind
  max_concurrent = 16
  rate_limit     = "3/h"          # per-requester
  ```
- `spawn_listeners` skips the physical bind for `stealth` entries; it
  spawns the `OnDemandRendezvous` controller instead.
- Config validation plus the reload path.

### Slice 6 — Mediator-relay routing (~250 LoC; **decision locked 2026-05-20**)

**Decision: reuse the existing `RecursiveQueryPayload` /
`RecursiveResponsePayload` envelope** rather than invent a new wire format.

#### Why this is the right primitive

The recursive-routing infrastructure already ships in production for DHT
FIND_NODE / FIND_VALUE / STORE, and it gives us the following for free:

* **Greedy forwarding** toward `target_key` by each intermediate node
  (`veil-proto::routing::handle_recursive_query`)
* **Per-query dedup** via a 16-byte random `query_id` plus the
  `recursive_query_seen` cache
* **TTL decrement** at each hop, with a canonical
  `MAX_RECURSIVE_RELAY_HOPS = 40` clamp
* **Reverse-path routing** through 4 fallback layers: sender, then a direct
  session to the initiator, then a route_cache hop, then the DHT k-closest
  (excluding self and sender to avoid loops)
* **Signed response** bound to the responder's long-term Ed25519 key, so a
  passive observer cannot forge a response with the captured `query_id`

PoW-Gated Rendezvous needs exactly this set of guarantees. Each alternative
— a new "ask-the-mediator" lookup, a PEX-walk piggy-back, session-layer
relay state — would duplicate some subset of the same machinery.

#### Wire contract — Slice 6a

* New constant `recursive_query_type::RENDEZVOUS_REQUEST = 4`
* Request envelope: `RecursiveQueryPayload`
  * `query_id` — a fresh 16-byte random value, initiator-allocated; used
    both for routing dedup and to correlate the initiator's response-await
  * `target_key` — `target_node_id` (where the request is destined)
  * `reply_to` — the initiator's `node_id`
  * `ttl` — operator-configurable; default `MAX_RECURSIVE_RELAY_HOPS`
  * `query_type = RENDEZVOUS_REQUEST`
  * `reply_port = 0` — route via the veil reverse path. A UDP-direct reply
    is not supported for rendezvous, since the target's IP is the very
    secret we're protecting.
  * `payload` — `RequestEphemeralEndpointPayload::encode()` bytes
    (148 bytes fixed, Slice 1)
* Response envelope: `RecursiveResponsePayload`
  * `query_id` — echoes the request's
  * `payload` — `EphemeralEndpointResponsePayload::encode()` bytes
    (≤ 410 bytes, Slice 1)
  * `responder_pubkey` — the target's Ed25519 verifying key, NOT a
    mediator's; the initiator validates `BLAKE3(responder_pubkey) ==
    target_node_id`
  * `signature` — the target's Ed25519(`query_id || payload`)
* The initiator runs its own check: `target_pubkey == responder_pubkey` AND
  the inner `EphemeralEndpointResponsePayload` passes
  `verify_ephemeral_endpoint_response()`

**Defense in depth:** the inner payload carries its own Ed25519 sig (Slice
1) over `requester_pubkey + transport_uri + psk + valid_until_unix`, under
domain `veil-rendezvous-response:v1` — disjoint from the outer envelope's
`query_id || payload` sig. A mediator that watched the response go by on the
wire cannot replay it to a different initiator, because the inner sig binds
`requester_pubkey`.

#### Slice 6 sub-slices

* **6a — proto extension** (~50 LoC + tests):
  * New constant `recursive_query_type::RENDEZVOUS_REQUEST = 4`
  * A doc comment that spells out the contract
  * One round-trip integration test through the proto layer
* **6b — target-side dispatcher arm** (~150 LoC + tests):
  * Extend the match in `dispatcher/routing.rs::handle_recursive_query`
    with a `RENDEZVOUS_REQUEST` arm
  * That arm parses the inner `RequestEphemeralEndpointPayload`, calls
    `dispatcher.rendezvous_weak.upgrade()?.handle_request(...)`, packs the
    granted response bytes into the outer `RecursiveResponsePayload`, and
    sends it back through the existing reverse-path layer
  * Reject the `RENDEZVOUS_REQUEST` arm when the controller is `None`
    (no stealth listener configured)
* **6c — initiator-side client** (~100 LoC + tests):
  * Extend `veilclient::rendezvous::RendezvousRequestBuilder` with a
    `build_recursive_query(target_pubkey)` helper that wraps the signed
    `RequestEphemeralEndpointPayload` in the recursive envelope with a
    fresh `query_id`
  * A `parse_recursive_response(bytes, expected_target_pubkey)` helper that
    extracts the inner `EphemeralEndpointResponsePayload` and runs the
    existing parse_and_verify
  * The caller-side response-await wiring lives outside the SDK, in a higher
    layer that bridges OVL1 sessions; the SDK ships only the encode/decode
    primitives

### Slice 7 — Anti-abuse instrumentation (~150 LoC)

- Prometheus metrics: `rendezvous_requests_received_total`,
  `_rejected_pow_failed_total`, `_rejected_rate_limit_total`,
  `_listeners_bound_total`, `_accepted_sessions_total`,
  `_ttl_expired_total`.
- A per-source rate limiter shared with the existing AbuseContext.

### Slice 8 — Tests + DPI shape verify (~500 LoC)

- Two-node integration test: an initiator with a canned identity plus a
  stealth target. It asserts that an nmap-equivalent socket scan shows zero
  open ports before the request, the listener appears within milliseconds
  of a valid request, and it disappears within the TTL.
- Sad path: forged sig, replayed timestamp, attempted PoW difficulty
  downgrade.
- Adaptive-difficulty soak: a burst of 1000 requests/sec triggers a
  difficulty bump; verify mid-soak that a legitimate slow rate still gets
  through.

### Slice 9 — Operator docs + testnet canary (~200 LoC docs + ansible)

- A `[listen.on_demand]` section in `docs/ru/config-reference.md`, mirroring
  Phase 5f's docs structure.
- `ansible/enable-stealth-canary.yml` plus a revert playbook.
- Testnet canary procedure: pick one node, enable stealth, confirm nmap from
  outside sees zero ports, and confirm a legit dial still succeeds through a
  relay.

## Acceptance gates (per slice)

Following Phase 5 precedent:

1. `cargo check --workspace --all-features` clean.
2. `cargo test -p <touched-crate>` green.
3. `cargo clippy --workspace --all-features --tests` zero new warnings.
4. Slice-specific behaviour test (the table in each slice description).
5. **Slice 3 and later**: an integration test that a stealth node stays
   nmap-invisible with no in-flight request, and accepts a one-shot session
   only after a valid PoW-gated request.

## Re-open triggers vs out-of-scope items

- **Zero-knowledge PoW** (the verifier can't forge requests it didn't
  relay): on hold. Significant cryptographic complexity for only a marginal
  threat-model gain over the PoW-cost-to-attacker scheme.
- **PoW difficulty learning** (a Bayesian estimator of the attacker's CPU
  budget): on hold; ship the linear adaptive bump first.
- **Multi-hop relay for the rendezvous request**: on hold. The first slice
  uses a single mediator. Extend to multi-hop once `veil-anonymity` circuits
  are more widely deployed.

## Total estimate

~2100 LoC plus ~500 LoC of tests, plus docs and ansible. 6-10 sessions,
depending on the Slice 6 mediator-channel decision — which may pull in PEX
or DHT work that would shift the line.

## How this composes with existing features

- **Phase 5f rotation** is orthogonal. A node can run BOTH a Phase 5f
  rotating listener (for high-bandwidth peers the operator wants reachable
  through PEX/DHT) AND a stealth listener (for anonymity-prioritised
  contacts). Different listen-table entries, different `visibility` levels.
- **Sovereign Identity** (Epic 462): `requester_pubkey` is the initiator's
  device-level identity_sk, already available on every node. No new keying
  material.
- **PEX PoW** (the existing `PEX_POW_DIFFICULTY`): reuse the same BLAKE3
  primitive and similar difficulty units, but a separate domain string so a
  PEX-PoW solution cannot replay as a rendezvous-PoW solution.
- **`veil-anonymity` circuits** (Epic 482): the initiator can route the
  rendezvous request *through* an anonymity circuit, decoupling its IP from
  what the mediator sees. This composes cleanly and needs no changes to
  either layer.
