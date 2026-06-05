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
> Successor к Phase 5 (per-listener visibility / ephemeral rotation
> [commits `bdbf256`..`08b3f57`]).  Phase 5 made listener ports
> **rotating** but still **persistently bound**.  This plan goes further:
> listener bound **on-demand only** for peers that prove proof-of-work,
> с automatic shutdown after а short TTL or one accepted session.

## Threat model

### What we want к defend against

| Threat | Current state с Phase 5f | After this epic |
|---|---|---|
| Internet-wide port scanning (Shodan / nmap / Censys) finds the node | Listener bound on rotating port в configured range → scanner does find it within the range / TTL | Listener bound **only когда vetted peer asks** → nmap sees zero open ports unless а PoW-gated request landed recently |
| Censor block-listing reachable node-IP | IP discoverable through scan even с Phase 5f rotation | IP undiscoverable from passive observation |
| DPI-based identification of veil traffic | Phase 1+5 obfs4 already disguises wire bytes | Same |
| DDoS amplification (cheap-to-issue requests trigger expensive operations) | Open listener accepts всё, handshake CPU is the gate | PoW gate moves the cost к the requester (X CPU-seconds per dial-attempt) |
| Sybil flooding the rendezvous mechanism | N/A (Phase 5 trusted by allowlist OR public broadcast) | Per-requester rate-limit + adaptive PoW difficulty |

### Out of scope

- **Sender-side anonymity** — requesting peer's IP is still visible к the
  rendezvous-mediator (DHT/PEX node).  Existing `veil-anonymity` circuits
  (Epic 482) provide that layer separately и compose с this work.
- **Defeating active probing by а compromised mediator** — а mediator
  что accepts а forged rendezvous request can leak the target's
  ephemeral URI.  The PoW gate raises the cost, не eliminates the
  attack.  Future work: zero-knowledge PoW where the verifier cannot
  forge requests it didn't relay.
- **Bandwidth amplification** — out of scope; existing
  `veil-abuse::BandwidthGate` covers it.

### Non-goals

- This is **NOT а replacement** для Phase 5 visibility levels.  Public /
  Trusted / Hidden / Ephemeral remain valid choices для their
  use-cases.  PoW-gated rendezvous is а NEW level "Stealth" or
  similar.
- **NOT а Tor onion-service clone** — veil's identity model + DHT
  routing has different invariants than Tor's HSDir / intro-circuit
  / rendezvous-circuit chain.  We re-use veil's existing pieces
  rather than transplant Tor's.

## Architecture

### Components

```
                        ┌─────────────────────────────────┐
                        │  Initiator (wants к dial Bob)   │
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
                        │  with а session к Bob)          │
                        │  - relays the request к Bob     │
                        │    via the existing OVL1 session│
                        │  - takes а small fee in PoW     │
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
                        │  с psk; obfs4 handshake         │
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

### Why route the request through а mediator

Two alternatives и why we pick the relay model:

1. **Direct: initiator connects к Bob's transport URI first, sends
   request на the OVL1 plane.**  Cannot work — Bob has no listener
   bound; нечем connect к.

2. **Relay-mediated** (chosen): initiator's existing connectivity
   (bootstrap peers, PEX-discovered relays) carries the request.
   Bob receives it через his ALREADY-OPEN sessions с relay nodes.
   No new bootstrap mechanism needed.

3. **DHT publication**: Bob publishes "ask-the-mediator" record под
   his node_id.  Initiator does DHT lookup → finds mediator
   addresses → routes request.  More overhead; deferred к а follow-up
   slice (initial implementation uses (2) directly).

### Wire formats

New session-level message family `Rendezvous` (or reuse `Session` с
fresh msg_types).  Two frames:

```
// SessionMsg = 22 (next after Phase 5b TransportMigrationNotify = 21)

RequestEphemeralEndpointPayload {
    target_node_id:    [u8; 32],  // who the initiator wants к dial
    requester_pubkey:  [u8; 32],  // initiator's Ed25519 identity
    timestamp_unix:    u64,       // anti-replay window anchor
    pow_difficulty:    u32,       // claimed (verifier re-checks)
    pow_nonce:         u64,       // such что BLAKE3(canonical) has
                                  //   >= pow_difficulty leading zero bits
    requester_sig:     [u8; 64],  // Ed25519 sig over (target||requester||
                                  //   timestamp||difficulty||nonce)
                                  //   under requester_pubkey
}

// signable_bytes() = target_node_id || requester_pubkey || timestamp_be ||
//                    difficulty_be || nonce_be
// pow input = SIG_DOMAIN_REQUEST || signable_bytes()
//                    (separate domain от migration-notify к prevent
//                     cross-purpose replay)
// Wire size: 32 + 32 + 8 + 4 + 8 + 64 = 148 bytes

// SessionMsg = 23

EphemeralEndpointResponsePayload {
    target_node_id:    [u8; 32],  // who answered (== Bob's node_id)
    requester_pubkey:  [u8; 32],  // echo (anti-replay для another peer)
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

PoW canonical form **МUST** include `requester_pubkey` so PoW solutions
are not transferable к а different requester.  Difficulty included
inside the signable surface so adaptive bumps can't be downgraded by
а stripping mediator.

### PoW design

- Function: BLAKE3 (matches existing `IdentityConfig.nonce` PoW
  primitive).
- Difficulty unit: leading-zero **bits** в `BLAKE3(SIG_DOMAIN || canonical)`.
- Initial deployment difficulty: **24 bits** (~16M tries ≈ 0.5 CPU-sec
  на typical 2-vCPU VPS).  Tuneable per-target ноde via config.
- Adaptive: target ноde measures incoming request rate; bumps the
  exposed `min_pow_difficulty` field on its rendezvous-config record
  (separate DHT/PEX advertisement) когда rate exceeds threshold.
- Mining: simple incremental loop on `pow_nonce` field.

### On-demand listener controller

Extension of Phase 5f's `EphemeralPortBinder` + accept-loop swap channel:

```rust
// crates/veil-transport/src/on_demand.rs (new module)

pub enum OnDemandTrigger {
    /// Request к bind а listener для exactly one accepted session.
    /// Listener drops после the first OVL1 handshake completes OR after
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

The drop_signal path: accept-loop, after handing the connection к
spawn_inbound_session, fires `drop_signal_tx`.  The on-demand controller's
TTL timer и the drop signal race; first-to-complete wins, then the
controller pushes а **null listener** (or signals close some other way)
к unbind.

### Anti-abuse infrastructure

- `OnDemandRendezvous::request_limiter: HashMap<NodeIdBytes, RateState>`
  — per-requester rate limit, e.g. **3 requests per hour per pubkey**.
- Replay window: timestamp must be within ±5 minutes of `now_unix()`.
- Forged-sig rejection: requester's sig must verify under their declared
  pubkey, и that pubkey must not be banned.
- Quota on concurrent ephemeral listeners (e.g. 16 max in-flight) к
  prevent а PoW-funded burst from exhausting file descriptors.

## Slice plan

Estimated 6-10 implementation sessions.  Slices independent enough
that mid-stack abandonment leaves а working tree.

### Slice 1 — Wire frames + PoW primitives (~300 LoC)

- New `veil-proto::rendezvous` module с two payload structs
  (`RequestEphemeralEndpointPayload`, `EphemeralEndpointResponsePayload`),
  signable_bytes/encode/decode, sign/verify helpers.
- `pow_score` + `mine_pow_nonce` helpers, separate from identity-PoW
  но re-using BLAKE3 primitive.
- New `SessionMsg::RequestEphemeralEndpoint = 22`,
  `SessionMsg::EphemeralEndpointResponse = 23`, family.rs entries.
- Tests: 10-15 unit tests covering wire round-trip, sig verify,
  PoW difficulty boundary, replay-window, domain-separation.

### Slice 2 — On-demand listener controller (~500 LoC)

- New `veil-transport::on_demand` module.
- `bind_on_demand` async fn что combines `bind_random_port` (Phase 5а)
  + per-request TTL timer + accept-once drop signal.
- Test fixture: ScriptedBinder + 1-session limit + drop-signal verify.
- Integration с the swap-channel mechanism shipped Phase 5f Step 3.

### Slice 3 — Rendezvous controller (server-side) (~400 LoC)

- New `veilcore::node::rendezvous` module.
- `OnDemandRendezvous` struct holding: per-requester rate limiter,
  PoW verifier, concurrent-listener semaphore, в-flight pubkey table.
- Dispatcher arm для `SessionMsg::RequestEphemeralEndpoint` в session
  runner (similar pattern к Phase 5e migration-notify arm).
- On valid request: call `bind_on_demand`, sign response, push back via
  session_tx_registry to the requester.
- Tests: 8-10 covering happy-path + replay-rejection + bad-sig-rejection
  + rate-limit boundary + concurrent-listener quota.

### Slice 4 — Initiator client (~300 LoC)

- `veilclient::rendezvous` module: `request_ephemeral_endpoint(target,
  difficulty_hint) -> Result<TransportUri + PSK>`.
- Mines PoW (with а progress callback so UI can show spinner),
  signs request, sends via existing OVL1 outbox, awaits matching
  response, validates signature и timestamp.
- Tests: mock target server что responds с canned response, verify
  client's PoW solution decodes correctly.

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
  ttl            = "5m"           # listener TTL после bind
  max_concurrent = 16
  rate_limit     = "3/h"          # per-requester
  ```
- `spawn_listeners` skips physical bind для `stealth` entries; instead
  spawns the `OnDemandRendezvous` controller.
- Config validation + reload path.

### Slice 6 — Mediator-relay routing (~250 LoC; **decision locked 2026-05-20**)

**Decision: reuse the existing `RecursiveQueryPayload` /
`RecursiveResponsePayload` envelope** instead of inventing а new
wire format.

#### Why это is the right primitive

The recursive-routing infrastructure (already shipped в production
for DHT FIND_NODE / FIND_VALUE / STORE) gives us для free:

* **Greedy forwarding** toward `target_key` by each intermediate node
  (`veil-proto::routing::handle_recursive_query`)
* **Per-query dedup** via а 16-byte random `query_id` + the
  `recursive_query_seen` cache
* **TTL decrement** at each hop с canonical
  `MAX_RECURSIVE_RELAY_HOPS = 40` clamp
* **Reverse-path routing** through 4 fallback layers:
  sender → direct session к initiator → route_cache hop → DHT
  k-closest (excluding self + sender к avoid loops)
* **Signed response** binding к the responder's long-term Ed25519
  key so passive observers cannot forge а response с the captured
  `query_id`

PoW-Gated Rendezvous needs exactly this set of guarantees.  The
alternatives (new "ask-the-mediator" lookup, PEX-walk piggy-back,
session-layer relay state) each require duplicating some subset of
the same machinery.

#### Wire contract — Slice 6a

* New constant `recursive_query_type::RENDEZVOUS_REQUEST = 4`
* Request envelope: `RecursiveQueryPayload`
  * `query_id` — fresh 16-byte random (initiator-allocated;
    used both for routing dedup и для initiator's response-await
    correlation)
  * `target_key` — `target_node_id` (where the request is destined)
  * `reply_to` — initiator's `node_id`
  * `ttl` — operator-configurable; default `MAX_RECURSIVE_RELAY_HOPS`
  * `query_type = RENDEZVOUS_REQUEST`
  * `reply_port = 0` (route via veil reverse path; UDP-direct
    reply not supported for rendezvous since target's IP is the
    secret we're protecting)
  * `payload` — `RequestEphemeralEndpointPayload::encode()` bytes
    (148 bytes fixed, Slice 1)
* Response envelope: `RecursiveResponsePayload`
  * `query_id` — echoes the request's
  * `payload` — `EphemeralEndpointResponsePayload::encode()` bytes
    (≤ 410 bytes, Slice 1)
  * `responder_pubkey` — target's Ed25519 verifying key (NOT а
    mediator's); initiator validates `BLAKE3(responder_pubkey) ==
    target_node_id`
  * `signature` — target's Ed25519(`query_id || payload`)
* Initiator computes its own verify: `target_pubkey ==
  responder_pubkey` AND inner `EphemeralEndpointResponsePayload`
  passes `verify_ephemeral_endpoint_response()`

**Defense in depth:** the inner payload's own Ed25519 sig (Slice 1)
covers `requester_pubkey + transport_uri + psk + valid_until_unix`
under domain `veil-rendezvous-response:v1`, disjoint от the
outer envelope's `query_id || payload` sig.  А mediator that observed
the response on the wire cannot replay it к а different initiator
because the inner sig binds `requester_pubkey`.

#### Slice 6 sub-slices

* **6a — proto extension** (~50 LoC + tests):
  * New constant `recursive_query_type::RENDEZVOUS_REQUEST = 4`
  * Doc что spells the contract
  * One round-trip integration test через the proto layer
* **6b — target-side dispatcher arm** (~150 LoC + tests):
  * Extend `dispatcher/routing.rs::handle_recursive_query`'s match
    с а `RENDEZVOUS_REQUEST` arm
  * The arm: parse inner `RequestEphemeralEndpointPayload`, call
    `dispatcher.rendezvous_weak.upgrade()?.handle_request(...)`,
    pack the granted response bytes into the outer
    `RecursiveResponsePayload`, send back через the existing
    reverse-path layer
  * Reject `RENDEZVOUS_REQUEST` arms когда controller is `None`
    (no stealth listener configured)
* **6c — initiator-side client** (~100 LoC + tests):
  * Extend `veilclient::rendezvous::RendezvousRequestBuilder` с
    а `build_recursive_query(target_pubkey)` helper що wraps the
    signed `RequestEphemeralEndpointPayload` в the recursive
    envelope с а fresh `query_id`
  * `parse_recursive_response(bytes, expected_target_pubkey)` helper
    что extracts the inner `EphemeralEndpointResponsePayload` и runs
    the existing parse_and_verify
  * Caller-side response-await wiring lives outside the SDK (in а
    higher layer что bridges OVL1 sessions); SDK ships только the
    encode/decode primitives

### Slice 7 — Anti-abuse instrumentation (~150 LoC)

- Prometheus metrics: `rendezvous_requests_received_total`,
  `_rejected_pow_failed_total`, `_rejected_rate_limit_total`,
  `_listeners_bound_total`, `_accepted_sessions_total`,
  `_ttl_expired_total`.
- Per-source rate-limiter shared с existing AbuseContext.

### Slice 8 — Tests + DPI shape verify (~500 LoC)

- Two-node integration test: initiator с canned identity + stealth
  target.  Asserts: nmap-equivalent socket scan shows zero open ports
  before the request, listener appears within milliseconds после
  valid request, disappears within TTL.
- Sad-path: forged sig, replayed timestamp, exhausted PoW
  difficulty downgrade.
- Adaptive difficulty soak: burst of 1000 requests/sec triggers
  difficulty bump, verify mid-soak that legitimate slow rate still
  gets through.

### Slice 9 — Operator docs + testnet canary (~200 LoC docs + ansible)

- `[listen.on_demand]` section в `docs/ru/config-reference.md` (mirror
  Phase 5f's docs structure).
- `ansible/enable-stealth-canary.yml` + revert playbook.
- Testnet canary procedure: pick one node, enable stealth, verify
  nmap from outside sees zero ports, verify legit dial succeeds через
  relay.

## Acceptance gates (per slice)

Following Phase 5 precedent:

1. `cargo check --workspace --all-features` clean.
2. `cargo test -p <touched-crate>` green.
3. `cargo clippy --workspace --all-features --tests` zero new warnings.
4. Slice-specific behaviour test (table в each slice description).
5. **Slice 3 + later**: integration test что а stealth-node remains
   nmap-invisible с no in-flight request, и accepts а one-shot session
   only после valid PoW-gated request.

## Re-open triggers vs out-of-scope items

- **Zero-knowledge PoW** (verifier can't forge requests it didn't relay):
  hold; significant cryptographic complexity, marginal threat-model
  improvement over PoW-cost-to-attacker scheme.
- **PoW difficulty learning** (bayesian estimator of attacker's CPU
  budget):  hold; ship the linear adaptive bump first.
- **Multi-hop relay для rendezvous request**: hold; first slice
  uses а single mediator.  Extends к multi-hop когда `veil-anonymity`
  circuits are wider-deployed.

## Total estimate

~2100 LoC + ~500 LoC tests + docs/ansible.  6-10 sessions depending
on Slice 6 mediator-channel decision (which may pull in PEX или DHT
work что would shift the line).

## Composition с existing features

- **Phase 5f rotation** is orthogonal — а ноде can run BOTH а Phase 5f
  rotating listener (для high-bandwidth peers что the operator wants
  reachable through PEX/DHT) AND а stealth listener (для anonymity-
  prioritised contacts).  Different listen-table entries, different
  `visibility` levels.
- **Sovereign Identity** (Epic 462) — `requester_pubkey` is the
  initiator's device-level identity_sk (already available на every
  ноde).  No new keying material.
- **PEX PoW** (existing `PEX_POW_DIFFICULTY`) — re-use the same BLAKE3
  primitive и similar difficulty units, но separate domain string so а
  PEX-PoW solution cannot replay as а rendezvous-PoW solution.
- **`veil-anonymity` circuits** (Epic 482) — initiator can route
  the rendezvous request *through* an anonymity circuit, decoupling
  initiator-IP from mediator visibility.  Composes cleanly; не
  requires changes к either layer.
