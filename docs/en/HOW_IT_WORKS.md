# How the Veil Network Works

A guided tour of the internal architecture, intended for engineers who
want to understand the system before diving into source.

For exhaustive source-level reference see
[ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md) (full walkthrough),
[NETWORK.md](NETWORK.md) (data-plane focus), and
[WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) (byte-level wire format).
Russian: [HOW_IT_WORKS.md](../ru/HOW_IT_WORKS.md).

---

## 1. What is this

A peer-to-peer veil network: nodes form a Kademlia DHT, exchange
encrypted messages, traverse NAT automatically, and fall back to
mailbox storage for offline recipients.  End-to-end encryption is
post-quantum (ML-KEM-768 + AEAD).  Two node roles only:

- **Leaf** — phones, IoT, lightweight clients.  No DHT, no relay, no
  mailbox.  Connects to one or more Core nodes via configured peers
  or local mesh.
- **Core** — full participant.  K=20 Kademlia bucket, relays for
  others, hosts mailboxes, may act as gateway for Leaf attachment
  records.

```
              ┌──────────────────────────────────────┐
              │            CORE VEIL               │
              │                                      │
              │   Core ─── Core ─── Core ─── Core    │
              │     │      ╱  ╲      │       │       │
              │     │    ╱     ╲     │       │       │
              │   Core ─ Core ─ Core ─ Core           │
              │    DHT (Kademlia, K=20)              │
              └────┬──────────────────────────┬──────┘
                   │                          │
              ┌────┴────┐                ┌────┴────┐
              │  Leaf   │                │  Leaf   │
              │ (phone) │                │ (phone) │
              └─────────┘                └─────────┘
                  │                          │
              ┌───┴───┐                  ┌───┴───┐
              │  App  │                  │  App  │
              └───────┘                  └───────┘
```

Leaf-to-Core attachment is registered via Discovery (`AttachmentPayload`)
so other nodes can route messages back to the Leaf.

---

## 2. Stack: layers per node

```
┌──────────────────────────────────────────────────────┐
│   APP                                                │
│   ├─ IPC client (Unix / NamedPipe / TCP loopback)    │
│   └─ Veil client library (veilclient)          │
└────────────────────────┬─────────────────────────────┘
                         │ IPC frames
┌────────────────────────┴─────────────────────────────┐
│   APPLICATION LAYER                                  │
│   ├─ AppEndpointRegistry  (endpoint mailbox channels)│
│   ├─ AppStreamTable       (stream FSM, windowing)    │
│   └─ IPC server           (auth, capability gates)   │
├──────────────────────────────────────────────────────┤
│   DISPATCH LAYER                                     │
│   FrameDispatcher — pure-sync family switch:         │
│   Session, Control, Discovery, Delivery, Routing,    │
│   App, Mesh, PeerExchange, Tunnel, RelayChain, Diag  │
├──────────────────────────────────────────────────────┤
│   SESSION LAYER                                      │
│   ├─ SessionRunner (one per peer; AEAD + WRR sched)  │
│   ├─ Handshake FSM (Hello→Identity→Caps→KEX→Confirm) │
│   ├─ Keepalive / Rekey / Hot-standby                 │
│   └─ Session TX registry (lock-free fan-out)         │
├──────────────────────────────────────────────────────┤
│   ROUTING / DHT                                      │
│   ├─ KademliaService (K=20, iterative lookup)        │
│   ├─ RouteCache (TTL, multi-path scoring)            │
│   ├─ Discovery (Attachment, AppEndpoint, MailboxRef) │
│   └─ MeshForwarder (UDP beacon, gateway bridge)      │
├──────────────────────────────────────────────────────┤
│   TRANSPORT                                          │
│   TCP / TLS / QUIC / WebSocket (ws,wss) / Unix       │
│   ─ pluggable; per-listener + per-peer overrides ─   │
└──────────────────────────────────────────────────────┘
```

Each layer is **sync** unless explicitly async — the dispatcher
returns `DispatchResult` (Response | NoResponse | Violation |
RateLimited) and never awaits.  All I/O lives in `tokio` tasks above
or below.

---

## 3. Identity

```
keygen(Ed25519 | Falcon-512)  →  (public_key, private_key)
mine(pk, difficulty=24 bits)  →  nonce
node_id                       =  BLAKE3(public_key)
identity_proof                =  (pk, nonce, sign(pk, nonce))
```

- `node_id` is a flat 256-bit ID; **no PKI**, no domain names.
- Two signature algorithms supported: **Ed25519** (default, fast) and
  **Falcon-512** (post-quantum, larger keys).  Choice is per-node,
  set via `[identity] algo`.  BLAKE3 collapses all pubkey
  formats to the same 32-byte node_id.
- PoW difficulty: 24 bits baseline (16 in debug); adaptive:
  `24 + ceil(log2(N / 100K))` from the DHT-tracked epoch.

Identity can be **sovereign** — a master Falcon-512 key signs delegated
Ed25519 device keys, enabling multi-device messengers with per-device
revocation.  See [identity-model.md](identity-model.md).

---

## 4. Sessions: handshake → AEAD frames

OVL1 handshake (6 round-trips, all OVL1-framed):

```
   Client                                    Server
     │                                         │
     │ ──Hello(OVL1, v1, node_id)──→           │
     │           ←──Hello──                    │
     │ ──Identity(algo, pk, nonce, mlkem_ek?)→ │
     │           ←──Identity──                 │
     │ ──Capabilities(role_bits, flags)──→     │
     │           ←──Capabilities──             │
     │ ──KeyAgreement(X25519 ephemeral pk)──→  │
     │           ←──KeyAgreement──             │
     │   [HKDF-SHA256 → tx_key, rx_key,        │
     │                  session_id]            │
     │ ──SessionConfirm(session_id, HMAC)──→   │
     │           ←──SessionConfirm──           │
     │                                         │
     │  ... all subsequent frames AEAD'd      │
     │      with ChaCha20-Poly1305            │
```

After `SessionConfirm`:
- Every frame is wrapped: `header || ciphertext`, where `ciphertext =
  ChaCha20-Poly1305(key, nonce=session_id||counter, plaintext, AAD=header)`.
- Rekey triggered at **128 GiB** of frames, **32 days**, or AEAD
  counter wrap-around — whichever comes first.
- Padding frames (`SessionMsg::Padding`) round wire-level records up
  to MTU so passive observers cannot infer message-length structure.

### Hot-standby

Every session can transparently migrate its underlying transport
(TCP → TLS, IPv4 → IPv6, port → port) without re-handshaking: the
AEAD state is preserved, the writer task swaps the underlying socket
between frame boundaries.  See [hot-standby.md](hot-standby.md).

---

## 5. Routing: how messages find their destination

Three independent mechanisms work in concert:

### 5.1 Route cache (local gossip)

```
A announces route to D → B (TTL=2) → C (TTL=1, re-announce only to
                                       directly-connected) → STOP
```

`ROUTE_ANNOUNCE` is sent with TTL=2, so popular routes propagate
exactly 2 hops.  Cache is TTL-based (60 s default), priced by
RTT + jitter + congestion + battery (configurable scoring weights
via `[routing]`).  Multi-path: top-K paths kept per destination for
load-balancing and failover.

### 5.2 Kademlia DHT (cache miss)

```
Sender A wants to reach D, no cached route:

   A finds N3 closest to node_id(D) in its bucket
   A sends RecursiveRelay(dst=D, payload) to N3

   N3: do I have a direct session to D?
       yes →  forward via session; done
       no  →  find N3's closest to D, forward to N3'
       ...
   After ≤ 16 hops, or mailbox fallback if D is offline.
```

This is **O(log N)** in expectation.  Every successful delivery
inserts a **reverse-path** entry into the cache, so subsequent
messages in the same direction skip the DHT walk.

### 5.3 Source routing (sender-specified path)

When the sender already knows the relay path (e.g. operator-supplied
trusted relay chain, or connectivity testing tool), it can send a
`DeliveryMsg::RelayPath` frame carrying the full chain inside the
payload.  Each hop just forwards to the next entry — no DHT lookups,
no cache dependencies.  Max 64 hops in one frame.

```
A → RelayPath{path=[B,C,D,E,F], next_hop=0, inner=msg}
B receives, sees path[0]=self, forwards to C with next_hop=1
C → D → E → F (terminal): F decodes inner and delivers locally
```

Used for: bridging pathological topologies, deterministic relay
chains, debug connectivity testing.

### 5.4 Mailbox fallback

If a message cannot be delivered live (recipient sleeping, hop
exhausted) it lands in a mailbox replica set:

```
sender → STORE(MailboxRef.put(content_id, payload), 3 replicas)
recipient (on wake): FETCH(MailboxRef.list(my_node_id))
              → FETCH(content_id, ack)
```

Mailbox is sharded by `BLAKE3(node_id)` to 3 replicas, persisted via
WAL, and ACKed once recipient confirms.

---

## 6. End-to-end encryption

There are **two** distinct encryption layers:

| Layer | Algorithm | Scope | Purpose |
|-------|-----------|-------|---------|
| Session | X25519 ephemeral + HKDF + ChaCha20-Poly1305 | per-hop | Wire encryption between adjacent nodes |
| E2E | ML-KEM-768 + ChaCha20-Poly1305 | sender ↔ recipient | Payload is opaque to relays |

Session keys rotate every reconnect.  E2E uses the recipient's
**published** ML-KEM-768 encapsulation key (in DHT or session
piggyback) — relays cannot read the payload even if they cooperate.
Markers `0xE2`/`0xE3` flag E2E-wrapped envelopes inside `Forward`
payloads.

---

## 7. Application layer

Apps talk to the node daemon over IPC (Unix socket / Windows NamedPipe
/ TCP loopback).  Two primary primitives:

- **AppSend** — fire-and-forget datagram to a remote `(node_id,
  app_id, endpoint_id)` triple.
- **Stream** — windowed reliable stream over the veil; the
  daemon's `AppStreamTable` tracks per-stream state.

App authentication uses `app_id` (a 32-byte handle issued at
registration).  The IPC server gates capabilities — a Leaf-mode IPC
client cannot, for example, request transit-relay.

---

## 8. Wire protocol at a glance

Every frame on the wire:

```
[0..4]   magic        = "OVL1" (0x4F564C31)
[4..5]   version      = 0x01
[5..6]   family       = u8  (Session, Control, Discovery, Delivery, ...)
[6..8]   msg_type     = u16 BE (variant within family)
[8..12]  reserved     = 0x00000000
[12..16] body_len     = u32 BE
[16..20] trace_id     = u32 BE (sampled tracing)
[20..24] flags+prio   = u8 prio | u8 traffic_class | u16 reserved
[24..]   body         = msg_type-specific payload
```

Header is **24 bytes**, no TLV extensions in v1 (kill-switch rotates
the magic to a new value if a variant is needed).  Body is opaque until
dispatch.  Full reference: [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

---

## 9. NAT traversal

Two-phase: **discovery** + **establishment**.

```
Phase 1 — Discovery:
  Leaf → Core: NatProbeRequest                    "what address do you see?"
  Core → Leaf: NatProbeResponse(observed_addr)    "I see you at A.B.C.D:port"
  Leaf stores `observed_addr` and publishes it via Discovery.

Phase 2 — Establishment:
  Peer X wants to reach Peer Y (both behind NAT):
    X publishes own NatProbe → Y publishes its own
    Each side simultaneously sends UDP punch packets
    First reply wins; session establishes
  Fallback: relay tunnel through a common Core node
            (configurable, off by default for Leaf).
```

Local-network discovery uses UDP **mesh beacons** (multicast 239.x.x.x)
so two phones on the same Wi-Fi find each other without going through
a Core node at all.

---

## 10. Anti-abuse

Layered defense, all per-peer:

| Layer | Action |
|-------|--------|
| Session limit | Max 32 sessions per IP source |
| PoW challenge | First-contact PoW (16-bit dev, 24-bit prod) |
| Rate limiter | Per-peer token bucket (configurable) |
| Violation tracker | 5 violations → 1 h ban; ban resets at 1 day |
| Reputation | Long-term per-peer score (uptime + relay success + vouches); transit gate 200 points |
| Memory budget | Global RAM cap with priority-based eviction |
| Congestion monitor | Real-time load; >78% → drop transit frames |

Violations are emitted by every dispatch handler that detects a
protocol invariant break (bad signature, decode failure, mis-routed
frame, etc.).  Specifics in [SECURITY.md](SECURITY.md).

---

## 11. Where to look next

| If you want to ... | Read |
|---|---|
| The byte-for-byte wire format | [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) |
| Every constant, every locking rule, every subsystem | [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md) |
| Operate a node in production | [OPERATIONS.md](OPERATIONS.md) |
| Read metrics + alerts | [MONITORING.md](MONITORING.md) |
| Build apps on top of the veil | [developer-guide.md](developer-guide.md), [messenger-dev.md](messenger-dev.md) |
| Understand identity & multi-device | [identity-model.md](identity-model.md), [multi-device.md](multi-device.md) |
| Configure transport handover | [hot-standby.md](hot-standby.md) |
| Adaptive routing / failover scoring | [adaptive-failover.md](adaptive-failover.md) |
| Private veil networks (membership-controlled) | [p-net.md](p-net.md) |
| Bridge veil traffic over TUN/TAP | [ogate.md](ogate.md) |

---

## 12. A note on terminology

The version of OVL1 documented here is **OVL1 v1** (magic
`0x4F564C31`, version byte `0x01`).  Capability negotiation extends
the protocol forward; old nodes simply ignore unknown frame families
(`Unknown → forward-compatible`).
