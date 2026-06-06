# How the Veil Network Works

A guided tour of how Veil is built inside, for engineers who want the
shape of the system before they open the source.

Want more depth later? Three references go deeper:
[ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md) walks the whole system,
[NETWORK.md](NETWORK.md) focuses on how data moves, and
[WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) spells out the exact bytes on the
wire. Russian: [HOW_IT_WORKS.md](../ru/HOW_IT_WORKS.md).

---

## 1. What is this

Veil is a peer-to-peer network — every participant is an equal node,
with no central server. The nodes together form a **DHT** (a shared,
distributed address book; here a Kademlia one) so they can find each
other. They exchange encrypted messages, punch through home routers on
their own, and drop a message in a **mailbox** when the recipient is
offline so it waits there until they wake up. Encryption runs end to
end and is post-quantum: only the two endpoints can read a message, and
the math holds up even against a future quantum computer (ML-KEM-768 +
AEAD). There are just two kinds of node:

- **Leaf** — phones, IoT, lightweight clients. A leaf keeps no DHT,
  relays nothing, and hosts no mailbox. It simply connects to one or
  more Core nodes, either through peers you list in the config or
  through other nodes it discovers on the local network.
- **Core** — a full participant. It keeps a K=20 Kademlia bucket (its
  slice of the address book), relays traffic for others, hosts
  mailboxes, and can act as a gateway that holds the records pointing
  back to attached leaves.

```
              ┌──────────────────────────────────────┐
              │            CORE VEIL                 │
              │                                      │
              │   Core ─── Core ─── Core ─── Core    │
              │     │      ╱  ╲      │       │       │
              │     │    ╱     ╲     │       │       │
              │   Core ─ Core ─ Core ─ Core          │
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

When a leaf attaches to a Core node, that link is recorded through
Discovery (an `AttachmentPayload`) so the rest of the network knows how
to route a reply back to the leaf.

---

## 2. Stack: layers per node

```
┌──────────────────────────────────────────────────────┐
│   APP                                                │
│   ├─ IPC client (Unix / NamedPipe / TCP loopback)    │
│   └─ Veil client library (veilclient)                │
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

One rule keeps this stack easy to reason about: each layer runs
synchronously unless it is explicitly marked async. The dispatcher
(the part that looks at a frame and decides what to do with it) just
returns a `DispatchResult` — one of `Response`, `NoResponse`,
`Violation`, or `RateLimited` — and never waits on anything. All the
actual I/O happens in `tokio` tasks (lightweight background threads)
that sit above or below it.

---

## 3. Identity

```
keygen(Ed25519 | Falcon-512)  →  (public_key, private_key)
mine(pk, difficulty=24 bits)  →  nonce
node_id                       =  BLAKE3(public_key)
identity_proof                =  (pk, nonce, sign(pk, nonce))
```

- The `node_id` is a flat 256-bit name. There is **no PKI** and there
  are no domain names — a node's identity is just its key, nothing to
  register and no authority to trust.
- A node can sign with one of two algorithms: **Ed25519** (the default,
  and fast) or **Falcon-512** (post-quantum, with larger keys). You
  pick per node via `[identity] algo`. Either way BLAKE3 (a hash
  function) folds the public key down to the same 32-byte node_id.
- The Proof of Work — a small puzzle that makes minting fake identities
  cost real CPU — starts at 24 bits of difficulty (16 in debug builds).
  It scales with the network: `24 + ceil(log2(N / 100K))`, where N is
  the node count the DHT tracks per epoch.

An identity can also be **sovereign**: one master Falcon-512 key signs
the everyday Ed25519 keys of your individual devices. That is what lets
a messenger run on several devices at once and revoke any one of them on
its own. See [identity-model.md](identity-model.md).

---

## 4. Sessions: handshake → AEAD frames

Before two nodes can talk, they shake hands. A **handshake** is the
short back-and-forth where they prove who they are and agree on the keys
for everything that follows. Veil's handshake takes six round-trips, and
every step rides in an OVL1 frame:

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
     │  ... all subsequent frames AEAD'd       │
     │      with ChaCha20-Poly1305             │
```

Once `SessionConfirm` lands, the session is live and everything after it
is encrypted:
- Every frame goes out as `header || ciphertext`, where `ciphertext =
  ChaCha20-Poly1305(key, nonce=session_id||counter, plaintext, AAD=header)`.
  (AEAD just means the cipher both hides the contents and detects any
  tampering.)
- The keys don't last forever. A rekey kicks in after **128 GiB** of
  frames, after **32 days**, or when the AEAD counter wraps around —
  whichever comes first.
- Padding frames (`SessionMsg::Padding`) pad each record on the wire up
  to the MTU, so someone merely watching the traffic can't read message
  lengths off it.

### Hot-standby

A session can move from one transport to another mid-flight — TCP to
TLS, IPv4 to IPv6, one port to another — without redoing the handshake.
The AEAD state carries over, and the writer task simply swaps the
underlying socket at a frame boundary, so nothing notices the change.
See [hot-standby.md](hot-standby.md).

---

## 5. Routing: how messages find their destination

Routing is the job of getting a message to the right node when you only
know its address, not where it is. Veil leans on three mechanisms that
work together — a fast local cache, a global DHT lookup when the cache
misses, and a sender-drawn path when you already know the way:

### 5.1 Route cache (local gossip)

```
A announces route to D → B (TTL=2) → C (TTL=1, re-announce only to
                                       directly-connected) → STOP
```

A `ROUTE_ANNOUNCE` carries a TTL (time-to-live) of 2, so a popular route
spreads exactly two hops and no further. Entries in the cache expire on
their own (60 s by default). Each route gets a score from how it
behaves — round-trip time, jitter, congestion, and the peer's battery —
and you can tune what each factor counts for under `[routing]`. Veil
keeps the best few paths to each destination, not just one, so it can
spread load across them and fail over if one dies.

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

Each hop roughly halves the distance to the target, so a message reaches
it in about **O(log N)** hops — the count grows only slowly as the
network grows. And every delivery that succeeds drops a **reverse-path**
entry into the cache, so the next message heading the same way skips the
DHT walk entirely.

### 5.3 Source routing (sender-specified path)

Sometimes the sender already knows the exact relay chain to use — say an
operator handed it a trusted list, or a tool is testing connectivity. In
that case it sends a `DeliveryMsg::RelayPath` frame with the whole chain
packed inside. Each hop just hands the message to the next name on the
list — no DHT lookups, nothing read from any cache. One frame can carry
up to 64 hops.

```
A → RelayPath{path=[B,C,D,E,F], next_hop=0, inner=msg}
B receives, sees path[0]=self, forwards to C with next_hop=1
C → D → E → F (terminal): F decodes inner and delivers locally
```

This is handy for reaching across awkward network shapes the DHT
struggles with, for relay chains that must stay fixed, and for debugging
whether two nodes can reach each other at all.

### 5.4 Mailbox fallback

If a message can't be handed over live — the recipient is asleep, or the
hop budget ran out — it goes into a mailbox instead, copied across a
small set of nodes so it survives:

```
sender → STORE(MailboxRef.put(content_id, payload), 3 replicas)
recipient (on wake): FETCH(MailboxRef.list(my_node_id))
              → FETCH(content_id, ack)
```

Which nodes hold a given mailbox is decided by `BLAKE3(node_id)`, spread
across 3 replicas. Each one writes the message to a write-ahead log so a
crash won't lose it, and clears it only after the recipient confirms it
arrived.

---

## 6. End-to-end encryption

Veil encrypts in **two** separate layers, and they do different jobs:

| Layer | Algorithm | Scope | Purpose |
|-------|-----------|-------|---------|
| Session | X25519 ephemeral + HKDF + ChaCha20-Poly1305 | per-hop | Wire encryption between adjacent nodes |
| E2E | ML-KEM-768 + ChaCha20-Poly1305 | sender ↔ recipient | Payload is opaque to relays |

The session keys are fresh on every reconnect. The end-to-end layer
seals the message with the recipient's **published** ML-KEM-768 key —
found in the DHT, or piggybacked on a session — so the relays in between
can't read the contents no matter how many of them collude. The markers
`0xE2` and `0xE3` flag an end-to-end-wrapped envelope inside a `Forward`
payload.

---

## 7. Application layer

An app talks to the node — which runs as a background daemon — over IPC,
the local channel between two programs on the same machine (a Unix
socket, a Windows named pipe, or TCP over loopback). There are two ways
to send:

- **AppSend** — a fire-and-forget datagram aimed at a remote
  `(node_id, app_id, endpoint_id)` triple. You send it and move on; the
  network makes its best effort.
- **Stream** — a reliable, ordered stream over the veil, with flow
  control so a fast sender can't drown a slow reader. The daemon's
  `AppStreamTable` keeps the state for each open stream.

An app proves who it is with its `app_id`, a 32-byte handle it's given
when it registers. The IPC server decides what each app may do — a
client running in Leaf mode can't ask to relay transit traffic, for
instance.

---

## 8. Wire protocol at a glance

Every frame Veil sends starts with the same fixed header, laid out
byte by byte like this:

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

The header is a fixed **24 bytes**. There are no optional tacked-on
fields in v1 — if a new variant is ever needed, a kill-switch simply
rotates the magic number to a new value rather than bolting extensions
onto the old one. The body stays untouched until dispatch decides what
it is. Full reference: [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

---

## 9. NAT traversal

Most nodes sit behind a home router that hides them behind one shared
public address (this is NAT, network address translation), which makes
them hard to reach directly. Veil gets two such nodes connected in two
phases — first **discovery**, then **establishment**:

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

On a local network there's an even shorter path: nodes send out UDP
**mesh beacons** (multicast to 239.x.x.x), so two phones on the same
Wi-Fi find each other directly, without involving a Core node at all.

---

## 10. Anti-abuse

Defenses stack in layers, and each one is tracked per peer, so one bad
actor can't spoil things for everyone else:

| Layer | Action |
|-------|--------|
| Session limit | Max 32 sessions per IP source |
| PoW challenge | First-contact PoW (16-bit dev, 24-bit prod) |
| Rate limiter | Per-peer token bucket (configurable) |
| Violation tracker | 5 violations → 1 h ban; ban resets at 1 day |
| Reputation | Long-term per-peer score (uptime + relay success + vouches); transit gate 200 points |
| Memory budget | Global RAM cap with priority-based eviction |
| Congestion monitor | Real-time load; >78% → drop transit frames |

Any dispatch handler that spots a peer breaking the rules — a bad
signature, a frame it can't decode, a frame sent to the wrong place —
records a violation against that peer. The details are in
[SECURITY.md](SECURITY.md).

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

Everything above describes **OVL1 v1** (magic `0x4F564C31`, version byte
`0x01`). The protocol grows by having nodes negotiate which features
they support, and it grows safely: an old node that meets a frame family
it doesn't recognize just ignores it (`Unknown → forward-compatible`)
rather than choking on it.
