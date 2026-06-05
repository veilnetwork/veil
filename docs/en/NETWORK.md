# How the Veil Network Works

> This document gives a high-level tour.  For the full source-level description
> (wire formats, every constant, locking rules, subsystem interactions) see
> [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).

## Overview

A decentralized, E2E encrypted veil network with NAT traversal, DHT-routed delivery, and mesh capability.

```
App ←→ Leaf ←→ Core ←→ Core ←→ Core ←→ Leaf ←→ App
```

Key properties: E2E encryption (ML-KEM-768 + ChaCha20-Poly1305), O(log N) routing via Kademlia DHT, automatic NAT traversal, local mesh discovery, offline mailbox delivery.

## Node Roles

| Role | DHT | Relay | Mailbox | Gateway | Typical environment |
|------|-----|-------|---------|---------|---------------------|
| **Leaf** | - | - | - | - | Mobile phone, IoT sensor |
| **Core** | yes (K=20) | yes | yes | yes | Server, VPS, home server |

All Core nodes are equal participants: DHT, relay/forwarding, mailbox, gateway
(attachment records for leaf nodes). PoW ≥ 24 bits. Gateway can be disabled per-node
via `[gateway] enabled = false`.

Only two roles exist; the legacy `Relay`/`Gateway`/`CoreRouter` roles are not part of the protocol.

## Identity & PoW

```
keygen(Ed25519 | Falcon512) → (pubkey, privkey)
mine_nonce(pubkey, privkey, difficulty=24) → nonce
node_id = BLAKE3(pubkey)
identity_proof = (pubkey, nonce, sign(pubkey, nonce))
```

Both **Ed25519** and **Falcon-512** are first-class signing algorithms; choice is per-node (`[identity] algo`, which also offers the `ed25519+falcon512` / `ed25519+falcon1024` hybrids). BLAKE3(pubkey) yields the 32-byte `node_id` identically for both.

PoW difficulty: 24 bits baseline (16 in debug builds); adaptive = `24 + ceil(log2(N / 100K))` via epoch-based DHT records.

## Handshake (OVL1)

```
Client → Server: Hello(magic="OVL1", version=1, node_id)
Server → Client: Hello
Client → Server: Identity(algo, pubkey, nonce, node_id, mlkem_ek?)
Server → Client: Identity
Client → Server: Capabilities(role_bits, flags, max_frame, ovl1_minor=1)
Server → Client: Capabilities
Client → Server: KeyAgreement(X25519_pubkey)
Server → Client: KeyAgreement(X25519_pubkey)
  [HKDF-SHA256 → tx_key, rx_key, session_id]   (lex-order swap of tx/rx)
Client → Server: SessionConfirm(session_id, HMAC)
Server → Client: SessionConfirm
  [All subsequent frames: ChaCha20-Poly1305 AEAD encrypted]
```

ML-KEM-768 encapsulation key is carried inside `IdentityPayload` (1184 bytes; `mlkem_pk_len=0` means the peer does not publish one). Session keys come from the X25519 ephemeral DH plus HKDF-SHA256; ML-KEM is *not* used at the session layer today, only for E2E.

Rekey thresholds: 128 GiB of frames **or** 32 days **or** nonce-counter wrap-around. Both byte- and time-thresholds are configurable via `[session] rekey_bytes_threshold` / `rekey_time_threshold_secs`.

## Frame Dispatch

```
bytes → FrameHeader decode → AEAD decrypt → family switch:
  Session  → Hello/Identity/Capabilities/KeyAgreement/SessionConfirm, Rekey, Ticket, Padding
  Control  → Ping/Pong, NatProbe*, Keepalive, Backpressure, Epidemic
  Discovery→ FindNode, FindValue, Store, Delete, Attachment, Mailbox/AppEndpoint lookup
  Delivery → Forward, Mailbox PUT/Fetch/Ack, Transit, RecursiveRelay, Chunks
  Routing  → RouteAnnounce/Withdraw (+Aliased), RouteRequest/Response, PoW, RouteDiscover
  App      → AppOpen, AppData, AppRtData, AppReceipt, AppWindowUpdate
  Mesh     → MeshBeacon, MeshForward, MeshAck
  PeerExchange → Walk, Challenge, Response, Result
  Tunnel   → IpPacket (TUN/TAP)
  RelayChain → Hop (onion)
  Diag     → DiagPing/Pong, TraceProbe/Hop
  Unknown  → ignored (forward-compatible)
```

## Routing: Gossip + DHT

**Local gossip** (TTL=2): ROUTE_ANNOUNCE → immediate neighbors learn routes.

**DHT forwarding** (cache miss): RecursiveRelay wraps ForwardPayload → sent to XOR-closest DHT node → each hop checks for live session to dst → deliver or forward closer → mailbox fallback after 20 hops.

```
A announces → B (TTL=1) → C (TTL=0, stop)
A → route cache miss → RecursiveRelay(dst=D)
  → closest node X → X has session to D? → deliver!
  → X doesn't → forward to closer Y → ... → mailbox fallback
```

Reverse path caching: successful RecursiveRelay delivery inserts `originator → peer_id` in route cache.

## Message Delivery (3 Paths)

**Path 1 — Direct** (route cache hit):
```
Sender → FORWARD(dst) → route_cache.lookup(dst) → next_hop → ... → Recipient
```

**Path 2 — DHT-routed** (cache miss):
```
Sender → FORWARD(dst) → cache miss → RecursiveRelay(dst, hop=20)
  → DHT hop chain → node with live session to dst → deliver
```

**Path 3 — Mailbox** (offline recipient):
```
Sender → MAILBOX_PUT → Primary (recipient's attachment gateway from DHT)
  Primary:
    store locally
    select_quorum_replicas:
      shard_target = BLAKE3("shard" || recipient_id || shard_id)
      pool         = DHT.find_closest_nodes(shard_target, (replica_count-1)*4)
      filter out   self, origin, low-battery, unreliable relays
      take         replica_count - 1 replicas
    MAILBOX_REPLICATE → replicas (envelope encrypted for privacy)
    wait for write_quorum DeliveryStatus::QUEUED → ACK sender

Recipient comes online:
  MAILBOX_FETCH → primary gateway
    local store → DHT fallback → fan-out MAILBOX_FETCH_REPLICA on replicas
    SEC check: recipient_node_id == authenticated peer_id
```

Selection of replicas is **deterministic**: any Core node with a DHT view can independently compute `shard_target` and find the same closest replicas — the sender and the recipient don't need to exchange host addresses.

## DHT (Kademlia)

256 k-buckets × K contacts (K=20 per the Kademlia paper). XOR distance metric.

**Iterative lookup**: seed K closest → query α=3 per round → merge responses → converge (at most `MAX_ROUNDS=20`).

**Sharding**: `shard_id = key[0]`; each node covers 16 nearest shards out of 256. Shard-aware STORE filtering is opt-in.

**Tiered storage**: hot HashMap + cold tier; LRU promotion on access; demotion on hot overflow; eviction on cold overflow. The cold tier is an in-memory HashMap by default, but can be a disk-backed RocksDB store via `[dht] cold_store_path` (cargo feature `rocksdb-cold`, on by default for `veil-cli`), which lifts the entry-count ceiling from RAM to disk (>1M entries) and survives restarts. Falls back to the in-memory cold tier — with a startup log line — if the feature is absent or the RocksDB open fails.

**Eclipse defense**: at most `K/4 = 5` contacts per /24 IPv4 (/48 IPv6) subnet in a single bucket.

**STORE / DELETE authentication**:
- `StorePayload` carries optional Ed25519 signature over `key || value`.
- `DeletePayload` requires `algo + pubkey + signature` (any identity signature algo — Ed25519, Falcon-512, or an Ed25519+Falcon hybrid); accepted only when `BLAKE3(pubkey) == key`.

## Discovery & Attachment

```
Leaf starts → attach to Core → AnnounceAttachment(node_id, role, gateways, mailboxes, expires_at)
  → signed → stored in DHT at attachment_key(node_id)
Peer wants to reach Leaf → GetAttachment(node_id) → learns Core gateways/mailboxes → route
```

## E2E Encryption

```
sender: (ct, ss) = ML-KEM-768.Encaps(recipient_ek)
        plaintext_envelope → ChaCha20-Poly1305(ss, nonce) → ciphertext
        send(E2E_MARKER || ct || ciphertext)

recipient: ss = ML-KEM-768.Decaps(dk, ct)
           plaintext = ChaCha20-Poly1305.open(ss, nonce, ciphertext)
```

Relay nodes see only ciphertext — no access to plaintext.

## NAT Traversal

```
A behind NAT → connect to Relay R
A wants to reach B (also behind NAT):
  A → R: NatProbe(B's observed addr)
  R → B: NatProbeRelay(A's observed addr)
  B opens port for A → A connects directly
  Fallback: relay tunnel through R
```

## Mesh Networking

```
IoT device ← UDP beacon (multicast/broadcast, 30-sec interval) → Gateway
  Gateway sees beacon → auto-discover → establish veil session
  Gateway bridges local mesh ↔ global veil
```

Beacons carry node_id, realm_id (UUID), transport URIs, and a signed algo/pubkey.
Multiple realms can coexist on the same physical segment — peers ignore beacons
with a foreign `realm_id`.

## Peer Exchange (PEX)

Random-walk-based transport discovery (Family 11):

```
Originator → seed:        PexWalk (walk_id, pubkey, nonce, signature, TTL)
Terminator → originator:  PexChallenge (PoW challenge)
Originator → terminator:  PexResponse (solution, origin_sig)
Terminator → originator:  PexResult (peer list with transport URIs)
```

Multi-algo: `origin_sig` is verified as Ed25519 (32-byte pubkey) or Falcon-512 (longer pubkey) via `crypto::verify_message`.

## Abuse Protection

```
Inbound connection:
  1. Per-IP session limit (32 max)
  2. PoW challenge (if configured)
  3. Handshake timeout (10s — `HANDSHAKE_TIMEOUT_SECS`)
  4. Per-peer rate limiter (token bucket)
  5. Violation tracker (5 violations → ban)
  6. Ban list (auto-expire after TTL)
  7. Congestion backpressure (>78% → drop transit)
  8. Reputation gate (200 points for transit)
```

## Observability

- **Prometheus metrics**: `GET /metrics` — counters, gauges for all subsystems
- **Structured logging**: `[timestamp] LEVEL event message` (JSON-L optional)
- **Debug capture**: `debug capture` CLI — live frame capture to file
- **DiagPing**: end-to-end latency probe through veil
- **Trace buffer**: last N dispatch events for debugging
