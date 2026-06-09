# Veil — detailed network design

This document describes the Veil network (the OVL1 protocol) in enough detail to implement a compatible node from scratch, or to run a security audit. Every numeric constant and structure here is taken straight from `veilcore/src/` at the current state of the repository.

> For an introductory overview, see [ARCHITECTURE.md](ARCHITECTURE.md). For the field-level wire format, see [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) and [protocol-spec.md](protocol-spec.md).

---

## Contents

1. [Overview and principles](#1-overview-and-principles)
2. [Topology: node roles](#2-topology-node-roles)
3. [Identity: node_id, PoW, keys](#3-identity-node_id-pow-keys)
4. [Transport layer](#4-transport-layer)
5. [The OVL1 wire protocol](#5-the-ovl1-wire-protocol)
6. [Session plane (handshake and channel encryption)](#6-session-plane-handshake-and-channel-encryption)
7. [E2E encryption](#7-e2e-encryption)
8. [Discovery: DHT (Kademlia)](#8-discovery-dht-kademlia)
9. [Discovery: service records](#9-discovery-service-records)
10. [Routing](#10-routing)
11. [Delivery](#11-delivery)
12. [Mailbox (offline delivery)](#12-mailbox-offline-delivery)
13. [Peer Exchange (PEX)](#13-peer-exchange-pex)
14. [Mesh (local UDP network)](#14-mesh-local-udp-network)
15. [NAT traversal](#15-nat-traversal)
16. [Anti-abuse and protection](#16-anti-abuse-and-protection)
17. [Adaptive parameters](#17-adaptive-parameters)
18. [App layer and IPC](#18-app-layer-and-ipc)
19. [Observability](#19-observability)
20. [Runtime and process structure](#20-runtime-and-process-structure)

---

## 1. Overview and principles

Veil is a decentralized peer-to-peer (P2P) network that relays messages between applications. Its key properties:

- **Stable identifiers.** `node_id = BLAKE3(public_key)` — 32 bytes, independent of IP, NAT, and transport.
- **Cryptography.** Signatures use Ed25519 or Falcon-512 (the latter is post-quantum, or PQ). The handshake runs an ephemeral X25519 Diffie-Hellman exchange, then protects the channel with ChaCha20-Poly1305 AEAD; end-to-end (E2E) traffic adds ML-KEM-768 on top (see §7).
- **E2E encryption.** ML-KEM-768 at the application layer. Relays see only ciphertext.
- **DHT routing.** Kademlia (K=20, α=3) gives O(log N) lookup and recursive delivery.
- **Multiple transports.** TCP, TLS, QUIC, WebSocket (ws/wss), Unix socket, and SOCKS5 with wrappers.
- **NAT traversal.** ICE-like hole-punching, with a relay fallback through a Core node when a direct path fails.
- **Mailbox.** When the recipient is offline, the message is parked on Core nodes and replicated through a write-ahead log (WAL).
- **Local mesh network.** A UDP beacon plus a realm bridge keep a segment working even with no internet.
- **Sybil protection.** Proof of Work (PoW) of at least 24 bits — adaptive — on the node identifier.
- **Flood protection.** A per-peer token bucket feeds a violation tracker, which feeds a ban list; congestion triggers backpressure.

### Layers

```
Application          App ↔ IPC (Unix socket) ↔ AppEndpointRegistry
                                     │
Dispatch             FrameDispatcher — family-switch by FrameFamily
                                     │
Session              SessionRunner — ChaCha20-Poly1305 AEAD, WRR
                                     │
Transport            TCP / TLS / QUIC / WS / WSS / Unix / SOCKS5
```

---

## 2. Topology: node roles

File: [`crates/veil-cfg/src/model.rs`](../../crates/veil-cfg/src/model.rs), enum `NodeRole`.

| Role | DHT | Relay | Mailbox | Gateway | Use case |
|------|-----|-------|---------|---------|----------|
| **Leaf** | no | no | no | no | Mobile clients, IoT, limited connectivity |
| **Core** | yes (K=20) | yes | yes | yes (by flag) | Servers, VPS, always online |

The default role is `Core`. A node has exactly one role, fixed in the config for the life of the process. Capability-exchange packets carry it as a bitmask in `CapabilitiesPayload.roles_supported`:

```
bit 0 — LEAF
bit 3 — CORE
```

Bits `1 (RELAY)`, `2 (GATEWAY)`, and `4 (CORE_ROUTER)` were once standalone roles. They have since been removed.

### Capability flags

`CapabilitiesPayload.flags` (1 byte) — `cap_flags` from [`proto/session.rs`](../../crates/veil-proto/src/session.rs):

| Bit | Constant | Meaning |
|-----|----------|---------|
| 0 | `CAN_RELAY` | Willing to forward third-party traffic |
| 1 | `CAN_MAILBOX` | Willing to accept Mailbox records |
| 2 | `CAN_GATEWAY_LOCAL_MESH` | Acts as a bridge between mesh and veil |
| 3 | `CAN_PARTICIPATE_DHT` | Participates in the DHT table |
| 4 | `CAN_ACCEPT_APP_STREAMS` | Accepts AppOpen/AppData |
| 5 | `CAN_STORE` | Stores DHT values locally |
| 6 | `SUPPORTS_TRANSIT` | Can handle `DeliveryMsg::Transit` (stateless relay) |

A Core node defaults to `CAN_RELAY | CAN_PARTICIPATE_DHT | CAN_STORE | CAN_MAILBOX`. A Leaf sets nothing — it is a passive consumer.

---

## 3. Identity: node_id, PoW, keys

### 3.1 node_id

```
node_id = BLAKE3(raw_public_key_bytes)        // 32 bytes
```

The hash runs over the raw public-key bytes, not the base64 string. The CLI and config show the result as a 64-character hex string.

### 3.2 Signature algorithms

- **Ed25519** — 32-byte pubkey, 64-byte signature. Fast and classical.
- **Falcon-512** — roughly 897-byte pubkey, roughly 666-byte signature. Post-quantum, for nodes that require PQ.

You configure the choice with `[identity] algo = "ed25519" | "falcon512" | "ed25519+falcon512" | "ed25519+falcon1024"`. The enum is `veil_types::SignatureAlgorithm`.

On the wire, `algo` travels as a single byte. `IdentityPayload` and the mesh beacon follow this convention:

```
algo = 0  — Ed25519
algo = 2  — Falcon-512
algo = 3  — Ed25519+Falcon-512 hybrid
algo = 4  — Ed25519+Falcon-1024 hybrid
```

(The DHT `DeletePayload` accepts all canonical signature algorithms — `0`/`1` Ed25519, `2` Falcon-512, `3`/`4` hybrid — so hybrid-signed records can be self-deleted by their owner.)

In the session handshake, `algo = 1 → Ed25519` — a historical quirk (see `handshake::algo_to_u8`).

### 3.3 Proof-of-Work (Sybil protection)

Every `node_id` must carry a PoW proof. The rule is `leading_zero_bits(BLAKE3(pubkey ∥ nonce ∥ sign(pubkey, nonce))) ≥ difficulty` — the hash has to start with at least `difficulty` zero bits.

- **Base difficulty:** 24 bits in production, 16 bits in debug builds. See [`identity_policy.rs`](../../crates/veil-cfg/src/identity_policy.rs).
- **Maximum:** `MAX_POW_DIFFICULTY = 24` (from [`proto/budget.rs`](../../crates/veil-proto/src/budget.rs)).
- **Adaptive difficulty:** `24 + ceil(log2(N / 100_000))`, where `N` is the estimated network size. It is published as an `EpochDifficultyRecord` in the DHT (the epoch is a unix-day).
- **Recommended production floor:** `RECOMMENDED_PRODUCTION_POW_DIFFICULTY = 16` — the lowest difficulty a production node should accept.
- **Concurrent solvers:** `MAX_CONCURRENT_POW_SOLVERS = 4` — caps a fork attack that grinds many candidates at once.

Mining lives in `identity_ops.rs` and `cmd/identity/mine.rs`, with a lazy miner in `node/lazy_miner.rs`.

### 3.4 Key material

| Key | Size | Purpose | Storage |
|-----|------|---------|---------|
| Ed25519 sk | 32 B seed | Identity signing, DHT DELETE | Config (base64) |
| Ed25519 pk | 32 B | Verification | In handshake |
| Falcon-512 sk | 1281 B | Signing (alternative to Ed25519) | Config |
| Falcon-512 pk | 897 B | Verification | In handshake |
| ML-KEM-768 ek | 1184 B | Encapsulation for E2E | Published in DHT |
| ML-KEM-768 dk | seed 64 B | E2E decapsulation | Config |
| X25519 ephemeral | 32 B × 2 | Session exchange | Generated per-session |

Sensitive types (`Base64PrivateKey`, `PowParams`, `SessionKeys`) carry a custom `Debug` that redacts their contents, so a key never leaks into a log line.

---

## 4. Transport layer

File: [`crates/veil-transport/src/`](../../crates/veil-transport/src/).

### 4.1 Supported URI schemes

The parser is [`transport/uri.rs`](../../crates/veil-transport/src/uri.rs), enum `TransportUri`:

| Scheme | Description |
|--------|-------------|
| `tcp://host:port` | Raw TCP |
| `tls://host:port?sni=...&alpn=...` | TLS over TCP (BoringSSL by default, rustls — fallback) |
| `quic://host:port?sni=...&alpn=...` | QUIC via `quinn` |
| `unix:///path` | Unix domain socket |
| `socks://proxy/target` | TCP via SOCKS5 |
| `sockstls://proxy/target` | TLS via SOCKS5 |
| `ws://host:port/path` | WebSocket wrapper over TCP |
| `wss://host:port/path` | WebSocket + TLS |

They nest through `TransportStack::Wrapped { lower, wrapper }`. For example, `sockstls://` becomes `Wrapped(Wrapped(Tcp, Socks), Tls)` — TLS wrapping SOCKS5 wrapping TCP.

### 4.2 Back-ends and fingerprints

- **`TransportBackendKind`**: BoringSSL (feature `tls-boring`) is the **default** TLS back-end for the `veil-cli`, `ogate`, and `oproxy` binaries (`veil-cli` Cargo.toml: `default = ["rocksdb-cold", "tls-boring"]`); the `veilcore` **library** defaults to rustls (`default = ["rocksdb-cold"]`). BoringSSL produces a Chrome-like ClientHello fingerprint (JA3/JA4) and rotates it — the main way to slip past deep packet inspection (DPI). Turn it off with `--no-default-features`.
- **`TransportFingerprintMode`**: picks which TLS fingerprint (the ClientHello) to present, so Veil can hide behind a Chrome or Firefox template.
- **`TransportOperatingMode`**: Server, Client, or Mixed.
- **`WebSocketHandshakeMode`**: legacy or extended.

### 4.3 Transport discovery

A node announces its transports in the `TransportRegistry`. The actual listener starts through `listener_supervisor.rs`. If a listener dies, the supervisor restarts it with backoff.

---

## 5. The OVL1 wire protocol

### 5.1 Frame header (24 bytes)

[`proto/header.rs`](../../crates/veil-proto/src/header.rs):

```
Offset  Len  Type   Field        Description
------  ---  -----  -----------  -------------------------------------
  0      4   bytes  magic        "OVL1" = 0x4F564C31
  4      1   u8     version      = 1
  5      1   u8     family       FrameFamily (0..11)
  6      2   u16BE  msg_type     type within the family
  8      2   u16BE  flags        bitmask (see below)
 10      2   u16BE  header_len   24 (or more with TLV extensions)
 12      4   u32BE  body_len     payload size
 16      4   u32BE  stream_id    stream multiplexing
 20      4   u32BE  request_id   RPC correlation
```

`body_len` tops out at `MAX_FRAME_BODY = 16 MiB`. Each listener also has a configurable soft limit, `max_frame_body_bytes` (default 1 MiB).

### 5.2 Flags

Bits in `flags`:

```
0..1  priority       0=RealTime, 1=Interactive, 2=Bulk, 3=Background
```

The remaining bits are reserved and must be 0. Older docs list `encrypted` and `require_ack` as wire flags. They are not: encryption is a property of the whole session, and `require_ack` lives in the body of the `DeliveryEnvelope`.

### 5.3 Frame families

[`proto/family.rs`](../../crates/veil-proto/src/family.rs), enum `FrameFamily`:

| ID | Family | Messages |
|----|--------|----------|
| 0 | Session | Hello, Identity, Capabilities, KeyAgreement, SessionConfirm, Attach, Detach, Keepalive, RekeyInit/Ack, MlKemRekeyEk/Ack, Ticket, SleepAdvertisement, Padding, and the connection-handoff variants: HandoffInit(16), HandoffAck(17), HandoffAttach(18), HandoffChallenge(24), HandoffResponse(25). HandoffChallenge=24/HandoffResponse=25 — handoff wire v2 (challenge-response), which replaced the old static HMAC over HandoffAttach=18 |
| 1 | Control | Ping/Pong, NeighborOffer, RouteProbe/Reply, Error, NatProbeRequest/Reply, NatRelayRequest, Keepalive(0x10)/Ack, EpidemicBroadcast(0x20), Backpressure(0x30) |
| 2 | Discovery | FindNode, FindValue, Store, Delete, AnnounceAttachment, GetAttachment, GetMailboxSet, GetAppEndpoint, FindNodeResponse, FindValueResponse |
| 3 | Delivery | MailboxPut/Fetch/Ack, Forward, DeliveryStatus, MailboxReplicate, MailboxFetchReplica, ChunkManifest, Chunk, Transit(0x10), RecursiveRelay(0x11) |
| 4 | App | AppOpen, AppData, AppClose, AppSend, AppReceipt, AppWindowUpdate, AppRtData |
| 5 | Mesh | Forward, Beacon, Ack |
| 6 | LocalApp | 22 types of IPC messages (see §18) |
| 7 | Tunnel | IpPacket — TUN/TAP encapsulation |
| 8 | Routing | RouteAnnounce/Withdraw, RouteRequest/Response, PowChallenge/Response/Accept, RouteAnnounceAliased/WithdrawAliased, RouteDiscover/Offer, RecursiveQuery/Response(0x10/0x11), RouteUpdate(0x12), VersionVectorSync(0x13) |
| 9 | Diag | Ping/Pong, TraceProbe, TraceHop |
| 10 | RelayChain | Hop — onion-encrypted chain |
| 11 | PeerExchange | Walk, Challenge, Response, Result |

An unknown `family` yields `ProtoError::UnknownFamily`; an unknown `msg_type` yields `UnknownMsgType`. The dispatcher simply ignores such frames, which keeps old nodes forward-compatible with newer ones.

### 5.4 Unified minor version

`OVL1_MINOR_VERSION = 1` (see `proto/budget.rs`). Features used to sit behind version gates, but every gate is now open unconditionally. The field stays on the wire in case it is needed again.

---

## 6. Session plane (handshake and channel encryption)

### 6.1 Sequence

The client opens the OVL1 handshake. Frames stay in plaintext up to `SessionConfirm`; from there on, every frame in the session is encrypted with ChaCha20-Poly1305.

```
Initiator                                        Responder
   │── Hello (magic "OVL1", version=1, node_id) ──→ │
   │ ←───────────── Hello (responder node_id) ──────│
   │── Identity (algo, pubkey, nonce, node_id, mlkem_ek?) ──→ │
   │ ←── Identity ───────────────────────────────────│
   │── Capabilities (role_bits, flags, frame_size) ──→ │
   │ ←── Capabilities ───────────────────────────────│
   │── KeyAgreement (X25519 ephemeral pubkey) ────→ │
   │ ←── KeyAgreement ───────────────────────────────│
   │          [HKDF-SHA256 → session keys]           │
   │── SessionConfirm (session_id, HMAC) ──────→ │
   │ ←── SessionConfirm ─────────────────────────────│
   │          [AEAD encrypted from here]             │
   │── Attach (optional; leaf → core gateway) ─→ │
```

### 6.2 HelloPayload (34 bytes)

```
[0..2]  ovl1_version  u16BE = 1
[2..34] node_id       [u8; 32]
```

### 6.3 IdentityPayload (variable)

```
[0]                  algo         u8 (0/1=Ed25519, 2=Falcon512, 3=Ed25519+Falcon512, 4=Ed25519+Falcon1024)
[1..3]               pk_len       u16BE
[3..3+pk]            public_key   bytes
[3+pk]               nonce_len    u8
[4+pk..4+pk+n]       nonce        bytes   (hex string of the PoW nonce)
[4+pk+n..4+pk+n+32]  node_id      [u8; 32]
[4+pk+n+32..+2]      mlkem_pk_len u16BE   (0 — no key)
[..]                 mlkem_pk     bytes   (1184 B for ML-KEM-768)
```

The pubkey always travels raw. The verifier confirms `BLAKE3(public_key) == node_id`.

### 6.4 CapabilitiesPayload (3 bytes, wire v3)

```
[0]  roles_supported  u8  (role_bits bitmask: bit0=leaf, bit3=core)
[1]  flags            u8  (cap_flags: CAN_RELAY=0x01, SUPPORTS_SOVEREIGN_IDENTITY=0x02,
                         ANONYMITY_RELAY=0x04, SUPPORTS_HYBRID_KEX=0x08)
[2]  discovery_mode   u8  (0=Public, 1=ContactsOnly)
```

Wire v3 dropped the legacy 12-byte form (`transports_sup`, `max_frame_size`, `max_streams`,
`ovl1_minor`). The decoder still accepts the 2-byte form (roles + flags), in which case
`discovery_mode` defaults to `Public`.

### 6.5 KeyAgreement + SessionKeys

Payload: `algo(1) + key_len(2) + X25519_pubkey(32)`.

The X25519 key is **ephemeral**: a fresh one is generated for each handshake, and
it has no link to the long-term identity (Ed25519 / Falcon-512). That gives forward
secrecy — compromising the identity does not unlock past sessions.

Both nodes compute the same keys:

```
shared_secret = X25519(my_ephemeral_sk, peer_ephemeral_pk)

salt = local_node_id XOR remote_node_id     // commutative — both sides
                                            // get the same salt
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a ‖ key_b ‖ session_id] = HKDF-SHA256(salt, ikm, info, L=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id  → (key_a, key_b)
                   else                                 → (key_b, key_a)
```

`tx_key` encrypts outgoing frames; `rx_key` decrypts incoming ones. Ordering the
two `node_id`s lexicographically guarantees that initiator and responder end up with
mirrored assignments — `alice.tx == bob.rx`, and the reverse. There is no separate
`mac_key`: the AEAD tag (`ChaCha20-Poly1305`) and the handshake MAC in
`SessionConfirm` cover integrity.

Implementation: [`crypto/session_kdf.rs::derive_session_keys`](../../crates/veil-crypto/src/session_kdf.rs).

### 6.6 SessionConfirm

```
[0..32]  session_id [u8; 32]
[32..64] mac        [u8; 32]
                    └ BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret
                            ‖ small_node_id ‖ large_node_id)
```

`small` and `large` are the node_id pair in lexicographic order, so both sides
arrive at the same MAC no matter who sent first.
Implementation: [`node/session/handshake.rs::compute_confirm_mac`](../../crates/veil-session/src/handshake.rs).

The MAC commits to the shared_secret and to both node_ids. An observer who lacks
the X25519 secret cannot forge it, even by replaying the handshake messages
verbatim. Once a side receives a valid `SessionConfirm`, it switches the channel
to AEAD. From then on the `session_id` keys the `SessionTxRegistry` and the
resumption ticket.

### 6.7 AEAD protection

Algorithm: **ChaCha20-Poly1305**.

- The nonce is 12 bytes — a per-session counter that only increases. As it nears overflow, the session rekeys.
- The frame `body` is encrypted; the 24-byte header stays in plaintext.
- The `aad` (additional authenticated data) is that 24-byte header.

### 6.8 Rekey

A rekey fires when any one of these is crossed:

- `REKEY_BYTES_THRESHOLD = 128 GiB` of data transferred, or
- `REKEY_TIME_THRESHOLD_SECS = 32 days` (2,764,800 s), or
- the nonce counter nearing overflow.

The byte and time thresholds are configurable via `[session] rekey_bytes_threshold` and
`rekey_time_threshold_secs` in the node config.

```
Initiator ── RekeyInit (new ephemeral X25519 pubkey) ──→ Responder
Initiator ← RekeyAck  (responding ephemeral X25519 pubkey) ── Responder

new_shared = X25519(new_ephemeral_priv, peer_new_ephemeral_pub)
salt       = session_id XOR local_node_id XOR remote_node_id
                       └ the chain-salt binds the new keys to the session history
info       = "ovl1-session-rekey-v1"
[key_a ‖ key_b ‖ new_session_id] = HKDF-SHA256(salt, new_shared, info, L=96)
(tx_key, rx_key) — swap by lex-order node_id, as in §6.5
```

Implementation: [`crypto/session_kdf.rs::derive_rekey_keys`](../../crates/veil-crypto/src/session_kdf.rs).

### 6.9 Ticket resumption

After a successful handshake, the server hands the client an encrypted `SessionTicket`. The client can present it in the TLV (type-length-value) extension of `HelloPayload` to resume a session quickly, skipping the full handshake.

- `SESSION_TICKET_TTL_SECS = 3600` (1 hour) — the normal lifetime.
- `SESSION_TICKET_MAX_AGE_SECS = 7200` — the hard age limit, with a grace window for clock skew.

### 6.10 Keepalive and hibernation

- `Keepalive` (Control, 0x10) and `KeepaliveAck` (0x11) — a heartbeat sent every `session.keepalive_interval_secs`.
- A session idle for longer than `session.idle_timeout_secs` is closed.
- `SleepAdvertisement` (Session, 13) — the node warns its mailbox hosts that it is about to go offline, and the hosts extend retention to `expected_wake_ts + grace`.

### 6.11 ML-KEM rekey

`MlKemRekeyEk` and `MlKemRekeyAck` carry a new public encapsulation key for E2E. They let a node rotate its long-lived ML-KEM key without a restart.

### 6.12 Padding

`SessionMsg::Padding` (14) — a no-op frame with a random body. It pads the real frames up to the MTU at the TLS-record level, which makes passive traffic analysis harder.

---

## 7. E2E encryption

File: [`proto/e2e.rs`](../../crates/veil-proto/src/e2e.rs).

### 7.1 Markers in `DeliveryEnvelope.payload`

| First byte | Constant | Meaning |
|------------|----------|---------|
| `0xE2` | `E2E_MARKER` | Ordinary E2E: `sender_node_id` in plaintext, payload encrypted |
| `0xE3` | `META_E2E_MARKER` | Meta-E2E (onion): the sender is hidden; `sender_node_id = [0; 32]` on the wire |
| any | (no marker) | Plain-text delivery (only with explicit opt-in) |

### 7.2 Format of `E2eEnvelope` (after the marker byte)

```
[0]            version       u8 = 1
[1..3]         kem_ct_len    u16BE  (1088 for ML-KEM-768)
[3..N]         kem_ct        bytes  (ML-KEM ciphertext)
[N..N+12]      nonce         [u8; 12]
[N+12..N+16]   ct_len        u32BE
[N+16..]       ciphertext    bytes  (ChaCha20-Poly1305 ct + 16 B tag)
```

### 7.3 Algorithm

```
1. (kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_ek)
2. key  = HKDF-SHA256(
             ikm  = shared_secret,
             info = "ovl1-e2e-v1" || src_id || dst_id
          )[0..32]
3. nonce = random[12]
4. aad   = src_id || dst_id
5. ct    = ChaCha20-Poly1305.Seal(key, nonce, plaintext, aad)
```

A relay sees only the `E2eEnvelope`. Without the recipient's secret key, it cannot decrypt the contents.

### 7.4 Key management

- **Publishing `ek`:** when an application binds an endpoint, the node publishes an `AppEndpointResponse` to the DHT (see §9), with the ek embedded in the record.
- **Storing `dk`:** in the config, as a 64-byte base64 seed; rotated via `MlKemRekeyEk` inside an active session.
- **Peer ek cache:** `peer_mlkem_keys` holds up to `MAX_PEER_MLKEM_CACHE = 4096` keys, each with TTL `ipc.e2e_key_ttl_secs` (default 3600 s).

### 7.5 Meta-E2E (onion)

Meta-E2E encrypts not just the payload but the `DeliveryEnvelope` itself — the `sender_node_id`, `src_app_id`, `app_id`, and `endpoint_id` fields. Relays then see only `recipient_node_id` plus `ttl/created_at`. This fits anonymous sending (`AppIpcSend` with flag=anonymous).

---

## 8. Discovery: DHT (Kademlia)

File: [`crates/veil-dht/src/`](../../crates/veil-dht/src/).

### 8.1 Parameters

| Constant | Value | Source |
|----------|-------|--------|
| `K` | 20 | `dht/routing.rs::K` |
| `ALPHA` | 3 | `dht/iterative.rs::ALPHA` |
| `MAX_ROUNDS` | 20 | `dht/iterative.rs::MAX_ROUNDS` |
| MAX per /24 subnet in a bucket | K/4 = 5 | `dht/routing.rs` (anti-Eclipse) |

### 8.2 Routing table

- 256 k-buckets, one per bit of XOR distance.
- Each bucket is a `VecDeque<Contact>` with capacity `K`.
- Least-recently-used (LRU) ordering: a contact seen recently moves to the tail.
- To insert into a full bucket, the node pings the oldest contact; if it answers, the newcomer is dropped.

### 8.3 XOR metric

```
distance(a, b) = a XOR b        // 32 bytes
closest_to(target, n) = sort_by(xor(node_id, target)).take(n)
```

### 8.4 Iterative lookup

`dht::iterative::find_node_iterative`:

```
shortlist = K closest known contacts to target
queried = {}
repeat until max_rounds or until shortlist stops improving:
    pick α unqueried nodes from shortlist
    send FindNode(target, k=K) in parallel
    merge respondents → shortlist (top-K by XOR)
    queried ∪= picked
return top-K of shortlist
```

`find_value_iterative` works the same way, except it returns the value the moment it gets a `FindValueResponse::Value(v)`.

### 8.5 Sharding and tiered storage

**Sharding.** `shard_id = key[0]`, and each node covers the 16 nearest shards out of 256. With `DhtConfig.shard_filtering = true`, a node discards any STORE that falls outside its shards.

**Tiered storage.** There are two tiers:
- **Hot** — a size-limited `HashMap<key, value>` for fast access.
- **Cold** — by default a larger in-memory `HashMap` that promotes an entry to hot when it is accessed. The cold tier can instead live on disk in RocksDB, enabled via `[dht] cold_store_path` (behind the cargo feature `rocksdb-cold`, on by default for `veil-cli` and `veilcore`). Disk storage lifts the capacity ceiling off RAM (over 1M entries) and survives restarts. If `cold_store_path` is unset, the feature is absent, or RocksDB fails to open, the node falls back to the in-memory cold tier and logs a line saying so.

When the hot tier overflows, entries demote to cold; when cold overflows, entries are evicted.

### 8.6 DhtValue envelope (§5.5 of the spec)

All DHT records are wrapped in a `DhtValue`:

```
[0..32]   key       [u8; 32]
[32]      kind      u8  (0=raw, 1=attachment, 2=mailbox, 3=app_endpoint)
[33..37]  epoch     u32BE
[37..41]  ttl_secs  u32BE
[41..49]  seq_no    u64BE
[49..53]  body_len  u32BE
[53..]    body      bytes
[+2]      sig_len   u16BE
[+slen]   signature bytes  (empty — unsigned)
```

The signature covers the prefix `[0..53+body_len]` — everything up to and including the body.

### 8.7 DHT operations

The `KademliaService` handles all of these ([`dht/kademlia.rs`](../../crates/veil-dht/src/kademlia.rs)).

#### Store

`StorePayload`:
```
[0..32]  key        [u8; 32]
[32..36] value_len  u32BE
[36..]   value      bytes
[+]      sig_flag   u8   (0=unsigned, 1=signed)
[+32]    ed25519_pk [u8; 32]      (if signed)
[+64]    ed25519_sig[u8; 64]      (if signed)
```

The signature is Ed25519 over `key || value`. A Core node stores the record; a Leaf rejects it (`KademliaError::NotAllowed`).

#### Delete

A delete requires proof that you own the key.

```
DeletePayload:
[0..32]           key         [u8; 32]
[32]              algo        u8  (0=Ed25519, 2=Falcon512)
[33..35]          pk_len      u16BE
[35..35+pk]       public_key  bytes
[+2]              sig_len     u16BE
[+slen]           signature   bytes
```

Verification in [`verify_store_ownership`](../../crates/veil-dht/src/kademlia.rs#L1524):

1. `algo` ∈ {0, 2}, otherwise `NotAllowed`.
2. `crypto::verify_message(algo, pk, key_bytes, sig)` → `Ok`.
3. `BLAKE3(public_key) == key` — self-owned only.

The "self-owned only" policy covers `node_id` keys. Nothing currently issues a DELETE for mailbox or app_endpoint keys.

#### FindNode / FindValue

```
FindNodePayload:     target[32] + k[2]
FindNodeResponse:    count[2] + NodeContact[]
FindValuePayload:    key[32]
FindValueResponse:   either Value(bytes) or Nodes(contacts[])
```

A `NodeContact` is `node_id[32] + transport_len[2] + transport_uri[bytes]`.

### 8.8 DHT protection

| Attack | Mitigation |
|--------|------------|
| Sybil on a bucket | PoW ≥ 24 on node_id |
| Eclipse /24 | Max `K/4 = 5` contacts from one /24 IPv4 (or /48 IPv6) in a bucket |
| Poisoning | `DhtValue.expires_at` + signature by the owner |
| DELETE abuse | Signature + `BLAKE3(pk) == key` |
| Seed dedup O(n²) | HashSet dedup in the iterative lookup |
| STORE flooding | Shard filtering (optional) |

---

## 9. Discovery: service records

These records sit on top of the DHT. Each is stored as a `DhtValue`, distinguished by its `kind`:

### 9.1 AnnounceAttachmentPayload (`kind=1`)

A Leaf announces which Core nodes can reach it:

```
[0..32]    leaf_node_id
[32..64]   gateway_node_id
[64..72]   epoch
[72..76]   expires_at (unix seconds)
[76..78]   gateways_count
[78..]     GatewayRef[] (node_id[32] + port + weight + flags = 38 B)
[..]       mailbox_count
[..]       MailboxRef[]
[..]       sig_len
[..]       signature
```

The DHT key is `attachment_key(leaf_node_id)`. To reach a Leaf, a sender first runs `GetAttachment(leaf_id)`, which returns the Core nodes through which the Leaf accepts traffic.

### 9.2 GetAttachment / AttachmentResponse

A request-response pair: given a node_id, return its list of gateways and mailboxes.

### 9.3 MailboxSet and GetMailboxSet

`MailboxSet` is the list of node_ids holding mailbox replicas for node `X`. It supports offline delivery.

```
GetMailboxSetPayload:  target_node_id[32] + epoch[4]
MailboxSetResponse:    count[2] + node_id[32][]
```

### 9.4 AppEndpoint and GetAppEndpoint

This maps the binding `(node_id, app_id, endpoint_id)` to an ML-KEM ek. Every application that announces a bind publishes such a record:

```
GetAppEndpointPayload:   node_id[32] + app_id[32] + endpoint_id[4]
AppEndpointResponse:     (variable) contains address + ek + expiry + signature
```

### 9.5 Name service

This maps a user-facing name to a node_id. The owner signs a name claim and writes it to the DHT under the key `name_key(name)`. The resolver checks the signature and the PoW chain straight from the DHT — there are no `NameContested` notifications.

---

## 10. Routing

File: [`crates/veil-routing/src/`](../../crates/veil-routing/src/) + [`node/dispatcher/routing.rs`](../../crates/veil-dispatcher/src/routing.rs).

### 10.1 Three levels

1. **Gossip** — `ROUTE_ANNOUNCE/WITHDRAW` with TTL=2, a narrow radius that reaches only neighbors.
2. **DHT forwarding** — `RecursiveRelay`, which carries messages through Kademlia.
3. **On-demand** — `ROUTE_REQUEST/RESPONSE`, used to fetch transports explicitly.

### 10.2 Route cache

`RouteCache` ([`routing/cache.rs`](../../crates/veil-routing/src/cache.rs)):

- Key: `dst_node_id`.
- Value: a set of paths, each holding `next_hop`, score, TTL, and hop_count.
- **Adaptive capacity**: `MAX_ROUTE_CACHE_SIZE = 1024` as a baseline, scaling up for large networks.
- `MAX_ROUTES_PER_DST = 4`, `MAX_ROUTES_PER_VIA = 256`.
- Eviction is TTL-based, with LRU on overflow.

### 10.3 Scoring

Each path gets a combined score (`RouteCache::score`):

```
score = w_rtt * rtt_ms
      + w_jitter * jitter
      + w_vivaldi * distance   // virtual coords
      + w_congestion * cong
      - w_battery * battery    // Leaf considerations
      - w_reputation * rep
```

The weights are set in the config under `routing.weights`.

### 10.4 RouteAnnounce

```
RouteAnnouncePayload:
[0..32]  origin_node_id
[32..64] via_node_id
[64]     hop_count
[65]     ttl (TTL=2 on the initial broadcast)
[66..70] sequence (u32BE monotonic at the origin)
[70..72] timestamp_secs
```

**Dedup and replay protection:**
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — frames older than this are rejected.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — the clock skew the node tolerates.
- Two layers of dedup: per-`(origin, via, seq)` and per-`(origin, seq)`.

`RouteWithdraw` mirrors `RouteAnnounce` but clears the entries instead. A monotonic `sequence` is mandatory, which blocks replays.

### 10.5 Aliased announce

`RouteAnnounceAliased` and `RouteWithdrawAliased` use 8-byte session aliases in place of 32-byte node_ids, which saves gossip-channel bandwidth on short local sessions.

### 10.6 Recursive routing

This kicks in when the route cache misses and there is no direct session to `dst`:

```
RecursiveRelayPayload:
[0..32]  dst_node_id
[32..64] originator_id
[64..68] query_id (u32BE — dedup token)
[68]     hop_count (decreases each hop, starts at 20)
[69..]   wrapped ForwardPayload body
```

When a node receives a RecursiveRelay, it does one of three things:

1. If `hop_count == 0`, it parks the message in the mailbox of `dst_node_id` as a last resort.
2. If it has a live session to `dst`, it unwraps the message and delivers it locally.
3. Otherwise, it finds the XOR-nearest peer to `dst` among its DHT neighbors and forwards with `hop_count - 1`.

**Reverse-path caching:** a successful delivery through node X writes `originator_id → X` into the recipient's route cache, so later replies travel direct.

### 10.7 Route request/response

An explicit query that asks, "who knows a transport for `target`?" The `RouteRequestPayload` carries the requester's ML-KEM ek (so the response can be E2E-encrypted), its Ed25519 pk, and a signature.

The response:

```
RouteResponsePayload:
target[32], requester[32], request_id[4]
transports[] (up to 32 URIs, MAX_TRANSPORT_ADDRS=32)
relays[]     (up to 32 node_id, MAX_RELAY_IDS=32)
mlkem_pk, ed25519_pk, signature
```

### 10.8 PoW bootstrap

`PowChallenge`, `PowResponse`, and `PowAccept` cover nodes that share no common contacts:

- The requester sends a FindNode, and the bootstrap answers with a PoW challenge.
- A valid solution satisfies `leading_zero_bits(BLAKE3(challenge || solution)) ≥ difficulty`.
- On success, the bootstrap sends `PowAccept` along with the transport.

### 10.9 Event-driven updates

- `RouteUpdate` (0x12) — pushed whenever a neighbor connects or disconnects.
- `VersionVectorSync` (0x13) — a periodic version-vector (VV) sync that reconciles state.

---

## 11. Delivery

File: [`crates/veil-dispatcher/src/delivery.rs`](../../crates/veil-dispatcher/src/delivery.rs).

### 11.1 DeliveryEnvelope

```
[0..32]    recipient_node_id
[32..64]   sender_node_id
[64..96]   src_app_id
[96..128]  app_id          (of the recipient)
[128..132] endpoint_id     u32BE
[132..164] content_id      (BLAKE3 of payload)
[164..172] created_at      u64BE  (unix seconds)
[172..176] ttl_secs        u32BE
[176..180] payload_len     u32BE
[180..]    payload         bytes
```

Two 1-bit flags travel separately: `require_ack` and `trace_id`.

### 11.2 Delivery paths

The dispatcher tries these in order:

**Path A — direct.** A live session to `recipient_node_id` exists, so the message goes straight there.

**Path B — route cache.** No direct session, but the cache holds an entry "for `recipient_node_id`, next_hop = X" — the node forwards to X.

**Path C — RecursiveRelay.** Neither a session nor a cache entry. The node builds a `RecursiveRelayPayload` and sends it to the XOR-nearest node in the DHT table.

**Path D — Mailbox.** The hop budget is spent, or the recipient is offline — the message settles into the mailbox(es).

### 11.3 Forward

`ForwardPayload` is just `DeliveryEnvelope.encode()`. The recipient recognizes itself by `recipient_node_id` and hands the message to its local application.

### 11.4 Transit

A stateless relay: `TransitFramePayload` keeps no per-flow state. It forwards packets fast without holding a session back to the origin. It needs minor ≥ 5, which is always the case today.

### 11.5 Chunked transfers

For payloads larger than the frame size:

```
ChunkManifestPayload (92 B):
  content_id[32], total_size[8], chunk_count[4], chunk_size[4],
  first_chunk_offset[4], sig_len[4], signature[up to 32]

ChunkPayload (20 B header + data):
  content_id[32 — in hdr], chunk_index[4], offset[8], data_len[2], data[]
```

From the manifest, the recipient allocates a `ReassemblyState`, collects the chunks, and rebuilds the payload.

### 11.6 Delivery status

`DeliveryStatusPayload` (65 bytes, wire-fixed):

```
[0..32]  content_id
[32]     status u8
         0 = OK / QUEUED
         1 = NOT_FOUND
         2 = FAILED / REJECTED
         3 = DUPLICATE
         4 = TTL_EXPIRED
[33..65] mac [u8; 32]   (C-09 — authenticated ACK; see below)
```

**C-09 — authenticated DELIVERED ACK.** The `mac` is a BLAKE3 keyed-MAC of
`content_id`, keyed by a per-message delivery-ACK key that both ends derive from the
E2E ML-KEM shared secret (`veil_e2e::derive_ack_key`). A relay on the path never
learns that secret, so only the genuine recipient can produce a valid MAC. The
originator therefore credits delivery reputation **only** when the MAC verifies.
If no ACK key was established — non-E2E or legacy delivery — the field is
all-zero: the originator clears the pending entry but credits no reputation. See
`handle_delivery_status` in `crates/veil-dispatcher/src/delivery.rs`.

### 11.7 5-stage delivery FSM

On the sender side (the IPC client), delivery moves through a five-stage state machine (FSM):

```
Accepted → Stored → Fetched → Delivered → AppAcked
```

The client follows along through `LocalAppMsg::DeliveryStage` notifications, so it can show an "in transit", "delivered", or "read" status.

---

## 12. Mailbox (offline delivery)

File: [`crates/veil-mailbox/src/`](../../crates/veil-mailbox/src/).

### 12.1 Model

The `MailboxService` accepts three operations from Core nodes:
- **PUT** — park a `DeliveryEnvelope` for an offline recipient.
- **FETCH** — an online recipient pulls its own messages, paging from an `after_seq` cursor.
- **ACK** — confirm which seqs were read.

A Leaf does not store a mailbox (`MailboxError::NotAllowed`).

### 12.2 Backend

The mailbox is a fixed **redb** key-value store at `<veil_dir>/mailbox/blobs.db`, with serializable transactions. The engine is not swappable — there is no `backend` config key. Turn the mailbox on with `[mailbox] enabled = true`. Implementation: [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs).

### 12.3 Quotas and limits

From [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs) and `crates/veil-proto/src/budget.rs`:

| Parameter | Value |
|-----------|-------|
| Global cap | 100,000 records (an absolute limit) |
| Per-recipient cap | config; default 1000 |
| Per-sender daily quota | `DEFAULT_MAX_MAILBOX_SENDERS` wraps the set |
| `MAX_MAILBOX_ACK_BATCH` | 256 seqs per batch |
| `MAX_MAILBOXES` | 32 mailbox references in an attachment |

On overflow, a new PUT is rejected with `status=REJECTED` instead of evicting old entries. This closes off race-based eviction attacks that would otherwise threaten data durability.

### 12.4 How storage nodes are determined

The idea: neither the sender nor the recipient needs to know the specific
mailbox hosts in advance. Both derive them independently from
`recipient_node_id` via the DHT.

#### Primary (attachment gateway)

When it connects, the recipient announces its set of gateways via
`AnnounceAttachmentPayload`, signed with its identity key. The record
settles in the DHT under the key `attachment_key(recipient_node_id)`.

A sender with no direct session to the recipient then:

1. Runs `GetAttachment(recipient_node_id)` to get the list of gateways.
2. Opens a session to one of them, in priority order by weight and flags.
3. Sends a `MAILBOX_PUT` with the `DeliveryEnvelope` inside.

#### Replicas (deterministic DHT selection)

Once the primary accepts the PUT, it picks up to `replica_count - 1`
extra storage nodes via [`select_quorum_replicas`](../../crates/veil-dispatcher/src/delivery.rs):

```text
shard_target = BLAKE3("shard" ‖ recipient_node_id ‖ shard_id_be_bytes)
                                                    └ usually 0 ┘
pool         = DHT.find_closest_nodes(shard_target, (replica_count - 1) × 4)
candidates   = pool.filter:
                 id != self
                 id != origin_peer (whoever sent the PUT)
                 battery_level ≥ 20                  (if known)
                 relay_success_ema ≥ 0.5             (if relay_attempts > 0)
                 not in circuit_breaker              (tracks consecutive
                                                      failures)
replicas     = candidates.take(replica_count - 1)
```

The point of this is **determinism**: `shard_target` and the XOR-nearest nodes
to it do not depend on who is looking. Any Core node that knows
`recipient_node_id` computes the same target and, through its own
DHT, lands on the same set of candidates (give or take the liveness filters). So
the *recipient* and any *future gateway* find the same replicas
without ever swapping addresses.

Sharding by `shard_id` lets a single recipient's backlog split
into several independent replica sets: `shard_id=0, 1, 2 …`
give different `shard_target`s, hence different replicas. That lowers the
correlated-failure risk for large mailboxes. Today only a single shard (`shard_id=0`)
is in use.

### 12.5 Replication

`MailboxReplicationConfig`:

```toml
[mailbox.replication]
replica_count = 3         # number of replicas, including the primary
write_quorum  = 2         # minimum successes for an ACK to the sender
replica_timeout_ms = 500  # timeout for a replica write
```

#### Write-path

```
Sender ── MAILBOX_PUT ──► Primary (the recipient's attachment gateway)
                          │
                          ├─ store locally (InMemory or WAL backend)
                          ├─ select_quorum_replicas(recipient) → [R1, R2]
                          │   (encrypt the envelope — see §12.6)
                          ├─ MAILBOX_REPLICATE ──► R1
                          ├─ MAILBOX_REPLICATE ──► R2
                          │   await DeliveryStatus::QUEUED
                          │   timeout = replica_timeout_ms
                          │
                          └─ ≥ write_quorum successes?
                                yes → DeliveryStatus::QUEUED to the sender
                                no  → DeliveryStatus::REJECTED to the sender
```

With `replica_count = 1`, the replica step is skipped and the PUT lives only on the primary.

#### Read-path

```
Recipient online ── MAILBOX_FETCH(after_seq) ──► Primary gateway
                                                 │
                                                 ├ SEC check:
                                                 │  payload.recipient_node_id
                                                 │  == authenticated peer_id
                                                 │  (otherwise Violation)
                                                 │
                                                 ├ backend.fetch(recipient, after_seq)
                                                 │   non-empty? → return entries
                                                 │
                                                 ├ (empty) If mailbox_dht_replication:
                                                 │   DHT.get_local(recipient) → envelope
                                                 │
                                                 └ (still empty) try_fetch_from_replicas:
                                                   ├─ the same replica_ids via select_quorum_replicas
                                                   ├─ fan-out: MAILBOX_FETCH_REPLICA to each
                                                   ├─ first non-empty response → entries
                                                   └─ all empty / timeout → empty response
```

After a `MAILBOX_FETCH`, the client sends `MAILBOX_ACK { recipient, seqs[] }`.
The primary deletes the confirmed seqs locally; the Ack to the replicas
happens lazily, and the replicas garbage-collect (GC) by TTL.

**Why this is safe:**
- Only an authenticated recipient can fetch, thanks to the
  `recipient_node_id == peer_id` check.
- Only the original sender knows the `sender_node_id` in the envelope,
  checked in `MAILBOX_PUT::handle_put`.
- Replicas hold the envelope encrypted (see §12.6), so they cannot read the
  payload even if compromised.

### 12.6 Envelope encryption for replicas

A replica host has no need to see the contents, so the envelope is encrypted just before `MAILBOX_REPLICATE`:

```
encrypted_blob = ChaCha20-Poly1305.Seal(
    key  = HKDF(primary_mlkem_dk, info="replica-v1"),
    aad  = recipient_node_id || seq,
    plaintext = DeliveryEnvelope.encode()
)
```

The replica stores the blob as-is; on fetch, the primary decrypts it back.

### 12.7 WAL structure

The WAL is a sequence of append-only lines:

```
magic[4] + version[1] + op_type[1] + len[4] + body[len] + crc32[4]
```

The `op_type` is one of Put, Ack, or Compact. On startup, the node replays the log to rebuild the current state. Once `wal_size > compact_threshold` (default 64 MiB), compaction runs: it snapshots the active records and deletes the old WAL.

---

## 13. Peer Exchange (PEX)

File: [`crates/veil-pex/src/`](../../crates/veil-pex/src/). Family 11.

### 13.1 Purpose

PEX collects fresh transport addresses of peers so a node can open direct connections instead of hopping through a relay. It runs on a **random-walk + PoW** model.

### 13.2 Protocol (4 frames)

1. **Walk** (originator → seed). Carries `walk_id`, `origin_pubkey`, `origin_nonce`, TTL, and a signature.
2. **Challenge** (terminator → originator). A PoW challenge at the required difficulty.
3. **Response** (originator → terminator). The PoW solution plus `origin_sig` (Ed25519 or Falcon512, dispatched through `verify_message`).
4. **Result** (terminator → originator). A list of peer records — node_id plus transport URIs.

### 13.3 Signature

`verify_origin_sig` supports both Ed25519 and Falcon512:

```rust
let algo = if pubkey.len() == 32 {
    SignatureAlgorithm::Ed25519
} else {
    SignatureAlgorithm::Falcon512
};
verify_message(algo, pubkey_b64, msg, signature)
```

### 13.4 Parameters

- `pex.walk_interval_secs` — how often the node starts a walk.
- `pex.max_hops` — the random-walk TTL.
- PoW difficulty — set by `AdaptiveParams`, and lower than the identity PoW since it is per-walk rather than per-node.

---

## 14. Mesh (local UDP network)

File: [`crates/veil-mesh/src/`](../../crates/veil-mesh/src/). Family 5.

### 14.1 Scenario

An IoT device or any node without internet can still:
- Find neighbors locally over UDP multicast or broadcast.
- Relay a message into the global Veil through a mesh bridge — a Core node with `CAN_GATEWAY_LOCAL_MESH`.

### 14.2 MeshBeacon

```
MESH_BEACON_SIZE = 48 + extension
[0..32]  node_id
[32..48] realm_id (UUID)
[48..]   extension (v2):  transport_count + transport_len + transport_uri + algo + pubkey + sig
```

A node sends a beacon every `DEFAULT_BEACON_INTERVAL` (30 s). Each beacon lives for `BEACON_WINDOW = 60 s`; once it ages out, the neighbor cache drops it.

### 14.3 MeshFrame

```
MESH_HEADER_SIZE = 83 B:
[0..16]  realm_id
[16..48] sender
[48..80] destination
[80]     hop_count
[81..83] payload_len u16BE
[83..]   payload
```

The `MeshForwarder` forwards it within the realm.

### 14.4 Realm

A `Realm` is a logical group of mesh nodes, identified by a UUID. One physical segment can hold several realms, and a node ignores beacons from any realm but its own.

### 14.5 Gateway bridge

A Core node with `CAN_GATEWAY_LOCAL_MESH`:
- On the mesh side, listens for UDP beacons and mesh frames.
- Mesh into Veil: it pulls the `DeliveryEnvelope` out of `MeshFrame.payload` and feeds it into its own dispatcher.
- Veil into mesh: when the `recipient_node_id` is a known mesh peer, it wraps the message in a `MeshFrame` and sends it over UDP.

---

## 15. NAT traversal

File: [`crates/veil-nat/src/`](../../crates/veil-nat/src/).

### 15.1 Steps

```
Idle → Discovering → Exchanging → Punching ─┬→ Connected (direct connection)
                                            ├→ Relaying  (through a Core)
                                            └→ Failed
```

### 15.2 ICE candidates

These come from `NatCandidate`, modeled on RFC 8445:

- `HOST` — a local interface (highest priority: `type_pref=126`).
- `SRFLX` — server-reflexive, learned from a Core's STUN echo (`type_pref=100`).
- `RELAY` — a relay tunnel through a Core (`type_pref=0`).

The priority formula:
```
priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
```
It uses saturating arithmetic ([`nat/coordinator.rs::ice_priority`](../../crates/veil-nat/src/coordinator.rs)).

### 15.3 Exchange

```
Alice → Core:  NatProbeRequest(session_token, Alice_candidates)
Core → Bob:    NatProbeRequest with Alice_candidates
Bob → Core:    NatProbeReply(Bob_candidates)
Core → Alice:  NatProbeReply with Bob_candidates
Alice ↔ Bob:   QUIC connect to all candidates in parallel
```

`NatPuncher::punch` races every candidate pair in parallel within `punch_timeout_ms`; the first handshake that lands becomes `PunchResult::Direct(conn)`.

### 15.4 Relay fallback

If `PunchResult::TimedOut`:

```
Alice → Core: NatRelayRequest(Alice, Bob, session_token)
Core opens ForwardTunnel(Alice ↔ Bob, token=session_token)
```

The Core then forwards `DeliveryMsg::Forward` between the two.

### 15.5 Local relay

If there is no global Core but a local Gateway advertises `IS_RELAY` in its mesh-beacon flags, `NatCoordinator::preferred_signal_peer` returns that Gateway:

```
priority: local_relay > global_core > None
```

`LOCAL_RELAY_TIMEOUT_SECS = 3` is how long the node waits on a local relay before falling back to a Core.

---

## 16. Anti-abuse and protection

### 16.1 The protection stack on an inbound connection

```
1. IP filter (bans)
2. Per-IP session limit (MAX_SESSIONS_PER_IP = 32)
3. PoW challenge (if configured)
4. Handshake timeout
5. Per-peer token bucket (rate limiter)
6. Violation tracker (5 violations → ban)
7. Ban list (TTL, max 8192)
8. Congestion backpressure (>78% → drop transit)
9. Reputation gate (MIN_REPUTATION_FOR_TRANSIT = 200)
```

### 16.2 Bandwidth / rate limits

[`abuse/bandwidth_gate.rs`](../../crates/veil-abuse/src/bandwidth_gate.rs) + [`abuse/per_peer_limiter.rs`](../../crates/veil-abuse/src/per_peer_limiter.rs):

- A token bucket per peer, with refill rate and burst size taken from the config.
- A drop on exhaustion bumps the violation counter.
- `MAX_PER_PEER_LIMITER_SIZE = 8192` caps how many peers are tracked at once.

### 16.3 Violation tracker

`MAX_VIOLATION_TRACKER_SIZE = 8192`. The violation categories include:
- `BadFrame` — the wire format is invalid.
- `SenderMismatch` — the envelope's sender does not match the authenticated peer.
- `PoWFail` — an incorrect solution.
- `RateExceeded` — the token bucket is empty.
- and more.

Once a peer hits `VIOLATION_THRESHOLD = 5` within the `VIOLATION_WINDOW_SECS = 300` window, it is banned.

### 16.4 Ban list

`MAX_BAN_LIST_SIZE = 8192`. The TTL comes from the config (`abuse.default_ban_secs`). The list persists to `bans.json` in the data-dir.

### 16.5 Congestion backpressure

`node/congestion.rs`:

- The load metric: `load_pct = (cpu_usage * 0.5) + (memory_usage * 0.3) + (queue_depth * 0.2)`.
- Above **50%**, the node halves its adaptive fan-out.
- Above **78%**, it drops TRANSIT and RECURSIVE_RELAY frames; ordinary delivery keeps going.
- To push back actively, it sends a `Backpressure` control frame asking the peer to slow down.

### 16.6 Reputation

[`node/reputation.rs`](../../crates/veil-reputation/src/lib.rs):

- Initial score: 0.
- Uptime: +1 / hour.
- Successful relay: +0.1.
- Failed relay: -1.
- Peer vouch (`ReputationAttestation`): +5.
- Transit gate: `MIN_REPUTATION_FOR_TRANSIT = 200.0`.

A fresh node cannot forward third-party traffic right away — this is the cold-start gate.

### 16.7 PoW challenge on a connection

Optional, for hardening the handshake:

```
Server → Client: PowChallenge(challenge_nonce[32], difficulty)
Client → Server: PowResponse(solution) where BLAKE3(challenge||solution) has ≥ difficulty zero bits
```

Limits:
- `MAX_POW_DIFFICULTY = 24` — the server cannot demand more than this.
- `MAX_CONCURRENT_POW_SOLVERS = 4` — a cap on how much the client solves in parallel.

---

## 17. Adaptive parameters

File: [`crates/veil-cfg/src/adaptive.rs`](../../crates/veil-cfg/src/adaptive.rs).

### 17.1 Network size estimation

The node estimates `N`, the size of the network, from three signals:

1. Its own DHT table — the number of buckets holding at least one contact.
2. The `EpochDifficultyRecord` from the DHT, which bootstrap nodes publish.
3. FindNode responses — specifically, the size of the lists they return.

### 17.2 Scalable parameters

| Parameter | Formula | Min | Max |
|-----------|---------|-----|-----|
| PoW difficulty | `24 + ceil(log2(N / 100_000))` | 24 | — |
| Fan-out (epidemic) | `ceil(log2(N))` | 2 | 16 |
| DHT α (parallelism) | 3 when N < 100k, 4 when N ≥ 1M | 3 | 5 |
| Route cache size | `1024 + N / 1000` | 1024 | 65536 |
| Mailbox cap | `100_000` | — | — (hard) |
| Ban TTL | `60 * 60 * (1 + log10(N))` | 1 hour | 24 hours |

### 17.3 Sync

`NodeRuntime::tick` refreshes `AdaptiveParams` periodically. Changes apply lazily, so they never interrupt a session already in flight.

---

## 18. App layer and IPC

### 18.1 Model

An application — a CLI client, a user bot, or a GUI — runs like this:

```
App process ──Unix socket (JSON-L / binary)──► veild (node)
                                                   ↓
                                               OVL1 network
```

The default socket is `/run/veil/ipc.sock`, or `$XDG_RUNTIME_DIR/veil/ipc.sock`.

### 18.2 Address: AppAddress

```
AppAddress {
    node_id:     [u8; 32],   // Which node hosts the application
    app_id:      [u8; 32],   // derive_key("veil.app_id.v1", node_id || ns_len(4) || ns
                             //            || name_len(4) || name) — see §1.2 of protocol-spec
    endpoint_id: u32,        // A "port" within the application (1..65535)
}
```

**namespace** and **name** are UTF-8 strings the developer chooses — by convention, reverse-DNS
like `"com.example.chat"` plus `"main"` — up to 255 bytes each. The length-prefix and domain
separator (`"veil.app_id.v1"`) guard against concat-shift collisions, where two different
`(namespace, name)` pairs would otherwise hash to the same digest.

For IPC applications, the default bind is **ephemeral**: the node mixes in a 16-byte
`client_token` (issued in `AppHelloOk`) and a separate domain separator
(`"veil.ephemeral_app_id.v1"`), so two processes on the same node get
different `app_id`s for the same `(namespace, name)`. Well-known services
(`bind_named`) use the stable form, without the token.

### 18.3 IPC protocol

Family 6 (LocalApp). The sequence:

```
Client → Node: AppHello (version=1)
Node → Client: AppHelloOk
Client → Node: AppBind(namespace, name, endpoint_id)
Node → Client: AppBindOk(app_id)
  [client listens for AppDeliver]
Client → Node: AppIpcSend(recipient, payload)  or StreamOpen(...)
Node → Client: AppDeliver(envelope)
Client → Node: AppUnbind
```

Types from `LocalAppMsg`:

| Type | ID | Direction | Purpose |
|------|----|-----------|---------|
| AppHello | 0 | → | Hello (version) |
| AppHelloOk/Err | 1/2 | ← | Response |
| AppBind | 3 | → | Bind an endpoint |
| AppBindOk/Err | 4/5 | ← | Response |
| AppUnbind | 6 | → | Unbind |
| AppDeliver | 7 | ← | Incoming message |
| AppIpcSend | 8 | → | One-shot send |
| AppSendOk | 9 | ← | Accumulation sent (local) |
| StreamOpen | 10 | → | Open a bidirectional stream |
| StreamOpenOk/Err | 11/12 | ← | Response |
| StreamData | 13 | → / ← | Stream data |
| StreamClose | 14 | → / ← | Close |
| StreamWindow | 15 | → / ← | Flow-control update |
| StreamRtData | 16 | → / ← | Real-time data |
| AppSendFailed | 17 | ← | Permanent failure (MAX_DELIVERY_ATTEMPTS) |
| AppRtSend | 18 | → | Real-time send |
| DeliveryStage | 19 | ← | 5-stage FSM notification |
| AnycastResolve | 20 | → | Anycast resolver |
| AnycastResult | 21 | ← | Anycast response |

### 18.4 App messages over the wire (Family 4)

On the Veil side, applications talk to each other through:

- `AppOpen(app_id, endpoint_id, initial_window)` — open a stream.
- `AppData(data, ack?)` — carry data.
- `AppWindowUpdate(bytes)` — flow control.
- `AppClose(reason)` — close the stream.
- `AppRtData` — a real-time frame (REALTIME priority, no ACK).
- `AppReceipt` — confirm delivery.

### 18.5 Anycast

Anycast resolves a service name to any node_id that bound an endpoint under that name:

```
Client → Node: AnycastResolve(service_name)
Node: looks up the DHT by anycast_key(service_name) → gets a candidate list → picks the closest
Node → Client: AnycastResult(node_id + endpoint)
```

### 18.6 E2E in IPC

The client requests E2E by setting `encrypt: true` in `AppIpcSend`. The node then:

1. Fetches the recipient's ML-KEM ek from the DHT (`GetAppEndpoint`).
2. Wraps the payload in an `E2eEnvelope` with the `0xE2` marker.
3. Packs that into a `DeliveryEnvelope` and sends it.

Setting `anonymous: true` switches to `META_E2E_MARKER (0xE3)`, which hides the sender.

---

## 19. Observability

### 19.1 Prometheus metrics

Endpoint: `GET /metrics` on `metrics.listen` from the config (the default path is `/metrics`,
overridden by `metrics.path`).

Every metric lives in [`observability.rs::render_prometheus`](../../crates/veil-observability/src/lib.rs) and carries the `veil_` prefix.
The main groups follow (for the full list, see [admin-guide.md](admin-guide.md#available-counters)):

- Transport: `veil_active_sessions`, `veil_inbound_sessions_total`,
  `veil_transport_bytes_rx_total`, `veil_transport_bytes_tx_total`.
- Session: `veil_session_handshake_failures_total`, `veil_session_tx_drops_total`.
- Delivery: `veil_delivery_rejects_total`, `veil_chunks_reassembled_total`.
- DHT / Routing: `veil_dht_store_total`, `veil_dht_lookup_total`,
  `veil_route_cache_hits_total`, `veil_route_miss_total`,
  `veil_recursive_relay_initiated_total`.
- Routing quality: `veil_route_selection_avg_rtt_ms`,
  `veil_vivaldi_prediction_error_ms`, `veil_vivaldi_coord_{x,y,height,error}`.
- Abuse: `veil_rate_limit_drops_total`, `veil_ban_actions_total`.
- Real-time: `veil_rt_frames_{rx,tx}_total`, `veil_rt_seq_gaps_total`.

### 19.2 Logs

By default, logs are structured text lines:

```
[timestamp] LEVEL event.name field1=val1 field2=val2 ...
```

Set `logging.format = "json"` in the config to switch to JSON-L instead.

The levels are ERROR, WARN, INFO, DEBUG, and TRACE. Filter them with `RUST_LOG` or `logging.filters`.

### 19.3 Debug capture

`veil-cli debug capture --output FILE` writes a JSON stream of frames in on-the-wire order. It takes `--node-id HEX`, `--family N`, and `--limit N` to narrow the capture.

### 19.4 DiagPing / TraceRoute

Family 9 (Diag):

- `DiagPing/DiagPong` — an end-to-end round-trip-time (RTT) probe across Veil.
- `TraceProbe/TraceHop` — a hop-by-hop traceroute. Each hop decrements the TTL, and at `TTL=0` the node sends a `TraceHop` back carrying its own `node_id`.

### 19.5 Trace buffer

An in-memory ring buffer of the last `TRACE_BUFFER_SIZE = 1024` dispatch events. The runtime uses it internally; there is no admin command to read it directly. You observe that state through metrics and `veil-cli debug capture`.

---

## 20. Runtime and process structure

### 20.1 Structure of `NodeRuntime`

[`crates/veil-node-runtime/src/lib.rs`](../../crates/veil-node-runtime/src/lib.rs). The main fields:

```rust
pub struct NodeRuntime {
    config:           Arc<RwLock<cfg::Config>>,
    local_identity:   Arc<LocalIdentity>,
    session_registry: Arc<Mutex<SessionRegistry>>,
    dispatcher:       Arc<FrameDispatcher>,
    dht:              Arc<KademliaService>,
    mailbox:          Arc<MailboxService>,
    route_cache:      Arc<RwLock<RouteCache>>,
    ban_list:         Arc<Mutex<BanList>>,
    metrics:          Option<Arc<NodeMetrics>>,
    // ... ~70 more fields (see `struct NodeServices` in runtime.rs)
}
```

It is cheap to clone, since everything sits behind an `Arc`.

### 20.2 Lifecycle

```
Config::load → ResolvedConfig → NodeRuntime::new
  ├── listener_supervisor starts the TCP/QUIC/WS listeners
  ├── dispatcher registers handlers per-family
  ├── periodic tasks (tokio::spawn):
  │     ├── keepalive_tick (pick a session → Keepalive)
  │     ├── mailbox_gc (expire old entries)
  │     ├── dht_refresh (bucket refresh, republish)
  │     ├── route_cache_gc
  │     ├── lazy_miner (PoW mining if enabled)
  │     ├── pex_walker
  │     ├── ban_list_persist
  │     ├── mesh_beacon_send / mesh_beacon_recv
  │     └── metrics_scrape
  └── NodeRuntime::run — main loop (currently empty: everything is in the tasks)
```

### 20.3 FrameDispatcher

[`crates/veil-dispatcher/src/lib.rs`](../../crates/veil-dispatcher/src/lib.rs):

```rust
pub fn dispatch(&self, hdr: &FrameHeader, body: &[u8], peer: PeerContext) -> DispatchResult {
    match FrameFamily::try_from(hdr.family)? {
        FrameFamily::Session    => self.session.dispatch(...),
        FrameFamily::Control    => self.control.dispatch(...),
        FrameFamily::Discovery  => self.discovery.dispatch(...),
        FrameFamily::Delivery   => self.delivery.dispatch(...),
        FrameFamily::Routing    => self.routing.dispatch(...),
        // ...
    }
}
```

A `DispatchResult` is one of:
- `NoResponse` — handled, nothing to send back.
- `Reply(bytes)` — send a response frame.
- `Violation(reason)` — bump the violation counter, and maybe disconnect.
- `Disconnect(reason)` — close the session.

### 20.4 SessionRunner

[`node/session/runner.rs`](../../crates/veil-session/src/runner.rs) runs one async task per session. Each task:

1. Reads bytes from the transport.
2. Runs `decode_header` to get a `FrameHeader`.
3. If `body_len > MAX_FRAME_BODY`, logs a violation and disconnects.
4. AEAD-decrypts the body.
5. Passes it to `dispatcher.dispatch` — a synchronous call, no await.
6. Takes the `DispatchResult` and acts on it (Reply, Disconnect, and so on).

Outgoing frames go out through the `SessionTxRegistry`:
- A per-session **weighted round-robin (WRR) scheduler** across 4 priorities (RealTime w=8, Interactive w=4, Bulk w=2, Background w=1).
- The out-queue is guarded against overflow: once `len > MAX_QUEUE_DEPTH` (default 1000), the frame is dropped or backpressure kicks in.

### 20.5 Locking patterns

- All shared state sits behind `Arc<Mutex<_>>` or `Arc<RwLock<_>>`.
- The rule is **no nested locks**: take a lock, do the work, release it. That keeps deadlocks out.
- Hot paths such as dispatch never hold a lock across an `.await`.
- Metrics use atomic counters (`Arc<AtomicU64>`).

### 20.6 Admin interface

The admin interface is a Unix socket from `global.admin_socket` (configured as `unix:///path`).
It speaks JSON over the Unix domain socket (UDS), and the `veil-cli` CLI wraps it. The key subcommands:

- `node show` — the overall state (uptime, sessions, role).
- `node health` — tick counter + session count + loop status.
- `node metrics` — a snapshot of all counters/gauges.
- `node listens` — active listeners; `node routes` — the route cache.
- `node dht list / get KEY / put KEY VALUE / routing` — DHT introspection and manual modification.
- `node discovery-list`, `node gateway-list` — attachment / gateway records.
- `sessions list / kill LINK_ID` — active sessions.
- `peers list / add / del / ban / unban / banned` — managing peers and bans.
- `debug ping / trace / capture / peers connect / node accept` — diagnostics.
- `node stop / restart / reload` — lifecycle management.

For the full list of subcommands — `veil-cli --help` and [admin-guide.md](admin-guide.md).

### 20.7 Configuration

[`docs/config-reference.md`](config-reference.md) — the full table of options.

The format is TOML, and `veil-cli config locate` prints its path. The key sections:

- `[global]` — `admin_socket`, `runtime_flavor`, logging (`logs`, `log_file`, `log_level`, `log_format`).
- `[Identity]` — `algo`, `public_key`, `private_key`, `nonce`, `node_id`, `names[]`.
- `listen = [...]` / `peers = [...]` — at the top level (not sections), transport listeners and static peers.
- `[dht]` — `k`, `alpha`, `vivaldi_weight`, `shard_filtering`, `max_store_entries`, `cold_store_path` (the RocksDB disk cold tier, behind the feature `rocksdb-cold`).
- `[routing]` — gossip / cache parameters, including `vivaldi_persist_path`.
- `[session]` — `keepalive_interval_secs`, `idle_timeout_secs`, `rekey_bytes_threshold`, `rekey_time_threshold_secs`.
- `[mailbox]` — `enabled`, quotas (`quota_per_receiver_bytes`/`quota_global_bytes`/`quota_per_sender_bytes`), `ttl_secs`, `require_capability_token`; storage is a fixed redb KV (no `backend` selection).
- `[abuse]` — `rate_limit_fps`, `ban_threshold`, `pow_min_difficulty`.
- `[nat]` — hole-punch parameters, STUN.
- `[mesh]` — beacon/realm parameters.
- `[pex]` — random-walk discovery.
- `[ipc]` — the Unix socket path for local applications.
- `[proxy]` — SOCKS5 exit.
- `[gateway]` — `enabled`, attachment policy.
- `[metrics]` — `listen`, `path`.

For the full description — [config-reference.md](config-reference.md).

---

## Appendices

### A. References to key modules

| Subsystem | Module | Key types |
|-----------|--------|-----------|
| Wire protocol | `veil-proto` | `FrameHeader`, `FrameFamily`, `*Msg` enums |
| Session handshake | `veil-session` (`handshake.rs` + `fsm.rs`) | `perform_ovl1_handshake`, `SessionFsm`, `SessionKeys` |
| Session runner | `veil-session` (`runner.rs`) | `SessionRunner`, `SessionTxRegistry` |
| Dispatcher | `veil-dispatcher` | `FrameDispatcher`, `DispatchResult` |
| DHT | `veil-dht` | `KademliaService`, `RoutingTable`, `IterativeParams` |
| Discovery | `veil-discovery` | `DirectoryService`, `AnnounceAttachmentPayload` |
| Routing | `veil-routing` | `RouteCache`, `RouteAnnouncePayload` |
| Mailbox | `veil-mailbox` | `MailboxService` (redb) |
| NAT | `veil-nat` | `NatCoordinator`, `NatPuncher`, `RelayFallback` |
| Mesh | `veil-mesh` | `MeshForwarder`, `BeaconSender` |
| PEX | `veil-pex` | dispatcher, initiator |
| Anti-abuse | `veil-abuse` | `BanList`, `ViolationTracker`, `PerPeerLimiter` |
| Transport | `veil-transport` | `TransportUri`, `TcpTransport`, `QuicTransport` |
| E2E | `veil-e2e` + `veil-crypto` | `E2eEnvelope` |
| Config | `veil-cfg` | `Config`, `SessionConfig`, `DhtConfig`, `MetricsConfig` |
| Runtime | `veil-node-runtime` | `NodeRuntime` |

### B. Key numeric constants (as of the current repository state)

```text
MAGIC              = "OVL1" (0x4F564C31)
OVL1_MINOR         = 1
FRAME_HEADER_SIZE  = 24
MAX_FRAME_BODY     = 16 MiB (default listener cap 1 MiB)

DHT K              = 20
DHT ALPHA          = 3
DHT MAX_ROUNDS     = 20
MAX_NEIGHBOR_TABLE = 256

POW baseline       = 24 bits (prod), 16 bits (debug)
MAX_POW_DIFFICULTY = 24
POW solvers cap    = 4

REKEY_BYTES        = 128 GiB   (config: [session] rekey_bytes_threshold)
REKEY_TIME         = 32 days   (config: [session] rekey_time_threshold_secs)
TICKET_TTL         = 3600 s / MAX 7200 s

Mailbox global cap = 100 000
Mailbox ACK batch  = 256
Replica default    = 3, quorum 2, timeout 500 ms

Bans max           = 8 192
Violations max     = 8 192
Per-peer limit max = 8 192
MAX_SESSIONS_PER_IP = 32

Congestion thresholds = 50% (halve fan-out), 78% (drop transit)
Reputation transit    = 200
MAX_PEER_PUBKEYS_CACHE = 65 536
MAX_PEER_MLKEM_CACHE   = 4 096
MAX_PEER_VIVALDI_CACHE = 32 768

Local relay timeout = 3 s
Beacon interval     = 30 s / window 60 s
```
