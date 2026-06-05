# RFC 0001 — Hybrid Veil Network Architecture

**Status:** Accepted
**Repository:** veilnetwork/veil
**Related document:** `specification.md`

---

## Summary

This RFC defines the complete wire protocol, data model, and component architecture for the veil network stack (`OVL1`). It serves as the authoritative reference for all on-wire formats, DHT key derivation formulas, and milestone acceptance criteria.

---

## 1. Invariants

These are fixed and must not change without a new RFC superseding this one.

### 1.1 Node identity

```
node_id = BLAKE3(raw_public_key_bytes)   // [u8; 32]
node_addr := node_id                     // no separate address concept
```

Implementation: `cfg::model::NodeId::from_public_key(algo, base64_pubkey)`.

### 1.2 Application addressing

```
app_id = BLAKE3-derive_key(
    context = "veil.app_id.v1",
    ikm     = node_id || ns_len(u32 BE) || app_namespace
                       || name_len(u32 BE) || app_name
)

AppAddress {
  node_id:     [u8; 32],
  app_id:      [u8; 32],
  endpoint_id: u32,
}
```

Implementation: `node::app::address::app_id(node_id, namespace, name)`.

### 1.3 Content addressing

```
content_id = BLAKE3(content_bytes)
// with domain separation:
content_id = BLAKE3(app_id || content_type || payload)
```

### 1.4 Node roles

| Role   | DHT owner | Leaf attachment | Routes traffic |
|--------|-----------|-----------------|----------------|
| `leaf` | ❌ never  | yes (client)    | no             |
| `core` | ✅ yes (K=20) | yes (server) | yes           |

One binary, two roles. Selected via config `[Identity] role = "leaf" | "core"`.
Core nodes handle DHT, relay/forwarding, gateway (attachment records), and mailbox.
Gateway functionality can be disabled per-node via `[gateway] enabled = false`.

### 1.5 Plane separation

| Plane | Responsibility |
|---|---|
| transport | Raw byte streams (TCP/QUIC/WS/Unix/SOCKS/BLE) |
| session/security | Identity, key agreement, session lifecycle |
| veil control | Ping/pong, neighbor offers, RTT probes, NAT traversal |
| discovery | Kademlia DHT, attachment/mailbox/app-endpoint lookup |
| delivery | Mailbox, store-and-forward, forward tunnels |
| local mesh | UDP realm, BLE/Wi-Fi, gateway bridging |
| application | App addressing, stream multiplexing, IPC |

### 1.6 Vivaldi — optimization hint only

Vivaldi coordinates (if used) are **never** used as:
- `node_id` or address space
- DHT placement key
- trust or ownership anchor

They are **only** used for: preferred gateway selection, mailbox replica ordering, neighbor/relay ranking, route scoring.

---

## 2. Wire format

### 2.1 Frame header (`OVL1`)

```
FrameHeader {
  magic:      [u8; 4]  = "OVL1"
  version:    u8       = 1
  family:     u8       // see §2.2
  msg_type:   u16 BE
  flags:      u16 BE
  header_len: u16 BE   // = 24 (fixed header only, no TLV extensions yet)
  body_len:   u32 BE   // max 16 MiB (MAX_FRAME_BODY); default listener cap 1 MiB
  stream_id:  u32 BE
  request_id: u32 BE
}
```

Total fixed header size: **24 bytes**.

### 2.2 Frame families

| `family` | Name | Description |
|---|---|---|
| 0 | `Session` | Session setup and lifecycle |
| 1 | `Control` | Control plane (ping, probes, NAT) |
| 2 | `Discovery` | Kademlia DHT |
| 3 | `Delivery` | Mailbox and forwarding |
| 4 | `App` | Application data plane |
| 5 | `Mesh` | Local mesh (UDP realm, BLE) |
| 6 | `LocalApp` | IPC between node and local app processes |
| 7 | `Tunnel` | TUN/TAP virtual interface (VPN) |
| 8 | `Routing` | Route gossip, RouteRequest/Response, PoW, RecursiveRelay |
| 9 | `Diag` | End-to-end diagnostics (DiagPing, TraceProbe) |
| 10 | `RelayChain` | Onion-encrypted relay chain hop (Epic 246) |
| 11 | `PeerExchange` | PEX random-walk (Epic 436) |

### 2.3 Session family message types (`family=0`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `Hello` | Initial handshake probe |
| 1 | `Identity` | Public key + node_id + nonce |
| 2 | `Capabilities` | Role/feature advertisement |
| 3 | `KeyAgreement` | X25519 ephemeral key exchange |
| 4 | `SessionConfirm` | Confirm session established |
| 5 | `Attach` | Attach to session with role |
| 6 | `Detach` | Graceful detach |
| 7 | `Keepalive` | Session liveness probe |

### 2.4 Control family message types (`family=1`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `Ping` | RTT probe initiator |
| 1 | `Pong` | RTT probe echo |
| 2 | `NeighborOffer` | Announce self as reachable neighbor |
| 3 | `RouteProbe` | Route latency measurement |
| 4 | `RouteReply` | Echo of RouteProbe + measured RTT |
| 5 | `Error` | Protocol error notification |
| 6 | `NatProbeRequest` | NAT traversal: send candidates to peer |
| 7 | `NatProbeReply` | NAT traversal: peer's candidate reply |
| 8 | `NatRelayRequest` | Request core node to relay traffic |

### 2.5 Discovery family message types (`family=2`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `FindNode` | Kademlia FIND_NODE |
| 1 | `FindValue` | Kademlia FIND_VALUE |
| 2 | `Store` | Kademlia STORE |
| 3 | `Delete` | Remove DHT record |
| 4 | `AnnounceAttachment` | Publish node attachment record |
| 5 | `GetAttachment` | Lookup attachment record |
| 6 | `GetMailboxSet` | Lookup mailbox set for node |
| 7 | `GetAppEndpoint` | Lookup app endpoint record |
| 8 | `FindNodeResponse` | Response to FindNode |

### 2.6 Delivery family message types (`family=3`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `MailboxPut` | Store message in mailbox |
| 1 | `MailboxFetch` | Retrieve messages from mailbox |
| 2 | `MailboxAck` | Acknowledge and delete fetched messages |
| 3 | `Forward` | Forward payload to destination node |
| 4 | `DeliveryStatus` | Delivery receipt |

### 2.7 App family message types (`family=4`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `AppOpen` | Open application stream |
| 1 | `AppData` | Application data frame |
| 2 | `AppClose` | Close stream |
| 3 | `AppSend` | Datagram-style send |
| 4 | `AppReceipt` | Delivery receipt |
| 5 | `AppWindowUpdate` | Flow control window update |
| 6 | `AppRtData` | Realtime (unordered) data |

### 2.8 Tunnel family message types (`family=7`)

| `msg_type` | Name | Description |
|---|---|---|
| 0 | `IpPacket` | Raw IP packet from/to TUN device |

---

## 3. Data model

### 3.1 Attachment record

```
AnnounceAttachmentPayload {
  node_id:       [u8; 32]
  role:          u8
  realm_id:      u32 BE
  epoch:         u32 BE
  expires_at:    u64 BE  (Unix seconds)
  gateway_count: u8
  mailbox_count: u8
  gateways:      GatewayRef[gateway_count]
  mailboxes:     MailboxRef[mailbox_count]
  seq_no:        u64 BE  (monotonic; larger wins on conflict)
  sig_len:       u16 BE  (0 = unsigned)
  signature:     bytes[sig_len]
}
```

The **signature** covers the "signable body" = all bytes from `node_id` through `seq_no` (inclusive). Key used: node's own identity public key.

### 3.2 GatewayRef

```
GatewayRef {
  gateway_node_id: [u8; 32]
  priority:        u16 BE
  weight:          u16 BE
  flags:           u16 BE
}
// WIRE_SIZE = 38 bytes
```

### 3.3 MailboxRef

```
MailboxRef {
  mailbox_node_id: [u8; 32]
  shard_id:        u32 BE
  priority:        u16 BE
  flags:           u16 BE
}
// WIRE_SIZE = 40 bytes
```

### 3.4 DHT value envelope

```
DhtValue {
  key:       [u8; 32]
  kind:      u8    (0=raw, 1=attachment, 2=mailbox, 3=app_endpoint)
  epoch:     u32 BE
  ttl_secs:  u32 BE
  seq_no:    u64 BE
  body_len:  u32 BE
  body:      bytes[body_len]
  sig_len:   u16 BE  (0 = unsigned)
  signature: bytes[sig_len]
}
```

The **signable prefix** covers bytes `key` through `body` (inclusive). Signature uses the originating node's identity key.

### 3.5 DHT key derivation (spec §6.5)

```
node routing key  = node_id
attachment key    = BLAKE3("attach"  || node_id)
mailbox key       = BLAKE3("mailbox" || node_id || epoch_be4)
app endpoint key  = BLAKE3("app"     || node_id || app_id || endpoint_id_be4)
```

### 3.6 Delivery envelope

```
DeliveryEnvelope {
  recipient_node_id: [u8; 32]
  app_id:            [u8; 32]
  endpoint_id:       u32 BE
  content_id:        [u8; 32]  (BLAKE3 of payload)
  created_at:        u64 BE    (Unix seconds)
  ttl_secs:          u32 BE
  payload_len:       u32 BE
  payload:           bytes[payload_len]
}
```

---

## 4. Session protocol

### 4.1 Handshake phases

```
Initiator                       Responder
   |------ HELLO -------------->|
   |<----- HELLO ---------------|
   |------ IDENTITY ----------->|
   |<----- IDENTITY ------------|
   |------ CAPABILITIES ------->|
   |<----- CAPABILITIES --------|
   |------ KEY_AGREEMENT ------>|
   |<----- KEY_AGREEMENT -------|
   |------ SESSION_CONFIRM ---->|
   |<----- SESSION_CONFIRM -----|
   |------ ATTACH ------------->|   (role + realm negotiation)
   |<----- ATTACH --------------|
   |== encrypted session active |
```

### 4.2 Key agreement

X25519 ephemeral Diffie-Hellman with HKDF-SHA256 key derivation. The derived symmetric key is used for AEAD encryption (ChaCha20-Poly1305) of subsequent frames.

### 4.3 Signature algorithms

| `algo` byte | Algorithm | Public key size | Signature size |
|---|---|---|---|
| 0 | Ed25519 | 32 bytes | 64 bytes |
| 1 | Falcon-512 | 897 bytes | ~690 bytes (variable) |

---

## 5. DHT — Kademlia

### 5.1 Who participates

- **`core`**: full Kademlia participant, stores and replicates records.
- **`gateway`**: stores records for its attached leaves, participates partially.
- **`relay`**, **`leaf`**: never own DHT records.

### 5.2 Distance metric

```
distance(a, b) = a XOR b   // XOR-space
```

### 5.3 Routing table

K-bucket table with K=20. Bucket split on first contact in range.

### 5.4 Record replication

Records are replicated to the K closest nodes by key. TTL enforced at storage time; expired records filtered at fetch time.

---

## 6. NAT traversal

### 6.1 Flow

```
Alice                  Core                  Bob
  |--NAT_PROBE_REQUEST-->|                   |
  |                      |--relay to Bob---->|
  |                      |<--NAT_PROBE_REPLY-|
  |<-----relay to Alice--|                   |
  |-------UDP hole punch simultaneously----->|
  |<=============== QUIC direct connection ===|
```

### 6.2 Relay fallback

If hole punching fails within the deadline (configurable, default 500 ms), the initiator sends `NAT_RELAY_REQUEST` to a `Core` node. The relay creates a bidirectional `Forward` tunnel between the two peers.

Only `Core` nodes may accept `NAT_RELAY_REQUEST` (`RelayFallback::core_should_relay`). Legacy `Gateway` role was removed in Epic 435 and rolled into `Core`.

---

## 7. QUIC multi-stream transport

For QUIC transport sessions, frames are split across QUIC streams by priority to eliminate head-of-line blocking:

| Priority | QUIC stream type |
|---|---|
| `REALTIME` (0) | Unidirectional `open_uni()` |
| `INTERACTIVE`, `BULK`, `BACKGROUND` | Bidirectional `open_bi()` |

Each veil `stream_id` maps to one QUIC stream, created lazily on first use. Quinn's built-in CUBIC/BBR congestion control applies per-stream automatically.

---

## 8. TUN/TAP virtual interface

The `tun-interface` feature enables a virtual TUN network device:

```
[OS network stack] ↕ TUN (10.99.0.1/16)
[TunRunner] reads IP packets → encapsulates as Tunnel/IpPacket frames → veil
[TunRunner] receives Tunnel/IpPacket frames → decapsulates → writes to TUN
```

Config section `[tun]`:
```toml
[tun]
enabled = true
veil_prefix = "10.99.0.0/16"
local_addr = "10.99.0.1"
iface_name = "ovltun0"

[[tun.peer_routes]]
peer_node_id = "<64-hex node_id>"
remote_addr  = "10.99.0.2"
```

Requires OS-level TUN support and usually root privileges.

---

## 9. Priority system

Outgoing frames are queued by priority with weighted round-robin scheduling:

| Level | Constant | Default weight | Use case |
|---|---|---|---|
| `REALTIME` | 0 | 8 | Voice, real-time audio |
| `INTERACTIVE` | 1 | 4 | RPC, interactive UI |
| `BULK` | 2 | 2 | File transfer |
| `BACKGROUND` | 3 | 1 | Sync, housekeeping |

Priority is encoded in `FrameHeader.flags` bits `[1:0]`.

---

## 10. SOCKS5 proxy

A SOCKS5 ingress proxy allows any TCP application to tunnel traffic through the veil:

```
[App] → SOCKS5(localhost:1080) → [Local Node] → APP_STREAM → [Exit Node] → TCP → [Target]
```

Config:
```toml
[proxy.socks5]
enabled = true
listen  = "127.0.0.1:1080"

[proxy.exit]
enabled = true   # only on Core/Gateway with can_exit_proxy
```

Only `Core` and `Gateway` nodes with `exit.enabled = true` accept exit proxy connections.

---

## 11. Mailbox

Mailbox provides store-and-forward delivery for offline/intermittent nodes.

```
PUT:   sender → MAILBOX_PUT → mailbox_node
FETCH: recipient → MAILBOX_FETCH(after_seq) → mailbox_node → entries[]
ACK:   recipient → MAILBOX_ACK(up_to_seq) → mailbox_node
```

Backends: `memory` (не сохраняется на диск), `wal` (crash-safe WAL), `rocksdb` (требует feature `rocksdb-cold`, активен по умолчанию).

---

## 12. Milestone checklist

All items below correspond to epics in `TASKS.md`.

- [x] **Epic 1** — OVL1 binary protocol (`proto/`)
- [x] **Epic 2** — Session plane FSM (`node/session/`)
- [x] **Epic 3** — Runtime decomposition (listeners, outbound connector, session registry)
- [x] **Epic 4** — Role model (`leaf`, `relay`, `gateway`, `core`)
- [x] **Epic 5** — Mailbox (put/fetch/ack, TTL, delivery envelope)
- [x] **Epic 6** — App addressing (`app_id`, endpoint registry, IPC)
- [x] **Epic 7** — Gateway/leaf attachment
- [x] **Epic 8** — Static discovery directory
- [x] **Epic 9** — Core-only Kademlia DHT
- [x] **Epic 10** — Local mesh (UDP realm, beacon discovery, gateway bridge)
- [x] **Epic 12** — Routing optimization (RTT probes, Vivaldi, neighbor scoring, route cache)
- [x] **Epic 13** — Storage hardening (frame size limits, codec, TLV)
- [x] **Epic 14** — Abuse resistance (rate limits, PoW, ban system)
- [x] **Epic 15** — Observability (metrics, admin API, structured logs)
- [x] **Epic 16** — Compatibility (legacy JSON handshake feature flag)
- [x] **Epic 17** — Devnet scripts + benchmark harness
- [x] **Epic 20** — Priority queue (WRR, 4 levels)
- [x] **Epic 21** — Mailbox persistence (RocksDB backend)
- [x] **Epic 22** — TCP keepalive
- [x] **Epic 26** — App data plane via IPC
- [x] **Epic 27** — App stream API via IPC
- [x] **Epic 30** — QUIC multi-stream transport
- [x] **Epic 32** — NAT traversal (hole punching + relay fallback)
- [x] **Epic 33** — SOCKS5 proxy
- [x] **Epic 34** — TUN/TAP virtual interface
- [x] **Epic 35** — Rust client SDK (`veilclient` crate)
- [x] **Epic 36** — Cross-node DHT (`NetworkPeerQuerier`)
- [x] **Epic 37** — Devnet scripts
- [x] **Epic 38** — Benchmark harness
- [x] **RFC 0001** — This document (signed DHT values, `DhtValue` envelope)
- [ ] **Epic 11** — Real local transports (BLE, Wi-Fi Direct) — hardware-specific

---

## 13. Security considerations

- **Authentication**: All sessions require identity verification via Ed25519 or Falcon-512 public keys.
- **Integrity**: DHT records are optionally signed by originating nodes (`DhtValue.signature`, `AnnounceAttachmentPayload.signature`). Receivers should reject records with invalid signatures.
- **Replay prevention**: `seq_no` fields provide monotonic ordering; receivers should reject records with `seq_no` lower than the last accepted value from the same node.
- **Rate limiting**: All peer connections subject to configurable frame-rate limits with exponential backoff and temporary bans on excessive violations.
- **PoW admission**: Optional BLAKE3 proof-of-work on identity phase prevents cheap Sybil registration.
- **Exit proxy authorization**: Exit proxy connections only accepted by nodes with explicit `exit.enabled = true` capability. Role check enforced: `Core` or `Gateway` only.

---

## 14. Implementation map

| Spec section | Implementation |
|---|---|
| §2.1 Frame header | `proto/header.rs`, `proto/codec.rs` |
| §2.2 Families | `proto/family.rs` |
| §3.1 Attachment record | `proto/discovery.rs::AnnounceAttachmentPayload` |
| §3.4 DHT value envelope | `proto/discovery.rs::DhtValue` |
| §3.5 DHT keys | `proto/discovery.rs::{attachment_key,mailbox_key,app_endpoint_key}` |
| §4 Session protocol | `node/session/` (handshake — `node/session/handshake.rs`) |
| §5 DHT Kademlia | `node/dht/` |
| §6 NAT traversal | `node/nat/` |
| §7 QUIC multi-stream | `node/session/quic_transport.rs` |
| §8 TUN/TAP | `node/tun/` |
| §9 Priority system | `node/session/priority_queue.rs` |
| §10 SOCKS5 proxy | `node/proxy/socks5.rs`, `node/proxy/exit.rs` |
| §11 Mailbox | `node/mailbox/` |

---

*RFC status: Accepted. Last updated: 2026-03-26.*
