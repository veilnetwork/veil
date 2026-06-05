# OVL1 Network Contracts

This document specifies what the veil network **guarantees** to applications, what it explicitly **does not guarantee**, and how the protocol is **versioned**.  It is the authoritative reference for application developers building on top of OVL1.

---

## 1. Delivery

**Protocol:** `IPC_SEND` / `DELIVERY_FORWARD` plane.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **Best-effort delivery** | Always — the network makes a single-path forwarding attempt; no retransmissions at the network layer. |
| **At-least-once ACK** | When the sender sets `IPC_SEND_FLAG_REQUIRE_ACK`; the node retransmits until it receives a `DELIVERY_ACK` from the destination mailbox. |
| **Duplicate suppression at destination** | The destination node deduplicates by `content_id` (32-byte identifier); applications may still see duplicates if they bypass the mailbox layer. |

### What is NOT guaranteed

- **Ordering** between independent datagrams: two messages sent to the same peer may arrive out of order.
- **Delivery** without `IPC_SEND_FLAG_REQUIRE_ACK`: the frame may be silently dropped at any hop.
- **Timeliness**: no latency SLA; congestion, routing changes, or offline peers may delay delivery arbitrarily up to `ttl_secs`.

### Key constants

- `MAX_CLOCK_SKEW_SECS = 300` — envelope `created_at` may not be more than 5 minutes in the future.
- `MAX_RELAY_HOPS = 16` — envelopes exceeding this hop count are dropped by relay nodes.

---

## 2. Streams

**Protocol:** `APP_OPEN` / `APP_DATA` / `APP_CLOSE` plane (OVL1 application layer).

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **Ordered delivery** | All bytes within a single `stream_id` arrive in the order they were sent. |
| **Reliable delivery** | The underlying session transport retransmits lost frames; the stream layer does not add independent retransmit logic. |
| **Half-close semantics** | Either side may send `APP_CLOSE` to signal it will send no more data; the other side may continue sending until it also closes. |
| **Flow control** | The sender respects `initial_window` advertised in `APP_RECEIPT`; the receiver must issue window updates to avoid stalling. |

### What is NOT guaranteed

- **Cross-stream ordering**: bytes on `stream_id = 1` and `stream_id = 2` may interleave arbitrarily.
- **Delivery if the session drops**: if the underlying session is terminated, open streams are silently aborted (no `APP_CLOSE` is guaranteed to reach the peer).

### Key constants

- `MAX_STREAM_SEND_WINDOW = 16 MiB` — maximum in-flight bytes per stream; senders that exceed this are backpressured.
- `MAX_STREAM_INITIAL_WINDOW = 16 MiB` — the peer-advertised `initial_window` is clamped to this (on both stream open and `window_update`), so a peer cannot advertise an oversized window to force unbounded local buffering (U3).

---

## 3. Security

**Protocol:** session handshake + E2E encryption layer.

### Identity

- **Node identity**: `node_id = BLAKE3(public_key_bytes)`.  The signing key is Ed25519 **or** Falcon-512 (selected per-node).  The session handshake (`SESS_IDENTITY` / `SESS_CONFIRM`) proves knowledge of the private key; a relay cannot impersonate a peer without its private key.
- **Session confidentiality**: after handshake, all session frames are encrypted with a shared X25519-ephemeral-DH-derived key (HKDF-SHA256); relay nodes cannot read frame content.

### End-to-end encryption

- **Content opacity**: application payload is E2E encrypted (`ChaCha20-Poly1305`) between sender and recipient node; relay nodes see only `dst_node_id` and `content_id`.
- **Sender authentication**: by default the sender's `node_id` is authenticated inside the ciphertext; only the recipient can verify it.
- **Replay protection**: the destination node maintains a 32-second replay window keyed on `content_id`; a peer that replays outside this window triggers a ban.

### What is NOT guaranteed

- **Forward secrecy at the datagram layer**: the current E2E layer uses long-term recipient pubkey; session keys provide forward secrecy at the transport layer only.
- **Anonymity from the recipient**: the recipient always learns the sender's `node_id` from the authenticated ciphertext (unless `IPC_SEND_FLAG_ANONYMOUS` is set — see §4).

---

## 4. Privacy

**Protocol:** `IPC_SEND_FLAG_ANONYMOUS` + meta-E2E encryption.

### Anonymous send

When a client sets `IPC_SEND_FLAG_ANONYMOUS` in `IPC_SEND`:

1. The node calls `meta_encrypt` instead of the standard `encrypt`; the outer `DeliveryEnvelope` carries `sender_node_id = [0u8; 32]`.
2. **Relay nodes** see only `dst_node_id`; the sender's identity is invisible to them.
3. **The recipient** decrypts the meta-E2E ciphertext and recovers the sender's ephemeral key, but **not** a stable `node_id` (unless the application includes one in the payload).

### What is NOT guaranteed

- **Sender anonymity from the recipient**: the current meta-E2E scheme uses a per-message ephemeral key pair; the recipient cannot link two anonymous messages to the same sender, but the sender is not hidden from traffic analysis if the application sends identifying content.
- **Network-level anonymity**: relay nodes forward frames based on `dst_node_id`; traffic-analysis adversaries observing multiple hops may correlate sender and recipient.
- **Proxy anonymity**: the SOCKS5 exit proxy (`IPC_PROXY_*`) knows the originating node that requested the connection.

---

## 5. DHT

**Protocol:** Kademlia-based distributed hash table over the discovery plane.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **k-replication** | Each DHT value is stored at up to `k = 20` nodes closest to the key. |
| **TTL-bounded storage** | Values are not stored permanently; they expire after the TTL set by the publisher. |
| **O(log N) lookup** | Under the assumption that fewer than `k/2` nodes in every k-bucket are Byzantine, a `FIND_VALUE` lookup converges in `O(log N)` rounds. |
| **Iterative routing** | The lookup is iterative (initiator contacts nodes directly), not recursive; this limits the blast radius of a malicious node to a single lookup step. |

### What is NOT guaranteed

- **Consistency**: the DHT is eventually consistent; stale or missing values are possible during churn.
- **Byzantine tolerance beyond `k/2` per bucket**: if more than half the nodes in a specific k-bucket are adversarial, lookups through that bucket may return incorrect results.
- **Persistence across total network partition**: values are republished by the publisher; if the publisher goes offline before republication, values are lost after TTL expiry.

### Key constants

- `K = 20` — number of closest nodes per bucket; replication factor.
- `MAX_NODES_PER_RESPONSE = 32` — maximum contacts returned in a single `FIND_NODE` response.

---

## 6. Routing

**Protocol:** `DELIVERY_FORWARD` relay path + `RouteAnnounce` gossip.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **Best-effort multi-path** | The `RouteCache` stores up to `MAX_ROUTES_PER_DST = 4` next-hop candidates per destination; the node picks the best-scoring one at send time. |
| **Loop prevention** | Each relay hop increments `relay_hops`; frames with `relay_hops >= MAX_RELAY_HOPS` are dropped. |
| **Split-horizon** | A frame received from peer P is not forwarded back to P (the relay checks `via_node_id != src_peer`). |
| **TTL expiry** | Frames with `created_at + ttl_secs < now` are dropped before forwarding; this bounds the lifetime of stale traffic in the network. |

### What is NOT guaranteed

- **Guaranteed delivery**: routing is best-effort; a frame may be dropped if no route exists or the route becomes stale between send and delivery.
- **Latency bounds**: no SLA; multi-hop forwarding adds variable latency depending on network topology and congestion.
- **Stable paths**: route selection may change between consecutive frames to the same destination.

### Key constants

- `MAX_RELAY_HOPS = 16` — maximum relay hops before a frame is dropped.
- `MAX_ROUTES_PER_DST = 4` — maximum next-hop candidates per destination in `RouteCache`.
- `MAX_ROUTES_PER_VIA = 256` — maximum destinations a single relay node may be next-hop for.
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — gossip announcements older than 5 minutes are rejected.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — future-dated gossip announcements are rejected.

---

## Protocol versioning

### IPC protocol (client ↔ node)

The IPC protocol version is declared in `proto/ipc.rs`:

```rust
pub const IPC_PROTOCOL_VERSION: u16 = 1;  // current wire version
pub const CLIENT_MIN_VERSION: u16   = 1;  // oldest client version accepted
pub const CLIENT_MAX_VERSION: u16   = 1;  // newest client version accepted
```

The node rejects clients whose `version` is outside `[CLIENT_MIN_VERSION, CLIENT_MAX_VERSION]` with `ipc_hello_err::VERSION_MISMATCH`.

### OVL1 wire protocol

The session-layer protocol version is declared in `HelloPayload::ovl1_version`.  Breaking changes increment this field; old and new nodes that cannot negotiate a common version disconnect.

---

*This document is updated whenever a network contract changes.  Implementation details (timeouts, cache sizes, gossip fanout) are documented in `proto/budget.rs` and may change between releases without notice.*
