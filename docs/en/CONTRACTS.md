# OVL1 Network Contracts

This document spells out three things: what the veil network **guarantees** to applications, what it explicitly **does not guarantee**, and how the protocol is **versioned**. It is the authoritative reference if you're building an application on top of OVL1.

Throughout, a **contract** means a promise the network makes about its behavior — something you can rely on without reading the implementation. When a guarantee comes with a condition, the condition is the catch: the promise holds only when that condition is met.

---

## 1. Delivery

**Protocol:** `IPC_SEND` / `DELIVERY_FORWARD` plane.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **Best-effort delivery** | Always. The network makes one forwarding attempt down a single path. There are no retransmissions at the network layer. |
| **At-least-once ACK** | When the sender sets `IPC_SEND_FLAG_REQUIRE_ACK`. The node then retransmits until the destination mailbox returns a `DELIVERY_ACK`. |
| **Duplicate suppression at destination** | The destination node drops duplicates by `content_id` (a 32-byte identifier). Applications that bypass the mailbox layer may still see duplicates. |

### What is NOT guaranteed

- **Ordering** between independent datagrams. Two messages sent to the same peer may arrive in either order.
- **Delivery** without `IPC_SEND_FLAG_REQUIRE_ACK`. The frame may be dropped at any hop, with no warning.
- **Timeliness**. There is no latency SLA. Congestion, routing changes, or an offline peer can delay delivery by any amount, up to `ttl_secs`.

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
| **Reliable delivery** | The underlying session transport retransmits lost frames. The stream layer adds no retransmit logic of its own. |
| **Half-close** | Either side may send `APP_CLOSE` to say it is done sending. The other side keeps sending until it closes too. (This is *half-close*: one direction shuts down while the other stays open.) |
| **Flow control** | The sender respects the `initial_window` advertised in `APP_RECEIPT`. The receiver must issue window updates, or the sender stalls. |

### What is NOT guaranteed

- **Cross-stream ordering**. Bytes on `stream_id = 1` and `stream_id = 2` may interleave in any way.
- **Delivery if the session drops**. If the underlying session ends, open streams are aborted without notice — no `APP_CLOSE` is guaranteed to reach the peer.

### Key constants

- `MAX_STREAM_SEND_WINDOW = 16 MiB` — the most in-flight (sent but not yet acknowledged) bytes allowed per stream. A sender that hits this limit is held back until the receiver catches up.
- `MAX_STREAM_INITIAL_WINDOW = 16 MiB` — an upper bound on the `initial_window` a peer can advertise, applied both when the stream opens and on every `window_update`. Without it, a peer could advertise a huge window and force the local side to buffer without limit (U3).

---

## 3. Security

**Protocol:** session handshake + E2E encryption layer.

### Identity

- **Node identity**: `node_id = BLAKE3(public_key_bytes)`. The signing key is Ed25519 **or** Falcon-512, chosen per node. The session handshake (`SESS_IDENTITY` / `SESS_CONFIRM`) proves the node holds the matching private key. A relay can't impersonate a peer without that key.
- **Session confidentiality**: once the handshake completes, every session frame is encrypted with a shared key derived from an ephemeral X25519 Diffie-Hellman exchange (via HKDF-SHA256). Relay nodes can't read frame content.

### End-to-end encryption

- **Content opacity**: the application payload is end-to-end encrypted (`ChaCha20-Poly1305`) between the sending node and the recipient node. Relay nodes see only `dst_node_id` and `content_id`.
- **Sender authentication**: by default the sender's `node_id` is authenticated inside the ciphertext. Only the recipient can verify it.
- **Replay protection**: the destination node keeps a 60-second replay window keyed on `content_id`. A message whose `content_id` was already seen inside that window is silently dropped (deduplicated), not processed again.

### What is NOT guaranteed

- **Forward secrecy at the datagram layer**. The current E2E layer encrypts to the recipient's long-term public key, so a later key compromise can expose past datagrams. Session keys give forward secrecy at the transport layer only. (*Forward secrecy* means stealing today's keys doesn't unlock yesterday's traffic.)
- **Anonymity from the recipient**. The recipient always learns the sender's `node_id` from the authenticated ciphertext — unless `IPC_SEND_FLAG_ANONYMOUS` is set (see §4).

---

## 4. Privacy

**Protocol:** `IPC_SEND_FLAG_ANONYMOUS` + meta-E2E encryption.

### Anonymous send

When a client sets `IPC_SEND_FLAG_ANONYMOUS` in `IPC_SEND`:

1. The node calls `meta_encrypt` instead of the usual `encrypt`. The outer `DeliveryEnvelope` then carries `sender_node_id = [0u8; 32]` — all zeros.
2. **Relay nodes** see only `dst_node_id`. The sender's identity is invisible to them.
3. **The recipient** decrypts the meta-E2E ciphertext and recovers the sender's ephemeral key — but **not** a stable `node_id`, unless the application put one in the payload itself.

### What is NOT guaranteed

- **Sender anonymity from the recipient**. The meta-E2E scheme uses a fresh ephemeral key pair per message, so the recipient can't link two anonymous messages to the same sender. But the application can still give the sender away: if its content is identifying, traffic analysis sees through the anonymity.
- **Network-level anonymity**. Relay nodes forward frames by `dst_node_id`. An adversary watching several hops can correlate sender and recipient.
- **Proxy anonymity**. The SOCKS5 exit proxy (`IPC_PROXY_*`) knows which node opened the connection.

---

## 5. DHT

**Protocol:** Kademlia-based distributed hash table over the discovery plane.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **k-replication** | Each DHT value is stored on up to `k = 20` of the nodes closest to its key. |
| **TTL-bounded storage** | Values don't live forever. Each expires after the TTL (time-to-live) set by the node that published it. |
| **O(log N) lookup** | A `FIND_VALUE` lookup converges in `O(log N)` rounds, as long as fewer than `k/2` nodes in every k-bucket are misbehaving. (A *k-bucket* is the set of known peers in one slice of the address space; *misbehaving*, or Byzantine, nodes may lie or drop requests rather than just go offline.) |
| **Iterative routing** | The initiator drives the lookup itself, contacting each node directly rather than asking one node to chase the answer on its behalf. So a single malicious node can spoil at most one step of the lookup, not the whole thing. |

### What is NOT guaranteed

- **Consistency**. The DHT is only eventually consistent. While nodes are joining and leaving (*churn*), a lookup may return a stale value or miss one entirely.
- **Byzantine tolerance beyond `k/2` per bucket**. If more than half the nodes in a given k-bucket are adversarial, lookups through that bucket can return wrong answers.
- **Persistence across a total network partition**. Only the publisher keeps a value alive, by republishing it. If the publisher goes offline before it republishes, the value is lost once its TTL expires.

### Key constants

- `K = 20` — number of closest nodes per bucket; replication factor.
- `MAX_NODES_PER_RESPONSE = 32` — maximum contacts returned in a single `FIND_NODE` response.

---

## 6. Routing

**Protocol:** `DELIVERY_FORWARD` relay path + `RouteAnnounce` gossip.

### What is guaranteed

| Guarantee | Condition |
|-----------|-----------|
| **Best-effort multi-path** | The `RouteCache` holds up to `MAX_ROUTES_PER_DST = 4` next-hop candidates per destination. At send time the node picks the best-scoring one. |
| **Loop prevention** | Each relay hop bumps `relay_hops`. A frame is dropped once `relay_hops >= MAX_RELAY_HOPS`, so it can't loop forever. |
| **Split-horizon** | A frame received from peer P is never forwarded straight back to P (the relay checks `via_node_id != src_peer`). This keeps a frame from bouncing between two relays. |
| **TTL expiry** | A frame is dropped before forwarding once `created_at + ttl_secs < now`. This caps how long stale traffic can linger in the network. |

### What is NOT guaranteed

- **Guaranteed delivery**. Routing is best-effort. A frame may be dropped if no route exists, or if the route goes stale between send and delivery.
- **Latency bounds**. There is no SLA. Each extra hop adds latency, and how much depends on the network's shape and how congested it is.
- **Stable paths**. The chosen route can change from one frame to the next, even for the same destination.

### Key constants

- `MAX_RELAY_HOPS = 16` — how many relay hops a frame may take before it's dropped.
- `MAX_ROUTES_PER_DST = 4` — how many next-hop candidates `RouteCache` keeps per destination.
- `MAX_ROUTES_PER_VIA = 256` — how many destinations a single relay node may be the next hop for.
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — gossip announcements older than 5 minutes are rejected.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — gossip announcements dated in the future are rejected.

---

## Protocol versioning

### IPC protocol (client ↔ node)

The IPC protocol version is declared in `proto/ipc.rs`:

```rust
pub const IPC_PROTOCOL_VERSION: u16 = 1;  // current wire version
pub const CLIENT_MIN_VERSION: u16   = 1;  // oldest client version accepted
pub const CLIENT_MAX_VERSION: u16   = 1;  // newest client version accepted
```

If a client's `version` falls outside `[CLIENT_MIN_VERSION, CLIENT_MAX_VERSION]`, the node rejects it with `ipc_hello_err::VERSION_MISMATCH`.

### OVL1 wire protocol

The session-layer protocol version lives in `HelloPayload::ovl1_version`. A breaking change bumps this field. If an old node and a new node can't settle on a shared version, they disconnect.

---

*This document is updated whenever a network contract changes. Implementation details — timeouts, cache sizes, gossip fanout — live in `proto/budget.rs` and may change between releases without notice.*
