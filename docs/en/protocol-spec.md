# OVL1 Protocol Specification

Version: **1** (magic `0x4F564C31`), minor = 1.

This document is the authoritative wire-format reference for OVL1 — the on-the-wire protocol that Veil nodes speak to each other. It is precise by design. Field names, byte offsets, and constants here match the code.

> For an architectural overview — [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).
> For a quick wire-format reference — [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

---

## 1. Identification

### 1.1 node_id

```text
node_id = BLAKE3(raw_public_key_bytes)   // 32 bytes
```

Implementation: `cfg::model::NodeId::from_public_key(algo, base64_pubkey)`.

Properties:
- Stable global identifier — independent of IP, location, transport
- Bound to a cryptographic key
- Hashing algorithm: BLAKE3, input: raw bytes of the public key (not the base64 string)
- Represented as a 64-character hex string in the CLI and config

### 1.2 app_id

```text
app_id = BLAKE3-derive_key(
    context = "veil.app_id.v1",
    ikm     = node_id || ns_len(u32 BE) || app_namespace
                       || name_len(u32 BE) || app_name
)     // 32 bytes
```

`app_namespace` and `app_name` are UTF-8 strings with arbitrary content. The
application developer picks them (convention: reverse-DNS, for example
`"com.example.chat"` + `"main"`). On the wire they are limited to 255 bytes each
(see §9.3 `AppBind`).

The length-prefixes and the domain separator (the `context` string) are
**mandatory**. Without them, naive concatenation produces collisions: `("foo","bar")`
and `("fo","obar")` both concatenate to `"foobar"` and would yield the same digest.
The v1 derivation above keeps each input distinct, so the result is unique.

For IPC applications in ephemeral mode (the default), the formula gains a 16-byte
`client_token` that the node issues in `AppHelloOk`:

```text
ephemeral_app_id = BLAKE3-derive_key(
    context = "veil.ephemeral_app_id.v1",
    ikm     = node_id || client_token(16) || ns_len(u32 BE) || app_namespace
                                           || name_len(u32 BE) || app_name
)
```

This makes the `app_id` unique per connection: two processes on the same node that
bind the same `(namespace, name)` still get different addresses. Well-known services
that need a fixed address use the stable form above instead (via `bind_named`).

The application endpoint address:

```
AppAddress {
  node_id:     [u8; 32],    // Node on which the application is running
  app_id:      [u8; 32],    // Application identifier
  endpoint_id: u32,         // Port within the application (1..65535)
}
```

### 1.3 content_id

```text
content_id = BLAKE3(payload_bytes)   // 32 bytes
```

This is the fingerprint of a message body. Nodes use it to spot and drop duplicates while a message is in flight.

---

## 2. Frame Wire Format

Every OVL1 message is a *frame*: a fixed 24-byte header followed by a body. The header says what kind of message it is and how long the body runs; the body is opaque to the framing layer.

### 2.1 Frame Header (FrameHeader)

Fixed header — **24 bytes**:

```text
Offset  Len  Type   Description
------  ---  -----  ---------
  0      4   u32 BE Magic = 0x4F564C31 ("OVL1")
  4      1   u8     Version = 1
  5      1   u8     Family (see table below)
  6      2   u16 BE msg_type (depends on Family)
  8      2   u16 BE flags (priority bits, encryption, ACK-request)
 10      2   u16 BE header_len = 24
 12      4   u32 BE body_len (0 .. MAX_FRAME_BODY = 16 MiB; default listener cap = 1 MiB)
 16      4   u32 BE stream_id (endpoint multiplexing)
 20      4   u32 BE request_id (RPC correlation)
 24      ?   bytes  Body (body_len bytes)
```

### 2.2 Frame Flags (flags, bits)

| Bit | Name | Description |
|-----|-----|----------|
| 0..1 | priority | 0=RT, 1=Interactive, 2=Bulk, 3=Background |
| 2 | encrypted | Body encrypted with ChaCha20-Poly1305 |
| 3 | require_ack | Request delivery confirmation |
| 4..15 | reserved | Reserved, must be 0 |

### 2.3 Family — Protocol Families

A *family* groups related message types. The `Family` byte in the header picks the group; `msg_type` then picks the specific message within it. Each family owns one functional area of the protocol — sessions, discovery, delivery, and so on.

| Family | Number | Purpose |
|--------|-------|------------|
| Session | 0 | OVL1 handshake, keepalive, rekey, resumption ticket, padding |
| Control | 1 | Ping, NeighborOffer, RouteProbe, NAT, Keepalive, Backpressure, Epidemic |
| Discovery | 2 | DHT FindNode, FindValue, Store, Delete, Attachment/Mailbox/AppEndpoint lookup |
| Delivery | 3 | Forward, DeliveryStatus, ChunkManifest, Chunk, Transit, RecursiveRelay, RelayPath |
| App | 4 | Application streams (open, data, close, real-time) |
| Mesh | 5 | Local UDP network (beacons, forward) |
| LocalApp | 6 | IPC for local applications |
| Tunnel | 7 | TUN/TAP IP tunnel |
| Routing | 8 | RouteAnnounce/Withdraw, RouteRequest/Response, PoW, Recursive*, VersionVectorSync |
| Diag | 9 | Diagnostics: DiagPing, DiagPong, TraceProbe, TraceHop |
| RelayChain | 10 | Onion-encrypted relay chain hop |
| PeerExchange | 11 | PEX random-walk: Walk, Challenge, Response, Result |

---

## 3. Session Plane (Family 0)

### 3.1 Handshake

Before two nodes exchange anything else, they run a *handshake* — a short opening dialogue that proves identities and agrees on encryption keys. It is asymmetric: the side that dials out (the initiator) leads, and the other side (the responder) answers. The exchange runs in this order:

```
    Initiator                             Responder
    │── Hello ──────────────────────────►│   OVL1 version + node_id
    │◄─ Hello ───────────────────────────│
    │── Identity ───────────────────────►│   pubkey + nonce + algo + ML-KEM ek
    │◄─ Identity ────────────────────────│
    │── Capabilities ───────────────────►│   role bits + feature flags
    │◄─ Capabilities ────────────────────│
    │── KeyAgreement ───────────────────►│   ephemeral X25519 pubkey
    │◄─ KeyAgreement ────────────────────│
    │── SessionConfirm ─────────────────►│   session_id + MAC
    │◄─ SessionConfirm ──────────────────│
    │── Attach (optional) ──────────────►│   (leaf → gateway)
    │   [CONNECTED]                      │
```

### 3.2 HelloPayload (34 bytes)

```text
[0..2]   ovl1_version   u16 BE = 1
[2..34]  node_id        [u8; 32]
```

### 3.3 IdentityPayload

```text
[0]                  algo           u8  (IdentityPayload: 0=Ed25519, 2=Falcon512, 3=Ed25519+Falcon512, 4=Ed25519+Falcon1024;
                                         session handshake: 1=Ed25519, 2=Falcon512)
[1..3]               pk_len         u16 BE
[3..3+pk]            public_key     bytes
[3+pk]               nonce_len      u8
[4+pk..4+pk+n]       nonce          bytes  (PoW-nonce hex-string)
[4+pk+n..+32]        node_id        [u8; 32]  (must equal BLAKE3(public_key))
[+2]                 mlkem_pk_len   u16 BE  (0 = not transmitted)
[..]                 mlkem_pk       bytes   (1184 B for ML-KEM-768)
```

### 3.4 CapabilitiesPayload (3 bytes)

```text
[0]     roles_supported      u8  (bit 0 = LEAF, bit 3 = CORE; the rest are reserved)
[1]     flags                u8  (cap_flags: CAN_RELAY=0x01,
                                  SUPPORTS_SOVEREIGN_IDENTITY=0x02)
[2]     discovery_mode       u8  (0 = Public, 1 = ContactsOnly,
                                  2 = IntroductionOnly; unknown values
                                  are treated as IntroductionOnly —
                                  forward-compat default)
```

**Backward compatibility:** older peers send only 2 bytes, without the
`discovery_mode` field. The decoder fills the missing byte with `0` (Public) —
those peers predate opt-in privacy, so Public is the right default for them. Any
payload of `>= 2` bytes is accepted.

**What `discovery_mode` means.** It controls how willing a peer is to be found by
strangers:

- `Public` — the peer wants to be discoverable through a DHT walk (a search that hops across the distributed hash table; see §5.5). Other nodes will include it in their FIND_NODE responses.
- `ContactsOnly` — keep the peer out of FIND_NODE responses entirely. It is reachable only through a direct session with a contact it has already handshaked with, or via a pre-shared bootstrap.
- `IntroductionOnly` — same as `ContactsOnly` for FIND_NODE, and stricter still: RouteResponse must strip `transports[]` (see §3.6), so even a successful route lookup hands back no address.

Legacy fields:
- Role bits `RELAY (0x02)`, `GATEWAY (0x04)`, `CORE_ROUTER (0x10)` — removed.
- Cap flags `CAN_MAILBOX=0x02`, `CAN_GATEWAY_LOCAL_MESH=0x04`, `CAN_PARTICIPATE_DHT=0x08`, `CAN_ACCEPT_APP_STREAMS=0x10`, `CAN_STORE=0x20`, `SUPPORTS_TRANSIT=0x40` — nothing ever read them, so they were removed.
- The wire format shrank over time: 12 bytes (legacy) → 2 bytes → 3 bytes.

### 3.5 SessionKeys (derived keys)

The two sides derive their session keys from an ephemeral **X25519** Diffie-Hellman
exchange — a one-time key pair generated just for this session. Do not confuse it
with the identity key (Ed25519/Falcon-512), which only signs the `IdentityPayload`
and never encrypts anything. The derivation runs like this:

```
shared_secret = X25519(my_ephemeral_priv, peer_ephemeral_pub)

salt = local_node_id XOR remote_node_id           // commutative — both sides
                                                  // get the same salt
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a ‖ key_b ‖ session_id] = HKDF-SHA256(salt, ikm, info, len=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id  → (key_a, key_b)
                   else                                 → (key_b, key_a)
```

`tx_key` encrypts outgoing frames; `rx_key` decrypts incoming ones. Ordering the
two `node_id`s lexicographically guarantees the initiator and responder end up with
`tx_key` and `rx_key` swapped — so alice.tx equals bob.rx, and vice versa. That is
what lets each side decrypt what the other sent.

Frames are encrypted with **ChaCha20-Poly1305** (an authenticated cipher): the
32-byte `tx_key`/`rx_key`, a 12-byte counter nonce kept per direction, and the frame
header as additional authenticated data (AAD) — data that is authenticated but not
encrypted.

`session_id` (32 bytes) is a public identifier. It rides in the
`SessionConfirmPayload` and later seeds the salt for rekeys (§3.7).

The identity key (Ed25519/Falcon-512) plays **no part** in this derivation. That is
deliberate, and it buys forward secrecy: even if the long-term identity key later
leaks, past sessions stay sealed.

### 3.6 KeepalivePayload

```text
[0..8]   timestamp_secs  u64 BE
```

A keepalive goes out every `session.keepalive_interval_secs` to show the session is still live. If nothing arrives for longer than `session.idle_timeout_secs`, the session is considered dead and closed.

### 3.7 Rekey (key change)

A long-lived session periodically swaps in fresh keys — a *rekey* — so that no single
key protects too much traffic or stands for too long. It triggers when either
threshold is crossed: `REKEY_BYTES_THRESHOLD` = 128 GiB of traffic, or
`REKEY_TIME_THRESHOLD_SECS` = 32 days (2,764,800 s) of wall-clock time. Both are
configurable via `[session] rekey_bytes_threshold` and
`[session] rekey_time_threshold_secs`, and highly sensitive deployments may lower
them on purpose.

There is a second, parallel rekey clock for the post-quantum (ML-KEM) layer. Its byte
budget, `MLKEM_REKEY_BYTES_THRESHOLD`, is now 128 GiB — the same as
`REKEY_BYTES_THRESHOLD`. The only difference is its timer:
`MLKEM_REKEY_TIME_THRESHOLD_SECS` = 1 hour. That short window keeps the forward-secrecy
horizon of the X25519 session key in step with the ML-KEM end-to-end key.

```
Initiator ── RekeyInit ──► Responder   (new ephemeral X25519 pubkey)
Initiator ◄─ RekeyAck ──── Responder   (responding ephemeral X25519 pubkey)

new_shared = X25519(new_ephemeral_priv, peer_new_ephemeral_pub)
salt       = session_id XOR local_node_id XOR remote_node_id
                                    └ chain-salt links the new keys to the session history
info       = "ovl1-session-rekey-v1"
[key_a ‖ key_b ‖ new_session_id] = HKDF-SHA256(salt, new_shared, info, len=96)
(tx_key, rx_key) — swap by lex-order of node_id, as in §3.5
```

---

## 4. Control Plane (Family 1)

### 4.1 RouteProbePayload

```text
[0..4]   probe_id      u32 BE
[4..12]  timestamp_ms  u64 BE  (local time of the sender)
```

### 4.2 RouteReplyPayload

```text
[0..4]   probe_id      u32 BE  (echo from RouteProbe)
[4..12]  timestamp_ms  u64 BE  (echo)
[12..16] rtt_ms        u32 BE  (RTT measured by the responder; 0 = unknown)
[16]     congestion    u8      (0=free … 255=saturated)
```

### 4.3 NeighborOfferPayload

```text
[0..32]  node_id    [u8; 32]
[32..34] addr_len   u16 BE
[34..N]  addr       bytes  (transport URI)
[N]      flags      u8     (neighbor capabilities)
```

### 4.4 EpidemicPayload (epidemic broadcast)

```text
[0..16]          msg_id      [u8; 16]  (random 128-bit ID)
[16]             ttl         u8        (remaining hop-count)
[17..49]         origin      [u8; 32]  (sender's node_id)
[49..51]         payload_len u16 BE
[51..51+len]     payload     bytes
```

When a node sees a message for the first time, it delivers the message locally and forwards a copy to **K random neighbors** with `ttl - 1`. Each node tracks which `msg_id`s it has already seen, so duplicates stop spreading.

### 4.5 NAT — NatProbeRequestPayload / NatProbeReplyPayload

```text
[0..32]  initiator_node_id  [u8; 32]
[32..36] session_token       u32 BE
[36..38] candidate_count     u16 BE
[38..]   candidates[]        NatCandidate (variable)
```

**NatCandidate**:

```text
[0]      atyp             u8     (address type: 4=IPv4, 6=IPv6, etc.)
[1]      candidate_type   u8     (0=host, 1=server-reflexive, 2=relay)
[2..6]   priority         u32 BE
[6..6+L] addr             bytes  (L depends on atyp)
[6+L..]  port             u16 BE
```

---

## 5. Discovery Plane (Family 2) — DHT (Kademlia)

### 5.1 FindNode (V2 only — V1 removed)

The original V1 messages — `FindNode` (slot 0) and `FindNodeResponse` (slot 8), whose
layout was target+k → `Vec<NodeContact{node_id, transport}>` — have been dropped. The
problem with V1 was that one response handed back a *transport* (the address you dial)
for every contact, all in a single round trip. That leaked the routing graph wholesale
and made it trivially cheap to enumerate the whole network. All FIND_NODE traffic now
runs over V2 plus a separate `ResolveTransport` step (§5.4.1). A sender that still emits
slots 0 or 8 fails `DiscoveryMsg::try_from` and is logged as a `Violation` by the
dispatcher.

**`NodeContact`** survives only as a wire-helper for the "not found" branch of
`FindValue`:

```text
[0..32]  node_id       [u8; 32]
[32..34] transport_len u16 BE
[34..N]  transport     bytes  (URI string)
```

Since **C-06**, that "not found" branch zeroes the transport field
(`transport_len = 0`, empty URI). Like FIND_NODE V2, it returns **node-ids only**; the
requester then resolves each node's transport on demand through `ResolveTransport`
(§5.4.1). This plugs the same bulk routing-graph leak on the value-lookup path. The
iterative (and recursive) walk still converges, because transports are resolved
hop by hop instead of inlined in the response — the 64-node linear-chain regression
test in `crates/veil-dht/src/iterative.rs` guards exactly this.

#### 5.2.1 discovery_mode filter + half-cap

V2 FIND_NODE (`handle_find_node_v2`) and the `FindValue` not-found fallback both run
returned contacts through two filters first, via the shared `ranked_public_contacts`
helper:

1. **Public-only filter.** Peers whose `discovery_mode` is not `Public` (declared in `CapabilitiesPayload.discovery_mode` at handshake) are dropped from the response. This is what closes the enumeration leak for opt-in privacy nodes: a `ContactsOnly` or `IntroductionOnly` peer never shows up in anyone else's FIND_NODE responses, so DHT-walk scanners simply cannot see it.

2. **Half-cap.** A response returns at most `min(K_requested, K_local, ceil(N_public / 2))` contacts, where `N_public` is how many Public peers sit in our routing table. Capping at half means an attacker mapping the Public network must send **at least twice as many FIND_NODE requests** to cover it all. The smallest case still works: with 1 Public peer, 1 is returned, so Kademlia stays connected.

Similar filtering is applied in:

- `handle_find_value::FindValueResponse::Nodes` (closest-nodes fallback)
- `handle_recursive_query::FIND_NODE` (via the `find_closest_public_node_ids` helper)

What is **not** filtered is internal routing — `find_closest_nodes` for next-hop selection, and NeighborOffer. Filtering there would break routing through privacy-opt-in nodes that are acting as relays, which is the opposite of what we want.

**Threat model.** The target is scanner resistance against passive enumeration over DHT FIND_NODE. Before this change, a scanner pulled K transports from a single FIND_NODE, walked the whole Public keyspace in roughly 10 round trips for a /20, and had a full address map within minutes. Half-cap plus Public-only makes that walk at least 2× slower for Public nodes, and impossible for opt-in privacy nodes.

**Limitation.** Public nodes (the default config) are still enumerable, just in chunks of at most half the table at a time. Fully decoupling the routing graph from the address graph is future work — see Decoupled transport resolution / hidden services (planned).

### 5.3 StorePayload

```text
[0..32]  key       [u8; 32]
[32..36] ttl_secs  u32 BE
[36..40] value_len u32 BE
[40..]   value     bytes
```

### 5.4 AnnounceAttachmentPayload

When a leaf attaches to a gateway, it publishes this record in the DHT so others can find which Core nodes currently carry it. The exact format lives in [`proto/discovery.rs::AnnounceAttachmentPayload`](../../crates/veil-proto/src/discovery.rs):

```text
[0..32]   node_id          [u8; 32]
[32]      role             u8          (NodeRole: 0x01=Leaf, 0x08=Core)
[33..37]  realm_id         u32 BE
[37..41]  epoch            u32 BE      (monotonic counter across reconnects)
[41..49]  expires_at       u64 BE      (Unix seconds)
[49]      gateway_count    u8          (≤ MAX_GATEWAYS = 32)
[50]      mailbox_count    u8          (≤ MAX_MAILBOXES = 32)
[51..]    gateways[]       GatewayRef × gateway_count (38 bytes each)
[..]      mailboxes[]      MailboxRef × mailbox_count (40 bytes each)
[..]      seq_no           u64 BE      (larger seq_no wins on conflict)
[..]      sig_len          u16 BE      (0 = unsigned)
[..]      signature        bytes       (Ed25519 = 64 B, Falcon-512 = variable)
[..]      (optional TLV)   EphemeralEndpoint
```

The signature covers everything from `node_id` through `seq_no` inclusive (the body returned by `signable_body()`).

### 5.4.1 V2 FIND_NODE + ResolveTransport

**Wire-protocol.** `DiscoveryMsg` slots 10-14:

| msg_type | Name | Body |
|---|---|---|
| 10 | `FindNodeV2` | `FindNodeV2Payload` (32 bytes target + 1 byte k) |
| 11 | `FindNodeV2Response` | `FindNodeV2Response` (count u8 + node_ids `[u8; 32] × count`) |
| 12 | `ResolveTransport` | `ResolveTransportPayload` (52 bytes: 32 node_id + 4 time_bucket BE + 16 pow_nonce) |
| 13 | `ResolveTransportResponse` | `ResolveTransportResponse` — carries `Option<SignedTransportAnnouncement>` |
| 14 | `AnnounceTransport` | `SignedTransportAnnouncement` — fire-and-forget post-handshake gossip |

**FindNodeV2Response** (variable):
```text
[0]                  count       u8  (≤ MAX_NODES_PER_RESPONSE = 32)
[1..1+count*32]      node_ids    [u8; 32] × count
```

Note there are **no transport fields** here, unlike the removed V1 (§5.1). The caller learns only the node-ids; for any node it actually wants to reach, it calls `ResolveTransport` separately to get the address.

**ResolveTransportResponse** (variable):
```text
[0..32]    node_id           [u8; 32]    — echo for caller-correlation
[32]       found             u8          (0 = not found, 1 = found)
if found == 1:
  [33..35]   transport_len   u16 BE
  [35..N]    transport       UTF-8 bytes
  [N..N+8]   observed_at     u64 BE      (Unix seconds; the resolver sets this at insert
                                            into its Contact, typically — handshake-complete time)
```

The resolver answers `not_found` in two cases:
- It has no `Contact` for the requested `node_id` in its routing table.
- It has a contact, but that contact's `discovery_mode` is not `Public`. This is the privacy filter: a non-Public peer's very existence is not confirmed through this RPC. Folding this case together with "I've never heard of it" is deliberate — a distinct "I know it, but I won't tell you" answer would itself be a signal an attacker could exploit.

**Threat model.** Previously, any FIND_NODE returned K transports in one round trip, so a mass scan mapped the network in O(N/K) round trips (~10 RTT for 200 Public nodes in a /20 keyspace). The DHT walker now defaults to V2, where each transport costs its own RPC — cumulative cost O(N) round trips, roughly **10× slower** to scan. The PoW gate and signed responses pile on more: per-resolve CPU work (~17 ms of BLAKE3) and resistance to cache poisoning.

**Status.** Wire types, handlers, the in-memory cache, and the V2 flow are all wired into `NetworkPeerQuerier`. **The defense is active**: outbound DHT walks use the V2 flow by default (`FindNodeV2 → node_ids → cache lookup → ResolveTransport(id) on a miss`). V1 is gone — wire slots 0/8 are rejected as a `Violation`.

**PoW gate.** `ResolveTransportPayload`:

```text
[0..32]    node_id      [u8; 32]   — what to resolve
[32..36]   time_bucket  u32 BE     — `unix_secs() / RESOLVE_POW_BUCKET_SECONDS`
[36..52]   pow_nonce    [u8; 16]   — solution
```

The PoW input hash is

```text
BLAKE3( "epic475.4b/resolve_pow/v1" || requester_node_id[32] ||
         target_node_id[32] || time_bucket_be[4] || pow_nonce[16] )
```

`requester_node_id` is not on the wire. The responder takes it from session context — it is the `peer_id` that the OVL1 session already authenticated. The server accepts the proof only if both hold: `leading_zero_bits(hash) ≥ RESOLVE_POW_DIFFICULTY`, and `|time_bucket − now_bucket| ≤ RESOLVE_POW_TIME_WINDOW_BUCKETS`. Defaults: `RESOLVE_POW_DIFFICULTY = 16` (a median of ~7 ms to mine on a fast x86 core, ~14 ms on low-end ARM), `RESOLVE_POW_BUCKET_SECONDS = 60`, and `RESOLVE_POW_TIME_WINDOW_BUCKETS = 1` (about a 120 s replay window).

A failed PoW — bad solution, stale bucket, or the wrong target/requester binding — gets a silent `not_found`, **not** a `Violation`. The reasoning: verifying the proof is a single BLAKE3 hash (~1 µs), so the per-peer `dht_quota` already caps how much CPU a peer can burn, and treating failures as violations would turn ordinary clock drift into a false-positive eviction path. Legacy senders that omit the PoW fields entirely (a 32-byte payload) fail to decode and *do* draw a `Violation` from the dispatcher.

Net effect: an attacker's cost rises from `O(N) RTT` to `O(N) × ~7 ms` of CPU per probed `node_id`. For a `/20` keyspace (~200 Public peers) that is about 1.5 s of single-core mining for one full enumeration sweep, and it scales linearly with the size of the target set — while an honest client pays it just once, on a cache miss.

**Signed responses.** `ResolveTransportResponse.transport: Option<String>` carries `Option<SignedTransportAnnouncement>`:

```text
[0..32]    node_id          [u8; 32]
[32..64]   identity_pubkey  [u8; 32]   Ed25519 raw pubkey
[64..128]  signature        [u8; 64]   Ed25519 signature
[128..136] expiry_unix      u64 BE
[136..138] transport_len    u16 BE
[138..N]   transport        UTF-8 (≤ MAX_TRANSPORT_URI_LEN = 256)
```

The signing input is

```text
BLAKE3( "epic475.4c/transport_announce/v1" || node_id ||
         expiry_unix_be || transport_len_be || transport_utf8 )
```

Each node mints its own bundle at startup (valid for 30 days, per `ANNOUNCEMENT_VALIDITY_SECS`) and **gossips it via `DiscoveryMsg::AnnounceTransport` (slot 14) every time a handshake completes** — one fire-and-forget frame per session, on both inbound and outbound paths. Receivers verify it and store it under `transport_announcements: HashMap<node_id, …>` on `KademliaService`. `handle_resolve_transport` then hands back the cached bundle verbatim, so a resolver only ever relays what the target itself signed. A maintenance tick prunes orphan announcements — peers that have dropped out of the routing table.

**Walker verification (`NetworkPeerQuerier`).** Before it puts any resolved transport into `TransportCache`, the walker checks four things:
1. `BLAKE3(identity_pubkey) == announcement.node_id` — the pubkey is bound to the identity.
2. The Ed25519 signature is valid over the canonical input.
3. `expiry_unix > now()` — the bundle has not expired.
4. `announcement.node_id == requested node_id` — defence in depth: even if a resolver attaches a valid announcement for the *wrong* peer, the walker throws it out.

So a malicious resolver can **deny** that a peer exists (`not_found`), but it cannot **redirect** you to attacker-controlled infrastructure. Redirection would mean forging an Ed25519 signature whose pubkey hashes to the target's `node_id` — which is the whole point of the binding.

The dispatcher adds one more guard: on `AnnounceTransport` it enforces `announcement.node_id == session_peer_id`. A peer may only announce *its own* node_id, which blocks gossip-flood pollution attacks.

**On-disk persistence.** The `transport_announcements: HashMap<node_id, SignedTransportAnnouncement>` map is flushed to a JSON snapshot on a timer (every 120 s by default, plus a final flush on a clean shutdown). On restart the snapshot is re-loaded, and every entry is re-verified — signature, pubkey↔node_id binding, and non-expiry — with any failure silently dropped.

Why JSON rather than the in-memory binary layout? Each entry is tiny (~250 B as JSON), the file stays greppable for an operator, and the tamper-resistance comes from the signatures (re-checked on load), not from the file format. Someone who edits the file can only hurt availability — drop entries, and the walker simply re-handshakes — but **cannot** inject forged transports, since that again needs an Ed25519 keypair whose pubkey hashes to the target's node_id.

Config knobs (`[dht]`):
- `transport_announcements_persist_path: Option<String>` — `None` disables persistence.
- `transport_announcements_persist_interval_secs: u64` — default 120.

The `TransportCache` itself is deliberately **not** persisted. It is just a derivation of verified announcements, and the next walk repopulates it on demand.

**Remaining caveats:**
- Each `ResolveTransport` also spends a `dht_quota` token (the existing per-peer rate limit), on top of the PoW.
- Rotating a key invalidates every outstanding announcement signed by the old one. Peers re-gossip on their next handshake — there is no graceful migration window yet.

### 5.5 The Kademlia Algorithm

- **K** = 20 — the k-bucket size, the classic Kademlia constant.
- **α** = 3 — how many queries run in parallel each round.
- **max_rounds** = 20.
- Distance metric is XOR: `dist(a, b) = a XOR b`.
- Lookup is iterative: α parallel FindNode queries per round, repeated until the result stops improving or the rounds run out.
- Anti-eclipse: at most `K/4 = 5` contacts from any single /24 IPv4 (or /48 IPv6) per bucket, so one network can't pack a bucket.

### 5.6 DeletePayload (multi-algo)

```text
[0..32]           key         [u8; 32]
[32]              algo        u8   (0/1 = Ed25519, 2 = Falcon-512, 3 = Ed25519+Falcon-512, 4 = Ed25519+Falcon-1024)
[33..35]          pk_len      u16 BE
[35..35+pk]       public_key  bytes (algo-dependent: 32 Ed25519, 897 Falcon-512; hybrids carry both)
[+2]              sig_len     u16 BE
[+slen]           signature   bytes (algo-dependent: 64 Ed25519, ~666 Falcon-512; hybrids carry both)
```

Validation runs three checks:
1. `algo ∈ {0, 1, 2, 3, 4}` — every value `SignatureAlgorithm::from_wire_byte` accepts, hybrids included. Accepting the hybrids (the `U1` change) lets hybrid-identity nodes delete their own records, not just Ed25519/Falcon-512 owners.
2. `crypto::verify_message(algo, public_key, key_bytes, signature) = Ok` — the signature checks out.
3. `BLAKE3(public_key) == key` — the key is self-owned, so only its owner can delete it.

---

## 6. Delivery Plane (Family 3)

### 6.1 DeliveryEnvelope (197-byte header + payload)

```text
[0..49]    recipient          Recipient (node_id[32] + tag[1] + instance_id[16])
[49..81]   sender_node_id     [u8; 32]
[81..113]  src_app_id         [u8; 32]
[113..145] app_id             [u8; 32]   (recipient's app_id)
[145..149] endpoint_id        u32 BE
[149..181] content_id         [u8; 32]   (BLAKE3 payload)
[181..189] created_at         u64 BE     (Unix creation time)
[189..193] ttl_secs           u32 BE
[193..197] payload_len        u32 BE
[197..]    payload            bytes
```

The recipient is a fixed-49-byte `Recipient` (`encode_fixed_into`): a 32-byte `node_id`, a 1-byte `InstanceTag` (0=Any, 1=All, 2=Specific), and a 16-byte `instance_id` (zero-padded for Any/All).

**Flags in the frame header:**
- `require_ack = true` — request delivery confirmation
- `trace_id` — the frame's stream_id is used as the trace correlator

### 6.2 MailboxFetchPayload

```text
[0..32]  recipient_node_id  [u8; 32]
[32..40] after_seq          u64 LE     (fetch only seq > after_seq)
```

### 6.3 MailboxAckPayload

```text
[0..32]  recipient_node_id  [u8; 32]
[32..34] count              u16 BE
[34..]   seqs[]             u64 LE × count
```

Acknowledges specific seq numbers, which need not be consecutive. A single batch holds at most `MAX_MAILBOX_ACK_BATCH = 256` of them.

### 6.4 DeliveryStatusPayload

```text
[0..32]  content_id  [u8; 32]
[32]     status      u8  (see legend below)
[33..65] mac         [u8; 32]   (C-09 authenticated ACK; BLAKE3 keyed-MAC of
                                  content_id under veil_e2e::derive_ack_key)
```

WIRE_SIZE = 65 bytes. Status codes:
- `0` = ACCEPTED — gateway accepted the envelope into the delivery pipeline
- `1` = DELIVERED — final recipient delivered the payload to its app layer
- `2` = QUEUED — mailbox stored the envelope durably (replica quorum acked)
- `3` = NOT_FOUND — no mailbox entry for this content_id
- `4` = REJECTED — delivery explicitly rejected (quota, policy, auth)
- `5` = EXPIRED — envelope expired before it could be delivered
- `6` = FETCHED — mailbox sent the envelope to the recipient (fetched from storage)
- `7` = APP_ACKED — recipient application explicitly acknowledged via IPC

---

## 7. E2E Encryption

End-to-end (E2E) encryption seals a message so that only the final recipient can open it — the relays in between carry sealed bytes. A `DeliveryEnvelope` whose `payload[0] == 0xE2` is E2E-encrypted; that leading byte is the marker.

### 7.1 E2eEnvelope Wire Format (payload[1..])

```text
[0]           version         u8 = 1
[1..3]        kem_ct_len      u16 BE   (1088 for ML-KEM-768)
[3..1091]     kem_ciphertext  [u8; 1088]  (ML-KEM encapsulated key)
[1091..1103]  nonce           [u8; 12]    (ChaCha20-Poly1305 nonce)
[1103..1107]  ct_len          u32 BE
[1107..]      ciphertext      bytes       (ciphertext + 16-byte auth tag)
```

### 7.2 Encryption Algorithm

```
1. (kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_encapsulation_key)
2. key = HKDF-SHA256(
       ikm  = shared_secret,
       info = "ovl1-e2e-v1" || src_id || dst_id
   )[0..32]
3. nonce = random[12]
4. ciphertext = ChaCha20-Poly1305.Seal(
       key    = key,
       nonce  = nonce,
       plain  = plaintext,
       aad    = src_id || dst_id
   )
```

### 7.3 Key Management

- The encapsulation key (the public ML-KEM key, 1184 bytes) is published in the DHT when an IPC endpoint registers, so senders can find it.
- The decapsulation key (the matching private key, a 64-byte seed) never leaves the node's memory.
- Resolved keys are cached for `ipc.e2e_key_ttl_secs` (default 3600 sec).

---

## 8. Routing Plane (Family 8)

### 8.1 RouteAnnouncePayload

```text
[0..32]  origin_node_id  [u8; 32]
[32..64] via_node_id     [u8; 32]    (next-hop)
[64]     hop_count       u8
[65]     ttl             u8
[66..70] sequence        u32 BE      (monotonically increasing at the origin)
[70..72] timestamp       u32 BE      (Unix announcement time, seconds)
```

Constraints: `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300`, `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30`.

### 8.2 RouteRequestPayload

```text
[0..32]  target_node_id     [u8; 32]
[32..64] requester_node_id  [u8; 32]
[64..68] request_id         u32 BE
[68]     ttl                u8
[69..71] mlkem_pk_len       u16 BE
[71..N]  mlkem_pk           bytes   (requester's ML-KEM pubkey, for the E2E response)
[N..N+2] ed25519_pk_len     u16 BE
[N+2..]  ed25519_pk         bytes   (pubkey for signature verification)
[..]     signature          bytes
```

### 8.3 RouteResponsePayload

```text
[0..32]  target_node_id     [u8; 32]
[32..64] requester_node_id  [u8; 32]
[64..68] request_id         u32 BE
[68..70] transport_count    u16 BE
[70..]   transports[]       (len u16 BE + bytes)  — URI strings
[..]     relay_count        u16 BE
[..]     relays[]           [u8; 32]  — relay node_ids
[..]     mlkem_pk_len       u16 BE
[..]     mlkem_pk           bytes
[..]     ed25519_pk_len     u16 BE
[..]     ed25519_pk         bytes
[..]     signature          bytes
```

Limits: `MAX_TRANSPORT_ADDRS = 32`, `MAX_RELAY_IDS = 32`.

### 8.4 Proof-of-Work (PoW)

**Hash function:** BLAKE3

```
challenge = random [u8; 32]
difficulty = N  (leading zero bits)

Solution: find solution such that
BLAKE3(challenge || solution).leading_zero_bits() >= difficulty
```

**PowChallengePayload:**

```text
[0..32]  requester_node_id  [u8; 32]
[32..64] acceptor_node_id   [u8; 32]
[64..96] challenge_nonce    [u8; 32]
[96]     difficulty         u8
[97..161] signature         [u8; 64]   (Ed25519, signed by the acceptor)
```

Constraints: `MAX_POW_DIFFICULTY = 24`, `MAX_CONCURRENT_POW_SOLVERS = 4`.

#### 8.4.1 PoW-gated discovery

If the target node is configured with `abuse.pow_min_difficulty > 0`, it **holds back the `RouteResponse` (the one carrying `transports`) until the requester solves a PoW**:

```
Requester ── RouteRequest{target=victim, requester=us} ──► Victim
Requester ◄──────────── PowChallenge{nonce, difficulty} ── Victim   (RouteResponse is NOT sent)
                                                  │
                                  Requester solves PoW (BLAKE3)
                                                  │
Requester ── PowResponse{nonce, solution} ────────────────► Victim
Requester ◄── RouteResponse{transports, mlkem_pk, sig} ─── Victim   (deferred — request_id is echoed from pow_pending)
Requester ◄── PowAccept{transport} ───────────────────────── Victim   (legacy backward-compat, signals "session bootstrap OK")
```

**Without PoW (`pow_min_difficulty = 0`):** the `RouteResponse` goes out as soon as the `RouteRequest` arrives — the legacy behavior.

**Why bother.** Without the gate, any node could fire off a `RouteRequest{target=X}` for any `X` it liked, for free, and get back `RouteResponse{transports[X]}` — handing over X's IP and port given nothing but its `node_id`. The PoW gate makes probing by id cost real work.

#### 8.4.2 DiscoveryMode

An additional config option `[routing] discovery_mode` (default: `public`):

| Mode | Behavior |
|---|---|
| `public` | The default. With `pow_min_difficulty > 0` the response is gated through PoW; otherwise the `RouteResponse` is immediate. |
| `contacts_only` | A `RouteRequest` from a requester outside `peer_pubkeys` (one we have not handshaked with) is **silently dropped** — no `PowChallenge`, no `RouteResponse`. The node's existence stays hidden. |
| `introduction_only` | `RouteResponse.transports` is always empty. The requester has to connect through one of the `relay_ids` — a rough, rendezvous-free approximation of Tor-style introduction. |

---

## 9. IPC Protocol (LocalApp, Family 6)

### 9.1 Connection Protocol

This is how a local app talks to the node it runs alongside — IPC, inter-process communication on the same machine. The app connects to the node's IPC server at `ipc.socket_uri`: either a Unix socket (`unix:///path`) or a TCP loopback address (`tcp://127.0.0.1:port`).

Each message on this socket is framed simply: `u16 BE msg_type`, then `u32 BE body_len`, then the body.

Protocol version: `IPC_PROTOCOL_VERSION = 1`.

### 9.2 Sequence

```
 App                               Node
 │── AppHello (v=1) ─────────────►│
 │◄─ AppHelloOk ──────────────────│
 │── AppBind (ns, name, ep) ─────►│   Endpoint registration
 │◄─ AppBindOk (app_id) ──────────│
 │── AppIpcSend / StreamOpen ────►│   Send / open a stream
 │◄─ AppDeliver ──────────────────│   Incoming message
 │── AppUnbind ──────────────────►│   Termination
```

### 9.3 LocalApp Message Types

The `msg_type` values are from `LocalAppMsg` in [`proto/family.rs`](../../crates/veil-proto/src/family.rs).

| Type | `msg_type` | Direction | Description |
|-----|-----------|-------------|----------|
| AppHello | 0 | App→Node | Protocol version |
| AppHelloOk | 1 | Node→App | Acknowledgement |
| AppHelloErr | 2 | Node→App | Version error |
| AppBind | 3 | App→Node | Register an endpoint |
| AppBindOk | 4 | Node→App | app_id assigned |
| AppBindErr | 5 | Node→App | Registration error |
| AppUnbind | 6 | App→Node | Cancel registration |
| AppDeliver | 7 | Node→App | Incoming message |
| AppIpcSend | 8 | App→Node | Send a message (without acknowledgement) |
| AppSendOk | 9 | Node→App | Acknowledgement of AppIpcSend |
| StreamOpen | 10 | App→Node | Open a bidirectional stream |
| StreamOpenOk | 11 | Node→App | Stream opened (initial_window) |
| StreamOpenErr | 12 | Node→App | Stream open error |
| StreamData | 13 | Bidirectional | Stream data |
| StreamClose | 14 | Bidirectional | Close a stream |
| StreamWindow | 15 | Bidirectional | Increase the send-window |
| StreamRtData | 16 | Bidirectional | Realtime stream data |
| AppSendFailed | 17 | Node→App | Delivery failed (require_ack) |
| AppRtSend | 18 | App→Node | Outbound realtime frame |
| DeliveryStage | 19 | Node→App | Delivery stage (Accepted/Stored/Fetched/Delivered/AppAcked) |
| AnycastResolve | 20 | App→Node | Anycast service resolution request |
| AnycastResult | 21 | Node→App | Anycast resolution response |

### 9.4 AppBindPayload

```text
[0..2]   namespace_len  u16 BE
[2..N]   namespace      bytes  (UTF-8, e.g. "veil.chat")
[N..N+2] name_len       u16 BE
[N+2..M] app_name       bytes  (UTF-8, e.g. "main")
[M..M+4] endpoint_id    u32 BE (1..65535)
```

The AppBindOk response carries the `app_id [u8; 32]` — §1.2 has the exact formula (length-prefixed BLAKE3 `derive_key`). In ephemeral mode (the default) the node returns an `ephemeral_app_id`, mixing in the `client_token`; under `bind_named` it returns the stable `app_id` instead.

### 9.5 Stream Flow Control

Flow control keeps a fast sender from overrunning a slow receiver. It works on a credit (window) scheme:

- **Send window** — the sender tracks how much it may still send and blocks once the window hits `0`.
- **StreamWindow** — the receiver sends this message to grant more credit, growing the sender's window.
- **Initial window** — `STREAM_INITIAL_WINDOW` (default 256 KiB).
- **Maximum window** — `MAX_STREAM_SEND_WINDOW = 16 MB`.

---

## 10. Mesh Plane (Family 5)

### 10.1 MeshFrame

```text
[0..16]  realm_id   [u8; 16]   (16-byte realm identifier)
[16..48] src        [u8; 32]   (source node_id)
[48..80] dst        [u8; 32]   (destination node_id; [0u8;32] = broadcast)
[80]     ttl        u8
[81..83] payload_len u16 BE
[83..]   payload    bytes
```

### 10.2 MeshBeaconPayload

```text
[0..32]  node_id      [u8; 32]
[32..48] realm_id     [u8; 16]
[48]     role_flags   u8  (v2: IS_GATEWAY=0x01, IS_CORE=0x02)
[49]     addr_len     u8  (v2: length of veil_addr)
[50..N]  veil_addr bytes  (TCP/TLS URI, e.g. "tls://10.0.0.1:9443")
[N]      battery_level u8  (v3: 0=unknown/AC, 1..100=%)
```

### 10.3 MeshAckPayload

```text
[0..16]  frame_id  [u8; 16]
[16]     status    u8  (0=OK, 1=REJECTED, 2=DUPLICATE, 3=NO_ROUTE)
```

---

## 11. Node Roles

| Role | Code | DHT | Relay | Mailbox | Gateway | Use case |
|------|-----|-----|-------|---------|---------|------------|
| Leaf | 0x01 | No | No | No | No | Mobile/IoT |
| Core | 0x08 | Yes (K=20) | Yes | Yes | Yes | Servers, VPS |

The legacy codes 0x02 (Relay), 0x04 (Gateway), and 0x10 (CoreRouter) are gone; if an
old peer still sends one, it is discarded.

**Leaf node** — the lightweight role, for phones, IoT, anything behind a NAT:
- Reaches the network through a Core node, via an attachment lease.
- Keeps its mailbox on Core nodes rather than locally.
- Does not accept inbound connections from arbitrary nodes.
- Needs minimal resources.

**Core node** — the always-on role, for servers and VPS instances:
- A full DHT participant (K=20), and it relays and forwards traffic.
- Acts as a gateway, serving the attachment records of leaf nodes (turn this off with `[gateway] enabled = false`).
- Holds the mailbox for recipients who are offline.
- Serves FindNode/FindValue/Store/Delete.
- Should run a PoW difficulty of ≥ 24 (the default is `16`, and `MAX_POW_DIFFICULTY = 24` is the hard ceiling) and stay up 24/7.

---

## 12. Cryptography

### 12.1 Signature Algorithms

| Algorithm | Wire-byte `algo` | Pubkey | Privkey | Signature |
|----------|------------------|--------|---------|---------|
| Ed25519 | 0 / 1 | 32 bytes | 32 bytes | 64 bytes |
| Falcon512 | 2 | 897 bytes | 1281 bytes | 666 bytes |
| Ed25519+Falcon512 (hybrid) | 3 | 929 bytes | composite | Ed25519 ‖ Falcon-512 |
| Ed25519+Falcon1024 (hybrid) | 4 | 1825 bytes | composite | Ed25519 ‖ Falcon-1024 |

The `algo` byte appears in `IdentityPayload`, `DeletePayload`, the mesh beacon, and PEX signatures.
One exception: the session handshake (`KeyAgreementPayload`) uses a different convention — 1 = Ed25519, 2 = Falcon512.

### 12.2 Session KDF

```
shared_secret = X25519(ephemeral_private, ephemeral_public_peer)

salt = local_node_id XOR remote_node_id    // commutative — both sides get the same
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a || key_b || session_id] = HKDF-SHA256(salt, ikm, info, len=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id → (key_a, key_b)
                   else                               → (key_b, key_a)
```

See §3.5 for the full story. There is no separate `mac_key`: integrity comes from the
AEAD tag (ChaCha20-Poly1305) on each frame, plus the handshake MAC inside
`SessionConfirm` (`BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret ‖ small_id ‖ large_id)`).

### 12.3 Frame Encryption

```
ciphertext = ChaCha20-Poly1305.Seal(
    key   = tx_key (for outgoing) / rx_key.open for incoming,
    nonce = 12-byte counter (per-direction, monotonic),
    plain = frame_body,
    aad   = frame_header_bytes (24 bytes)
)
```

### 12.4 E2E (Post-Quantum)

```
# Encapsulation (the sender knows recipient_ek)
(kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_encapsulation_key)

key = HKDF-SHA256(shared_secret, info="ovl1-e2e-v1" || src_id || dst_id)[0..32]
nonce = random[12]
ciphertext = ChaCha20-Poly1305.Seal(key, nonce, plaintext, aad=src_id||dst_id)

# Decapsulation (the recipient)
shared_secret = ML-KEM-768.Decaps(kem_ct, decapsulation_key)
key = HKDF-SHA256(shared_secret, info="ovl1-e2e-v1" || src_id || dst_id)[0..32]
plaintext = ChaCha20-Poly1305.Open(key, nonce, ciphertext, aad=src_id||dst_id)
```

### 12.5 PoW

```
challenge: [u8; 32]  (random)
difficulty: u8       (number of leading zero bits)

# Searching for a solution:
loop:
    solution = random[32]
    hash = BLAKE3(challenge || solution)
    if hash.leading_zero_bits() >= difficulty:
        break

# Verification:
assert BLAKE3(challenge || solution).leading_zero_bits() >= difficulty
```

### 12.6 Derived Identifiers

```
node_id    = BLAKE3(raw_pubkey_bytes)     // 32 bytes
app_id     = derive_key("veil.app_id.v1",
                        node_id || ns_len(4) || ns ||
                        name_len(4) || name)  // 32 bytes (see §1.2)
content_id = BLAKE3(payload)              // 32 bytes
```

---

## 13. Budgets and Limits

These are the hard caps that keep a node's memory and CPU bounded under load. All of them live in `crates/veil-proto/src/budget.rs`.

| Constant | Value | Description |
|-----------|---------|----------|
| `MAX_FRAME_BODY` | 16 MiB | Absolute ceiling of the frame body (in `proto/codec.rs`); the listener by default caps it to `DEFAULT_MAX_FRAME_BODY = 1 MiB` |
| `MAX_NEIGHBOR_TABLE_SIZE` | 256 | Maximum neighbors in the NeighborTable |
| `MAX_ROUTE_CACHE_SIZE` | 1024 | Entries in the RouteCache |
| `MAX_ROUTES_PER_DST` | 4 | Paths per recipient |
| `MAX_ROUTES_PER_VIA` | 256 | Routes through one next-hop |
| `DEFAULT_MAX_QUEUE_DEPTH` | 1000 | Messages in the queue per recipient |
| `MAX_MAILBOX_RECIPIENTS` | 4096 | Distinct recipients in a mailbox |
| `MAX_MAILBOX_ACK_BATCH` | 256 | ACKs per message |
| `MAX_CONCURRENT_SESSIONS` | 65,536 | Active sessions |
| `MAX_SESSIONS_PER_IP` | 32 | Sessions from one IP |
| `MAX_BAN_LIST_SIZE` | 8192 | Entries in the BanList |
| `MAX_VIOLATION_TRACKER_SIZE` | 8192 | Entries in the ViolationTracker |
| `dht.max_store_entries` (config) | 25,000 | KV pairs in the DHT store (configured in `[dht]`, not a constant; operators with large RAM raise it explicitly) |
| `MAX_DHT_VALUE_BYTES` | 16384 (16 KiB) | Bytes in a single DHT value |
| `MAX_PENDING_ACK_ENTRIES` | 1024 | In-flight require_ack messages |
| `MAX_DELIVERY_ATTEMPTS` | 3 | Delivery attempts with require_ack |
| `DELIVERY_ACK_TIMEOUT_MS` | 5000 | Timeout of a single attempt (ms) |
| `MAX_TRANSPORT_ADDRS` | 32 | URIs in a RouteResponse |
| `MAX_RELAY_IDS` | 32 | Relay nodes in a RouteResponse |
| `MAX_GATEWAYS` | 32 | Core references in an AnnounceAttachment |
| `MAX_GATEWAY_ATTACHMENTS` | 4096 | Leaf nodes on a single Core node |
| `MAX_TRANSPORT_STR_LEN` | 255 | Bytes in a transport URI |
| `MAX_NODES_PER_RESPONSE` | 32 | Nodes in a FindNodeResponse |
| `MAX_IPC_ENDPOINTS_PER_CLIENT` | 64 | Endpoints per IPC client |
| `MAX_FORWARD_SEEN_SET_SIZE` | 100000 | Entries in the relay dedup cache |
| `FORWARD_SEEN_SET_TTL_SECS` | 60 | TTL of an entry in the dedup cache |
| `MAX_BEACON_DEDUP_ENTRIES` | 4096 | Entries in the beacon dedup map |
| `MAX_TOTAL_STREAMS` | 65536 | Total open streams |
| `MAX_STREAMS_PER_PEER` | 256 | Streams per peer |
| `MAX_STREAM_SEND_WINDOW` | 16 MB | Maximum stream send-window |
| `REKEY_BYTES_THRESHOLD` | 128 GiB | Bytes before a session key change (config: `[session] rekey_bytes_threshold`) |
| `REKEY_TIME_THRESHOLD_SECS` | 2,764,800 (32 days) | Seconds before a session key change (config: `[session] rekey_time_threshold_secs`) |
| `MAX_POW_DIFFICULTY` | 24 | Maximum PoW difficulty |
| `MAX_CONCURRENT_POW_SOLVERS` | 4 | Parallel PoW solvers |
| `HANDSHAKE_TIMEOUT_SECS` | 10 | OVL1 handshake timeout |
| `MAX_CLOCK_SKEW_SECS` | 300 | Allowed clock skew |
| `MAX_ROUTE_ANNOUNCE_AGE_SECS` | 300 | Maximum age of a RouteAnnounce |
