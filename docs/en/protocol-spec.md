# OVL1 Protocol Specification

Version: **1** (magic `0x4F564C31`), minor = 1.

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

`app_namespace` and `app_name` are UTF-8 strings with arbitrary content, chosen by
the application developer (convention: reverse-DNS, for example `"com.example.chat"`
+ `"main"`). At the wire level they are limited to 255 bytes each (see §9.3 `AppBind`).

**Length-prefixes and the domain separator are mandatory** — without them, naive
concatenation produces collisions: `("foo","bar")` and `("fo","obar")` both
concatenate to `"foobar"` and yield the same digest. The v1 derivation guarantees
uniqueness.

For IPC applications in ephemeral mode (the default), the formula is extended
with a 16-byte `client_token` issued by the node in `AppHelloOk`:

```text
ephemeral_app_id = BLAKE3-derive_key(
    context = "veil.ephemeral_app_id.v1",
    ikm     = node_id || client_token(16) || ns_len(u32 BE) || app_namespace
                                           || name_len(u32 BE) || app_name
)
```

This makes the `app_id` unique per-connection — two processes on the same node
binding the same `(namespace, name)` get different addresses. For
well-known services the stable form above is used (via `bind_named`).

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

Used for deduplication of messages in transit.

---

## 2. Frame Wire Format

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

| Family | Number | Purpose |
|--------|-------|------------|
| Session | 0 | OVL1 handshake, keepalive, rekey, resumption ticket, padding |
| Control | 1 | Ping, NeighborOffer, RouteProbe, NAT, Keepalive, Backpressure, Epidemic |
| Discovery | 2 | DHT FindNode, FindValue, Store, Delete, Attachment/Mailbox/AppEndpoint lookup |
| Delivery | 3 | Mailbox Put/Fetch/Ack, DeliveryForward, Status, Chunks, Transit, RecursiveRelay |
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

The OVL1 handshake is asymmetric and client-initiated. Sequence:

```
Initiator                              Responder
    │── Hello ──────────────────────────►│   OVL1 version + node_id
    │◄─ Hello ───────────────────────────│
    │── Identity ─────────────────────►│   pubkey + nonce + algo + ML-KEM ek
    │◄─ Identity ────────────────────────│
    │── Capabilities ─────────────────►│   role bits + feature flags
    │◄─ Capabilities ─────────────────────│
    │── KeyAgreement ─────────────────►│   ephemeral X25519 pubkey
    │◄─ KeyAgreement ─────────────────────│
    │── SessionConfirm ───────────────►│   session_id + MAC
    │◄─ SessionConfirm ───────────────────│
    │── Attach (optional) ─────────────►│   (leaf → gateway)
    │   [CONNECTED]                      │
```

### 3.2 HelloPayload (24 bytes)

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

**Backward-compat:** legacy peers send 2 bytes (without `discovery_mode`); the decoder defaults the missing byte to `0` (Public) — legacy peers had no concept of opt-in privacy and were effectively Public. The decoder accepts `>= 2` bytes.

**discovery_mode semantics:**

- `Public` — the peer wants to be discoverable through a DHT-walk; FIND_NODE responses from other nodes will include it.
- `ContactsOnly` — the peer must be excluded from FIND_NODE responses; reachable only through direct sessions with already-handshaked contacts or a pre-shared bootstrap.
- `IntroductionOnly` — same as `ContactsOnly` for FIND_NODE; additionally, RouteResponse is strictly required to strip `transports[]` (see §3.6).

Legacy fields:
- Role bits `RELAY (0x02)`, `GATEWAY (0x04)`, `CORE_ROUTER (0x10)` — removed.
- Cap flags `CAN_MAILBOX=0x02`, `CAN_GATEWAY_LOCAL_MESH=0x04`, `CAN_PARTICIPATE_DHT=0x08`, `CAN_ACCEPT_APP_STREAMS=0x10`, `CAN_STORE=0x20`, `SUPPORTS_TRANSIT=0x40` — were never read, removed.
- Wire format shrunk from 12 bytes (legacy) → 2 bytes → 3 bytes.

### 3.5 SessionKeys (derived keys)

After the ephemeral **X25519** exchange (this is NOT the identity key — the identity key, Ed25519/Falcon-512, is used only for signing in `IdentityPayload`):

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

`tx_key` is for encrypting outgoing frames; `rx_key` for decrypting incoming ones.
The lexicographic ordering by `node_id` guarantees that the initiator and the
responder have `tx_key`/`rx_key` swapped: alice.tx == bob.rx and vice versa.

Frames are encrypted with **ChaCha20-Poly1305** (using the 32-byte key `tx_key` / `rx_key`,
a 12-byte counter-nonce per-direction; AAD is the frame header).

`session_id` (32 bytes) is a public identifier, placed in the
`SessionConfirmPayload` and used as the chain-salt for subsequent rekeys.

The identity key (Ed25519/Falcon-512) is **not involved** in this derivation: forward
secrecy — compromise of the long-term identity key does not reveal past sessions.

### 3.6 KeepalivePayload

```text
[0..8]   timestamp_secs  u64 BE
```

Sent at the interval `session.keepalive_interval_secs`. When there is no activity for longer than `session.idle_timeout_secs`, the session is closed.

### 3.7 Rekey (key change)

Initiated when the `REKEY_BYTES_THRESHOLD` = 128 GiB or `REKEY_TIME_THRESHOLD_SECS` = 32 days (2,764,800 s) threshold is exceeded. Both thresholds are configurable: `[session] rekey_bytes_threshold` and `[session] rekey_time_threshold_secs` — highly sensitive deployments may lower them explicitly. The byte threshold `MLKEM_REKEY_BYTES_THRESHOLD` is now equal to 128 GiB (the same as `REKEY_BYTES_THRESHOLD`); it differs from the main thresholds only in the time-based `MLKEM_REKEY_TIME_THRESHOLD_SECS` = 1 hour, which aligns the forward-secrecy window of the X25519 session key with the ML-KEM E2E key.

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

Each node that receives a new (unseen) message delivers it locally and forwards it to **K random neighbors** with `ttl - 1`. Deduplication is by `msg_id`.

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

V1 `FindNode` (slot 0) and `FindNodeResponse` (slot 8) — wire layout:
target+k → `Vec<NodeContact{node_id, transport}>` — were dropped.
V1 returned a transport per contact in the same RTT, which leaked the
routing graph en masse and made network-wide enumeration trivially
cheap.  All FIND_NODE traffic now goes through V2 + `ResolveTransport`
(§5.4.1).  Senders that emit slots 0 / 8 fail `DiscoveryMsg::try_from`
→ `Violation` in the dispatcher.

**`NodeContact`** is retained as a wire-helper for the `FindValue` not-found branch:

```text
[0..32]  node_id       [u8; 32]
[32..34] transport_len u16 BE
[34..N]  transport     bytes  (URI string)
```

Since **C-06** the `FindValue` not-found branch zeroes this field
(`transport_len = 0`, empty URI): like FIND_NODE V2 it returns **node-ids
only**, and the requester re-resolves each returned node's transport on demand
via `ResolveTransport` (§5.4.1). This closes the same bulk routing-graph leak on
the value-lookup path; the iterative/recursive walk still converges because
transports are resolved hop-by-hop rather than inlined in the response (see the
64-node linear-chain regression in `crates/veil-dht/src/iterative.rs`).

#### 5.2.1 discovery_mode filter + half-cap

The V2 FIND_NODE (`handle_find_node_v2`) and `FindValue` not-found
fallback both apply two levels of filtering before returning contacts
(via the shared `ranked_public_contacts` helper):

1. **Public-only filter:** peers with `discovery_mode != Public` (declared in `CapabilitiesPayload.discovery_mode` at handshake) are excluded from the response. This closes the enumeration-leak for opt-in privacy nodes: a `ContactsOnly` / `IntroductionOnly` peer will not appear in other nodes' FIND_NODE responses — and is therefore invisible to DHT-walk scanners.

2. **Half-cap:** no more than `min(K_requested, K_local, ceil(N_public / 2))` contacts are returned, where `N_public` is the number of Public peers in our routing table. This forces an attacker enumerating the Public network to make **at least 2× more FIND_NODE requests** to cover the full carto. Smallest case: with 1 Public peer, 1 is returned (Kademlia connectivity preserved).

Similar filtering is applied in:

- `handle_find_value::FindValueResponse::Nodes` (closest-nodes fallback)
- `handle_recursive_query::FIND_NODE` (via the `find_closest_public_node_ids` helper)

**NOT filtered** is internal routing (`find_closest_nodes` for next-hop selection, NeighborOffer) — there the filter would break routing through privacy-opt-in nodes acting as relays.

**Threat model:** scanner-resistance — passive enumeration via DHT FIND_NODE. Previously a scanner obtained K transports with a single FIND_NODE → ~10 RTT enumeration of all Public nodes in a /20 keyspace → a full address map within minutes. Half-cap + Public-only makes enumeration ≥ 2× slower and impossible for opt-in privacy nodes at all.

**Limitation:** Public nodes (default config) are still enumerable (although in chunks ≤50%). For full decoupling of the routing graph from the address graph — see Decoupled transport resolution / hidden services (planned).

### 5.3 StorePayload

```text
[0..32]  key       [u8; 32]
[32..36] ttl_secs  u32 BE
[36..40] value_len u32 BE
[40..]   value     bytes
```

### 5.4 AnnounceAttachmentPayload

A leaf → gateway announcement, published in the DHT. The exact format — [`proto/discovery.rs::AnnounceAttachmentPayload`](../../crates/veil-proto/src/discovery.rs):

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

**No transport fields** (unlike the removed V1 — see §5.1). The caller knows only the node_ids, and must call `ResolveTransport` separately for each one whose transport it actually needs.

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

`not_found` is returned when:
- The resolver has no `Contact` for the requested `node_id` in its routing table.
- A contact exists, but `discovery_mode != Public` (privacy filter — a non-Public peer's existence is not confirmed via this RPC; aggregating with the unknown-case is intentional — leaking "I know, but won't tell" gives an attacker a signal).

**Threat-model.** Previously any FIND_NODE returned K transports in a single RTT → a mass scan builds the cargo IP in O(N/K) RTT (~10 RTT for 200 Public nodes in a /20 keyspace). The DHT-walker now uses V2 by default — each transport requires a separate RPC → cumulative cost O(N) RTT, **~10× slower**. The PoW-gate + signed responses add per-resolve CPU cost (~17ms BLAKE3) + cache-poisoning resistance.

**Status:** wire-types + handlers + in-memory cache + V2-flow integrated into `NetworkPeerQuerier`. **Defense is active** — outbound DHT-walks use the V2-flow by default (`FindNodeV2 → node_ids → cache lookup → ResolveTransport(id) on miss`). V1 is removed — wire slots 0/8 → `Violation`.

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

`requester_node_id` is the OVL1-session-authenticated `peer_id` on the responder (not on the wire — taken from session context).  Server accepts iff `leading_zero_bits(hash) ≥ RESOLVE_POW_DIFFICULTY` AND `|time_bucket − now_bucket| ≤ RESOLVE_POW_TIME_WINDOW_BUCKETS`.  Defaults: `RESOLVE_POW_DIFFICULTY = 16` (median ~7 ms client mining on a fast x86 core, ~14 ms on low-end ARM); `RESOLVE_POW_BUCKET_SECONDS = 60`; `RESOLVE_POW_TIME_WINDOW_BUCKETS = 1` (≈ 120 s replay window).

PoW failure (invalid solution OR stale bucket OR wrong target / wrong requester binding) → silent `not_found` response, NOT a `Violation` — verification cost is one BLAKE3 hash (~1 µs) so per-peer dht_quota already bounds CPU spend; raising failures to violations would create a clock-drift false-positive eviction path.  Legacy senders without the PoW fields (32-byte payload) fail decode → `Violation` from the dispatcher.

Cumulative attacker cost goes from `O(N) RTT` to `O(N) × ~7 ms CPU` per probed `node_id` — for a `/20` keyspace (~200 Public peers) that's ~1.5 s of single-core mining for one full enumeration sweep, and the cost scales linearly with target set size while honest clients pay it only once per cache miss.

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

Each node mints its own bundle at startup (validity = 30 days; `ANNOUNCEMENT_VALIDITY_SECS`) and **gossips it via `DiscoveryMsg::AnnounceTransport` (slot 14) on every handshake-complete** (one fire-and-forget frame per session, both inbound and outbound paths).  Receivers verify and store under `transport_announcements: HashMap<node_id, …>` on `KademliaService`; `handle_resolve_transport` returns the cached bundle verbatim, so the resolver only relays what the target itself signed.  The maintenance tick prunes orphan announcements (peers no longer in the routing table).

**Walker verification (`NetworkPeerQuerier`).** Before inserting any resolved transport into `TransportCache`, the walker checks:
1. `BLAKE3(identity_pubkey) == announcement.node_id` — pubkey ↔ identity binding.
2. Ed25519 signature is valid over the canonical input.
3. `expiry_unix > now()`.
4. `announcement.node_id == requested node_id` (defence-in-depth: even if the resolver attached a valid announcement for the wrong peer, the walker discards it).

A malicious resolver can still **deny** existence (`not_found`) but cannot **redirect** traffic to attacker-controlled infrastructure: that would require forging an Ed25519 signature whose pubkey hashes to the target's `node_id`.

The dispatcher additionally enforces `announcement.node_id == session_peer_id` on `AnnounceTransport` — peers can only announce *their own* node_id, blocking gossip-flood pollution attacks.

**On-disk persistence.** The `transport_announcements: HashMap<node_id, SignedTransportAnnouncement>` map is periodically flushed to a JSON snapshot (default every 120 s + a final flush on clean shutdown).  On restart the snapshot is re-loaded; each entry's signature, pubkey↔node_id binding, and non-expiry are re-verified — failures are silently dropped.

Why JSON instead of the in-memory binary layout: each entry is small (~250 B JSON), the file is operator-grep-able, and the tamper-resistance comes from the signatures (verified on load), not from the on-disk format.  An attacker who edits the file can downgrade availability (drop entries → walker has to re-handshake) but **cannot** inject forged transports — they'd need an Ed25519 keypair whose pubkey hashes to a target's node_id.

Config knobs (`[dht]`):
- `transport_announcements_persist_path: Option<String>` — `None` disables.
- `transport_announcements_persist_interval_secs: u64` — default 120.

The `TransportCache` itself is intentionally **not** persisted — it's a derivation of verified announcements, and the next walk repopulates it on demand.

**Remaining caveats:**
- Each `ResolveTransport` additionally consumes a `dht_quota` token (the existing per-peer rate-limit) on top of PoW.
- Key rotation invalidates all outstanding announcements signed by the old key — peers re-gossip on the next handshake (no graceful migration window yet).

### 5.5 The Kademlia Algorithm

- **K** = 20 (k-bucket size — the classic Kademlia constant)
- **α** = 3 (parallel queries per round)
- **max_rounds** = 20
- XOR distance metric: `dist(a, b) = a XOR b`
- Lookup: iterative, α parallel FindNode per round, until the result no longer improves or the rounds are exhausted
- Anti-eclipse: at most `K/4 = 5` contacts from one /24 IPv4 (or /48 IPv6) per bucket

### 5.6 DeletePayload (multi-algo)

```text
[0..32]           key         [u8; 32]
[32]              algo        u8   (0/1 = Ed25519, 2 = Falcon-512, 3 = Ed25519+Falcon-512, 4 = Ed25519+Falcon-1024)
[33..35]          pk_len      u16 BE
[35..35+pk]       public_key  bytes (algo-dependent: 32 Ed25519, 897 Falcon-512; hybrids carry both)
[+2]              sig_len     u16 BE
[+slen]           signature   bytes (algo-dependent: 64 Ed25519, ~666 Falcon-512; hybrids carry both)
```

Validation:
1. `algo ∈ {0, 1, 2, 3, 4}` (every `SignatureAlgorithm::from_wire_byte` value, incl. the hybrids — U1, so hybrid-identity nodes can delete their own records, not just Ed25519/Falcon-512 owners);
2. `crypto::verify_message(algo, public_key, key_bytes, signature) = Ok`;
3. `BLAKE3(public_key) == key` — only the owner of a self-owned key can delete it.

---

## 6. Delivery Plane (Family 3)

### 6.1 DeliveryEnvelope (180-byte header + payload)

```text
[0..32]    recipient_node_id  [u8; 32]
[32..64]   sender_node_id     [u8; 32]
[64..96]   src_app_id         [u8; 32]
[96..128]  app_id             [u8; 32]   (recipient's app_id)
[128..132] endpoint_id        u32 BE
[132..164] content_id         [u8; 32]   (BLAKE3 payload)
[164..172] created_at         u64 BE     (Unix creation time)
[172..176] ttl_secs           u32 BE
[176..180] payload_len        u32 BE
[180..]    payload            bytes
```

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

Acknowledgement of specific (not necessarily consecutive) seq numbers. Maximum batch: `MAX_MAILBOX_ACK_BATCH = 256`.

### 6.4 DeliveryStatusPayload

```text
[0..32]  content_id  [u8; 32]
[32]     status      u8  (0=OK, 1=NOT_FOUND, 2=FAILED, 3=DUPLICATE, 4=TTL_EXPIRED)
```

---

## 7. E2E Encryption

When `payload[0] == 0xE2` in a `DeliveryEnvelope`, the payload is E2E-encrypted.

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

- The encapsulation key (public, 1184 bytes) is published in the DHT when an IPC endpoint is registered
- The decapsulation key (private, 64-byte seed) is held in the node's memory
- Key cache TTL: `ipc.e2e_key_ttl_secs` (default 3600 sec)

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

When the target node has `abuse.pow_min_difficulty > 0` configured, **`RouteResponse` (with `transports`) is deferred until the PoW is solved**:

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

**Without PoW (`pow_min_difficulty = 0`):** `RouteResponse` is sent immediately upon receiving the `RouteRequest` (legacy behavior).

**Why:** without a PoW gate, any node could send a `RouteRequest{target=X}` for an arbitrary `X` for free and get back a `RouteResponse{transports[X]}` — disclosure of the IP/port by `node_id`. The PoW gate makes probe-by-id costly.

#### 8.4.2 DiscoveryMode

An additional config option `[routing] discovery_mode` (default: `public`):

| Mode | Behavior |
|---|---|
| `public` | Current. If `pow_min_difficulty > 0` — gated through PoW; otherwise — immediate `RouteResponse`. |
| `contacts_only` | A `RouteRequest` from a requester outside `peer_pubkeys` (not handshaked) is **silently dropped** — neither `PowChallenge` nor `RouteResponse`. The node's existence stays hidden. |
| `introduction_only` | `RouteResponse.transports` is always empty. The requester must connect through one of the `relay_ids` (Tor-style introduction approximation without rendezvous). |

---

## 9. IPC Protocol (LocalApp, Family 6)

### 9.1 Connection Protocol

A local application connects to the IPC server through `ipc.socket_uri` (a Unix socket `unix:///path` or a TCP-loopback `tcp://127.0.0.1:port`).

Each message: `u16 BE msg_type` + `u32 BE body_len` + body.

Protocol version: `IPC_PROTOCOL_VERSION = 1`.

### 9.2 Sequence

```
App                              Node
 │── AppHello (v=1) ────────────►│
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

The AppBindOk response contains `app_id [u8; 32]` — see §1.2 for the exact formula (length-prefixed BLAKE3 `derive_key`).  In ephemeral mode (default), `ephemeral_app_id` with `client_token` mixing is used; in `bind_named` — the stable form of `app_id`.

### 9.5 Stream Flow Control

- **Send window**: the sender tracks the remaining window; blocks when `window = 0`
- **StreamWindow**: the receiver sends this to increase the sender's window
- **Initial window**: `STREAM_INITIAL_WINDOW` (default 256 KiB)
- **Maximum window**: `MAX_STREAM_SEND_WINDOW = 16 MB`

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

Legacy codes 0x02 (Relay), 0x04 (Gateway), 0x10 (CoreRouter) are removed;
such values from old peers are discarded.

**Leaf node:**
- Operates through a Core node (attachment lease)
- The mailbox is stored on Core nodes
- Does not accept inbound connections from arbitrary nodes
- Minimal resource requirements

**Core node:**
- A full participant in the DHT (K=20), relay, forwarding
- Gateway: serves the attachment records of leaf nodes (disabled via `[gateway] enabled = false`)
- Stores the mailbox for offline recipients
- Serves FindNode/FindValue/Store/Delete
- Recommended PoW difficulty ≥ 24 (the default is `16`; `MAX_POW_DIFFICULTY = 24` is the hard cap), high uptime (24/7)

---

## 12. Cryptography

### 12.1 Signature Algorithms

| Algorithm | Wire-byte `algo` | Pubkey | Privkey | Signature |
|----------|------------------|--------|---------|---------|
| Ed25519 | 0 / 1 | 32 bytes | 32 bytes | 64 bytes |
| Falcon512 | 2 | 897 bytes | 1281 bytes | 666 bytes |
| Ed25519+Falcon512 (hybrid) | 3 | 929 bytes | composite | Ed25519 ‖ Falcon-512 |
| Ed25519+Falcon1024 (hybrid) | 4 | 1825 bytes | composite | Ed25519 ‖ Falcon-1024 |

The `algo` byte is used in `IdentityPayload`, `DeletePayload`, mesh beacon, and PEX signatures.
The session handshake (`KeyAgreementPayload`) applies a different convention: 1 = Ed25519, 2 = Falcon512.

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

Details in §3.5. There is no separate `mac_key` — integrity is covered by the AEAD tag
(ChaCha20-Poly1305) and the handshake MAC in `SessionConfirm`
(`BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret ‖ small_id ‖ large_id)`).

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

All constants are defined in `crates/veil-proto/src/budget.rs`.

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
