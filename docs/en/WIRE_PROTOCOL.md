# OVL1 Wire Protocol

> A byte-by-byte reference for anyone implementing the protocol. It defines what
> goes on the wire, field by field. For the full system description, see
> [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md). For what each payload means, see
> [protocol-spec.md](protocol-spec.md).

## Frame Header (24 bytes)

Every message on the wire is a *frame*: a fixed 24-byte header followed by an
optional body. The header below is the same on every frame; multi-byte fields are
big-endian (BE).

```
Offset  Size  Field        Description
0       4     magic        "OVL1" (0x4F564C31)
4       1     version      Protocol version (1)
5       1     family       FrameFamily discriminant (0..11)
6       2     msg_type     Message type within family (BE u16)
8       2     flags        Frame flags (BE u16); bits[1:0] = priority class
10      2     header_len   Total header size incl. TLV extensions (BE u16; =24 w/o TLV)
12      4     body_len     Body length in bytes (BE u32; cap 16 MiB)
16      4     stream_id    Logical stream ID (BE u32)
20      4     request_id   Request/response correlation ID (BE u32)
```

Constants (`proto/codec.rs`, `proto/header.rs`):
- `MAGIC = "OVL1"`
- `VERSION = 1`
- `HEADER_SIZE = 24`
- `MAX_FRAME_BODY = 16 MiB`
- `DEFAULT_MAX_FRAME_BODY = 1 MiB` (soft limit per listener)

### Priority bits (flags[1:0])

The low two bits of `flags` set the frame's priority class. The scheduler drains
the four classes by weighted round-robin (WRR), so a higher weight gets more turns
under load.

| Value | Class | WRR weight |
|-------|-------|------------|
| 0 | RealTime | 8 |
| 1 | Interactive | 4 |
| 2 | Bulk | 2 |
| 3 | Background | 1 |

Every other flag bit is reserved. Senders MUST clear them; receivers MUST ignore
any bit they don't recognize.

## Frame Families

A *family* groups related message types under one `family` byte; the `msg_type`
field then picks the specific message within that family. The numbers in
parentheses below are the `msg_type` values. The source of truth is
[`family.rs`](../../crates/veil-proto/src/family.rs).

| ID | Family | Messages |
|----|--------|----------|
| 0 | Session | Hello(0), Identity(1), Capabilities(2), KeyAgreement(3), SessionConfirm(4), Attach(5), Detach(6), Keepalive(7), RekeyInit(8), RekeyAck(9), MlKemRekeyEk(10), MlKemRekeyAck(11), Ticket(12), SleepAdvertisement(13), Padding(14), IdentityProof(15), HandoffInit(16), HandoffAck(17), HandoffAttach(18), HybridKexCt(19), RekeyKeptInit(20), TransportMigrationNotify(21), RequestEphemeralEndpoint(22), EphemeralEndpointResponse(23), HandoffChallenge(24), HandoffResponse(25) |
| 1 | Control | Ping(0), Pong(1), NeighborOffer(2), RouteProbe(3), RouteReply(4), Error(5), NatProbeRequest(6), NatProbeReply(7), NatRelayRequest(8), Keepalive(0x10), KeepaliveAck(0x11), EpidemicBroadcast(0x20), Backpressure(0x30) |
| 2 | Discovery | FindValue(1), Store(2), Delete(3), AnnounceAttachment(4), GetAttachment(5), GetAppEndpoint(7), FindValueResponse(9), FindNodeV2(10), FindNodeV2Response(11), ResolveTransport(12), ResolveTransportResponse(13), AnnounceTransport(14) — slots 0/6/8 removed (unallocated) |
| 3 | Delivery | Forward(3), DeliveryStatus(4), ChunkManifest(7), Chunk(8), Transit(0x10), RecursiveRelay(0x11), RelayPath(0x12) — mailbox slots 0/1/2/5/6 removed (unallocated) |
| 4 | App | AppOpen(0), AppData(1), AppClose(2), AppSend(3), AppReceipt(4), AppWindowUpdate(5), AppRtData(6) |
| 5 | Mesh | Forward(0), Beacon(1), Ack(2) |
| 6 | LocalApp | 79 IPC message types (AppHello=0 … SendAnonymousDirectResult=78); see [`family.rs`](../../crates/veil-proto/src/family.rs) for the full list |
| 7 | Tunnel | IpPacket(0) — TUN/TAP |
| 8 | Routing | RouteAnnounce(0), RouteWithdraw(1), RouteRequest(2), RouteResponse(3), PowChallenge(4), PowResponse(5), PowAccept(6), RouteAnnounceAliased(7), RouteWithdrawAliased(8), RouteDiscover(9), RouteDiscoverOffer(10), RecursiveQuery(0x10), RecursiveResponse(0x11), RouteUpdate(0x12), VersionVectorSync(0x13) |
| 9 | Diag | Ping(1), Pong(2), TraceProbe(3), TraceHop(4) |
| 10 | RelayChain | Hop(0) — onion-encrypted relay chain; RegisterRendezvous(1), UnregisterRendezvous(2), ForwardIntroduce(3) — plain control payloads over an established session (not onion-encrypted) |
| 11 | PeerExchange | Walk(0), Challenge(1), Response(2), Result(3) |

A frame with an unknown `family` is simply ignored, which keeps the protocol
forward-compatible: old nodes skip messages they don't understand instead of
breaking. An unknown `msg_type` inside a family you do know is ignored the same
way.

## Handshake Sequence

Before any real traffic flows, the two sides run a *handshake* — a fixed exchange
that proves identity and agrees on a shared key. Each step below is sent by the
client and echoed by the server, in order:

```
Client                               Server
  │                                     │
  ├── Hello(magic, version, node_id) ──→│
  │ ←── Hello ──────────────────────────┤
  │                                     │
  ├── Identity(algo, pubkey, nonce, ───→│
  │            node_id, mlkem_ek?)      │
  │ ←── Identity ───────────────────────┤
  │                                     │
  ├── Capabilities(role_bits, flags, ──→│
  │                discovery_mode)      │
  │ ←── Capabilities ───────────────────┤
  │                                     │
  ├── KeyAgreement(X25519_pubkey) ─────→│
  │ ←── KeyAgreement ───────────────────┤
  │    [HKDF-SHA256 → session keys]     │
  │                                     │
  ├── SessionConfirm(session_id, mac) ─→│
  │ ←── SessionConfirm ─────────────────┤
  │    [AEAD encrypted from here]       │
```

From `SessionConfirm` onward, every frame body is encrypted with
ChaCha20-Poly1305. The 24-byte header stays in plaintext, but it is fed to the
cipher as additional authenticated data (AAD): it isn't hidden, yet any tampering
with it makes decryption fail.

## Key Payloads

A *payload* is the body of a frame — the bytes that follow the 24-byte header.
Each layout below uses `[start..end]` byte ranges, half-open (the end index is
excluded), and the same big-endian convention as the header.

### HelloPayload (34 bytes)
```
[0..2]   ovl1_version  u16 BE = 1
[2..34]  node_id       [u8; 32]
```

### IdentityPayload (variable)
```
[0]                  algo         u8 (0/1=Ed25519, 2=Falcon512, 3=Ed25519+Falcon512, 4=Ed25519+Falcon1024)
[1..3]               pk_len       u16 BE
[3..3+pk]            public_key   bytes
[3+pk]               nonce_len    u8
[4+pk..4+pk+n]       nonce        bytes (PoW nonce, hex-string form)
[4+pk+n..+32]        node_id      [u8; 32]  (must equal BLAKE3(public_key))
[+2]                 mlkem_pk_len u16 BE    (0 = no ML-KEM key)
[..]                 mlkem_pk     bytes     (1184 B for ML-KEM-768)
```

### CapabilitiesPayload (3 bytes, wire v3)
```
[0]      roles_supported u8  (bit 0=LEAF, bit 3=CORE)
[1]      flags           u8  (CAN_RELAY=0x01, SUPPORTS_SOVEREIGN_IDENTITY=0x02,
                             ANONYMITY_RELAY=0x04, SUPPORTS_HYBRID_KEX=0x08)
[2]      discovery_mode  u8  (0=Public, 1=ContactsOnly)
```
> Wire v3 dropped the old 12-byte form. Gone are the fields `transports_supported`,
> `max_frame_size`, `max_streams`, and `ovl1_minor`, along with the
> `CAN_MAILBOX/CAN_GATEWAY_LOCAL_MESH/CAN_PARTICIPATE_DHT/`
> `CAN_ACCEPT_APP_STREAMS/CAN_STORE/SUPPORTS_TRANSIT` flags. For compatibility the
> decoder still accepts a 2-byte form (`roles + flags`); when it does, it defaults
> `discovery_mode` to `Public`.

### DeletePayload (variable)
An authenticated request to delete a value from the DHT. It carries a signature, so
only the rightful owner can remove an entry. Every identity signature algorithm is
supported — Ed25519, Falcon-512, and the Ed25519+Falcon-512/1024 hybrids — through
`SignatureAlgorithm::from_wire_byte`.

```
[0..32]             key         [u8; 32]
[32]                algo        u8  (0 = Ed25519, 2 = Falcon-512)
[33..35]            pk_len      u16 BE
[35..35+pk]         public_key  bytes (32 for Ed25519, 897 for Falcon-512)
[+2]                sig_len     u16 BE
[+slen]             signature   bytes (64 for Ed25519, ~666 for Falcon-512)
```

The server accepts the delete only if all three checks pass:
1. the algorithm is one it allows here — `algo ∈ {0, 2}`;
2. the signature verifies — `crypto::verify_message(algo, public_key, key_bytes, signature)` returns OK;
3. the key belongs to the signer — `BLAKE3(public_key) == key`, so only the node whose `node_id == key` can delete it.

### RecursiveRelayPayload
```
[0..32]   dst_node_id     final destination
[32..64]  originator_pseudonym  BLAKE3("rr_pseudo" || originator_id || query_id) — privacy-preserving pseudonym for reverse-path cache; raw originator_id never travels on the wire
[64..68]  query_id        dedup token (u32 BE)
[68]      hop_count       remaining hops (decremented each hop)
[69..]    payload         wrapped DELIVERY_FORWARD body (DeliveryEnvelope::encode())
```

### EpochDifficultyRecord
```
[0..4]    epoch              unix days (u32 BE)
[4..8]    difficulty         required leading-zero bits (u32 BE)
[8..40]   publisher_node_id  bootstrap node that published
[40..104] signature          Ed25519 over [0..8]
```

### ReputationAttestation
```
[0..32]   subject_node_id   node being vouched for
[32..64]  voucher_node_id   node giving the vouch
[64..68]  epoch             unix days (u32 BE)
[68..72]  score_milliunits  observed score (u32 BE)
[72..136] signature         Ed25519 over [0..72]
```

### E2eEnvelope (prefixed by 0xE2 or 0xE3 marker byte in DeliveryEnvelope.payload)
```
[0]         version        u8 = 1
[1..3]      kem_ct_len     u16 BE  (1088 for ML-KEM-768)
[3..N]      kem_ct         bytes   (ML-KEM encapsulated key)
[N..N+12]   nonce          [u8; 12] (ChaCha20-Poly1305 nonce)
[N+12..+4]  ct_len         u32 BE
[N+16..]    ciphertext     bytes    (ChaCha20-Poly1305 ciphertext + 16 B auth tag)
```

## Constants quick-reference

A handful of limits worth keeping nearby. The authoritative list lives in
[`budget.rs`](../../crates/veil-proto/src/budget.rs); the table below is just a
convenience copy.

| Constant | Value |
|----------|-------|
| `FRAME_HEADER_SIZE` | 24 |
| `MAX_FRAME_BODY` | 16 MiB |
| `DEFAULT_MAX_FRAME_BODY` | 1 MiB |
| `OVL1_MINOR_VERSION` | 1 |
| `MAX_POW_DIFFICULTY` | 24 |
| `MAX_CONCURRENT_POW_SOLVERS` | 4 |
| `SESSION_TICKET_TTL_SECS` | 3600 |
| `SESSION_TICKET_MAX_AGE_SECS` | 7200 |
| `MAX_MAILBOX_ACK_BATCH` | 256 |
| `MAX_TRANSPORT_ADDRS` | 32 |
| `MAX_RELAY_IDS` | 32 |
| `MAX_MLKEM_PK_LEN` | 1600 |
| `MAX_NAME_SIG_BYTES` | 65 536 |
| `MAX_ROUTE_ANNOUNCE_AGE_SECS` | 300 |
| `MAX_ROUTE_ANNOUNCE_SKEW_SECS` | 30 |
| `MAX_NEIGHBOR_TABLE_SIZE` | 256 |
| `MAX_ROUTE_CACHE_SIZE` | 1024 (baseline; adaptive) |
