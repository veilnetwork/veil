# Security Model

## Threat Model

| Attack | Mitigation | Status |
|--------|-----------|--------|
| **Sybil** | PoW difficulty (default 16, adaptive/epoch-based; `MAX_POW_DIFFICULTY=24` hard cap) | Implemented |
| **Eclipse (DHT)** | Subnet /24 diversity in k-buckets (K/4=5 max per subnet) | Implemented |
| **Mailbox Flood** | Reject when full (no eviction); per-sender quota; global 100K cap | Implemented |
| **Replay (routing)** | Two-layer dedup: per-(origin,via,seq) + per-(origin,seq); `MAX_ROUTE_ANNOUNCE_AGE_SECS=300` | Implemented |
| **DHT Poisoning** | `expires_at` validation; signed STORE announcements | Implemented |
| **DHT Delete abuse** | `DeletePayload` requires `(algo, pubkey, signature)`; `BLAKE3(pubkey)==key` (self-owned only) | Implemented |
| **DHT seed exhaustion** | HashSet-based O(1) dedup in iterative lookups | Implemented |
| **DHT enumeration** | FIND_NODE V2 + FIND_VALUE return node-ids only (transports re-resolved per-hop via `ResolveTransport`); Public-only + half-cap filter on closest-node responses | Implemented (C-06) |
| **Gateway Spoofing (session)** | `peer_roles` cache verified against handshake capabilities | Implemented |
| **Mesh-beacon spoofing (on-link)** | Unsigned beacons dropped by default (`require_signed_beacons=true`); role flags not advertised unless `advertise_role_in_beacon` is set | Implemented (C-03) |
| **Rate flood** | Per-peer token bucket → violation tracker (5 strikes / 5 min) → ban list | Implemented |
| **Connection flood** | `MAX_SESSIONS_PER_IP=32`; optional PoW challenge at handshake | Implemented |
| **Congestion** | Backpressure at >78% load; adaptive fan-out halved at >50% | Implemented |
| **Transit abuse** | Reputation gate: `MIN_REPUTATION_FOR_TRANSIT=200` | Implemented |
| **Reputation inflation (forged delivery ACK)** | DELIVERED ACK carries a BLAKE3-MAC of `content_id` under the per-message E2E key; reputation credited only on a valid MAC | Implemented (C-09) |
| **Cross-algo substitution** | All signatures verified via `crypto::verify_message(algo, ...)`; algo byte travels on the wire | Implemented |
| **Traffic analysis** | Optional `SessionMsg::Padding` frames aligned to MTU | Implemented |

## Cryptographic Primitives

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Identity | Ed25519, Falcon-512, or Ed25519+Falcon-512/1024 hybrids (PQ) | Configurable per-node; `node_id = BLAKE3(pubkey)` |
| Session key exchange | X25519 ephemeral DH | HKDF-SHA256 (salt = `local_id XOR remote_id`, info = `"ovl1-session-v1"`) yields `tx_key`/`rx_key`/`session_id`; lex-order swap of tx/rx keys gives both sides mirrored assignments |
| Session encryption | ChaCha20-Poly1305 | Per-frame AEAD; 12-byte counter nonce; rekey at 128 GiB / 32 days / counter wrap (configurable via `[session] rekey_bytes_threshold` + `rekey_time_threshold_secs`) |
| E2E encryption | ML-KEM-768 encapsulation + ChaCha20-Poly1305 | Markers `0xE2` (E2E) / `0xE3` (meta-E2E, hides sender) |
| Hashing | BLAKE3 | Node IDs, DHT keys, PoW, content hashing, HMAC (`keyed`) |
| PoW | `BLAKE3(pubkey ‖ nonce ‖ sign(pubkey, nonce))` with the configured leading-zero bits (default 16) | Sequential; adaptive — raised toward the `MAX_POW_DIFFICULTY=24` cap as the network grows |
| Mailbox replica encryption | HKDF(primary_mlkem_dk) + ChaCha20-Poly1305 | Replicas store opaque blobs |

## Key Material Protection

- `PowParams`, `Base64PrivateKey`, `Base64PublicKey`: Debug output redacted
- `SessionKeys`: custom Debug impl with redaction
- `IdentityConfig`, `MetricsConfig`: Debug output redacted (C-12)
- Session keys derived via HKDF-SHA256; tx/rx assignment is mirrored by lex-ordering both peers' node_ids
- Nonce counter overflow detected and session rekeyed

## Open Risks

| Risk | Description | Mitigation Plan |
|------|-------------|-----------------|
| Shard filtering bypass | `shard_filtering` is opt-in (default false) | Enable by default when network > 1M nodes |
| Reputation cold start | New nodes start at score 0 → can't transit immediately | Mitigation TBD (peer vouches via `ReputationAttestation` provide some acceleration) |
| Key material in memory | Master & identity seeds mlocked (`SensitiveBytesN`) + `madvise(MADV_DONTDUMP)`; some session-scoped AEAD keys still on the heap | Implemented (seeds); session keys pending |
| Protocol version gap | `OVL1_MINOR_VERSION = 1` but features gate at >=5 | Bump version with full test coverage |
