# Security Model

This page is the security and threat model for a Veil node. It is written to be
read top to bottom by an auditor: every row names a concrete attack, the defense
that ships today, and where in the code that defense lives. Terms of art are
spelled out the first time they appear.

A note on scope. "Implemented" means the defense is in the shipping code, not
that it is proven optimal. The [Open Risks](#open-risks) section at the bottom is
deliberately honest about what is still weak. Read it.

## Threat Model

Each row below pairs one attack with the mitigation that blocks (or blunts) it. A
few terms used in the table:

- **Sybil attack** — one operator spins up a flood of fake identities to gain
  outsized influence. Veil makes each identity cost CPU time to mint (Proof of
  Work), so a flood gets expensive.
- **Eclipse attack** — an attacker surrounds your node with nodes it controls,
  cutting you off from the honest network. Diversity rules in the routing table
  stop any one network neighborhood from owning all your slots.
- **Replay** — an attacker re-sends a message it captured earlier, hoping it gets
  acted on twice. Deduplication (**dedup**) remembers what was already seen and
  drops the repeat.
- **DHT** — the distributed hash table: the shared address book all nodes keep
  together. Poisoning, deletion abuse, and enumeration are the ways an attacker
  tries to corrupt or mine it.

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

These are the building blocks the rest of the system stands on. A few terms:
**AEAD** (authenticated encryption with associated data) both hides a message and
detects any tampering with it. **HKDF** is a key-derivation function — it turns
one shared secret into several purpose-specific keys. A **nonce** is a number
used once per encryption so the same plaintext never encrypts to the same bytes
twice; reusing one breaks the cipher, which is why we **rekey** (switch to fresh
keys) before any counter can wrap. **PoW** is the Proof of Work puzzle mentioned
above. "PQ" marks the post-quantum options, chosen to stay safe even against a
future quantum computer.

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

Secret keys are the crown jewels, so they get special handling. Two rules apply
throughout: keys never leak into debug logs, and long-lived secrets are pinned in
memory so they can't be swapped to disk or captured in a crash dump.

- `PowParams`, `Base64PrivateKey`, and `Base64PublicKey` redact their secrets
  from debug output.
- `SessionKeys` has a custom `Debug` implementation that does the same.
- `IdentityConfig` and `MetricsConfig` also redact their debug output (C-12).
- Session keys are derived with HKDF-SHA256. The two peers agree on which key is
  for sending versus receiving by lex-ordering both of their `node_id`s, so the
  assignment comes out mirrored on each side.
- If the nonce counter ever overflows, that is detected and the session is
  rekeyed before any nonce can repeat.

## Open Risks

Honest gaps. Each is a known weakness with a plan, not a surprise.

| Risk | Description | Mitigation Plan |
|------|-------------|-----------------|
| Shard filtering bypass | `shard_filtering` is opt-in (default false) | Enable by default when network > 1M nodes |
| Reputation cold start | New nodes start at score 0 → can't transit immediately | Mitigation TBD (peer vouches via `ReputationAttestation` provide some acceleration) |
| Key material in memory | Master & identity seeds mlocked (`SensitiveBytesN`) + `madvise(MADV_DONTDUMP)`; some session-scoped AEAD keys still on the heap | Implemented (seeds); session keys pending |
| Protocol version gap | `OVL1_MINOR_VERSION = 1` but features gate at >=5 | Bump version with full test coverage |
