# Veil Identity Model

**Status**: design-locked 2026-04-20.

This document is the reference specification for veil's sovereign identity
layer: stable `node_id`, master key + per-device subkeys, short-lived
delegations with auto-reissue, standalone (single-device) mode, and
multi-device operation under one master.

## Quick reference

```
node_id   = BLAKE3(master_pubkey)              // stable, master-pk-derived
device_id = BLAKE3(device_pubkey)              // deterministic per-device
                                                  address; verifier rejects mismatch
Delegation = IdentityKey {                     // per-device delegation
    pubkey,                                     // Ed25519 device pubkey
    device_id,                                  // = BLAKE3(pubkey)
    valid_from_unix,
    valid_until_unix,                           // default 7 days; re-issued at
                                                //   half-validity by maintenance tick
    master_sig,                                 // master_sk signs the cert
}

Standalone mode:
  master_pk == device_pk                        // device IS the master
  ⟹ node_id == device_id == BLAKE3(device_pk)  // single self-signed delegation
```

**No revocation flow**: the mitigation for compromise is
the short `valid_until_unix` window (default 7 days) plus auto-reissue
at half-validity.  A compromised device's cert ages out within ≤ 7 days
even without operator intervention.

## Goals

1. **Stable identity** — a `node_id` that survives key rotation, device
   loss, and compromise recovery. Once registered, it's permanent until user
   abandons it.
2. **Free registration** — any user with a keypair can register. No
   gatekeeper, no central registry, no DNS.  Short delegation validity
   replaces rate-limit-by-PoW at the document level.
3. **Standalone-mode default** — single-device users (phone-only, laptop-only)
   need no master-key ceremony.  The runtime auto-builds a degenerate
   `IdentityDocument` where `master_pk == device_pk` on first start.
4. **Multi-device** — one identity, many devices (phone + laptop + desktop).
   Each device runs with its own signing key, master-certified for ≤ 7 days
   at a time; auto-reissue at half-validity keeps long-running honest
   devices fresh.
5. **Load balancing** — the same `node_id` can route to multiple devices
   based on score / RTT / last-seen.
6. **Zero external trust** — no DNS verification, no guardians, no social
   recovery. Only cryptography.
7. **Forward secrecy for async messages** — compromise of keys later does not
   decrypt past messages (X3DH-style pre-keys).
8. **Time-bounded compromise** — no in-band revocation
   channel to defend.  Instead each delegation has a 7-day `valid_until`,
   re-issued by the master at half-validity.  A compromised device's cert
   ages out within ≤ 7 days regardless of operator action.

## Conceptual model

### Multi-device mode

```
master_seed (32 B random, BIP39 24-word backup, cold storage)
     │
     │ HKDF-SHA256(·, "veil.master.v1")
     ▼
 master_sk  ─ signs delegations (~weekly via auto-reissue, ad-hoc on
     │      delegate-device + rotate-device events)
 master_pk  (Ed25519 default; Falcon-512 opt-in for post-quantum)
     │
     │ BLAKE3(master_pubkey)            ← bare hash, no domain tag
     ▼
 node_id  [u8; 32]   ← STABLE FOREVER
     │
     ├── IdentityDocument (DHT record)
     │     ├── master_pubkey (plaintext; verifier recomputes node_id from this)
     │     ├── identity_keys[]  — per-device delegations (≤ 8), each
     │     │                       master-certified with its own short
     │     │                       valid_until_unix (default 7 days)
     │     ├── document_sig by the active subkey (sig_key_idx)
     │     └── (no revocation list, no master_freshness_sig, no PoW —
     │           short delegation validity + republish-often is the
     │           freshness mechanism)
     │
     ├── InstanceRegistry (separate DHT record)
     │     └── signed by any active identity_sk
     │
     ├── NameClaim records (separate per-name)
     │     └── signed by any active identity_sk
     │
     └── PrekeyBundle (X3DH, per-device)
           └── ML-KEM ephemeral + fallback keys, master-certified
```

### Standalone mode

```
device_sk_seed (32 B Ed25519 seed, runtime-generated or from [identity] config)
     │
 device_sk = master_sk = identity_sk    ← all three are the same key
     │
 device_pk = master_pk = identity_pk    ← all three are the same pubkey
     │
     │ BLAKE3(device_pubkey)
     ▼
 node_id == device_id   [u8; 32]        ← collapses; lone subkey covers
                                          both roles
     │
     ├── IdentityDocument (DHT record)
     │     ├── master_pubkey == identity_keys[0].pubkey
     │     ├── identity_keys[0]: self-signed delegation
     │     │   (master_sig produced by device_sk acting as master)
     │     └── document_sig by the lone subkey
```

The wire format is unchanged.  An external observer cannot distinguish a
standalone document from a freshly-created multi-device document with one
delegation: the `master_pubkey == identity_keys[0].pubkey` equivalence
holds for both.

**Key invariants**:

- `node_id` changes **only** on master_seed loss (catastrophic, analogous
  to Bitcoin wallet seed loss).
- In multi-device mode: `master_seed` lives **only on the primary device**;
  other devices get their own independent identity_sk via pairing or
  `identity delegate-device` with master certification.
- In standalone mode: there is no separate master_seed — the device key IS
  the master key.  Re-issue happens automatically every ~3.5 days via the
  maintenance tick; no operator action required.
- Per-device delegations: compromise of one device's cert
  naturally expires within ≤ 7 days even without operator action; the
  master simply stops re-issuing.
- Multiple devices under one `node_id` — native use case (load balancing +
  multi-device messenger).
- Session dedup by `(node_id, instance_id)` — per-peer.  `instance_id` is
  a 16-byte compatibility shim derived from `device_id[..16]`; new code
  should prefer the full 32-byte `device_id`.

## Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Hash (id binding, PoW, commitments) | BLAKE3-256 |
| Long-term signing | Ed25519 (default), Falcon-512, or the PQ hybrids Ed25519+Falcon-512 / Ed25519+Falcon-1024 (recommended for long-lived identities) |
| Key derivation from master_seed | HKDF-SHA256 |
| Symmetric encryption | ChaCha20-Poly1305 |
| Master-seed backup encoding | BIP39 (English, 24 words) |
| Password KDF (encrypted master file) | Argon2id |

Domain-separated signing contexts prevent cross-protocol sig substitution.
There is no `REVOKE_CONTEXT` or `FRESHNESS_CONTEXT` — no in-band
revocation, no separate freshness sig.  The document-level
`valid_until_unix` plus per-key `valid_until_unix` are the only freshness
mechanisms:

```rust
const CERTIFY_CONTEXT: &[u8] = b"veil.certify.v1";
const DOC_SIG_CONTEXT: &[u8] = b"veil.identity_doc.v1";
const PAIRING_INVITE_SIG_CONTEXT: &[u8] = b"veil.pairing_invite.v1";
const PREKEY_BUNDLE_SIG_CONTEXT:  &[u8] = b"veil.prekey_bundle.v1";
```

### Master key derivation

```
master_sk = HKDF-SHA256(
    salt: None,
    ikm:  master_seed,  // 32 bytes
    info: b"veil.master.v1",
    len:  32 (Ed25519) or 48 (Falcon-512 seed size)
)
```

### node_id binding

```
node_id = BLAKE3(master_pubkey)        // 32 bytes; bare hash, no domain tag
```

The binding is a bare BLAKE3 hash, matching the runtime's
`cfg::NodeId::from_public_key` derivation.
In standalone mode this yields `node_id == device_id ==
BLAKE3(device_pubkey)` byte-for-byte against the same pubkey.

Cross-algorithm collisions (e.g. an Ed25519 pubkey hashing to the same
BLAKE3 output as a Falcon-512 pubkey) are practically impossible: BLAKE3
is a 256-bit hash and the algorithm byte is part of the surrounding
`IdentityKey` cert that the verifier checks separately.

### device_id binding

Each per-device delegation carries an explicit `device_id` field, and the
verifier rejects any cert where the binding does not hold:

```
device_id = BLAKE3(device_pubkey)      // 32 bytes; same shape as node_id
```

This makes per-device addresses deterministic and observable from the wire
without trusting the sender.

## IdentityDocument wire format

DHT key: `BLAKE3("veil.identity_dht.v1" || node_id)`.

Source-of-truth: `crates/veil-proto/src/identity_document.rs`.  This
section reproduces the layout for documentation purposes only.

```
Layout (canonical bytes — all integers big-endian unless noted):
[0..2]       magic = "ID"                     u16 BE ('I'=0x49, 'D'=0x44)
[2]          version = 1                       u8
[3..35]      node_id                           [u8; 32]
[35]         master_algo                       u8 (0=Ed25519, 2=Falcon-512, 3=Ed25519+Falcon-512, 4=Ed25519+Falcon-1024)
[36..38]     master_pubkey_len                 u16 BE
[38..38+L]   master_pubkey                     [u8; L]  (L=32 or 897)
[...]        issued_at_unix                    u64 BE
[...]        valid_until_unix                  u64 BE   (≤ issued_at + 30d)
[...]        sig_key_idx                       u16 BE
[...]        identity_keys_count               u8
[...]        for each IdentityKey:             varies (see below)
[last]       document_sig_len                  u16 BE
[last]       document_sig                      [u8; S]
```

**Policy caps** (enforced at decode):
- `identity_keys_count ≤ MAX_IDENTITY_KEYS = 8`
- `valid_until_unix - issued_at_unix ≤ MAX_FRESHNESS_WINDOW_SECS = 30 days`
- Total document size ≤ `MAX_IDENTITY_DOCUMENT_BYTES = 16384` bytes (16 KiB,
  hard cap; sized to hold a fully-rotated Falcon hybrid document and matched
  to the DHT value cap)

The document carries no replay-guard `document_version`, no
`revocation_seq` / `revoked_keys[]` / `RevocationEntry`, no
`freshness_hour` / `master_freshness_sig` / document-level `pow_nonce`,
and no `extensions_root`.  Mitigation is short delegation validity; the
document's own `valid_until_unix` is the only freshness mechanism.

### `IdentityKey` (per-device delegation)

```
[0]           algo                       u8
[1..3]        pubkey_len                 u16 BE
[3..3+L]      pubkey                     [u8; L]
[...]         device_id                  [u8; 32]   (= BLAKE3(pubkey))
[...]         valid_from_unix            u64 BE
[...]         valid_until_unix           u64 BE     (per-key expiry,
                                                     default issued_at + 7 days)
[...]         master_sig_len             u16 BE
[...]         master_sig                 [u8; S]
```

`master_sig` covers:
```
CERTIFY_CONTEXT
|| node_id
|| algo
|| len(pubkey) as u16 BE
|| pubkey
|| device_id
|| valid_from_unix
|| valid_until_unix
```

### Document signing

`document_sig` covers the canonical bytes of all fields above (excluding
`document_sig_len` and `document_sig` itself):

```
DOC_SIG_CONTEXT || canonical_bytes_up_to_doc_sig
```

Signed by the current active identity_sk (referenced by `sig_key_idx`).
In standalone mode the active subkey IS the master, so the document_sig
and the lone `IdentityKey.master_sig` are produced by the same key.

## Verifier algorithm

Input: `doc: IdentityDocument`, `now_unix_secs: u64`.

Source-of-truth: `crates/veil-identity/src/verify.rs`.

1. Magic `"ID"` and version.
2. Recompute `node_id = BLAKE3(master_pubkey)`, reject on mismatch.
3. Check `now ≤ doc.valid_until_unix` (document freshness window).
4. For each `IdentityKey`:
   - **4a.** `device_id == BLAKE3(pubkey)` (deterministic binding).
     Reject `DeviceIdMismatch`.
   - **4b.** `now ≤ key.valid_until_unix` (per-delegation expiry).
     Reject `KeyExpired`.
   - **4c.** Verify `master_sig` with `master_pubkey` over
     `CERTIFY_CONTEXT || node_id || algo || len(pubkey) || pubkey ||
     device_id || valid_from || valid_until`.
5. Check `sig_key_idx` in bounds.
6. Verify `document_sig` with `identity_keys[sig_key_idx]` over
   `DOC_SIG_CONTEXT || canonical_signing_bytes()`.

Returns `ValidatedIdentity {
  node_id,
  master_algo, master_pubkey,
  active_identity_pubkey, active_identity_algo, active_key_idx,
  active_device_id,                  // deterministic device address
  active_instance_id,                // compat shim: device_id[..16]
}`.

The verifier does not touch a persistent revocation cache, does not
check document-level PoW, and does not verify a separate freshness
signature.

## Lifecycle operations

### Genesis — multi-device (`veil-cli identity create`)

1. Generate `master_seed = OsRng::gen(32)`.
2. Derive `master_sk`, `master_pk`; compute `node_id = BLAKE3(master_pk)`.
3. Generate first device's `identity_sk_0` (ephemeral random, not derived
   from master).
4. Compute `device_id_0 = BLAKE3(identity_pk_0)`.
5. `master_sig_0 = master_sk.sign(CERTIFY_CONTEXT || node_id || algo
   || len(identity_pk_0) || identity_pk_0 || device_id_0
   || valid_from || valid_until)`.  Default `valid_until = now + 7 days`.
6. Build IdentityDocument with one IdentityKey entry.
7. `document_sig = identity_sk_0.sign(DOC_SIG_CONTEXT || canonical)`.
8. Display BIP39 phrase; user writes it down.
9. Optionally save encrypted master file (Argon2id + ChaCha20-Poly1305).
10. Publish IdentityDocument to DHT (runtime does this on first start).

### Genesis — standalone (`veil-cli identity standalone`)

1. Generate `device_sk_seed = OsRng::gen(32)`.
2. `device_pk = derive(device_sk)`; `node_id = device_id =
   BLAKE3(device_pk)`.
3. Self-signed delegation: device_sk acts as master_sk.  `master_sig =
   device_sk.sign(CERTIFY_CONTEXT || node_id || ... )`.
4. `document_sig = device_sk.sign(DOC_SIG_CONTEXT || canonical)`.
5. Persist `identity_document.bin` + `device_identity_sk.bin`.

The runtime auto-runs steps 1-5 on first start when `identity_document.bin`
is absent and the `[identity]` config has an Ed25519 keypair
(auto-bootstrap).

### Auto-reissue at half-validity

The maintenance loop runs on every cleanup tick (~30 s default):

1. Read the active `IdentityKey.valid_until_unix`.
2. If `now + DELEGATION_VALIDITY_SECS / 2 < valid_until` — no-op (>
   half the window remains).
3. Otherwise, in **standalone mode**, the runtime re-signs in-place:
   `master_sk == device_sk == self.identity_sk` is already in memory.
   New `valid_until = now + 7 days` (full window again).
4. In **multi-device mode**, the tick is a no-op — the master_sk lives
   on a different device.  The operator runs `veil-cli identity
   delegate-device --pubkey-file ... --validity 7d` from the master
   device before the existing delegation expires; the resulting updated
   document is transported (USB / scp / QR) to the target device and
   dropped into `<veil_dir>/identity_document.bin`.  The on-change
   mtime poll in `runtime/sovereign_republish.rs` (60 s cadence) picks
   up the new document and DHT-republishes it.

### Pairing a new device (QR ceremony)

See `crates/veil-cli/src/cmd/sovereign_identity.rs::{pair_invite, pair_listen,
pair_accept}` for the runtime implementation.

### Compromise mitigation

There is **no in-band revocation channel**.  Instead:

1. The operator stops re-issuing the compromised device's delegation
   (multi-device: simply doesn't run `delegate-device` for that pubkey
   any more; standalone: rolls the device key via `identity standalone
   --force` if the master SK itself was compromised).
2. The compromised cert ages out within ≤ 7 days as `valid_until_unix`
   passes.  Verifiers reject the cert (step 4b
   `KeyExpired`); peers stop accepting handshakes from that device.
3. Long-term sessions already established with the compromised device
   continue until they hit their own session-rekey TTL.

This trades response time (≤ 7 days vs minutes for an in-band revoke)
for a much smaller protocol surface — no revocation gossip, no
revocation cache, no `revoked_keys[]` field, no `master_freshness_sig`.

## Name resolution

Names are claimed under ASCII-only whitelist `[a-z0-9#_-]`, case-insensitive
(normalized to lowercase before hashing):

```
name_dht_key = BLAKE3("veil.name_claim_dht.v1" || u16_be(len(name)) || name.as_bytes())
```

NameClaim value contains:
- name string
- node_id
- embedded `cert_proof` (master_pubkey + master_sig over signing
  identity_pubkey) for offline verification
- signing_identity_key_idx
- signature by any active identity_sk
- rarity-proportional PoW nonce

Resolver fetches NameClaim → extracts node_id → fetches IdentityDocument
→ validates cert chain → resolves to `ValidatedIdentity`.

**PoW difficulty scales by rarity**:
- 1-3 char ASCII alphabetic: 28-30 (hours of CPU)
- 4-6 char: 22-26 (minutes)
- 7-12 char: 18-22 (seconds to minutes)
- With discriminator (`alice#1234`): 14 (~1 sec)
- Long random (`AnonXYZ_7a3bf2`): 12 (~1 sec)

## InstanceRegistry

Separate DHT record, updated on online/offline transitions.  Compact
(typically < 2 KB).  Source-of-truth:
`crates/veil-proto/src/instance_registry.rs`.

```
DHT key = BLAKE3("veil.instances_dht.v1" || node_id)
```

The registry carries no `tier_b` block; `mailbox_anchor` and encrypted
contact hints are not part of the schema.  Transport hints live in
`SignedTransportAnnouncement` gossip.  The current shape:

```
InstanceRegistry {
    node_id:                  [u8; 32],
    instances:                Vec<InstanceEntry>,   // ≤ 16
    reg_version:              u64,                    // monotonic
    created_at_unix:          u64,
    signing_identity_key_idx: u16,                    // index in IdentityDocument
    sig:                      Vec<u8>,                // any active identity_sk
}

InstanceEntry {
    instance_id:              [u8; 16],   // truncated device_id (compat shim)
    bound_identity_key_idx:   u16,        // → IdentityDocument.identity_keys[i]
    label:                    String,     // ≤ 32 B, optional
    last_seen_ms:             u64,        // coarse granularity
}
```

## Routing: InstanceTag

Wire-level `Recipient`:

```
Recipient {
    node_id:      [u8; 32],
    instance_tag: InstanceTag,
}

enum InstanceTag {
    Any,                    // load-balanced — veil picks one device
    All,                    // fan-out broadcast — all devices
    Specific([u8; 16]),     // direct — exact instance_id (= device_id[..16])
}
```

Note: the runtime still keys on a 16-byte `instance_id` (truncation of
the full 32-byte `device_id`) for session dedup + dispatcher delivery.

## Threat model

See [`docs/recovery.md`](recovery.md) and
[`docs/opsec-user-guide.md`](opsec-user-guide.md) for user-facing
operational security concerns.

### In scope (veil defends)

- `node_id` hijacking via pre-image attack on BLAKE3 — infeasible (2^256).
- `device_id` spoofing — verifier rejects any cert where `device_id !=
  BLAKE3(pubkey)` (deterministic binding).
- Daily `identity_sk` leak (malware, stolen laptop) — compromised cert
  ages out within ≤ 7 days as the master stops re-issuing.
- Name squatting — rarity-proportional PoW (still in NameClaim layer).
- QR pairing phishing — OOB confirmation code.
- Document update flood from compromised key — per-identity DHT quota.
- Eclipse attack on identity resolution — multi-replica quorum.
- Forward secrecy for past async messages — X3DH one-time prekeys.

**Out of scope by design**:
- Sub-7-day compromise response.  Use `identity standalone --force` (for
  master compromise on a standalone) or `identity rotate` + waiting for
  the natural 7-day window (multi-device).
- Stale revocation attacks.  No revocation channel exists; nothing to be
  stale.

### Out of scope (user OpSec responsibility)

- `master_seed` physical backup loss — identity is permanently lost (as with
  Bitcoin wallet seed).
- Master storage compromise (physical theft of paper, unauthorized access to
  unlocked encrypted file) — full takeover, unrecoverable within this identity.
  Mitigation: paper in safe deposit, hardware keys, passphrase strength.
- Social engineering (user reveals BIP39 phrase) — documented in
  opsec-user-guide.md as warnings; protocol cannot prevent.
- Malware on device during BIP39 display, keylogging passwords — device
  security responsibility.
- Algorithm migration when quantum threat arrives — master_algo + per-subkey
  algo enables rotation to Falcon-512, but user must initiate.

## Algorithm agility

`master_algo: u8` and each `IdentityKey.algo: u8` allow mixed algorithm
deployments. A user can:

- Start with Ed25519 identity.
- Add Falcon-512 subkeys later (master certifies them).
- Eventually rotate master to a post-quantum algorithm (Falcon-512, or an Ed25519+Falcon-512/1024 hybrid) via re-issuance
  (new master_sk, new node_id; names / reputation need migration proof
  or re-claim — future work).

## See also

- [`docs/recovery.md`](recovery.md) — user guide for compromise recovery,
  device loss, BIP39 best practices.
- [`docs/multi-device.md`](multi-device.md) — LB vs messenger modes,
  Tier A vs B privacy trade-offs.
- [`docs/opsec-user-guide.md`](opsec-user-guide.md) — physical security
  checklist, phishing warnings.
- [`docs/messenger-dev.md`](messenger-dev.md) — how to build a messenger
  app on veil primitives.
