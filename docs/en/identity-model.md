# Veil Identity Model

**Status**: design-locked 2026-04-20.

This is the reference specification for veil's identity layer. "Identity"
here means a node's permanent name plus the keys that prove it owns that
name. Your identity is yours alone — no company issues it and no registry
can take it away. The pieces:

- a stable **`node_id`** — your permanent address, computed from your key;
- a **master key** that you keep safe, plus short-lived **device keys** it
  signs off on — one per phone, laptop, or server;
- **delegations** — the master key's signed permission slips that say "this
  device key is really mine," reissued automatically before they expire;
- **standalone mode** for people with a single device, and
- **multi-device** operation, where many devices share one identity.

Each of these is explained in full below; the bullets are just the map.

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

**There is no revocation flow** — no way to broadcast "cancel this key right
now." We don't need one. Every delegation expires on its own after a short
window (`valid_until_unix`, 7 days by default), and a healthy device renews
its delegation halfway through that window. So if a device is stolen, its
delegation simply stops being renewed and dies within 7 days on its own — no
emergency action required.

## Goals

1. **Stable identity.** Your `node_id` survives key rotation, a lost device,
   and recovery after a break-in. Once you register it, it's yours until you
   walk away from it.
2. **Free registration.** Anyone with a key pair can register. There's no
   gatekeeper, no central registry, and no DNS. Short delegation lifetimes do
   the rate-limiting that a proof-of-work puzzle would otherwise do at the
   document level. (Proof of work, or PoW, is a small CPU puzzle that makes
   spam expensive; it still guards name claims, covered later.)
3. **Standalone mode by default.** If you have just one device — only a phone,
   only a laptop — you shouldn't have to perform a master-key ceremony. On
   first start the runtime quietly builds a one-device `IdentityDocument`
   where the master key and the device key are the same key.
4. **Multi-device.** One identity, many devices — phone plus laptop plus
   desktop. Each device signs with its own key, and the master vouches for
   that key for 7 days at a stretch. Auto-reissue at the halfway mark keeps
   honest, long-running devices current.
5. **Load balancing.** The same `node_id` can route to several devices, picking
   one by score, round-trip time, or how recently it was seen.
6. **Zero external trust.** No DNS to verify against, no guardians, no social
   recovery. Cryptography is the only thing you rely on.
7. **Forward secrecy for async messages.** If your keys leak later, your past
   messages stay sealed (this uses X3DH-style pre-keys).
8. **Time-bounded compromise.** There's no live revocation channel to guard.
   Instead every delegation carries a 7-day `valid_until`, and the master
   reissues it at the halfway point. A stolen device's certificate ages out
   within 7 days no matter what the operator does.

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

The bytes on the wire are exactly the same in both modes. An outside observer
can't tell a standalone document apart from a brand-new multi-device document
that happens to have one delegation: in both, `master_pubkey` equals
`identity_keys[0].pubkey`.

**The invariants worth remembering**:

- Your `node_id` changes **only** if you lose the master seed (the 32-byte
  secret everything is derived from). That's catastrophic — the same kind of
  loss as misplacing a Bitcoin wallet's seed.
- In multi-device mode the master seed lives **only on your primary device**.
  Every other device gets its own independent device key, either by pairing or
  by running `identity delegate-device`, and the master certifies it.
- In standalone mode there is no separate master seed at all — the device key
  *is* the master key. The delegation renews itself roughly every 3.5 days on
  the maintenance tick, with nothing for you to do.
- Each device's delegation stands on its own. If one is compromised, it simply
  expires within 7 days; the master just stops renewing it.
- Running many devices under one `node_id` is the intended case, not a corner
  case — that's what powers load balancing and the multi-device messenger.
- veil keeps one session per `(node_id, instance_id)` pair for each peer.
  This `active_instance_id` is a 16-byte stand-in kept for backward
  compatibility, taken from the first half of `device_id` (`device_id[..16]`);
  new code should prefer the full 32-byte `device_id`. (Note: this deterministic
  compat-shim id is distinct from the device's locally-persisted *random*
  `instance_id` in `~/.config/veil/instance_id`, which is what
  `Recipient::Specific` targets — see [multi-device.md](multi-device.md).)

## Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Hash (id binding, PoW, commitments) | BLAKE3-256 |
| Long-term signing | Ed25519 (default), Falcon-512, or the PQ hybrids Ed25519+Falcon-512 / Ed25519+Falcon-1024 (recommended for long-lived identities) |
| Key derivation from master_seed | HKDF-SHA256 |
| Symmetric encryption | ChaCha20-Poly1305 |
| Master-seed backup encoding | BIP39 (English, 24 words) |
| Password KDF (encrypted master file) | Argon2id |

Every signature is tied to a named context string, so a signature made for one
purpose can never be replayed as if it meant another. Notice what's *missing*:
there's no `REVOKE_CONTEXT` and no `FRESHNESS_CONTEXT`, because there's no live
revocation and no separate freshness signature. The only things that say "this
is still current" are the document's `valid_until_unix` and each key's own
`valid_until_unix`:

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

It's a plain BLAKE3 hash with no extra tag — BLAKE3 is the fast, modern hash
function veil uses throughout. This matches the runtime's
`cfg::NodeId::from_public_key` exactly. In standalone mode the same public key
feeds both formulas, so `node_id == device_id == BLAKE3(device_pubkey)`,
byte for byte.

Could two different signature algorithms ever hash to the same `node_id` — say
an Ed25519 key and a Falcon-512 key landing on the same output? In practice,
no. BLAKE3 produces a 256-bit value, and on top of that the algorithm byte
lives inside the surrounding `IdentityKey` certificate, which the verifier
checks separately.

### device_id binding

Every per-device delegation carries its `device_id` right in the open, and the
verifier throws out any certificate where that field doesn't match the hash of
the key:

```
device_id = BLAKE3(device_pubkey)      // 32 bytes; same shape as node_id
```

Because the address is just a hash of the key, anyone can recompute it
straight from the wire and confirm it — there's no need to take the sender's
word for anything.

## IdentityDocument wire format

DHT key: `BLAKE3("veil.identity_dht.v1" || node_id)`.

The real definition lives in `crates/veil-proto/src/identity_document.rs`; the
layout below is here for reading, not as the authority.

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

**Hard limits**, checked the moment a document is decoded:
- at most 8 device keys (`identity_keys_count ≤ MAX_IDENTITY_KEYS = 8`);
- the freshness window can't exceed 30 days
  (`valid_until_unix - issued_at_unix ≤ MAX_FRESHNESS_WINDOW_SECS = 30 days`);
- the whole document must fit in 16 KiB
  (`MAX_IDENTITY_DOCUMENT_BYTES = 16384` bytes). That ceiling is big enough to
  hold a fully-rotated Falcon hybrid document and lines up with the largest
  value the DHT will store.

Notice what the document leaves out. There's no `document_version` replay
guard, no `revocation_seq` / `revoked_keys[]` / `RevocationEntry`, no
`freshness_hour` / `master_freshness_sig` / document-level `pow_nonce`, and no
`extensions_root`. Short delegation lifetimes do that job instead, and the
document's own `valid_until_unix` is the only thing that marks it as current.

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

`document_sig` is a signature over the canonical bytes of every field above —
all of them except `document_sig_len` and `document_sig` itself:

```
DOC_SIG_CONTEXT || canonical_bytes_up_to_doc_sig
```

The signer is whichever device key is currently active, pointed to by
`sig_key_idx`. In standalone mode that active key *is* the master, so the
`document_sig` and the single `IdentityKey.master_sig` both come from the same
key.

## Verifier algorithm

It takes two inputs: the document to check (`doc: IdentityDocument`) and the
current time (`now_unix_secs: u64`). Here's what it does, in order. The real
code lives in `crates/veil-identity/src/verify.rs`.

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

Notice the three things the verifier never does: it doesn't consult a saved
revocation list, it doesn't check any document-level proof of work, and it
doesn't look for a separate freshness signature. None of those exist.

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

You rarely run these steps by hand. On first start, if there's no
`identity_document.bin` yet and your `[identity]` config already holds an
Ed25519 key pair, the runtime walks through steps 1 to 5 for you. This is the
auto-bootstrap path.

### Auto-reissue at half-validity

A delegation that's renewed only when it's about to die would cut things too
close. So the maintenance loop checks on every cleanup tick (about every 30
seconds by default) and renews at the halfway mark:

1. Read the active `IdentityKey.valid_until_unix`.
2. If `now + DELEGATION_VALIDITY_SECS / 2 < valid_until` — no-op (>
   half the window remains).
3. Otherwise, in **standalone mode**, the runtime re-signs in-place:
   `master_sk == device_sk == self.identity_sk` is already in memory.
   New `valid_until = now + 7 days` (full window again).
4. In **multi-device mode** the tick does nothing, because the master key
   lives on another device. Here you renew by hand. Before the current
   delegation expires, run `veil-cli identity delegate-device --pubkey-file
   ... --validity 7d` on the master device. Then carry the updated document to
   the target device however you like — USB stick, `scp`, or a QR code — and
   drop it in `<veil_dir>/identity_document.bin`. The runtime watches that
   file's modification time (a 60-second poll in
   `runtime/sovereign_republish.rs`), notices the change, and republishes the
   new document to the DHT.

### Pairing a new device (QR ceremony)

To add a second device, the two devices run a short QR-code handshake. For the
working implementation, see `crates/veil-cli/src/cmd/sovereign_identity.rs::{pair_invite,
pair_listen, pair_accept}`.

### Compromise mitigation

Say a device gets stolen. There's **no live revocation channel** to shout
"cancel this key." Instead the fix plays out on its own:

1. You stop renewing that device's delegation. On multi-device, that just
   means you don't run `delegate-device` for its key any more. On standalone,
   if the master key itself leaked, you roll the device key with `identity
   standalone --force`.
2. Within 7 days the certificate ages out as its `valid_until_unix` slips into
   the past. From then on verifiers reject it (step 4b, `KeyExpired`), and
   peers stop accepting handshakes from that device.
3. Sessions already running with the stolen device keep going until they hit
   their own rekey deadline.

The trade is plain: you wait up to 7 days instead of cancelling in minutes,
and in return the protocol stays small — no revocation gossip, no revocation
cache, no `revoked_keys[]` field, no `master_freshness_sig`.

## Name resolution

A name lets a human-friendly handle stand in for a `node_id`. Names use only
the ASCII characters `[a-z0-9#_-]` and ignore case — everything is lowercased
before it's hashed:

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

Looking a name up is a short chain: the resolver fetches the NameClaim, reads
the `node_id` out of it, fetches that node's IdentityDocument, checks the
certificate chain, and ends up with a `ValidatedIdentity`.

The proof-of-work cost rises the rarer — and so the more valuable — a name is,
which is what keeps short, desirable names from being grabbed in bulk:
- 1-3 char ASCII alphabetic: 28-30 (hours of CPU)
- 4-6 char: 22-26 (minutes)
- 7-12 char: 18-22 (seconds to minutes)
- With discriminator (`alice#1234`): 14 (~1 sec)
- Long random (`AnonXYZ_7a3bf2`): 12 (~1 sec)

## InstanceRegistry

This is a small, separate DHT record that lists which devices are currently
online. It's refreshed whenever a device comes up or drops off, and it stays
compact — usually under 2 KB. The real definition is in
`crates/veil-proto/src/instance_registry.rs`.

```
DHT key = BLAKE3("veil.instances_dht.v1" || node_id)
```

A couple of things are deliberately absent: there's no `tier_b` block, and
neither `mailbox_anchor` nor encrypted contact hints belong here. Hints about
how to reach a device travel separately, in `SignedTransportAnnouncement`
gossip. Here's the shape today:

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
    last_seen_unix_ms:        u64,        // coarse granularity
}
```

## Routing: InstanceTag

When you address a message, you say *who* (`node_id`) and *which device* (an
`InstanceTag`). The tag is what lets one identity fan out to many devices.
Here's the `Recipient` as it appears on the wire:

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

One implementation note: internally the runtime still keys on the 16-byte
`instance_id` (the first half of the full 32-byte `device_id`) when it
deduplicates sessions and routes deliveries.

## Threat model

This section lays out which attacks veil stops, which it leaves to you, and
which it deliberately doesn't try to handle. For the everyday operational side
of staying safe, see [`docs/recovery.md`](recovery.md) and
[`docs/opsec-user-guide.md`](opsec-user-guide.md).

### What veil defends against

Each line below names an attack and the defense that turns it away:

- `node_id` hijacking via pre-image attack on BLAKE3 — infeasible (2^256).
- `device_id` spoofing — verifier rejects any cert where `device_id !=
  BLAKE3(pubkey)` (deterministic binding).
- Daily `identity_sk` leak (malware, stolen laptop) — compromised cert
  ages out within ≤ 7 days as the master stops re-issuing.
- Name squatting — rarity-proportional PoW (still in NameClaim layer).
- QR pairing phishing — an out-of-band confirmation code both sides compare.
- Document update flood from compromised key — per-identity DHT quota.
- Eclipse attack on identity resolution — multi-replica quorum.
- Forward secrecy for past async messages — X3DH one-time prekeys.

**Things veil deliberately doesn't try to do**:
- Cancel a compromised key in under 7 days. If you can't wait, use `identity
  standalone --force` (when the master leaks on a standalone) or `identity
  rotate` and let the natural 7-day window run out (multi-device).
- Defend against stale-revocation attacks. There's no revocation channel, so
  there's nothing that can go stale.

### What's on you (user OpSec)

These aren't bugs veil can fix — they're the parts that depend on how you
guard your secrets:

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

Both `master_algo: u8` and each key's `IdentityKey.algo: u8` record which
signature algorithm that key uses, so one identity can mix algorithms and
migrate over time. You can:

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
