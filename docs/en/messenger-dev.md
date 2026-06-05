# Messenger dev guide

How to build a Signal-style messenger (or any app that needs
sovereign identity + async delivery) on top of veil.

This doc points at the APIs; see the linked source files for
signatures and the companion docs for user-facing behaviour.

- [`identity-model.md`](identity-model.md) — protocol spec.
- [`multi-device.md`](multi-device.md) — the LB/messenger mode
  split.
- [`recovery.md`](recovery.md) — user-visible recovery flows.
- [`opsec-user-guide.md`](opsec-user-guide.md) — hand to your
  users.

---

## 1. What veil gives you, what veil does not

**Gives you**:

- Sovereign identity (`identity_id` stable across rotations).
- `@name` → `identity_id` resolution (eclipse-resistant quorum).
- Forward-secret synchronous E2E (X3DH prekeys + ML-KEM fan-out).
- Multi-device message delivery to **online** instances + own-instance
  state-blob fan-out (see [`integration_tests::scenario_app_state_sync_*`](../../crates/veil-identity/src/integration_tests.rs)).
- Safety-number fingerprints for out-of-band verification.
- Backup → restore via BIP-39 paper phrase (see
  [`integration_tests::scenario_chat_backup_restore_roundtrip`](../../crates/veil-identity/src/integration_tests.rs)).

**Does NOT give you**:

- **Async / offline delivery** — veil has no in-network mailbox
  subsystem.  If your messenger needs durable async, build it as a
  separate crate (`veil-mailbox`, not yet implemented; or use
  `DHT.store` with TTL, multi-node self-sync, or external relay).
- **Revocation + compromise recovery** — veil has no in-band
  revocation gossip, no `RevocationCache`, no `master_freshness_sig`.
  Recovery flow today: short-lived `IdentityKey.valid_until` (≤7 d) +
  re-issue from master.  Long-term revocation crate is open backlog.
- Message content schemas — pick your own (protobuf, JSON, whatever).
- Group chat — MLS (RFC 9420) is recommended; any library that speaks
  MLS slots in at the application layer.
- Presence / typing indicators / read receipts — build on top using
  app_state fan-out + direct sessions.
- Voice/video — veil's real-time stream channel carries the media;
  layer your SDP exchange on top.
- Push-notification delivery to mobile OSes — veil emits a
  `WakeHint`; your mobile app handles the APN/FCM round-trip.

---

## 2. The minimum viable messenger in veil primitives

```
                                   ┌──────────────────────────┐
   1. "alice" types "hi bob"       │ app text input           │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   2. Resolve @bob                 │ NameResolver::resolve    │
                                   │   ↳ quorum DHT fetch     │
                                   │   ↳ verify cert chain    │
                                   │   → ValidatedIdentity    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   3. Get Bob's MlKem certs        │ fetch InstanceRegistry   │
                                   │ fetch each MlKemKeyCert  │
                                   │ verify_mlkem_cert × N    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   4. Try X3DH prekey first        │ fetch PrekeyBundle for   │
      (forward secrecy)            │ each recipient instance  │
                                   │ pick_for_send            │
                                   │ x3dh::sender_encapsulate │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   5. ML-KEM fan-out encrypt       │ fanout_encrypt(payload,  │
                                   │   verified_certs,        │
                                   │   sender_id, bob_id)     │
                                   │ → Vec<FanoutEnvelope>    │
                                   └───────────┬──────────────┘
                                               │
                                   ┌───────────▼──────────────┐
   6. Wrap as DELIVERY_FORWARD     │ Recipient::All(bob_id)   │
                                   │ → veil dispatcher     │
                                   └───────────┬──────────────┘
                                               │
          ════════════════════════════════════╪═══════════════
                                               ▼     (wire)

                                   ┌──────────────────────────┐
   7. Online-only delivery         │ dispatcher.deliver():    │
                                   │  for each bob.instance{  │
                                   │   if online → push;      │
                                   │   else → SendFailed.     │
                                   │  }                       │
                                   └───────────┬──────────────┘
                                               │
                          ┌────────────────────┴──────────────┐
                          │                                   │
                  ┌───────▼─────┐                      ┌──────▼──────┐
                  │ bob phone   │ (online)             │ bob laptop  │ (offline)
                  │ receives    │                      │ — sender    │
                  │ envelope[1] │                      │ gets        │
                  └───────┬─────┘                      │ SendFailed  │
                          │                            │ for inst[2] │
                          │                            └─────────────┘
                  ┌───────▼─────────────────────────────────┐
                  │ phone picks its FanoutEnvelope           │
                  │ recipient_decapsulate via local ML-KEM   │
                  │ AEAD-decrypt payload                     │
                  │ forward to app ("incoming from @alice")  │
                  └──────────────────────────────────────────┘
```

All of the veil-side steps are already implemented (see
[`integration_tests::scenario_multi_device_fanout_messenger`](../../crates/veil-identity/src/integration_tests.rs)).
Your app sits at the top and bottom of this diagram.

> **Async / offline delivery is out-of-scope for the network layer.**
> Veil has no in-network mailbox.  If your messenger needs to
> store-and-forward to offline recipients, build it on top: either a
> dedicated `veil-mailbox` crate (TBD), or use existing primitives
> (`DHT.store` with TTL on a known shard, or pick an online relay-peer
> per-recipient and replicate).

---

## 3. Library cheat-sheet

Quick pointer table to current primitives.  Crate layout: identity
primitives live in [`veil-identity`](../../crates/veil-identity/),
crypto in [`veil-crypto`](../../crates/veil-crypto/), wire types in
[`veil-proto`](../../crates/veil-proto/).

| Concern | Module | Key entry points |
|---------|--------|------------------|
| Address resolution (`@bob` → identity) | [`veil-identity/resolver.rs`] | `NameResolver::resolve`, `VerifyConfig::resolver_quorum` |
| Identity document verification | [`veil-identity/verify.rs`] | `verify_identity_document` |
| Master-seed paper backup (BIP-39) | [`veil-identity/master_seed.rs`] | `encode_master_seed_to_phrase`, `decode_master_seed_from_phrase` |
| Master-seed encrypted file (Argon2id + ChaCha20) | [`veil-identity/master_file.rs`] | `save_master_seed_encrypted_with`, `load_master_seed_encrypted` |
| Per-device instance state | [`veil-identity/instance.rs`] | `LocalInstance::load_or_init` |
| ML-KEM cert + fan-out (multi-device) | [`veil-identity/mlkem_fanout.rs`] | `verify_mlkem_cert`, `fanout_encrypt`, `fanout_decrypt_one` |
| X3DH prekeys (forward secrecy) | [`veil-crypto/x3dh.rs`] | `generate_prekey`, `sender_encapsulate`, `recipient_decapsulate` |
| Safety-number fingerprint | [`veil-crypto/identity_fingerprint.rs`] | `identity_fingerprint` |
| Freshness lifecycle (when to re-publish doc) | [`veil-identity/freshness.rs`] | `severity`, `needs_refresh` |
| Identity wire types | [`veil-proto/identity_document.rs`] | `IdentityDocument`, `IdentityKey` |
| ML-KEM cert wire | [`veil-proto/mlkem_cert.rs`] | `MlKemKeyCert`, `MLKEM_CERT_SIG_CONTEXT` |
| Prekey bundle wire | [`veil-proto/prekey_bundle.rs`] | `PrekeyBundle`, `ALGO_ML_KEM_768` |
| Addressing types | [`veil-proto/recipient.rs`] | `Recipient`, `InstanceTag` |
| Wake-up hint (mobile push) | [`veil-proto/wake_hint.rs`] | `WakeHint` |

[`veil-identity/resolver.rs`]: ../crates/veil-identity/src/resolver.rs
[`veil-identity/verify.rs`]: ../crates/veil-identity/src/verify.rs
[`veil-identity/master_seed.rs`]: ../crates/veil-identity/src/master_seed.rs
[`veil-identity/master_file.rs`]: ../crates/veil-identity/src/master_file.rs
[`veil-identity/instance.rs`]: ../crates/veil-identity/src/instance.rs
[`veil-identity/mlkem_fanout.rs`]: ../crates/veil-identity/src/mlkem_fanout.rs
[`veil-identity/freshness.rs`]: ../crates/veil-identity/src/freshness.rs
[`veil-crypto/x3dh.rs`]: ../crates/veil-crypto/src/x3dh.rs
[`veil-crypto/identity_fingerprint.rs`]: ../crates/veil-crypto/src/identity_fingerprint.rs
[`veil-proto/identity_document.rs`]: ../crates/veil-proto/src/identity_document.rs
[`veil-proto/mlkem_cert.rs`]: ../crates/veil-proto/src/mlkem_cert.rs
[`veil-proto/prekey_bundle.rs`]: ../crates/veil-proto/src/prekey_bundle.rs
[`veil-proto/recipient.rs`]: ../crates/veil-proto/src/recipient.rs
[`veil-proto/wake_hint.rs`]: ../crates/veil-proto/src/wake_hint.rs

> **Removed by architectural decision**:
> `revocation_cache.rs`, `propagate.rs` (revocation gossip),
> `watcher.rs` (anomaly), `tier_b.rs`, `mailbox/*` — none of these
> exist in the current network layer.  Async-delivery and revocation
> crates may return as **separate** crates layered on top of the
> network layer (not yet implemented).  Sections 4-7 below may still
> reference these APIs; reading the cheat-sheet above is authoritative.

---

## 4. Building the happy path

### 4.1. App-layer message format

Your messages are opaque to veil — any serialisation works.
A good starting point:

```rust
struct AppMessage {
    msg_id: [u8; 16],          // random
    ts_unix_millis: u64,
    sender_name: String,       // "@alice" for display only
    kind: AppMessageKind,
    body: Vec<u8>,             // protobuf / JSON / whatever
}

enum AppMessageKind {
    Text,
    Typing,
    Delivered { ref_msg_id: [u8; 16] },
    Read { ref_msg_id: [u8; 16] },
}
```

Serialise to bytes — those are what `fanout_encrypt` sees.

### 4.2. Resolve a recipient

```rust
use veilcore::node::identity::resolver::{NameResolver, VerifyConfig};
use veilcore::node::identity::revocation_cache::RevocationCache;

let cfg = VerifyConfig {
    resolver_quorum: 2,            // require 2 matching replicas
    resolver_max_replicas: 5,
    ..Default::default()
};
let resolver = NameResolver::with_config(my_backend.clone(), cfg);
let cache = RevocationCache::open(config_dir.join("revocations.bin"))?;

let validated = resolver.resolve("alice", &cache, now_unix_secs()).await?;
let recipient_identity_id = validated.id;
```

The resolver has cached `alice → identity_id` for up to 5 minutes
after first success, so repeated sends are cheap.

### 4.3. Fetch the recipient's instances + ML-KEM certs

```rust
use veilcore::node::identity::mlkem_fanout::{
    verify_mlkem_cert, fanout_encrypt,
};
use veilcore::proto::mlkem_cert::MlKemKeyCert;
use veilcore::proto::instance_registry::InstanceRegistry;

let registry_bytes = backend
    .fetch(InstanceRegistry::dht_key(&recipient_identity_id))
    .await?
    .ok_or("no registry for recipient")?;
let registry = InstanceRegistry::decode(&registry_bytes)?;

// (Verify registry signature + identity binding — see identity-model.md §8.)

let mut certs = Vec::new();
for entry in &registry.instances {
    let bytes = backend
        .fetch(MlKemKeyCert::dht_key_for(&recipient_identity_id, &entry.instance_id))
        .await?
        .ok_or("missing cert")?;
    let cert = MlKemKeyCert::decode(&bytes)?;
    certs.push(verify_mlkem_cert(&cert, &recipient_doc, now_unix_secs())?);
}
```

### 4.4. Encrypt + send

```rust
let envelopes = fanout_encrypt(
    &serialised_message,
    &certs,
    &my_identity_id,
    &recipient_identity_id,
)?;

for env in envelopes {
    dispatcher.enqueue_forward(Recipient::specific(recipient_identity_id, env.recipient_instance_id), env)?;
}
```

That's the outbound path.

### 4.5. Receive + decrypt

On the recipient side, every time mailbox hands you an incoming
`FanoutEnvelope`:

```rust
use veilcore::node::identity::mlkem_fanout::fanout_decrypt_one;

let plaintext = fanout_decrypt_one(
    &[envelope],
    &my_instance_id,
    &my_identity_id,
    &sender_identity_id,
    &my_mlkem_dk_seed,
    my_current_cert_version,
)?;

let msg: AppMessage = deserialise(&plaintext)?;
app_display_inbound(msg);
```

### 4.6. For truly async delivery: X3DH prekeys first, fallback to ML-KEM cert

Forward secrecy matters when the recipient is offline.  The
message sits in the DHT/mailbox long enough that a later
compromise of the long-lived ML-KEM key could decrypt it.
X3DH prekeys solve this: a one-time key that's consumed and
deleted.

```rust
use veilcore::proto::prekey_bundle::PrekeyBundle;
use veilcore::crypto::x3dh::sender_encapsulate;

let bundle_bytes = backend
    .fetch(PrekeyBundle::dht_key(&recipient_identity_id, &recipient_instance_id))
    .await?;
let bundle = PrekeyBundle::decode(&bundle_bytes?)?;
// (Verify bundle.sig under recipient's identity_sk.)

match bundle.pick_for_send(&my_consumed_prekey_ids, now_unix_secs()) {
    PickedPrekey::OneTime(p) => {
        let enc = sender_encapsulate(
            bundle.algo, &p.encapsulation_key,
            &my_identity_id, &recipient_identity_id, &recipient_instance_id,
            p.prekey_id,
        )?;
        // Mark this prekey consumed locally to avoid reuse.
        my_consumed_prekey_ids.insert(p.prekey_id);
        send(enc, p.prekey_id, /* one_time = */ true);
    }
    PickedPrekey::Fallback(fb) => {
        // Pool exhausted — reduced-FS fallback, but still protected.
        let enc = sender_encapsulate(/* ... */)?;
        send(enc, fb.prekey_id, /* one_time = */ false);
    }
    PickedPrekey::None => {
        // All prekeys expired; fall back to the instance's
        // published MlKemKeyCert (long-lived).  Forward secrecy
        // reduced, but message goes through.
    }
}
```

### 4.7. Sync the contact list across devices

```rust
use veilcore::proto::app_state::{encrypt_app_state, decrypt_app_state, AppState};

// Write:
let mut state = encrypt_app_state(
    my_identity_id,
    "messenger".into(),
    b"contacts".to_vec(),
    &serialised_contacts,
    &my_app_state_secret,
    current_version + 1,
    now_unix_secs(),
    my_signing_key_idx,
)?;
state.sig = sign(state.canonical_signing_bytes())?;
backend.put(AppState::dht_key(&my_identity_id, "messenger", b"contacts"), state.encode()).await?;

// Read (on any of your devices):
let bytes = backend.fetch(AppState::dht_key(&my_identity_id, "messenger", b"contacts")).await?;
let state = AppState::decode(&bytes?)?;
// (Verify state.sig under any active identity_sk of my identity.)
let contacts = decrypt_app_state(&state, &my_app_state_secret)?;
```

### 4.8. Surface safety-number changes

Keep the last-observed safety number per contact.  When you
resolve a contact and the resulting `(my_id, their_id)`
fingerprint differs from what you stored, show an alert:

```
Alice's safety number changed.
Current:  12345 67890 13579 24680 11223 33445
                55667 78899 00112 23344 55667 78899
Contact Alice out-of-band to verify before sending anything
sensitive.
```

The `identity_fingerprint` function gives you the canonical
form (60 digits, 12 groups of 5):

```rust
use veilcore::crypto::identity_fingerprint::identity_fingerprint;
let number = identity_fingerprint(&my_id, &their_id);
```

### 4.9. Device-linking UX

Listen for `DeviceLinkedEvent` frames in your
incoming message stream.  Show the user:

```
A new device linked to your identity:
  Name: Pixel 8a
  Linked by: MacBook Pro 2025
  At: 2026-04-20 15:32 UTC

Did you initiate this?  [ I did ]  [ I did NOT — help! ]
```

If they tap "did NOT", immediately:

1. Revoke the new `identity_key` from the master device.
2. Run the anomaly watcher.
3. Consider full rotation (compromise scenario).

---

## 5. Group chat — MLS

Veil explicitly does NOT implement group-chat crypto.  The
right primitive is MLS (RFC 9420).  Typical integration:

- Each member runs an MLS group library (`openmls` is
  production-quality in Rust).
- MLS welcome messages, commits, and application messages are
  carried inside veil's `DELIVERY_FORWARD` as opaque bytes.
- Veil handles transport + identity; MLS handles group state.

The hand-off is clean: MLS sessions use veil's
`identity_id` as each member's long-term identity key; veil's
safety-number fingerprint verifies identity once out-of-band,
and MLS takes it from there for group crypto.

---

## 6. Building the user's first run

The UX everyone gets wrong:

```
Welcome to [your messenger].

To get started, choose your identity name:  [__________]

[ ] I already have an identity (restore from backup)
```

What the user actually needs, in order:

1. **Pick a name** (your UI should resolve in real time to
   show if it's taken).
2. **See the BIP-39 phrase + confirmation**.  Let the user
   physically write it down.  Show them veil's phrase-display
   mode (dimmed-screen, no scrollback), and make them retype 3
   random positions before proceeding.
3. **Optionally set a master-file password** for the local
   encrypted backup.  Skip by default — paper is the actual
   durable backup.
4. **Render the QR code for contact sharing**.  Encourage them
   to screenshot it or save to cloud — it contains no secrets,
   only the public `identity_id` + preferred name.
5. **Prompt to add contacts** or **link another device**.

Pair-invite + pair-accept round-trip, with OOB code matching,
should be under 90 seconds on a typical consumer setup.

---

## 7. Testing strategy for app integrations

`veilcore` exposes its backends as traits — use in-memory
fakes in your integration tests:

- `NameLookup` + `IdentityLookup` (see `resolver.rs` tests).
- Construct your own `MemBackend` and wire it up just like
  veil's existing tests do.
- Generate test identities with `master_seed = [0x42u8; 32]`
  so tests are deterministic.

Reference patterns live in every `tests` module in
`veilcore` — they are intentionally verbose so they double
as documentation.

---

## 8. Checklist before you ship your v1

☐ BIP-39 phrase displayed at create time, user retype
confirmation, screen dimmed.

☐ Encrypted-master-file support if you're not paper-only.

☐ Contacts synced via `AppState` (not an ad-hoc DHT record).

☐ Fan-out encryption for multi-device recipients.

☐ X3DH prekey pool maintained — refill when it drops below
`MIN_PREKEY_POOL_REMAINING = 3`.

☐ Revocation cache persistent at `~/.config/veil/revocations.bin`.

☐ Quorum resolver enabled (`resolver_quorum = 2`).

☐ Safety-number display in contact profiles.

☐ DeviceLinkedEvent alerts.

☐ Anomaly watcher run at every start (shows warnings if
present).

☐ Mailbox cursors tracked per instance (shared mailbox, not
per-device state).

☐ Freshness refresh scheduled (`veil-cli identity
refresh-freshness` or equivalent automation) ≥ every 25 days.

☐ User-facing docs linking to
[`opsec-user-guide.md`](opsec-user-guide.md) and
[`recovery.md`](recovery.md).

---

## 9. Where to ask questions

- Protocol details: [`identity-model.md`](identity-model.md)
  §10 (threat model) and §11 (algorithm agility).
- Integration bugs: veil's issue tracker, label
  `integration-help`.
- Crypto review: veil RFCs in `docs/rfcs/`.
