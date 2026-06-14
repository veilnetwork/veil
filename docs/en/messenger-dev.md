# Messenger dev guide

How to build a Signal-style messenger on top of veil. The same
recipe works for any app that needs a sovereign identity (an
account that belongs to the user, not to a server) plus async
delivery (messages that reach a recipient who is currently offline).

This doc points you at the APIs. For exact signatures, read the
linked source files. For user-facing behaviour, read the companion
docs.

- [`identity-model.md`](identity-model.md) — the protocol spec.
- [`multi-device.md`](multi-device.md) — the split between the two
  operating modes (load-balancer and messenger).
- [`recovery.md`](recovery.md) — recovery flows as the user sees
  them.
- [`opsec-user-guide.md`](opsec-user-guide.md) — hand this one to
  your users.

---

## 1. What veil gives you, what veil does not

**Gives you**:

- Sovereign identity. The `identity_id` stays stable even when the
  underlying keys rotate.
- Name resolution: `@name` → `identity_id`. It uses a quorum (several
  independent replicas must agree) so a single malicious node can't
  feed you a fake answer.
- Forward-secret end-to-end encryption for messages sent while the
  recipient is online. Built from X3DH prekeys and ML-KEM fan-out
  (both defined in section 2). Forward secrecy means that stealing
  today's keys can't decrypt yesterday's messages.
- Message delivery to a recipient's **online** instances across all
  their devices, plus state-blob fan-out between your *own* instances
  (see [`integration_tests::scenario_app_state_sync_*`](../../crates/veil-identity/src/integration_tests.rs)).
  An *instance* is one device's running copy of the identity.
- Safety-number fingerprints: short numeric codes two people can read
  to each other out of band (over a phone call, in person) to confirm
  nobody is impersonating either side.
- Backup and restore through a BIP-39 paper phrase — the kind of
  word list you write on paper (see
  [`integration_tests::scenario_chat_backup_restore_roundtrip`](../../crates/veil-identity/src/integration_tests.rs)).

**Does NOT give you**:

- **Async / offline delivery is opt-in, not on by default.** Veil ships a
  mailbox (`veil-mailbox`) for durable async delivery — encrypted blobs that
  wait for an offline recipient and survive a restart — but the daemon's
  `[mailbox] enabled` defaults to off. When you enable it, deposits are bounded
  by per-sender / global quotas and a rate limit; set
  `mailbox.require_capability_token = true` in production so only token-holding
  senders can deposit (the default is permissive for backward compatibility).
  If you'd rather not run the mailbox, the older primitives still work —
  `DHT.store` with a TTL (a record the network drops after a time-to-live),
  self-sync across your own nodes, or an external relay.
- **Revocation and compromise recovery.** Veil has no in-band way to
  gossip "this key is revoked" — no `RevocationCache`, no
  `master_freshness_sig`. Today's recovery flow is simpler: each
  `IdentityKey` is short-lived (`valid_until` ≤ 7 days), and you
  re-issue a fresh one from the master key. A proper long-term
  revocation crate is still on the backlog.
- Message content schemas. Pick your own — protobuf, JSON, whatever
  fits.
- Group chat. Use MLS (RFC 9420). Any library that speaks MLS slots
  in at the application layer.
- Presence, typing indicators, read receipts. Build these on top,
  using app_state fan-out plus direct sessions.
- Voice and video. Veil's real-time stream channel carries the media;
  you layer your own SDP exchange (the WebRTC call-setup handshake) on
  top.
- Push delivery to mobile operating systems. Veil emits a `WakeHint`;
  your mobile app handles the round-trip to Apple's or Google's push
  service (APN / FCM).

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
                                   │ → veil dispatcher        │
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
                  ┌───────▼──────────────────────────────────┐
                  │ phone picks its FanoutEnvelope           │
                  │ recipient_decapsulate via local ML-KEM   │
                  │ AEAD-decrypt payload                     │
                  │ forward to app ("incoming from @alice")  │
                  └──────────────────────────────────────────┘
```

Every veil-side step here is already implemented (see
[`integration_tests::scenario_multi_device_fanout_messenger`](../../crates/veil-identity/src/integration_tests.rs)).
Your app supplies the top and bottom of this diagram; veil does the
middle.

> **Async / offline delivery ships today via `veil-mailbox`.** When the
> recipient is offline, the sender's node deposits the encrypted blob into
> a store-and-forward mailbox at one of the recipient's replica relays; the
> recipient fetches and acknowledges the pending blobs when it next comes
> online (or wakes via a push notification), and the relay then deletes
> them. The store is a durable redb KV (it survives a relay restart) with
> per-receiver and per-relay quotas, a per-blob TTL, and a deposit rate
> limit. It is **opt-in**: the daemon's `[mailbox] enabled` defaults to off,
> so enable it (and set `mailbox.require_capability_token = true` in
> production) if your messenger needs offline delivery. If you'd rather not
> run the mailbox, the older primitives still work — `DHT.store` with a TTL
> on a known shard (a fixed slice of the address space), or pick one online
> relay peer per recipient and replicate to it.

---

## 3. Library cheat-sheet

A quick pointer table to the current primitives. The crates split up
like this: identity primitives live in
[`veil-identity`](../../crates/veil-identity/), crypto in
[`veil-crypto`](../../crates/veil-crypto/), and wire types — the
structs that actually go over the network — in
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

> **Removed by an architectural decision**:
> `revocation_cache.rs`, `propagate.rs` (revocation gossip),
> `watcher.rs` (anomaly detection), and `tier_b.rs`. None of these
> exist anymore — there is no in-band revocation and no anomaly
> watcher. Identity freshness is just the short `valid_until_unix`
> window (see `freshness.rs`); a compromised subkey ages out rather
> than being revoked. Async/offline delivery, by contrast, **does**
> ship — as the separate, opt-in `veil-mailbox` crate (see §1 and §2),
> not as part of the core network layer.

---

## 4. Building the happy path

### 4.1. App-layer message format

Veil never looks inside your messages, so any serialisation works.
Here is a reasonable starting point:

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

Serialise it to bytes. Those bytes are exactly what `fanout_encrypt`
sees.

### 4.2. Resolve a recipient

Resolving means turning a human-readable `@name` into the
`identity_id` you actually send to.

```rust
use veilcore::node::identity::resolver::{NameResolver, VerifyConfig};

let cfg = VerifyConfig {
    resolver_quorum: 2,            // require 2 matching replicas
    resolver_max_replicas: 5,
    ..Default::default()
};
let resolver = NameResolver::with_config(my_backend.clone(), cfg);

let validated = resolver.resolve("alice", now_unix_secs()).await?;
let recipient_identity_id = validated.id;
```

There is no revocation cache to consult: identity freshness is the
short `valid_until_unix` window carried in the signed document, which
the resolver checks against `now_unix_secs()`. A subkey that should no
longer be trusted simply ages out of its window rather than being
revoked. After the first successful lookup, the resolver caches
`alice → identity_id` for up to 5 minutes. Repeated sends in that
window are cheap — no second quorum fetch.

### 4.3. Fetch the recipient's instances and ML-KEM certs

You now know *who* Bob is. Next you need *where* to send: one ML-KEM
certificate per device he has online. The registry lists his devices;
each device publishes its own certificate.

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

That's the whole outbound path.

### 4.5. Receive + decrypt

On the recipient side, run this every time your mailbox hands you an
incoming `FanoutEnvelope` (one sealed copy of the message, addressed
to a single device):

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

### 4.6. For truly async delivery: X3DH prekeys first, ML-KEM cert as a fallback

Forward secrecy matters most when the recipient is offline. The
message then sits in the DHT or mailbox for a while. If someone later
steals the long-lived ML-KEM key, they could decrypt that waiting
message. X3DH prekeys close the gap. A *prekey* is a one-time key the
recipient publishes in advance; the sender uses it once, and then it
is consumed and deleted, so it can't decrypt anything a second time.

The picking logic has three outcomes, in order of preference: a fresh
one-time prekey, a reusable fallback prekey when the pool is empty,
or — if even those are gone — the device's long-lived certificate.

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

Store the contact list as an `AppState` record: one encrypted blob,
signed by your identity, that every one of your own devices can read
and overwrite. Bump the version on each write so devices can tell
which copy is newest.

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

Store the last safety number you saw for each contact. Each time you
resolve that contact, recompute the `(my_id, their_id)` fingerprint.
If it differs from what you stored, the contact's keys changed —
which is normal after a reinstall, but also what an impersonation
attack looks like. Either way, warn the user:

```
Alice's safety number changed.
Current:  12345 67890 13579 24680 11223 33445
                55667 78899 00112 23344 55667 78899
Contact Alice out-of-band to verify before sending anything
sensitive.
```

The `identity_fingerprint` function returns this number in its
canonical form — 60 digits, shown as 12 groups of 5:

```rust
use veilcore::crypto::identity_fingerprint::identity_fingerprint;
let number = identity_fingerprint(&my_id, &their_id);
```

### 4.9. Device-linking UX

Watch your incoming message stream for `DeviceLinkedEvent` frames.
One arrives whenever a new device is linked to the identity. Show the
user what happened:

```
A new device linked to your identity:
  Name: Pixel 8a
  Linked by: MacBook Pro 2025
  At: 2026-04-20 15:32 UTC

Did you initiate this?  [ I did ]  [ I did NOT — help! ]
```

If they tap "did NOT", treat it as a possible compromise and act at
once:

1. Rotate this device's signing subkey from the master device
   (`veil-cli identity rotate`) and re-publish the identity document so
   the unwanted subkey ages out of its `valid_until_unix` window. There
   is no in-band revocation; the short window is what limits the damage.
2. Audit your linked devices and unlink any you don't recognise.
3. If the master seed itself may be exposed, assume the worst: create a
   fresh identity from a new seed and migrate contacts to it.

---

## 5. Group chat — MLS

Veil deliberately does NOT implement group-chat crypto. The right
tool for that is MLS — Messaging Layer Security, RFC 9420. A typical
integration looks like this:

- Each member runs an MLS group library (`openmls` is a
  production-quality one in Rust).
- MLS messages of every kind — welcomes, commits, and application
  messages — ride inside veil's `DELIVERY_FORWARD` as opaque bytes.
  Veil never parses them.
- Veil handles transport and identity; MLS handles the shared group
  state.

The hand-off is clean. Each MLS session uses veil's `identity_id` as
that member's long-term identity key. You verify identity once, out
of band, with veil's safety-number fingerprint — and from there MLS
takes over the group crypto.

---

## 6. Building the user's first run

Here is the first-run screen that almost everyone gets wrong:

```
Welcome to [your messenger].

To get started, choose your identity name:  [__________]

[ ] I already have an identity (restore from backup)
```

What the user actually needs, in order:

1. **Pick a name.** Resolve it in real time as they type, so they can
   see whether it's already taken.
2. **See the BIP-39 phrase, then confirm it.** Let the user write it
   down on paper. Show it in veil's phrase-display mode — dimmed
   screen, no scrollback — and make them retype 3 random positions
   before they move on.
3. **Optionally set a master-file password** for the local encrypted
   backup. Skip it by default. Paper is the backup that actually
   lasts; the encrypted file is a convenience.
4. **Render a QR code for sharing the contact.** Encourage a
   screenshot or a save to the cloud — it holds no secrets, only the
   public `identity_id` and preferred name.
5. **Prompt them to add contacts** or **link another device**.

The full pair-invite plus pair-accept round-trip, including the
out-of-band code check, should take under 90 seconds on a typical
consumer setup.

---

## 7. Testing strategy for app integrations

`veilcore` exposes its backends as traits, so your integration tests
can swap in in-memory fakes instead of touching the real network:

- Fake out `NameLookup` and `IdentityLookup` (see the `resolver.rs`
  tests for how).
- Build your own `MemBackend` and wire it up exactly the way veil's
  own tests do.
- Generate test identities from a fixed seed,
  `master_seed = [0x42u8; 32]`, so every run is deterministic.

You'll find reference patterns in every `tests` module across
`veilcore`. They are verbose on purpose, so they double as worked
examples.

---

## 8. Checklist before you ship your v1

☐ BIP-39 phrase shown at create time, on a dimmed screen, with a
retype confirmation.

☐ Encrypted-master-file support, unless you are paper-only.

☐ Contacts synced through `AppState`, not an ad-hoc DHT record.

☐ Fan-out encryption for multi-device recipients.

☐ X3DH prekey pool kept topped up — refill it whenever it drops below
`MIN_PREKEY_POOL_REMAINING = 3`.

☐ Quorum resolver turned on (`resolver_quorum = 2`).

☐ Safety number shown in each contact's profile.

☐ DeviceLinkedEvent alerts wired up.

☐ Mailbox cursors tracked per instance — the mailbox is shared, so
this is not per-device state.

☐ Identity document re-published before `valid_until_unix` expiry —
schedule it inside the freshness window (`freshness::needs_refresh`;
spec default re-publishes 5 days before a 30-day window lapses), via
your own automation. Use `veil-cli identity rotate` for routine subkey
hygiene; there is no revocation, so the short window is the freshness
mechanism.

☐ User-facing docs that link to
[`opsec-user-guide.md`](opsec-user-guide.md) and
[`recovery.md`](recovery.md).

---

## 9. Where to ask questions

- Protocol details: [`identity-model.md`](identity-model.md), §10
  (threat model) and §11 (algorithm agility).
- Integration bugs: veil's issue tracker, under the `integration-help`
  label.
- Crypto review: the veil RFCs in `docs/rfcs/`.
