# Multi-device guide

How veil handles multiple devices under the same identity —
whether the goal is load balancing a service fleet or syncing
messages across a user's phone, laptop, and desktop.

For the underlying protocol, see
[`identity-model.md`](identity-model.md).

---

## 1. The two modes: **LB** vs **Messenger**

Multi-device behaviour is controlled by the
[`InstanceTag`](../../crates/veil-proto/src/recipient.rs) a sender
picks when addressing your identity:

| Tag | Meaning | Use case |
|-----|---------|----------|
| `InstanceTag::Any` | "Any one active instance" | Load balancing across a service fleet |
| `InstanceTag::All` | "All active instances" | Multi-device messaging |
| `InstanceTag::Specific(id)` | "This exact instance" | Targeted delivery / session continuation |

One identity can host **both** modes: a consumer messenger uses
`All` for user-to-user chats, while a business integration on the
same identity uses `Any` for a fleet of mail-server instances.

---

## 2. Instance primer

An **instance** is one veil process on one device.  It has:

- A 16-byte random **`instance_id`**, persisted to
  `~/.config/veil/instance_id` on first start.  Stable for the
  device's lifetime — survives reboots, identity rotations,
  master-seed recoveries.
- Its own Ed25519 **`identity_sk`**, master-certified
  separately from every other instance's key.  Compromise of one
  device's `identity_sk` only requires revoking *that* subkey.
- Its own ML-KEM-768 **encryption keypair**, certified under the
  instance's own `identity_sk`.
- A position in the shared **`IdentityRegistry`**
  that every peer fetches before routing a message.

```
             identity_id (stable)
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
 identity_keys[0]  [1]             [2]
 bound:            bound:          bound:
  laptop           phone           server-farm
  instance_id_A    instance_id_B   instance_id_C
     ▲                 ▲               ▲
  sig_sk_A          sig_sk_B        sig_sk_C
  mlkem_A           mlkem_B         mlkem_C
```

The identity is just the tree above.  Adding a device grows a
leaf.  Revoking a device prunes one leaf without affecting
siblings.

---

## 3. Adding a device — the pairing ceremony

```
          Primary device                          New device
          (has master_seed)                       (fresh install)

          $ veil-cli identity pair-invite              │
            ↳ pair_secret generated                       │
            ↳ PairingInvite published                     │
            ↳ QR displayed: veil:pair?id=X&secret=Y    │
            ↳ OOB 6-digit code shown: "123-456"           │
                                                          │
                                                 scan QR ◄┤
                                                          │
                                                          │  connect directly to
                                                          │  source via `secret`
                                 ┌──────────────────────► │
                                 │                         │
                                 │                         │  target generates
                                 │                         │  fresh identity_sk
                                 │                         │  (master_seed NEVER
                                 │                         │   transferred)
                                 │                         │
          source unlocks master ◄┤                         │
          master_sk certifies                              │
          target's identity_sk:                            │
            IdentityKey {                                  │
              pubkey: target_pk,                           │
              bound_instance_id: target_id,                │
              master_sig: ...                              │
            }                                              │
          Appended to                                      │
          IdentityDocument.                                │
          Republished.          ─────────────────────────► │
                                                          │
          OOB check: source displays "Target: XXX-XXX?"    │
                     target displays same deterministic    │
                     code derived from session key         │
          User compares visually, confirms on source. ────►│
                                                          │
                                 target's InstanceEntry ◄──┤
                                 appended to               │
                                 InstanceRegistry.         │
                                                          │
                                 DeviceLinkedEvent pushed  │
                                 to existing instances.    │
```

**Key security properties**:

- `master_seed` never leaves the primary.  The new device
  generates its own `identity_sk`, which only master can
  certify — so even a compromised new device can't certify
  further devices.
- OOB confirmation code defeats "fake target scans a QR from
  a legitimate primary" — the real target has to display the
  real code.  An attacker intercepting the QR would produce a
  different session key and therefore a different code.
- `pair_secret` has a 5-minute TTL and is one-time-use.

**CLI flow** (the actual commands your user types):

On primary, to print an invite URI + QR (`--endpoint` is
required so the new device knows where to dial back):
```bash
veil-cli identity pair-invite --ttl-secs 300 --endpoint tcp://HOST:PORT
# QR rendered + OOB code displayed.
```

For the interactive accept-and-certify ceremony — binding a
listener, accepting the dial-back, running the OOB compare, and
master-certifying the new subkey — use `pair-listen` instead:
```bash
veil-cli identity pair-listen --endpoint tcp://HOST:PORT
# Binds the listener, prints the URI + QR, runs the source side.
```

On new device (scanning phone) — the scanned URI is a
**positional** argument (not `--qr`):
```bash
veil-cli identity pair-accept <veil:pair?…-url>
# Displays the OOB code — user visually compares with primary.
# If codes match, user taps "confirm" on primary.
```

The OOB visual compare is the default interactive path on both
sides; `--yes-i-compared-codes` exists to skip the prompt for
scripted tests only.

Inside 60–90 seconds the new device is fully live.

---

## 4. Removing a device

> ⚠️ **No `identity revoke` CLI command exists yet.** Revocation
> today is a protocol-level operation performed by editing and
> re-publishing the `IdentityDocument` from a device that holds the
> master seed — there is no dedicated subcommand under
> `veil-cli identity` (the variants are `create`, `show`,
> `rotate`, `restore`, `claim-name`, `qr`, `pair-invite`,
> `inspect-uri`, `pair-listen`, `pair-accept`, `export-qr-backup`,
> `import-qr-backup`, `standalone`, `delegate-device`, `migrate`,
> `dht-key`, `name-dht-key`).

### 4.1. The mechanism

To remove a device, the master holder adds that device's
`identity_sk` (the subkey in `IdentityDocument.identity_keys` it was
bound to) to the document's `revoked_keys` set, bumps
`document_version`, re-signs, and re-publishes the updated
`IdentityDocument`.  An identity carries at most `MAX_IDENTITY_KEYS
= 8` live subkeys, so the document stays small.  Once a peer fetches
the new document it rejects future frames signed by the revoked
subkey.  The stale `InstanceEntry` ages out of the registry on the
next republish.

### 4.2. Propagation

A re-published document reaches peers via DHT republish (worst case
≈ DHT TTL, hours) and via gossip / direct push as sessions
re-establish (seconds for currently-connected peers).  There is no
separate `scheduled` vs `compromise` flag today; the urgency
difference is purely operational — for a compromised device,
re-publish immediately and rely on gossip rather than waiting for
the next scheduled republish tick.

---

## 5. Message delivery semantics

### 5.1. Messenger mode (`InstanceTag::All`)

Sender encrypts **once per active instance** (fan-out): looks up
every `MlKemKeyCert` in the recipient's registry, produces one
`FanoutEnvelope` per cert.  Each envelope
carries the instance_id plus the ML-KEM ciphertext + AEAD
ciphertext; each envelope decrypts under exactly one device's
ML-KEM decapsulation seed.

```
Sender                              Recipient identity @alice
   │
   │  fanout_encrypt(plaintext, certs=[A,B,C])
   │     → [env_A, env_B, env_C]
   │
   │─────── DELIVERY_FORWARD ─────────►  Alice's laptop     (instance A)
   │                                     Alice's phone      (instance B)
   │                                     Alice's desktop    (instance C)
   │
   │  Each device:
   │    - picks the envelope whose instance_id == self
   │    - decapsulates ML-KEM under its own seed
   │    - decrypts plaintext
   │    - delivers to application layer
```

- **Mailbox** stores offline copies keyed by the recipient
  (`receiver_id`), decoupled from `InstanceEntry` — there are no
  per-instance ACK cursors and no `instance_stale_after` knob.
  Blobs live under a `(receiver, content_id)` primary key; GC is
  driven by an eviction index keyed
  `(deposited_at_be || receiver || content_id)` plus per-sender and
  global byte quotas.  Under quota pressure the oldest deposits are
  evicted (anonymous-pool blobs first, then the identified pool);
  delivered blobs are dropped on ACK.
- **X3DH one-time prekeys** kick in when the
  recipient is entirely offline.  Sender picks an unused prekey
  from the recipient's published pool, encapsulates to that
  prekey instead of the long-lived ML-KEM cert, and the prekey
  is consumed on first decrypt — forward-secrecy for async
  messages.

### 5.2. Load-balancing mode (`InstanceTag::Any`)

Veil picks *one* of the active instances based on the
published `InstanceEntry.last_seen_unix_ms` + local reputation
score.  Exactly one ciphertext is produced; exactly one instance
decapsulates it.

Typical use: an email gateway identity `@mailserver` with 3
regional instances.  Clients send to `mailserver:Any`; veil
routes to whichever region has the lowest latency from the
sender.

### 5.3. Targeted mode (`InstanceTag::Specific`)

Used when a session has already landed on a specific instance
and subsequent packets in the same conversation must stick to
that instance (session continuity).  Session dedup keys on
`(identity_id, instance_id)` so two instances of the
same identity can independently maintain sessions with one peer.

---

## 6. What `InstanceRegistry` publishes

A current `InstanceEntry` carries only `instance_id`,
`bound_identity_key_idx`, `label`, and `last_seen_unix_ms` — there
is no `mailbox_anchor`, no `transports`, and no `encrypted_contact`
field.  The earlier Tier-A / Tier-B split (and the
`[identity.multi_device.tier_b]` config block) **no longer exists**:
the Tier-B encryption layer was removed along with `mailbox_anchor`
and `encrypted_contact`.  Transport hints now travel out-of-band via
`SignedTransportAnnouncement` gossip rather than being embedded in
the registry, so a passive DHT observer scraping `InstanceRegistry`
sees no anchors or transport endpoints to correlate — only the
device count, opaque `instance_id`s, and operator-chosen labels.
See [`identity-model.md`](identity-model.md) for the wire format.

---

## 7. Reputation: identity-wide, not per-device

Reputation is keyed by `identity_id`.  Every
instance contributes to and benefits from the shared score.
This is by design: a fleet of mailserver instances under one
identity builds reputation together; an attacker compromising
one device's `identity_sk` cannot independently trash the
identity's reputation because the revocation pipeline removes
that key from the network before the damage accumulates.

---

## 8. Sync story for app state (deferred)

> 🚧 **Status:** design only — the `AppState` primitive is not
> implemented as a concrete type yet.  The mechanism described
> below is the target shape; today applications wanting cross-
> device sync use ad-hoc DHT slots under their own app-key schema.

Contacts, block-list, preferences, profile — anything the app
wants synced across the user's devices — will ride on an
`AppState` primitive: one DHT slot per `(identity_id, app_id, key)`
tuple, encrypted under the identity's shared `app_state_secret`,
signed by any active `identity_sk`.

Every linked device can read and write.  Version-monotonic —
out-of-order updates are discarded.  Cap: 4 KB per blob; partition
your app state across multiple keys if you need more.

---

## 9. FAQ

**Q:** Can two instances of my identity run at the same time on
the same IP?

**A:** Yes.  They have distinct `instance_id`s, so session dedup
keeps their connections separate.  Peers just see two active
instances behind the same identity.

**Q:** Can I share `identity_sk` between two devices so I don't
have to pair them?

**A:** No.  Each instance has its own `identity_sk` by design.
Pairing exists precisely so that no key is shared.  This keeps
compromise blast radius at exactly one device.

**Q:** How many devices can I link?

**A:** 16 per `IdentityRegistry` cap.  For larger fleets, shard
across multiple identities.

**Q:** What happens if I revoke my laptop but my phone is offline
for a week?

**A:** The phone will still accept messages addressed to itself
specifically.  When it reconnects, it fetches the latest
`IdentityDocument`, notices its sibling was revoked, and shows
the operator a DeviceLinkedEvent-style alert.
Your name, reputation, and its own identity_sk are untouched.

**Q:** What if my phone is compromised while my laptop is
offline?

**A:** Revoke the phone's subkey from the laptop when it comes
back online.  Until the revocation reaches a given peer (via
DHT republish or direct push when sessions re-establish), that
peer may still accept frames from the phone's key.  Expected
worst-case propagation: DHT TTL (hours).  With gossip,
nearby peers pick it up in seconds.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol spec.
- [`recovery.md`](recovery.md) — recovery from device loss or
  key compromise.
- [`messenger-dev.md`](messenger-dev.md) — building a messenger
  that uses these primitives.
