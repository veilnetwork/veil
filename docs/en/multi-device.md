# Multi-device guide

This page is about running one **identity** — your cryptographic
"passport" on the network — across several devices at once. Maybe
you want to spread load across a fleet of servers. Maybe you just
want the same messages to show up on your phone, laptop, and
desktop. Both work the same way, and this page walks through it.

For the protocol underneath, see
[`identity-model.md`](identity-model.md).

---

## 1. The two modes: load-balancing vs messenger

There are two ways messages can fan out across your devices. Which
one happens is decided by the sender, not by you. When someone
addresses your identity, they attach an
[`InstanceTag`](../../crates/veil-proto/src/recipient.rs) — a small
flag that says which of your devices should receive the message:

| Tag | Meaning | Use case |
|-----|---------|----------|
| `InstanceTag::Any` | "Any one active instance" | Load balancing across a service fleet |
| `InstanceTag::All` | "All active instances" | Multi-device messaging |
| `InstanceTag::Specific(id)` | "This exact instance" | Targeted delivery / session continuation |

One identity can use **both** modes at once. A consumer messenger
picks `All` for person-to-person chats, so every device gets the
message. A business integration on the same identity picks `Any`
for a fleet of mail-server instances, so just one of them answers.

---

## 2. What an instance is

An **instance** is one veil process running on one device. Each
instance carries four things of its own:

- A random 16-byte name, the **`instance_id`**. It's written to
  `~/.config/veil/instance_id` the first time you start, then
  stays put for the life of the device. Reboots, identity
  rotations, and master-seed recoveries all leave it untouched.
- Its own Ed25519 signing key, the **`identity_sk`**. Each one is
  certified by the master key on its own. So if one device's
  `identity_sk` is stolen, you only revoke *that* subkey — the
  rest keep working.
- Its own ML-KEM-768 **encryption keypair**, certified under that
  same `identity_sk`.
- A slot in the shared **`IdentityRegistry`** — the list every
  peer fetches before it routes a message to you.

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

The identity is just the tree above. Adding a device grows a new
leaf. Removing a device prunes one leaf and leaves the others
alone.

---

## 3. Adding a device — the pairing ceremony

**Pairing** is how you link a new device to an identity you
already own. The two devices run a short back-and-forth — the
"ceremony" — at the end of which the new device has its own keys
and the network knows to trust it. The diagram below traces the
whole exchange; the prose after it explains why each step is
there.

```
          Primary device                          New device
          (has master_seed)                       (fresh install)

          $ veil-cli identity pair-invite                  │
            ↳ pair_secret generated                        │
            ↳ PairingInvite published                      │
            ↳ QR displayed: veil:pair?id=X&secret=Y        │
            ↳ OOB 6-digit code shown: "123-456"            │
                                                           │
                                                 scan QR  ◄┤
                                                           │
                                                           │  connect directly to
                                                           │  source via `secret`
                                 ┌──────────────────────►  │
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

**Why this is safe**:

- The `master_seed` — the root secret that controls the whole
  identity — never leaves the primary device. The new device
  makes its own `identity_sk`, and only the master can certify
  it. So even a device that's already compromised can't go on to
  certify more devices.
- The two devices each show a short confirmation code, computed
  out-of-band — that is, over a channel the attacker can't see,
  in this case your own eyes comparing the two screens. This
  stops a fake device from quietly scanning a QR code meant for
  the real one: the genuine device is the only one that can show
  the genuine code. An attacker who intercepted the QR would end
  up with a different session key, and so a different code, and
  the comparison would fail.
- The `pair_secret` lasts only 5 minutes and works exactly once.

**The commands you actually type**:

On the primary device, print an invite — a URI plus a QR code the
new device can scan. The `--endpoint` is required: it tells the
new device which address to call back on.
```bash
veil-cli identity pair-invite --ttl-secs 300 --endpoint tcp://HOST:PORT
# QR rendered + OOB code displayed.
```

To run the full interactive ceremony from the primary side —
opening a listener, accepting the call-back, doing the code
compare, and master-certifying the new subkey — use `pair-listen`
instead:
```bash
veil-cli identity pair-listen --endpoint tcp://HOST:PORT
# Binds the listener, prints the URI + QR, runs the source side.
```

On the new device — the phone doing the scanning — pass the
scanned URI as a **positional** argument (there is no `--qr`
flag):
```bash
veil-cli identity pair-accept <veil:pair?…-url>
# Displays the OOB code — user visually compares with primary.
# If codes match, user taps "confirm" on primary.
```

Comparing the codes by eye is the normal path on both sides. The
`--yes-i-compared-codes` flag skips that prompt, and it exists for
scripted tests only — don't reach for it by hand.

Within 60–90 seconds the new device is fully live.

---

## 4. Removing a device

> ⚠️ **There is no `identity revoke` command yet.** For now,
> removing a device is a protocol-level chore: from a device that
> holds the master seed, you edit the `IdentityDocument` and
> re-publish it by hand. No subcommand wraps this up for you. The
> `veil-cli identity` subcommands that *do* exist are `create`,
> `show`, `rotate`, `restore`, `claim-name`, `qr`, `pair-invite`,
> `inspect-uri`, `pair-listen`, `pair-accept`, `export-qr-backup`,
> `import-qr-backup`, `standalone`, `delegate-device`, `migrate`,
> `dht-key`, and `name-dht-key`.

### 4.1. How it works

Whoever holds the master does this. Take that device's
`identity_sk` — the subkey in `IdentityDocument.identity_keys` it
was bound to — and add it to the document's `revoked_keys` set.
Bump `document_version`, re-sign, and re-publish the updated
`IdentityDocument`. An identity holds at most
`MAX_IDENTITY_KEYS = 8` live subkeys, so the document stays small.
Once a peer fetches the new version, it refuses any future frame
signed by the revoked subkey. The dead `InstanceEntry` simply ages
out of the registry on the next republish.

### 4.2. How fast it spreads

The re-published document reaches peers two ways. The slow path is
the DHT — the shared address book — republishing on its own
schedule, which can take hours (up to the DHT TTL). The fast path
is gossip and direct push as sessions reconnect, which is seconds
for peers you're already talking to. There's no `scheduled` versus
`compromise` flag today; the difference is just how you act. If a
device is compromised, re-publish right away and lean on gossip
instead of waiting for the next scheduled republish.

---

## 5. Message delivery semantics

### 5.1. Messenger mode (`InstanceTag::All`)

Here the sender encrypts the message **once for every active
device** — a pattern called fan-out. It looks up each
`MlKemKeyCert` in the recipient's registry and builds one
`FanoutEnvelope` per cert. Every envelope carries the instance_id
plus the ML-KEM ciphertext and the AEAD ciphertext, and each one
only opens under a single device's ML-KEM decapsulation seed.

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

- **The mailbox** holds copies for devices that are offline. It
  keys them by recipient (`receiver_id`), not by device, so there
  are no per-instance ACK cursors and no `instance_stale_after`
  knob to tune. Each blob lives under a `(receiver, content_id)`
  primary key. Cleanup runs off an eviction index keyed
  `(deposited_at_be || receiver || content_id)`, together with
  per-sender and global byte quotas. When a quota fills up, the
  oldest deposits go first (anonymous-pool blobs before the
  identified pool), and any blob is dropped as soon as it's
  acknowledged.
- **X3DH one-time prekeys** take over when the recipient is
  offline entirely. The sender grabs an unused prekey from the
  pool the recipient published, and encapsulates to that prekey
  rather than the long-lived ML-KEM cert. The prekey is burned on
  first decrypt — that's what gives async messages
  forward-secrecy, so an old message can't be unlocked by a key
  stolen later.

### 5.2. Load-balancing mode (`InstanceTag::Any`)

Here veil picks just *one* of the active instances. It chooses
based on the published `InstanceEntry.last_seen_unix_ms` and a
local reputation score. Exactly one ciphertext is produced, and
exactly one instance opens it.

A typical use is an email gateway identity `@mailserver` with 3
regional instances. Clients send to `mailserver:Any`, and veil
routes each message to whichever region is closest — lowest
latency — to the sender.

### 5.3. Targeted mode (`InstanceTag::Specific`)

This one is for when a conversation has already settled on a
particular instance, and the rest of the packets need to keep
going to that same one. Session dedup keys on
`(identity_id, instance_id)`, so two instances of the same
identity can each hold their own separate session with one peer.

---

## 6. What `InstanceRegistry` publishes

A current `InstanceEntry` carries just four fields: `instance_id`,
`bound_identity_key_idx`, `label`, and `last_seen_unix_ms`. There's
no `mailbox_anchor`, no `transports`, and no `encrypted_contact`.
The old Tier-A / Tier-B split — and the
`[identity.multi_device.tier_b]` config block that went with it —
**is gone**. The Tier-B encryption layer was removed, and
`mailbox_anchor` and `encrypted_contact` left with it.

Transport hints — clues about how to reach a device — now travel
separately, over `SignedTransportAnnouncement` gossip, instead of
sitting in the registry. The upshot is privacy. Someone passively
scraping `InstanceRegistry` off the DHT finds nothing to correlate:
no anchors, no transport endpoints. All they see is how many
devices you run, their opaque `instance_id`s, and whatever labels
the operator chose. The wire format is in
[`identity-model.md`](identity-model.md).

---

## 7. Reputation is per-identity, not per-device

Reputation is keyed by `identity_id`. Every instance feeds the
same shared score and benefits from it. That's deliberate. A fleet
of mailserver instances under one identity builds its standing
together. And an attacker who compromises one device's
`identity_sk` can't single-handedly wreck the identity's
reputation, because revocation pulls that key off the network
before the damage piles up.

---

## 8. Syncing app state (still on the drawing board)

> 🚧 **Status:** design only. The `AppState` primitive isn't a real
> type yet. What follows is the shape we're aiming for. For now,
> apps that want to sync across devices roll their own DHT slots
> under whatever app-key scheme they like.

Contacts, block-list, preferences, profile — anything an app wants
to keep in sync across the user's devices — will ride on a piece
called `AppState`. It's one DHT slot per `(identity_id, app_id,
key)` tuple, encrypted under the identity's shared
`app_state_secret` and signed by any active `identity_sk`.

Every linked device can read and write. Updates are
version-monotonic: an out-of-order one is simply thrown away. Each
blob caps at 4 KB, so if you need more room, split your app state
across several keys.

---

## 9. FAQ

**Q:** Can two instances of my identity run at the same time on
the same IP?

**A:** Yes. They have different `instance_id`s, so session dedup
keeps their connections apart. Peers just see two active instances
behind the same identity.

**Q:** Can I share one `identity_sk` between two devices and skip
the pairing?

**A:** No. Each instance gets its own `identity_sk` on purpose.
Pairing exists precisely so that no key is ever shared — which is
what keeps the fallout from a compromise down to a single device.

**Q:** How many devices can I link?

**A:** Sixteen, the `IdentityRegistry` cap. For bigger fleets,
split the load across several identities.

**Q:** What happens if I revoke my laptop but my phone is offline
for a week?

**A:** The phone keeps accepting messages addressed to it
specifically. When it reconnects, it pulls the latest
`IdentityDocument`, sees that its sibling was revoked, and shows
the operator a DeviceLinkedEvent-style alert. Your name, your
reputation, and the phone's own identity_sk are all untouched.

**Q:** What if my phone is compromised while my laptop is offline?

**A:** Revoke the phone's subkey from the laptop once it's back
online. Until that revocation reaches a given peer — by DHT
republish, or by direct push when sessions reconnect — that peer
may still accept frames signed by the phone's key. Worst case, the
DHT path takes hours. With gossip, nearby peers pick it up in
seconds.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol spec.
- [`recovery.md`](recovery.md) — recovery from device loss or
  key compromise.
- [`messenger-dev.md`](messenger-dev.md) — building a messenger
  that uses these primitives.
