# Recovery guide

This guide walks you through getting your Veil identity back. Your **identity**
is your cryptographic "passport" — the keys that prove you are you on the
network. You might need to recover it after:

- you lose a device,
- a device is stolen or tampered with,
- you suspect someone leaked your identity's signing key (the private key that
  signs messages as you),
- you forget the password to your encrypted file.

Want the deep technical spec? See [`identity-model.md`](identity-model.md).
For everyday physical-security advice, see
[`opsec-user-guide.md`](opsec-user-guide.md).

---

## 1. The three things you should have

When you created your identity, the CLI showed you **three items**, listed here
from longest-lasting to shortest. (BIP-39 is the standard scheme for turning a
secret key into 24 plain English words you can write down — see artefact 1.)

| # | Artefact | Lifetime | Where it lives |
|---|----------|----------|----------------|
| 1 | **24-word BIP-39 phrase** | Decades (paper) | Written on paper, stored somewhere safe |
| 2 | **Encrypted master file** (`master.enc`) | Until your password is forgotten or file is corrupted | `~/.config/veil/master.enc` (optional) |
| 3 | **Identity-key file** (`identity.toml`) | Until this device is wiped | `~/.config/veil/identity.toml` (hot key, per device) |

**Only artefact 1 (the BIP-39 phrase) is mandatory.** Everything else can burn
down. A 24-word phrase written on paper in a safe deposit box still rebuilds
your whole identity — name, contacts, reputation, all of it — on any fresh
machine.

---

## 2. Recovery decision tree

Pick the leftmost branch that matches what you can still get to.

```
                   ┌────────────────────────┐
                   │ Do you still have the  │
                   │ original device and it │
                   │ boots?                 │
                   └───────────┬────────────┘
                               │
                    ┌──────────┼──────────┐
                    yes                   no
                    │                     │
                    ▼                     ▼
          section 3.1:                section 3.2:
          routine key                 device-loss
          rotation                    restore


┌──────────────────────────────────────────────┐
│ Do you suspect a key leak (device stolen     │
│ while unlocked, malware spotted, phishing    │
│ attempt succeeded)?                          │
└──────────────────┬───────────────────────────┘
                   yes
                   ▼
              section 3.3: compromise recovery
```

---

## 3. Recovery scenarios

### 3.1. Routine key rotation — you still control everything

Do this every 6–12 months as good hygiene. *Rotation* swaps your current
signing key for a fresh one: the old `identity_sk` is retired (revoked) and a
new one is generated. Your name, contacts, reputation, and linked devices all
carry over untouched.

```bash
# On the primary device (the one with master_seed available):
veil-cli identity rotate
# Prompts for master-file password (or BIP-39 phrase if you
# chose paper-only).  Generates a new identity_sk, certifies it
# under master_sk, pushes the updated IdentityDocument to the DHT.
```

Your other linked devices notice the new `document_version` on their own. Over
the DHT — the network's shared address book — that takes about 6 hours. Devices
you're directly connected to hear about it in about 30 seconds. Want a second
device to pick up the change right now? Just restart its daemon (the background
process that keeps your node running). On start-up it re-fetches the latest
signed document from the DHT. There is no `identity refresh` subcommand; the
running daemon already re-pulls on its own.

**Output to check**:

```
identity: rotated @alice
  old identity_key_idx = 0 (revoked, reason=Scheduled)
  new identity_key_idx = 1
  document_version 3 → 4
  published to DHT: ok
  notified N direct peers: ok
```

### 3.2. Device loss — restoring from BIP-39

Your laptop went off a cliff. You still have the paper phrase. Here's how to
come back.

On a fresh device:

```bash
# 1. Install veil.
# 2. Restore.
veil-cli identity restore
# Prompts: "Enter your 24-word BIP-39 phrase (word 1 of 24):"
# Enter each word as prompted.  The CLI echoes back the
# **checksum bytes** (last 2 of the derived master_sk) so you can
# spot-check you typed the correct phrase.
# Prompts: "Generate a new identity_sk for this device?  [Y/n]"
# Yes — each device has its own identity_sk (per 462.39).
# Optional: "Save a local encrypted master file?  [y/N]"
```

What happens under the hood:

1. BIP-39 phrase → 32-byte `master_seed`.
2. `master_seed` → `master_sk` (Ed25519).
3. Fresh ML-KEM-768 keypair generated for this device.
4. Fresh Ed25519 identity_sk generated for this device.
5. `master_sk` certifies the new `identity_sk` and `mlkem_cert`.
6. Published to the DHT as a new `IdentityKey` in the
   `IdentityDocument.identity_keys` list.
7. `instance_id` generated and persisted locally
   (`~/.config/veil/instance_id`).
8. Updated `InstanceRegistry` pushed.

If the DHT already holds your `IdentityDocument`, the restore just adds a new
subkey (a per-device signing key) and bumps `document_version`. Nothing old is
revoked. The previous device's `identity_sk` stays valid, because it was never
compromised — the device was only lost, not stolen. So if you later *find* that
device, its `identity_sk` still works.

### 3.3. Compromise recovery — somebody has your identity_sk

This is the scenario Veil's identity layer is built to survive. You keep your
handle, your contacts, and your reputation through it.

**Do this right away (about 5 minutes, from any device you trust that has the
`master_seed`):**

```bash
veil-cli identity rotate
# Prompts for the master-file password (or BIP-39 phrase).
# Revokes the currently-active identity_sk (it is added to the
# document's revoked-keys list), master-certifies a fresh
# identity_sk, bumps document_version, and persists the updated
# signed IdentityDocument.  The running daemon publishes the
# update to the DHT and pushes it to currently-connected peers.
```

> There is no standalone `identity revoke` subcommand today. Revocation happens
> as part of `identity rotate`, which retires the old subkey and mints a
> replacement in one step.

Within seconds, your peers (the nodes yours talks to) record the
`revoked_pubkey_hash` in their `RevocationCache` — a list of dead keys they keep
on disk. From then on, any frame signed by the old key is rejected.

**Next, check what the attacker might have done.** Re-fetch your current
document, print it, and compare it against what you expect:

```bash
veil-cli identity show
# Pretty-prints the on-disk identity (instance_id + most-recent
# signed IdentityDocument): the identity_keys list, the active
# sig_key_idx, document_version, and any revocations.
```

Compare the printed `identity_keys`, `sig_key_idx`, and revocations against what
you expect. Suppose an attacker managed to add a subkey (an unexpected pairing)
or point `sig_key_idx` at a key you don't recognise. A fresh `identity rotate`
on the device that holds your master key takes back control. It republishes a
master-signed document, and because `document_version` only ever counts upward,
that new version overrides anything the attacker published. Only `master_sk` can
certify subkeys or forge a `master_freshness_sig`, and the attacker doesn't have
it — more on that below.

**What an attacker with a stolen `identity_sk` can actually do, before you
revoke it:**

- Sign `IdentityDocument` updates. But the `master_freshness_sig` is signed by
  `master_sk`, which the attacker doesn't have, so any document they publish goes
  invalid after 30 days — even while you're offline.
- Sign `NameClaim` updates. These are version-monotonic (each version number
  only goes up), so your later rotate-and-republish overrides theirs.
- Sign `InstanceRegistry` updates. Same story: version-monotonic.

**What that attacker cannot do:**

- Rotate the `master_sk` — they don't have it.
- Certify a new subkey — that needs `master_sk`.
- Forge a `master_freshness_sig` — that needs `master_sk`.
- Read your encrypted app-state. It's locked with a secret derived from your
  master key, not from `identity_sk`.
- Forge a revocation — that needs `master_sk`.

**The blast radius is one subkey.** Each device has its own `identity_sk`, so a
break-in on one device only means revoking that one device's key. Your other
devices keep working.

### 3.4. Forgotten master-file password

You can't remember the password that unlocks `master.enc`. Good news: you still
have your paper BIP-39 phrase.

```bash
veil-cli identity restore
# Enter BIP-39 phrase.
# Prompts: "Overwrite existing encrypted master file? [y/N]"
# Yes.  Enter a new password.  Old file is replaced.
```

If you don't have the BIP-39 phrase either, the identity is gone for good — Veil
has no backdoor. Start fresh with `veil-cli identity create`.

### 3.5. Lost BIP-39 phrase, still have encrypted file

No drama. The 24-word phrase is shown only once, at `identity create` time, and
no subcommand ever prints it again. (`identity show` only displays the public
document, and there's no `--export-phrase` flag.) Instead, make a durable
disaster-recovery backup straight from the encrypted master file, as an
encrypted QR code that holds your master seed:

```bash
veil-cli identity export-qr-backup --password-file pw.txt
# Decrypts <veil_dir>/master.enc with the master-file
# password, then emits a scannable veil:master-backup?… QR.
# Choose a fresh QR password and convey it out-of-band; filming
# the QR alone is insufficient to recover the identity.
```

Restore later with `veil-cli identity import-qr-backup`. You end up in the same
place as a BIP-39 restore: the master `node_id` comes back, and a fresh
per-device `identity_sk` is generated.

---

## 4. What changes and what doesn't after recovery

| Artefact | Survives rotation? | Survives master_seed restore on fresh device? |
|----------|-------------------|----------------------------------------------|
| `identity_id` | Yes | Yes |
| Registered name `@handle` | Yes | Yes |
| Reputation score | Yes | Yes |
| Mailbox contents | Yes | Yes |
| Linked-devices list | Yes | Yes (but this new device is one of them) |
| Per-device identity_sk | No (revoked) | No (fresh one generated) |
| Per-device ML-KEM key | No (rotated) | No (fresh one generated) |
| `safety number` with contacts | No (changes) | No (changes) |

The safety-number change is **on purpose**. A *safety number* is a short code
two contacts can compare to confirm no one is impersonating either of them. When
it changes, that tells your contacts a key rotation happened and nudges them to
re-verify you on a separate channel. Someone who sees "Alice's safety number
changed" should call Alice on a channel they already trust and re-read the 60
digits aloud, to confirm nothing shady is going on.

---

## 5. Backup strategy recommendations

**Bare minimum (what the CLI insists on at create time)**:

1. The 24-word BIP-39 phrase, on paper. Keep it somewhere a fire won't reach it
   — a fireproof safe, a safe deposit box, that sort of thing.

**Recommended**:

2. A second paper copy in a different place geographically (home plus your
   parents' house, home plus your lawyer's office).
3. The encrypted `master.enc` file on a long-term storage device you check on
   now and then.

**Paranoia tier**:

4. An encrypted QR-code backup, photographed and archived offline. The password
   lives somewhere separate and never goes into the QR itself.
5. A Shamir Secret Sharing split of the master seed — the secret is cut into
   shares handed to trusted friends, and only a quorum of them can rebuild it.
   (Not in Veil yet; it's future work.)

---

## 6. Fail-safe limits

These are the guard rails that keep the system honest, even in bad situations.

- A verifier rejects any `IdentityDocument` whose `master_freshness_sig` hasn't
  been refreshed in over 30 days. So if you go fully offline for more than 30
  days, peers that never saw your document during that window won't connect until
  you come back online and refresh it. (Peers who *did* see it earlier hold on to
  it.)
- `RevocationCache` entries stick around forever. Once a peer has seen your
  revocation, it will never accept that dead key again — not even if the DHT is
  later flooded with old, pre-revocation documents.
- A peer rejects any `InstanceRegistry` whose `reg_version` goes backwards. You
  can't roll back the device list, and neither can an attacker — even one who has
  compromised every current key, because they'd still need the master.

---

## 7. Testing your recovery — do this every year

Most people find out their backup doesn't work at the exact moment they need it.
Don't be one of them. Once a year, on a **scratch device** (not your main one):

1. Run `veil-cli identity restore` and type in the BIP-39 phrase.
2. Check that the restored `identity_id` matches the one on your main device. Run
   `veil-cli identity show` on both and compare them.
3. Wipe the scratch device.

If the phrase doesn't rebuild the `identity_id` you expected, the phrase is
wrong. Fix it now — not when your laptop is on fire.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol spec.
- [`opsec-user-guide.md`](opsec-user-guide.md) — physical
  security and phishing-resistance guidance.
- [`multi-device.md`](multi-device.md) — how linked devices
  interact.
- [`messenger-dev.md`](messenger-dev.md) — integrating veil
  identity into a messaging app.
