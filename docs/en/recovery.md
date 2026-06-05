# Recovery guide

End-user guide to recovering an veil identity after:

- device loss,
- device theft or compromise,
- suspected leak of the identity's signing key,
- forgotten encrypted-file password.

For the protocol spec, see [`identity-model.md`](identity-model.md).
For user-facing physical-security guidance, see
[`opsec-user-guide.md`](opsec-user-guide.md).

---

## 1. The three things you should have

When you created your identity, the CLI presented **three artefacts**
in order of durability:

| # | Artefact | Lifetime | Where it lives |
|---|----------|----------|----------------|
| 1 | **24-word BIP-39 phrase** | Decades (paper) | Written on paper, stored somewhere safe |
| 2 | **Encrypted master file** (`master.enc`) | Until your password is forgotten or file is corrupted | `~/.config/veil/master.enc` (optional) |
| 3 | **Identity-key file** (`identity.toml`) | Until this device is wiped | `~/.config/veil/identity.toml` (hot key, per device) |

**Only artefact 1 (BIP-39) is mandatory.** If everything else burns
down, a 24-word phrase written on paper in a safe deposit box still
reconstitutes your entire identity — name, contacts, reputation, all
of it — on any fresh machine.

---

## 2. Recovery decision tree

Pick the leftmost branch that matches what you still have access to.

```
                   ┌────────────────────────┐
                   │ Do you still have the   │
                   │ original device and it  │
                   │ boots?                  │
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
└──────────────────┬──────────────────────────┘
                   yes
                   ▼
              section 3.3: compromise recovery
```

---

## 3. Recovery scenarios

### 3.1. Routine key rotation — you still control everything

Use this every 6–12 months as good hygiene.  The old identity_sk
is revoked; a fresh one is generated.  Name, contacts, reputation,
linked devices — all survive.

```bash
# On the primary device (the one with master_seed available):
veil-cli identity rotate
# Prompts for master-file password (or BIP-39 phrase if you
# chose paper-only).  Generates a new identity_sk, certifies it
# under master_sk, pushes the updated IdentityDocument to the DHT.
```

Other linked devices notice the new `document_version` within
~6 hours of the DHT republish cycle (or ~30 seconds via direct
push to currently-connected peers).  If you want to force an
immediate refresh on a second device, restart its daemon — on
start-up it re-fetches the latest signed document from the DHT.
(There is no dedicated `identity refresh` subcommand; the running
daemon re-pulls on its own maintenance tick.)

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

Your laptop was dropped off a cliff.  You have the paper phrase.

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

If the DHT already holds your `IdentityDocument`, the restore
appends a new subkey and bumps `document_version`.  Nothing old
is revoked — the previous device's identity_sk is left intact
because it was never compromised (the device was simply lost,
not stolen).  If you later *find* the lost device, its identity_sk
still works.

### 3.3. Compromise recovery — somebody has your identity_sk

This is the scenario veil's identity layer is specifically
designed to survive without losing your handle, contacts, or
reputation.

**Immediate steps (5 minutes, from any trusted device with the
master_seed available):**

```bash
veil-cli identity rotate
# Prompts for the master-file password (or BIP-39 phrase).
# Revokes the currently-active identity_sk (it is added to the
# document's revoked-keys list), master-certifies a fresh
# identity_sk, bumps document_version, and persists the updated
# signed IdentityDocument.  The running daemon publishes the
# update to the DHT and pushes it to currently-connected peers.
```

> There is no standalone `identity revoke` subcommand today —
> revocation happens as part of `identity rotate`, which both
> retires the old subkey and mints a replacement in one step.

Within seconds your peers have the `revoked_pubkey_hash` in their
persistent `RevocationCache`.  Any frame signed by the old key
is rejected.

**Next, inspect what the attacker may have done** by re-fetching
and printing your current document and comparing it against what
you expect:

```bash
veil-cli identity show
# Pretty-prints the on-disk identity (instance_id + most-recent
# signed IdentityDocument): the identity_keys list, the active
# sig_key_idx, document_version, and any revocations.
```

Compare the printed `identity_keys`, `sig_key_idx`, and
revocations against what you expect.  If an attacker managed to
append a subkey (unexpected pairing) or point `sig_key_idx` at a
key you don't recognise, a fresh `identity rotate` on the
master-holding device re-asserts control: it republishes a
master-signed document whose monotonic `document_version`
supersedes anything the attacker published.  (Only `master_sk`
can certify subkeys or forge `master_freshness_sig`, and the
attacker does not have it — see below.)

**What an attacker with a compromised identity_sk can actually
do, before you revoke:**

- Sign `IdentityDocument` updates (but `master_freshness_sig` is
  signed by `master_sk` which the attacker does not have — so the
  document they publish is invalid after 30 days even if you're
  offline).
- Sign `NameClaim` updates (but version-monotonic, so your later
  rotate-and-republish replaces theirs).
- Sign `InstanceRegistry` updates (same: version-monotonic).

**What an attacker with a compromised identity_sk cannot do:**

- Rotate the master_sk — they don't have it.
- Certify a new subkey — master_sk is required.
- Forge a `master_freshness_sig` — master_sk is required.
- Read your encrypted app-state (encrypted with identity-shared
  secret derived from master, not from identity_sk).
- Forge a revocation (master_sk is required).

**Blast radius is one subkey.**  Each device has its own
identity_sk — so compromising one device only requires revoking
that device's key.  Other devices keep working.

### 3.4. Forgotten master-file password

You can't remember the password that decrypts `master.enc`.  You
do have your paper BIP-39 phrase.

```bash
veil-cli identity restore
# Enter BIP-39 phrase.
# Prompts: "Overwrite existing encrypted master file? [y/N]"
# Yes.  Enter a new password.  Old file is replaced.
```

If you do NOT have the BIP-39 phrase either, the identity is
lost forever — veil has no backdoor.  Start fresh with
`veil-cli identity create`.

### 3.5. Lost BIP-39 phrase, still have encrypted file

No drama.  The 24-word phrase is shown once at
`identity create` time and is not re-printed by any subcommand
(`identity show` only pretty-prints the public document; there
is no `--export-phrase` flag).  Instead, make a durable
disaster-recovery backup directly from the encrypted master
file by emitting an encrypted master-seed QR:

```bash
veil-cli identity export-qr-backup --password-file pw.txt
# Decrypts <veil_dir>/master.enc with the master-file
# password, then emits a scannable veil:master-backup?… QR.
# Choose a fresh QR password and convey it out-of-band; filming
# the QR alone is insufficient to recover the identity.
```

Restore later with `veil-cli identity import-qr-backup` (same
end-state as a BIP-39 restore: the master node_id is recovered
and a fresh per-device identity_sk is generated).

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

The safety-number change is **by design** — it signals to
contacts that a key rotation happened and prompts them to
re-verify out-of-band.  A contact seeing "Alice's
safety number changed" should call Alice on an already-trusted
channel and re-read the 60 digits to confirm nothing shady is
going on.

---

## 5. Backup strategy recommendations

**Bare minimum (what the CLI enforces at create time)**:

1. 24-word BIP-39 phrase on paper.  Stored somewhere a fire won't
   destroy it (fireproof safe, safe deposit box, etc.).

**Recommended**:

2. Second paper copy in a geographically different location
   (home + parents' house, home + lawyer's office).
3. Encrypted `master.enc` file on a long-term storage device you
   revisit occasionally.

**Paranoia tier**:

4. Encrypted QR-code backup photographed and
   archived offline.  The password is stored out-of-band, never
   encoded into the QR.
5. Shamir Secret Sharing split of the master_seed across
   trusted-friend shares (not yet available in veil — future
   work).

---

## 6. Fail-safe limits

- An `IdentityDocument` whose `master_freshness_sig` has not been
  refreshed in > 30 days is rejected by verifiers.  If you go
  fully offline for > 30 days, peers that never saw your document
  during that window will refuse to connect until you come back
  online and refresh.  (Peers who *did* see the document earlier
  retain it.)
- `RevocationCache` entries persist indefinitely.  A peer who
  once saw your revocation will never accept the revoked key
  again, even if the DHT is later flooded with pre-revocation
  documents.
- An `InstanceRegistry` whose `reg_version` regresses is rejected.
  You cannot roll back the device list even if an attacker
  compromises every current key (they'd need the master).

---

## 7. Testing your recovery — do this every year

Most people discover their backup doesn't work at the moment
they need it.  Prevent that:

1. Once a year, on a **scratch device** (not your primary):
2. `veil-cli identity restore` using the BIP-39 phrase.
3. Verify the restored `identity_id` matches what you have on your
   primary (`veil-cli identity show` on both, compare).
4. Wipe the scratch device.

If the phrase doesn't reconstruct the expected `identity_id`,
the phrase is wrong — fix it now, not when your laptop is
burning.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol spec.
- [`opsec-user-guide.md`](opsec-user-guide.md) — physical
  security and phishing-resistance guidance.
- [`multi-device.md`](multi-device.md) — how linked devices
  interact.
- [`messenger-dev.md`](messenger-dev.md) — integrating veil
  identity into a messaging app.
