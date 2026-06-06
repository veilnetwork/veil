# Operator Runbook — Hybrid Identity Backup & Recovery

This is the operator's guide to the post-quantum *hybrid* identity
(`ed25519+falcon512`). It walks you through creating a hybrid
identity, deciding what to back up, and restoring it on a fresh
machine. *Hybrid* just means the identity is built from two different
key systems at once — see below. Read this **before** you run
`veil-cli identity create --algo hybrid` in production.

> **TL;DR**: a hybrid identity needs **two** separate backups — the
> BIP-39 paper phrase **and** the `master_falcon.bin` file. (BIP-39 is
> the standard way of writing a key down as 24 plain words; the file
> holds the second key.) Lose either one and you cannot restore the
> identity as hybrid — and your `node_id`, the address everyone knows
> you by, will change.

## Why two backups

A hybrid master key is two keypairs glued together. A *keypair* is a
matched public key (safe to share) and private key (kept secret):

| Half | Algorithm | Recoverable from |
|---|---|---|
| Classical | Ed25519 | BIP-39 paper phrase (24 words) |
| Post-quantum | Falcon-512 | `master_falcon.bin` file only |

The phrase rebuilds the Ed25519 half exactly, every time — that is
what the 24 words are for. Ed25519 is the classical signature scheme;
Falcon-512 is the post-quantum one that stays safe even against a
future quantum computer. The catch: the Falcon-512 half is rolled
fresh from the system random generator (`OsRng`) when you create the
identity. There is no way to regrow it from the phrase — the current
pqcrypto-falcon crate doesn't offer one. So the only copy of the
Falcon half is the file on disk. Lose the file, lose the half.

Here is why that matters. Your `node_id` is a hash of *both* public
keys: `BLAKE3(ed_pk(32) || falcon_pk(897))`, 929 bytes hashed
together. Without the Falcon half you can't reproduce that 929-byte
pubkey, so a restore has no choice but to mint a fresh Falcon keypair
— and that gives you a **different** `node_id`. Your @name
registration, contacts, and reputation all hang off the old
`node_id`, so they would be lost.

## Step 1: create a hybrid identity

```bash
veil-cli identity create \
    --algo hybrid \
    --label my-laptop \
    --veil-dir /var/lib/veil
```

The CLI emits the 24-word BIP-39 phrase to stdout and writes:

```
/var/lib/veil/
├── identity_document.bin     # 1860 B — the signed sovereign doc
├── device_identity_sk.bin    # 32 B   — per-device Ed25519 subkey
├── instance_id               # 16 B   — per-device label binding
└── master_falcon.bin         # 2191 B — hybrid master Falcon SK + PK
                              #          (the "OFAM" framed bundle)
```

Verify with:

```bash
veil-cli identity show --veil-dir /var/lib/veil
# master_algo:        ed25519+falcon512
# (master_pubkey is 929 bytes — implied by master_algo)
```

## Step 2: back up BOTH artifacts

### 2a. BIP-39 phrase (paper)

The phrase is printed once at create time and never again. Write it
down on paper, stamp it on metal, or otherwise store it offline:

```
1.  large       2.  decline     3.  palace      4.  grunt
5.  tired       6.  track       7.  tent        8.  sphere
9.  test        10. era         11. clinic      12. fortune
13. require     14. unfold      15. cluster     16. flat
17. robot       18. eagle       19. scale       20. step
21. decorate    22. banner      23. sausage     24. label
```

Do NOT save the phrase to a file on a live machine unless you also
encrypt it. (`--password-file` will write an encrypted `master.enc`
for you — but then the password becomes the one thing that can sink
you. Choose this only if you're comfortable with that trade-off.)

### 2b. `master_falcon.bin` (digital)

This file is **2191 bytes** of opaque binary. It starts with the four
ASCII bytes `OFAM` (a "magic" marker that lets tools recognize the
file format at a glance). Verify it:

```bash
xxd /var/lib/veil/master_falcon.bin | head -1
# 00000000: 4f46 414d 0100 0005 01...
#           O F A M  ver 1   sk_len=1281 (0x501)
```

How to store it:
- **Keep at least 2 of 3 copies** on independent media — say, an
  encrypted USB stick, an air-gapped second machine (one that never
  touches the network), and an encrypted cloud bucket. Any two
  surviving is enough.
- **Guard it as carefully as the phrase.** Anyone holding this file
  *and* the phrase has full post-quantum control of your identity.
- **Check on it now and then.** Make sure each copy still reads back
  *and* still parses — run `veil-cli identity show` on a copy.

> It's tempting to treat the Falcon file as "less critical" than the
> phrase, because the phrase recovers _something_ on its own. **Don't.**
> A hybrid identity restored without the Falcon file is no longer the
> same identity on the network — the `node_id` is different, and every
> name claim, contact, and routing entry tied to the old `node_id` is
> left stranded.

## Step 3: restore on a fresh machine

After device loss, on a clean machine:

```bash
veil-cli identity restore \
    --algo hybrid \
    --phrase-file /path/to/recovered_phrase.txt \
    --master-falcon-file /path/to/recovered_master_falcon.bin \
    --label new-laptop \
    --veil-dir /var/lib/veil
```

Verify the restored `node_id` matches the original:

```bash
veil-cli identity show --veil-dir /var/lib/veil
# node_id: <should match the value emitted by `identity create` on
#          the original machine>
# master_algo: ed25519+falcon512
```

If you leave out `--master-falcon-file` on a hybrid restore, the CLI
stops right away with:

```
restore: --algo=hybrid requires --master-falcon-file pointing at the
preserved master_falcon.bin (the BIP-39 phrase alone cannot recover
the post-quantum half — see docs/identity-hybrid-backup.md)
```

This is on purpose. There is no quiet fallback to Ed25519-only,
because that would change your `node_id` without telling you.

## Step 4: switching algorithms (`identity migrate`)

Say you started with a classical Ed25519 identity and now want to
upgrade to hybrid (or go the other way). That is a **migration**, not
a restore — use `veil-cli identity migrate`.

### 4a. Create the new identity

On any machine:

```bash
veil-cli identity create --algo hybrid \
    --veil-dir /var/lib/veil-new \
    --label new-master
```

This mints a fresh `node_id`. Save the new BIP-39 phrase **and** the
new `master_falcon.bin` — same care as in Step 2.

### 4b. Mint the migration cert

A migration cert is a small signed note that says "the old identity
now lives at the new one." Mint it on a machine that can reach BOTH
the OLD veil_dir AND the OLD master secrets — the BIP-39 phrase (or
the `master.enc` password), plus the OLD `master_falcon.bin` if the
OLD identity was hybrid or Falcon-only:

```bash
veil-cli identity migrate \
    --from /var/lib/veil-old \
    --to /var/lib/veil-new \
    --from-phrase-file /path/to/old_phrase.txt
```

(Add `--from-master-falcon-file /path/to/old_master_falcon.bin` if
the OLD identity was hybrid or standalone Falcon.)

Output:

```
migration cert minted: 1024 bytes
  old_node_id:     <hex>  (algo=ed25519)
  new_node_id:     <hex>  (algo=ed25519+falcon512)
  issued_at_unix:  ...
  valid_until_unix:...   (604800s window)
  cert written to: /var/lib/veil-new/migration_cert.bin
  dht_key:         <hex>

Next step: a running daemon serving --to will publish this cert on
its next maintenance tick.  Or run `node dht put <dht_key> <cert_path>`
against an admin socket for immediate propagation.
```

### 4c. Publish

Two options:

1. **Daemon-driven** (recommended) — start the daemon pointing at
   `--to /var/lib/veil-new`. On its next DHT republish tick it
   picks up `migration_cert.bin` and publishes both the new
   IdentityDocument AND the MigrationCert.
2. **Manual** — `veil-cli node dht put <dht_key> <cert_path>`
   against a running admin socket for immediate propagation.

Once it's published, anyone looking you up follows the chain on their
own — `resolve_identity_verified(old_node_id)` returns the NEW
identity. The lookup has built-in guards against loops, over-long
chains, and downgrades, all described in
`crates/veil-identity/src/resolver.rs`.

### 4d. You cannot migrate to a weaker algorithm

The `migrate` command — and the `migration::sign_migration_cert` call
underneath it — **refuses** any switch that drops to a weaker security
tier:

| OLD → NEW | Status |
|---|---|
| ed25519 → ed25519 | OK (refresh-only) |
| ed25519 → falcon512 | OK (PQ upgrade) |
| ed25519 → hybrid | OK (PQ upgrade, recommended) |
| falcon512 → hybrid | OK (regain BIP-39 path) |
| falcon512 → ed25519 | **REJECTED** (PQ → classical = downgrade) |
| hybrid → ed25519 | **REJECTED** (loses Falcon component) |
| hybrid → falcon512 | **REJECTED** (loses Ed25519 component) |

The tiers rank from weakest to strongest:
`ed25519 (1) < falcon512 (2) < ed25519+falcon512 (3)`.

Try to downgrade and the signing step fails with:

```
migrate: sign_migration_cert: security downgrade rejected
(old_algo=3, new_algo=1)
```

This is a belt-and-suspenders check. Even if someone slipped a cert
past the lookup guards another way, `sign` itself still won't produce
the cert.

## Step 5: what to do if the Falcon file is lost

The phrase survived, but `master_falcon.bin` is gone. You have two
options, and neither is painless:

1. **Mint a new hybrid identity** (`identity create --algo hybrid`)
   and publish a MigrationCert from the old hybrid `node_id` to the
   new one. The catch: the cert has to be signed by the *old* master,
   which needs the lost Falcon file. So this only works if you lost
   the file recently AND a live process is still running with the
   master loaded in memory. Once that process is gone, the chain
   can't be made.

2. **Mint a new Ed25519-only identity** (`identity create`, no
   `--algo`), using the phrase to recover one half. Accept that the
   new `node_id` is different — it's now a hash of 32 bytes instead
   of 929, so `BLAKE3(32 B) ≠ BLAKE3(929 B)` — and rebuild your @name
   and contacts from scratch. This is the "lost everything" path, and
   it's the only one left once the Falcon material is gone for good.

So the phrase on its own is **not enough** to recover a hybrid
identity. Treat the two backups as a single pair: you need both.

## Quick reference

| Need | File(s) |
|---|---|
| Boot a paired-down second device under the same identity | `master_falcon.bin` + BIP-39 phrase |
| Recover after device loss | `master_falcon.bin` + BIP-39 phrase |
| Decode `master.enc` if `--password-file` was used at create | password (separately stored) |
| Find the local `instance_id` for diagnostics | `<veil_dir>/instance_id` |

## Appendix A: standalone `--algo=falcon512`

Standalone Falcon-512 (`--algo=falcon512`) is supported but **not
recommended for production**. Read this section before you reach for
it.

### What it is

A pure post-quantum master keypair, and nothing else. There is **no**
classical Ed25519 half, **no** BIP-39 paper backup, and **no** way to
recover it other than `master_falcon.bin`.

```
node_id   = BLAKE3(falcon_pk(897 B))    // distinct from hybrid (BLAKE3(929 B))
master_pubkey = falcon_pk(897 B)
master_sk     = OsRng-derived Falcon-512 SK, lives ONLY in master_falcon.bin
```

### Why you might want it

- A pure post-quantum deployment with no classical key anywhere — no
  Ed25519 means nothing a future quantum computer could ever unwind,
  even in theory.
- You'd rather not have a BIP-39 phrase lying around at all. The
  phrase can recover your identity, but for that same reason it's also
  a thing an attacker can go after.
- Research or experiments with pure post-quantum identities.

### Why it's dangerous

In the hybrid path the BIP-39 phrase is there **for one reason: a
paper backup you can fall back on**. Drop it and every one of these
becomes fatal:

- You lose `master_falcon.bin` — that's the whole identity gone, with
  no second copy to fall back on.
- You mistype a path during backup — identity gone.
- A disk quietly fails mid-backup and you don't notice — identity
  gone.
- Someone steals a device holding `master_falcon.bin` and you never
  get an alert — your identity is fully compromised, with no "rotate
  from the old phrase" move left to make.

### Required acknowledgement

The CLI won't mint a standalone Falcon-512 identity unless you pass
`--accept-no-recovery` to say you understand there's no way back:

```bash
veil-cli identity create --algo falcon512 --label foo \
    --accept-no-recovery
```

Without the flag the command fails with:

```
create: --algo=falcon512 has NO recovery path — the master Falcon
SK is generated from OsRng and lives ONLY in <veil_dir>/master_falcon.bin.
Loss of that file = TOTAL identity loss with no paper backup.  Pass
--accept-no-recovery to acknowledge, or use --algo=hybrid which
retains BIP-39-recoverable Ed25519 half.  See docs/identity-hybrid-backup.md.
```

### What `create` prints for Falcon-512

- The 24-word BIP-39 block is **left out** — it can't recover
  anything here, so printing it would only mislead you.
- A loud `!!! WARNING ...` block prints to the operator stream.
- `master_falcon.bin` is created in `<veil_dir>` and printed with the
  note `(PRESERVE — operator-side recovery medium)`.

### Restore

```bash
veil-cli identity restore --algo falcon512 \
    --master-falcon-file /path/to/preserved_master_falcon.bin \
    --label new-host \
    --veil-dir /var/lib/veil
```

`--phrase-file` is **not required** here (and you'll get a loud
warning if you pass it — the file is decoded only to catch typos, its
bytes aren't used). The bundle reproduces the `node_id` byte for byte.

### Backup recommendation

Keep **3 of 3** copies. Standalone Falcon-512 has no margin for error
— one bad copy is already one too few. For every backup:

1. Check the file's `OFAM` magic header (`xxd | head -1`).
2. Check that it parses (`veil-cli identity show` against a temporary
   restore target).
3. Refresh on a set schedule — quarterly at the very least.

If you can't commit to all three, **use `--algo=hybrid` instead.** The
classical half of the hybrid path covers exactly the failure modes
listed above, and it costs you only an extra 64 bytes of signature on
each cert.

## See also

- `docs/identity-model.md` — the canonical sovereign-identity spec
  (master + delegations + auto-reissue).
- `docs/recovery.md` — classical (Ed25519-only) recovery flow.
- `docs/SECURITY.md` — operator-side threat model and mitigations.
