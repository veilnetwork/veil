# Operator Runbook — Hybrid Identity Backup & Recovery

This runbook covers the operator-side workflow for the post-quantum
hybrid (`ed25519+falcon512`) identity algorithm: how to create a
hybrid identity, what to back up, and how to restore it on a fresh
machine. Read this **before** running `veil-cli identity create
--algo hybrid` in production.

> **TL;DR**: hybrid identities require **two** independent backups —
> the BIP-39 paper phrase **and** the `master_falcon.bin` keypair
> file. Lose either one and the identity cannot be restored as
> hybrid; the `node_id` will change.

## Why two backups

A hybrid master key is two keypairs glued together:

| Half | Algorithm | Recoverable from |
|---|---|---|
| Classical | Ed25519 | BIP-39 paper phrase (24 words) |
| Post-quantum | Falcon-512 | `master_falcon.bin` file only |

The BIP-39 phrase deterministically reproduces the Ed25519 half. The
Falcon-512 half is generated fresh from `OsRng` at create time; there
is no seed-derivation path for Falcon-512 (current pqcrypto-falcon
crate doesn't expose one), so the only way to preserve the Falcon
half is to keep the on-disk file.

The `node_id` is `BLAKE3(ed_pk(32) || falcon_pk(897))` = 929 bytes
hashed. Lose the Falcon half and you cannot reproduce the original
929-byte hybrid pubkey, which means restore would have to fall back
to a fresh Falcon keypair — yielding a **different** `node_id`. Your
@name registration, contacts, and reputation are anchored to the old
`node_id` and would be lost.

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

DO NOT save the phrase to a hot file unless you also encrypt it
(`--password-file` will write `master.enc` for you, but the password
itself is then your single point of failure — pick this only if you
understand the trade-off).

### 2b. `master_falcon.bin` (digital)

This file is **2191 bytes** of opaque binary data starting with the
ASCII magic `OFAM`. Verify:

```bash
xxd /var/lib/veil/master_falcon.bin | head -1
# 00000000: 4f46 414d 0100 0005 01...
#           O F A M  ver 1   sk_len=1281 (0x501)
```

Recommended storage:
- **2-of-3 redundancy** across independent media — e.g. an encrypted
  USB stick, an air-gapped second machine, and an encrypted cloud
  storage bucket;
- **Same protection class as the BIP-39 phrase** — anyone who has
  this file plus the phrase has full PQ control of your identity;
- **Verify periodically** that the file is still readable AND that
  it still parses (use `veil-cli identity show` on a copy).

> Operators occasionally treat the Falcon file as "less critical"
> than the BIP-39 phrase because the phrase recovers _something_ on
> its own. **Do not.** A hybrid identity restored without the Falcon
> file is no longer the same identity at the network layer — the
> `node_id` differs, and every name claim, contact, and routing
> entry rooted at the old `node_id` becomes orphaned.

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

If `--master-falcon-file` is omitted on a hybrid restore the CLI
fails fast with:

```
restore: --algo=hybrid requires --master-falcon-file pointing at the
preserved master_falcon.bin (the BIP-39 phrase alone cannot recover
the post-quantum half — see docs/identity-hybrid-backup.md)
```

This is intentional; there is no silent degrade path to Ed25519-only
because that would change the `node_id` without warning.

## Step 4: rotation between algorithms (`identity migrate`)

If you start out with a classical Ed25519 identity and want to
upgrade to hybrid (or vice versa), the workflow is **migration**,
not restore. Available as `veil-cli identity migrate`.

### 4a. Create the new identity

On any machine:

```bash
veil-cli identity create --algo hybrid \
    --veil-dir /var/lib/veil-new \
    --label new-master
```

This mints a fresh `node_id`. Save the new BIP-39 phrase **and** the
new `master_falcon.bin` (same backup discipline as Step 2).

### 4b. Mint the migration cert

On a machine that has access to BOTH the OLD veil_dir AND the
OLD master secrets (BIP-39 phrase OR `master.enc` password, plus
the OLD `master_falcon.bin` if the OLD identity was hybrid /
Falcon-only):

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

After publish, current resolvers pick up the chain automatically —
`resolve_identity_verified(old_node_id)` returns
the NEW identity, with the cycle/depth/non-downgrade safeguards
described in `crates/veil-identity/src/resolver.rs`.

### 4d. Security non-downgrade enforcement

The CLI's `migrate` command (and the underlying
`migration::sign_migration_cert`) **rejects** any rotation that
lowers the security tier:

| OLD → NEW | Status |
|---|---|
| ed25519 → ed25519 | OK (refresh-only) |
| ed25519 → falcon512 | OK (PQ upgrade) |
| ed25519 → hybrid | OK (PQ upgrade, recommended) |
| falcon512 → hybrid | OK (regain BIP-39 path) |
| falcon512 → ed25519 | **REJECTED** (PQ → classical = downgrade) |
| hybrid → ed25519 | **REJECTED** (loses Falcon component) |
| hybrid → falcon512 | **REJECTED** (loses Ed25519 component) |

Tier ordering: `ed25519 (1) < falcon512 (2) < ed25519+falcon512 (3)`.

A downgrade attempt fails at sign time with:

```
migrate: sign_migration_cert: security downgrade rejected
(old_algo=3, new_algo=1)
```

This is a defence-in-depth check: even if the resolver-side check
were bypassed (e.g. by an out-of-band cert injection), `sign` itself
refuses to produce the cert blob.

## Step 5: forensics — what to do if the Falcon file is lost

If the BIP-39 phrase survives but `master_falcon.bin` is destroyed,
the operator has two choices:

1. **Mint a new hybrid identity** (`identity create --algo hybrid`)
   and publish a MigrationCert from the old hybrid `node_id` to the
   new one. The cert itself must be signed by the old master, which
   requires the lost Falcon file — so this path is **only** open if
   the Falcon file was lost recently and you still have a running
   live process holding the master in memory. If the live process
   is gone, the chain is broken.

2. **Mint a new Ed25519-only identity** (`identity create`, no
   `--algo`) using the BIP-39-recovered seed for ONE half, accept
   that the new `node_id` differs (BLAKE3(32 B) ≠ BLAKE3(929 B)),
   and re-establish your @name and contacts from scratch. This is
   the "lost everything" recovery — the only technically possible
   path when the Falcon material is gone permanently.

The BIP-39 phrase alone is therefore **not sufficient** for hybrid
recovery. Treat the two backups as a single recovery pair.

## Quick reference

| Need | File(s) |
|---|---|
| Boot a paired-down second device under the same identity | `master_falcon.bin` + BIP-39 phrase |
| Recover after device loss | `master_falcon.bin` + BIP-39 phrase |
| Decode `master.enc` if `--password-file` was used at create | password (separately stored) |
| Find the local `instance_id` for diagnostics | `<veil_dir>/instance_id` |

## Appendix A: standalone `--algo=falcon512`

Standalone Falcon-512 (`--algo=falcon512`) is supported but **not
recommended for production**. Read this section before considering it.

### What it is

A pure post-quantum master keypair. There is **no** classical
Ed25519 component, **no** BIP-39 paper-backup path, and **no**
recovery channel beyond `master_falcon.bin`.

```
node_id   = BLAKE3(falcon_pk(897 B))    // distinct from hybrid (BLAKE3(929 B))
master_pubkey = falcon_pk(897 B)
master_sk     = OsRng-derived Falcon-512 SK, lives ONLY in master_falcon.bin
```

### Why you might want it

- Pure-PQ deployment with no classical-key surface (no Ed25519 = no
  CRQC-recoverable artifact, even theoretically).
- Operator preference for not having a BIP-39 phrase as a forensic
  artifact (the phrase IS recoverable but also IS a target).
- Research / experimentation with pure post-quantum identities.

### Why it's dangerous

The BIP-39 phrase exists in the hybrid path **specifically to
provide a paper-backup recovery channel**. Removing it means:

- Loss of `master_falcon.bin` = total identity loss. No second
  channel.
- A mistyped path during backup = total identity loss.
- A failing disk you didn't notice during backup = total identity
  loss.
- A stolen device with `master_falcon.bin` and no operator alert =
  total identity compromise (no "rotate from the old phrase"
  recovery option).

### Required acknowledgement

The CLI refuses to mint a standalone Falcon-512 identity unless the
operator passes `--accept-no-recovery`:

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

### What `create` emits for Falcon-512

- The 24-word BIP-39 phrase block is **suppressed** — it doesn't
  recover anything, so showing it would be misleading.
- A loud `!!! WARNING ...` block prints on the operator stream.
- `master_falcon.bin` is created in `<veil_dir>` and printed with
  the `(PRESERVE — operator-side recovery medium)` annotation.

### Restore

```bash
veil-cli identity restore --algo falcon512 \
    --master-falcon-file /path/to/preserved_master_falcon.bin \
    --label new-host \
    --veil-dir /var/lib/veil
```

`--phrase-file` is **not required** (and noisy-warned if supplied —
the file is decoded for typo-detection but its bytes are not
consumed). The bundle reproduces the `node_id` byte-for-byte.

### Backup recommendation

**3-of-3** redundancy. Standalone Falcon-512 has zero recovery
buffer; one bad copy is one bad copy too few. For each backup:

1. Verify the file's `OFAM` magic header (`xxd | head -1`).
2. Verify the parser succeeds (`veil-cli identity show` against
   a temp restore-target).
3. Refresh on a known schedule (quarterly, at minimum).

If you cannot commit to 3-of-3, **use `--algo=hybrid` instead.** The
hybrid path's classical half mitigates exactly the failure modes
this section enumerates, at the cost of an extra 64 bytes of
signature on each cert.

## See also

- `docs/identity-model.md` — the canonical sovereign-identity spec
  (master + delegations + auto-reissue).
- `docs/recovery.md` — classical (Ed25519-only) recovery flow.
- `docs/SECURITY.md` — operator-side threat model and mitigations.
