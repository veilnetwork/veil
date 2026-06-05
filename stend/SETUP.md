# stend — local 5-node test stand setup

After cloning the repo the per-node identity files и `config.toml`
files do **not** exist (they're `.gitignore`d — see Phase 6.49 audit
follow-up: previously these files were committed, including private
keys, which was а security violation if the repo were ever published
or forked).

Regenerate them with:

```bash
bash stend/setup.sh
```

This creates:

- `stend/node{1..5}/veil/device_identity_sk.bin` (32-byte Ed25519 seed)
- `stend/node{1..5}/veil/identity_document.bin`
- `stend/node{1..5}/veil/instance_id`
- `stend/node{1..5}/config.toml` (с populated `[Identity]` section)
- `stend/node{1..5}/veil.txt` (operator's notes — empty by default)

## Why split out

Stend is а dev-only convenience — replacing each node's identity
between runs is fine, but committing keys was а mistake.  The setup
script is idempotent (skip-if-exists) so re-running is safe.

## Removing residue from а previous clone

If you cloned before this fix, your working tree may still have the
stale committed files.  Remove them с:

```bash
rm -rf stend/node{1..5}/veil
rm -f  stend/node{1..5}/config.toml
rm -f  stend/node{1..5}/veil.txt
bash stend/setup.sh
```

## TLS test cert (`ssl/`)

The `ssl/key.pem` + `ssl/cert.pem` test pair is also `.gitignore`d.
Regenerate с:

```bash
bash ssl/gen.sh
```

`ssl/gen.sh` issues а 365-day self-signed cert for `example.local`.
For production deployment use real certs (Let's Encrypt etc.) — this
pair is purely for local TLS-loopback testing.
