# Release-manifest signing (installer supply-chain authenticity)

> **Status:** key **pinned**; verification **live on both installers**;
> CI signing **optional (warn-fallback)**. The pinned Ed25519 public key is
> embedded in BOTH `scripts/install.sh` (`pinned_release_pubkey`) and
> `scripts/install.ps1` (`Get-PinnedReleasePubkey`). When the release workflow
> publishes a `sha256-<triple>.txt.sig` and a verifier is available
> (OpenSSL ≥ 3.0), the installer verifies it and **fail-closes on a bad/missing
> signature**. When no signature is published, or no capable OpenSSL is present,
> the installer **warns and falls back to sha256-only** — no regression versus
> the prior channel-trust behaviour. Pass `--require-signature` (Unix) /
> `-RequireSignature` (Windows) to make verification mandatory. The remaining
> "arm" action is making the CI `RELEASE_INSTALLER_ED25519_SK` secret required
> so every release publishes a signature (see the release workflow).

## What this protects (and what it does not)

`scripts/install.sh` downloads prebuilt binaries plus a `sha256-<triple>.txt`
manifest and checks each binary's hash against that manifest. On its own the
manifest only proves the **binary and manifest agree** — an attacker who can
write to the GitHub Release assets (or who controls a mirror / `VEIL_REPO`
fork) can serve a malicious binary **with a matching manifest** and the hash
check passes.

A detached **Ed25519 signature over the manifest**, verified against a public
key **pinned inside `install.sh`**, raises the bar to *forging the operator's
release private key*. Verification uses `openssl`, which is **independent of the
downloaded binary** — a malicious binary cannot "verify itself".

Scope:

* **Closes:** tampered/replaced release artifacts, malicious mirrors, and forks
  that serve a self-consistent (binary + sha256) pair.
* **Does NOT replace** the in-app self-update path, which already verifies the
  hybrid Ed25519+Falcon `UpdateManifest` (`veil-update`). This installer
  signature is a *separate, shell-verifiable* Ed25519 signature used only for
  the first-install bootstrap (the hybrid scheme can't be verified in pure
  shell because of Falcon).
* **Trust root** remains the pinned public key shipped *in the script itself*
  (fetched over TLS from `raw.githubusercontent.com`). Signing defends the
  Release artifacts even when the repo source is not compromised.

## Threat-model note

The signature is verified only when the installing host has **OpenSSL ≥ 3.0**
(`pkeyutl -rawin` for one-shot Ed25519). LibreSSL — the default `openssl` on
macOS — and OpenSSL ≤ 1.1 lack it. On such hosts the installer warns and falls
back to sha256-only unless `--require-signature` is passed (which then hard-
fails). For a guaranteed check, install OpenSSL 3.x or run with
`--require-signature`.

## Key ceremony (operator, one-time)

Do this on a trusted, offline-capable machine. The **private key never leaves**
it except as a CI secret.

Generate the keypair **outside the repository working tree** so the private
key can never be `git add`-ed by accident — e.g. under `~/.config/veil/`. The
repo `.gitignore` also globs `*-release-*.key` as a backstop, but the primary
control is keeping the file out of the tree in the first place.

```sh
# 1. Generate an Ed25519 release-signing keypair, OUTSIDE the repo.
umask 077
mkdir -p ~/.config/veil
openssl genpkey -algorithm ed25519 -out ~/.config/veil/veil-release-ed25519.key
openssl pkey -in ~/.config/veil/veil-release-ed25519.key \
  -pubout -out ~/.config/veil/veil-release-ed25519.pub

# 2. Inspect the public key you will pin.
cat ~/.config/veil/veil-release-ed25519.pub
# -----BEGIN PUBLIC KEY-----
# MCowBQYDK2VwAyEA....
# -----END PUBLIC KEY-----
```

### 2. Add the private key as a CI secret

Repository → Settings → Secrets and variables → Actions → **New repository
secret**:

* **Name:** `RELEASE_INSTALLER_ED25519_SK`
* **Value:** the full PEM body of `veil-release-ed25519.key` (the
  `-----BEGIN PRIVATE KEY----- … -----END PRIVATE KEY-----` block).

`.github/workflows/release.yml` (publish job) signs each `sha256-<triple>.txt`
with this key and uploads `sha256-<triple>.txt.sig`. The step self-verifies the
signature before release and is skipped automatically when the secret is unset.

### 3. Pin the public key in the installer

Paste the **public** PEM into the `pinned_release_pubkey()` heredoc in
`scripts/install.sh`:

```sh
pinned_release_pubkey() {
    cat <<'PUBKEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA....
-----END PUBLIC KEY-----
PUBKEY
}
```

Commit it. From the next release on, a host with OpenSSL ≥ 3.0 verifies the
signature **fail-closed** (missing or invalid signature aborts the install).

### 4. Store the private key safely

Keep `veil-release-ed25519.key` offline (hardware token / encrypted backup)
and **never inside the repo working tree** — store it under a per-user config
dir (`~/.config/veil/`) or a secrets manager, not the checkout. Compromise of
this key lets an attacker mint installer-trusted manifests, so treat it like
the `VEIL_RELEASE_IDENTITY_TOML` update-signing key.

The same rule applies to the **update-signing** identity (`release-identity.toml`,
read locally via `veil-cli ... update --identity <path>`): it takes an arbitrary
path, so point it at an out-of-tree file (`--identity ~/.config/veil/release-identity.toml`)
rather than dropping it in the repo root. In CI both keys come from repository
secrets (`RELEASE_INSTALLER_ED25519_SK`, `VEIL_RELEASE_IDENTITY_TOML`), never a
committed file. The repo `.gitignore` globs the conventional secret filenames
(`*-release-*.key`, `release-identity*.toml`, …) as a last-resort backstop —
defence in depth, not the primary control.

## Verification behaviour matrix

| Pinned key | OpenSSL ≥ 3.0 | `.sig` present & valid | `--require-signature` | Outcome |
|---|---|---|---|---|
| no  | —   | —   | no  | warn, sha256-only (status quo) |
| no  | —   | —   | yes | **abort** (no key to verify against) |
| yes | no  | —   | no  | warn, sha256-only |
| yes | no  | —   | yes | **abort** (no capable verifier) |
| yes | yes | missing | any | **abort** (key pinned, sig absent) |
| yes | yes | invalid | any | **abort** (tamper / wrong key) |
| yes | yes | valid   | any | verified ✓ |

`--no-verify` skips **all** verification (sha256 *and* signature) — escape hatch
only.

## Testnet keys

For a testnet you can use a throwaway key without touching the committed
installer: generate a key as above, set the `RELEASE_INSTALLER_ED25519_SK`
secret in the testnet repo, and run the installer with the public PEM in the
`VEIL_RELEASE_PUBKEY_PEM` environment variable (it overrides the pinned key):

```sh
VEIL_RELEASE_PUBKEY_PEM="$(cat ~/.config/veil/veil-release-ed25519.pub)" \
  sh install.sh --require-signature
```

## Rotation

1. Generate a new keypair (ceremony above).
2. Update the `RELEASE_INSTALLER_ED25519_SK` secret to the new private key.
3. Update `pinned_release_pubkey()` to the new public key; commit.
4. Cut a release — it is signed by the new key and verified by the updated
   installer.

Old installers (with the previous pinned key) will reject new releases until
users re-fetch `install.sh`; this is expected. There is no in-band revocation —
rotation is by republishing the script, same as the binary trust root.
