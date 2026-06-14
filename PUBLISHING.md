# Publishing checklist (anonymization)

This tree was anonymized for public release. All personal + infrastructure
identifiers were replaced with placeholders. **Before going public, fill in the
values below from your anonymous accounts.** Search-and-replace is safe — each
placeholder is unique.

> Git history was squashed to a single anonymous commit (`veilnetwork`
> author). The internal handover docs `CONTEXT.md` and `MEMORY.md` were removed.

---

## 1. Account names — already set to `veilnetwork`

Both the GitHub owner and the Docker Hub user are set to `veilnetwork`
everywhere. If your real anonymous handles differ, replace `veilnetwork`:

```sh
# GitHub owner + Docker Hub user (only if not literally "veilnetwork")
git grep -lI 'veilnetwork' | xargs sed -i '' 's#veilnetwork#YOUR_ANON_HANDLE#g'
```

Files that reference it: `README.md`, `docs/{en,ru}/install.md`,
`docs/{en,ru}/user-guide.md`, `scripts/install.sh`, `scripts/install.ps1`,
`scripts/install-bootstrap.sh`, `docker/*`, `ansible/group_vars/all.yml`,
`ansible/README.md`, `specification.md`, `TASKS.md`,
`flutter/veil_flutter/ios/veil_flutter.podspec`.

- **GitHub**: `github.com/veilnetwork/veil` + raw URLs +
  `releases/download/...` (install scripts resolve `VEIL_REPO` / `REPO`).
- **Docker Hub**: image `veilnetwork/veil` (build via
  `REPO=veilnetwork/veil ./docker/build-multiarch.sh`).

If the published repo name is not `veil`, also replace `/veil` in those URLs.

---

## 2. Git identity for future commits

The squashed commit is authored as
`veilnetwork <veilnetwork@users.noreply.github.com>`. Set your local identity
to the same anonymous values so new commits don't re-leak your real name/email:

```sh
git config user.name  "veilnetwork"
git config user.email "veilnetwork@users.noreply.github.com"
```

(Use a GitHub *noreply* email, or your anonymous account's email — never the
real one.)

---

## 3. Bootstrap seed nodes — currently EMPTY

`crates/veil-bootstrap/src/seeds.rs` ships an empty `builtin_seeds()`. A
public binary therefore knows no seed nodes and won't phone home to anyone's
infrastructure.

To run a real network you (or downstream operators) supply seeds one of three
ways — **none required for publication**:

- **Built in:** populate `builtin_seeds()` (see the example shape in the file)
  and build with `--features production-seeds`. *Only do this in a private
  build* — committing real seed domains/keys re-introduces the leak.
- **Config / CLI:** `veil-cli peers add ...` or `bootstrap_peers` in config.
- **Ansible:** fill `veil_bootstrap_peers` in `ansible/inventory.yml`.

The public binary must be built with `--features allow-empty-seeds`
(CI / `release.yml` already does, via the feature chain).

---

## 4. Deployment configs — placeholder values

These are templates with RFC 5737 documentation IPs (`203.0.113.0/24`),
`example.com` domains, and `REPLACE_...` placeholders. Fill in real values
**only in private** (do not commit real infra to the public repo):

| File | Placeholders to replace |
|---|---|
| `ansible/inventory.yml` | `203.0.113.11-13` (bootstrap IPs), `203.0.113.21-25` (node IPs), `b{1,2,3}.example.com`, `admin@example.com`, `REPLACE_WITH_*_PUBKEY`, `REPLACE==` nonces |
| `monitoring/prometheus.yml` | `203.0.113.*:19999` scrape targets |
| `docker/.env.example` | `VEIL_IMAGE` (already `veilnetwork/veil`) |
| `docs/{en,ru}/p-net.md` | `<base64 ed25519 owner pubkey>` example |
| `crates/{ogate,oproxy}/src/config_template.rs` | `<base64 ed25519 owner pubkey>` example |

---

## 5. Pre-publish verification

Re-run the leak sweep before pushing to the public remote (should print all
zeros / empty):

Fill in the bracketed patterns with the identifiers you are scrubbing (your
real email, name, maintainer-handle, bootstrap domain suffix, server IP
prefixes, and seed-key prefixes), then run — all should print the "clean"
fallbacks:

```sh
# personal: <your-email-localpart> <first> <last> <email-domain> <bootstrap-domain> <old-gh-owner> <old-docker-user> <home-dir>
git grep -niE '<your-real-identifiers-pipe-separated>' || echo "clean — no personal identifiers"
# real server IP prefixes you used (anything NOT in 203.0.113.0/24 / RFC1918):
git grep -nE '<ip-prefix-1>|<ip-prefix-2>' || echo "clean — no real IPs"
# first ~8 base64 chars of each real seed pubkey:
git grep -nE '<seed-pubkey-prefix-1>|<seed-pubkey-prefix-2>' || echo "clean — no real seed keys"
git log --format='%an %ae %cn %ce' | sort -u   # must show ONLY the anon identity
```

Also confirm the new public remote is a fresh anonymous repo (not the private
one):

```sh
git remote -v   # should point at the anonymous GitHub repo before any push
```

---

## 6. What was removed / changed (audit trail)

- **Removed:** internal session-handover docs.
- **Emptied:** `builtin_seeds()` (real bootstrap domains + Ed25519 keys/nonces).
- **Replaced:** real testnet IPs → `203.0.113.*` (RFC 5737); real domains →
  `*.example.com`; maintainer email/name → `admin@example.com` / removed; real
  home-dir paths; the prior GitHub owner + Docker Hub user → `veilnetwork`;
  leaked example `app_cert_trusted_owner_pubkey` (it equalled a real seed key)
  → placeholder.
- **History:** the full commit history was squashed to one anonymous root
  commit.
- **Naming:** the project ships under the `veil` name throughout — crate names
  (`veil-*`, `veilcore`, `veilclient`, `veilclient-ffi`), FFI C symbols and
  constants (`veil_*` / `VEIL_*`, header `veil_ffi.h`), env vars (`VEIL_*`),
  wire-domain separation strings, file/dir paths, and the Flutter plugin
  (`flutter/veil_flutter`). The two IPC sidecar binaries are `ogate` / `oproxy`.

> **CI release secret.** `.github/workflows/release.yml` reads the repository
> secret **`VEIL_RELEASE_IDENTITY_TOML`**. Create it under that exact name in
> the public repo, or the signed-release job will fail.
>
> Release/update-signing **private keys never belong in the working tree.** In
> CI they come from repository secrets; for local signing keep them out of the
> checkout (e.g. `~/.config/veil/`) and pass the path explicitly
> (`veil-cli ... update --identity ~/.config/veil/release-identity.toml`). The
> `.gitignore` globs the conventional secret filenames as a backstop only — see
> [`docs/en/release-signing.md`](docs/en/release-signing.md).

This file (`PUBLISHING.md`) can be deleted before or kept after publication —
it contains no sensitive data.
