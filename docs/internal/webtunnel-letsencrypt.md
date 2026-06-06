# Webtunnel + Let's Encrypt deployment guide

Anti-censorship strategy P1 #3 — closes DPI method #15 (FakeTLS validation by active probe).

This guide explains how to deploy a veil node's webtunnel-wss transport behind a Caddy reverse-proxy with a real Let's Encrypt cert, so the public-facing TLS endpoint is indistinguishable from any other small static site under active DPI probing.

## What changes vs. the old `deploy-webtunnel.yml`

The previous deployment put veil directly on `:443` with a self-signed cert + a one-paragraph default decoy.  Two failure modes for a VAS-class adversary's active probe:

1. **Cert-chain validation**: self-signed → fails any heuristic checking for a publicly-trusted issuer.
2. **Decoy thinness**: one paragraph ("Server status / All systems operational") looks machine-generated.

The new `deploy-webtunnel-autotls.yml` puts Caddy in front:

```
                ┌──────────────────────────────────────────┐
                │  Caddy on :443 (public)                  │
                │    – Let's Encrypt cert (auto-renewing)  │
                │    – Multi-page decoy site               │
   public  ───→ │    – reverse_proxy /_t/<secret>* to 127.0.0.1:18443
                └──────────────────────────────────────────┘
                                  │
                                  ▼
                ┌──────────────────────────────────────────┐
                │  veil on 127.0.0.1:18443 (loopback)      │
                │    – Webtunnel-WSS upgrade handler       │
                └──────────────────────────────────────────┘
```

## Prerequisites

* **Public DNS hostname** resolving to the host's public IP (Let's Encrypt's HTTP-01 challenge needs this).  Set via `veil_host` in the inventory entry.
* **ACME contact email** set via `veil_email` (same field used by the legacy bootstrap playbook).
* **Ports 80 + 443** reachable from the public internet.  Caddy listens on `:80` briefly for the HTTP-01 challenge and redirects to HTTPS.
* **Operator-controlled DNS**: you must be able to point the hostname at the host's IP.  An A record is sufficient.
* **Debian/Ubuntu** host (the playbook uses the `apt` module).  Caddy ships official packages for both.

## Run

```bash
cd ansible/
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml --limit b1
```

The playbook is **idempotent**: re-running re-stages config but only restarts Caddy if the Caddyfile changed.

### Per-host customization

The playbook ships sensible defaults.  Override per-host via `--extra-vars`:

```bash
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml \
  --extra-vars '
    decoy_site_name="Personal Blog"
    webtunnel_internal_port=18443
  ' \
  --limit b2
```

Available overrides:

| Variable | Default | Purpose |
|---|---|---|
| `decoy_site_name` | `Notes &amp; Drafts` | Visible site name in the decoy page title + header.  Personalize per host so they don't all look identical. |
| `webtunnel_internal_port` | `18443` | Loopback port where veil's webtunnel-wss listener binds.  Caddy reverse-proxies the secret path here.  Change if conflicting with other local services. |
| `webtunnel_listen_id` | `0x00000007` | veil `node.toml` listen-array id for the entry.  Change only when migrating an existing deployment with a different id. |
| `webtunnel_secret_path` | random 32 chars | The `/_t/<token>` path Caddy proxies to veil.  Regenerated every run by default — clients need a fresh invite after rotation. |

### Customizing the decoy site

The defaults in `ansible/templates/decoy-index.html.j2` and `decoy-about.html.j2` are placeholder content.  Replace with something more believable before deployment:

* A real snapshot of a small static site you used to maintain
* An open-source project landing page
* A portfolio site (with the contact info anonymized)

The goal is **historical substance**: pages with dates from previous years, internal cross-links, and plain content that survives Wayback-Machine spot-checks.

Where to stage replacements:

```bash
# Replace templates BEFORE running playbook:
cp my-real-site/* ansible/templates/
mv ansible/templates/index.html ansible/templates/decoy-index.html.j2
mv ansible/templates/about.html ansible/templates/decoy-about.html.j2
# Add Jinja2 variable interpolation for `{{ veil_host }}` etc.
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml --limit b1
```

## Client invite rotation

When the secret-path rotates (per re-run or manual change), existing client invites pointing to the old path will stop working.  Rotation requires:

1. **Save the new secret-path**: it's printed in the final task's `msg:` after deploy.
2. **Generate a new invite** on the host via the veil-cli `bootstrap invite create` flow.
3. **Distribute** to users (existing 481.x out-of-band paths: QR, HTTPS bootstrap URL, encrypted invite envelope).

To keep a stable secret-path across re-runs, pass it explicitly:

```bash
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml \
  --extra-vars 'webtunnel_secret_path=/_t/MyStableSecret12345678901234' \
  --limit b1
```

## Verification

The playbook runs three checks of its own once the deploy finishes:

1. **Decoy site serves expected content** — `curl https://veil_host/` matches the `decoy_site_name`.
2. **Secret path proxies to veil** — `curl https://veil_host/_t/<token>` doesn't return Caddy's file_server 404 (i.e., veil is on the other end and either rejects the non-WS request or returns a WSS-upgrade error — both confirm proxying works).
3. **Veil listens loopback-only** — `ss -tlnp` finds the webtunnel listener bound to `127.0.0.1:18443` (not `0.0.0.0`).

If any check fails, the playbook exits with the specific failure.  Common debug paths:

```bash
# Caddy status (cert-acquisition errors live here)
ssh root@<host> 'journalctl -u caddy --since "10 minutes ago" | tail -50'

# veil status
ssh root@<host> 'journalctl -u veil.service --since "5 minutes ago" | tail -50'

# Check the resolved DNS:
ssh root@<host> 'getent hosts <veil_host>'

# Manual cert-issuance test (from the host itself):
ssh root@<host> 'curl -fsS https://<veil_host>/.well-known/acme-challenge/foo'
```

## Rollback

The Caddy/Let's Encrypt path is a pure additive replacement of the old `deploy-webtunnel.yml`.  Rollback options:

* **To the old self-signed webtunnel**: re-run `deploy-webtunnel.yml` — it ignores the loopback config and puts a fresh `webtunnel-wss://0.0.0.0:8443` entry in the listen array.  The Caddy/Let's-Encrypt installation remains on disk but veil no longer requires Caddy.
* **To the pre-webtunnel state**: drop the listen entries with id `0x00000003` (old playbook) and `0x00000007` (this playbook) from `/var/lib/veil/node.toml`; restart veil; optionally `apt remove caddy`.

## Composition with other anti-censorship layers

This playbook closes #15 (FakeTLS via active probe).  Compose with:

* **PoW-Gated Rendezvous** (`enable-stealth-canary.yml`) — closes #4/#6/#16/#17 (IP-discovery via scan).  Stealth listeners can run alongside webtunnel — they're orthogonal: one is for anti-scan, the other for anti-probe.
* **DoT/DoH bootstrap** (shipped in `crates/veil-bootstrap/src/dns.rs`) — closes #9–#12 (DNS-level manipulation).
* **obfs4-tcp listener** (from `deploy-obfs4.yml`) — closes #1/#19/#33 (wire-level fingerprinting via obfuscated framing).

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) for the full DPI threat-model + roadmap.
