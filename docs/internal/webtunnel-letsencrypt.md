# Webtunnel + Let's Encrypt deployment guide

Anti-censorship strategy P1 #3 — closes DPI method #15 (FakeTLS validation by active probe).

This guide explains how к deploy an veil node's webtunnel-wss transport behind а Caddy reverse-proxy с а real Let's Encrypt cert, so the public-facing TLS endpoint is indistinguishable от any other small static site under active DPI probing.

## What changes vs. the old `deploy-webtunnel.yml`

The previous deployment put veil directly on `:443` с а self-signed cert + а one-paragraph default decoy.  Two failure modes for а VAS-class adversary's active probe:

1. **Cert-chain validation**: self-signed → fails any heuristic checking for а publicly-trusted issuer.
2. **Decoy thinness**: one paragraph ("Server status / All systems operational") looks machine-generated.

The new `deploy-webtunnel-autotls.yml` puts Caddy в front:

```
                ┌──────────────────────────────────────────┐
                │  Caddy on :443 (public)                  │
                │    – Let's Encrypt cert (auto-renewing)  │
                │    – Multi-page decoy site               │
   public  ───→ │    – reverse_proxy /_t/<secret>* к 127.0.0.1:18443
                └──────────────────────────────────────────┘
                                  │
                                  ▼
                ┌──────────────────────────────────────────┐
                │  veil on 127.0.0.1:18443 (loopback)   │
                │    – Webtunnel-WSS upgrade handler       │
                └──────────────────────────────────────────┘
```

## Prerequisites

* **Public DNS hostname** resolving к the host's public IP (Let's Encrypt's HTTP-01 challenge needs this).  Set via `veil_host` в the inventory entry.
* **ACME contact email** set via `veil_email` (same field used by the legacy bootstrap playbook).
* **Ports 80 + 443** reachable от the public internet.  Caddy listens on `:80` briefly для the HTTP-01 challenge и redirects к HTTPS.
* **Operator-controlled DNS**: you must be able к point the hostname at the host's IP.  An А record is sufficient.
* **Debian/Ubuntu** host (the playbook uses the `apt` module).  Caddy ships official packages для both.

## Run

```bash
cd ansible/
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml --limit b1
```

The playbook is **idempotent**: re-running re-stages config но only restarts Caddy если the Caddyfile changed.

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
| `webtunnel_internal_port` | `18443` | Loopback port где veil's webtunnel-wss listener binds.  Caddy reverse-proxies the secret path here.  Change if conflicting с other local services. |
| `webtunnel_listen_id` | `0x00000007` | veil `node.toml` listen-array id для the entry.  Change only when migrating an existing deployment с а different id. |
| `webtunnel_secret_path` | random 32 chars | The `/_t/<token>` path Caddy proxies к veil.  Regenerated every run by default — clients need а fresh invite после rotation. |

### Customizing the decoy site

The defaults в `ansible/templates/decoy-index.html.j2` и `decoy-about.html.j2` are placeholder content.  Replace с something more believable перед deployment:

* А real snapshot of а small static site you used к maintain
* An open-source project landing page
* А portfolio site (with the contact info anonymized)

The goal is **historical substance**: pages с dates from previous years, internal cross-links, и plain content that survives Wayback-Machine spot-checks.

Where к stage replacements:

```bash
# Replace templates BEFORE running playbook:
cp my-real-site/* ansible/templates/
mv ansible/templates/index.html ansible/templates/decoy-index.html.j2
mv ansible/templates/about.html ansible/templates/decoy-about.html.j2
# Add Jinja2 variable interpolation для `{{ veil_host }}` etc.
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml --limit b1
```

## Client invite rotation

When the secret-path rotates (per re-run или manual change), existing client invites pointing к the old path will stop working.  Rotation requires:

1. **Save the new secret-path**: it's printed в the final task's `msg:` after deploy.
2. **Generate а new invite** на the host via the veil-cli `bootstrap invite create` flow.
3. **Distribute** к users (existing 481.x out-of-band paths: QR, HTTPS bootstrap URL, encrypted invite envelope).

To keep а stable secret-path across re-runs, pass it explicitly:

```bash
ansible-playbook -i inventory.yml deploy-webtunnel-autotls.yml \
  --extra-vars 'webtunnel_secret_path=/_t/MyStableSecret12345678901234' \
  --limit b1
```

## Verification

The playbook itself runs three post-deploy checks:

1. **Decoy site serves expected content** — `curl https://veil_host/` matches the `decoy_site_name`.
2. **Secret path proxies к veil** — `curl https://veil_host/_t/<token>` doesn't return Caddy's file_server 404 (i.e., veil is on the other end и either rejects the non-WS request or returns а WSS-upgrade error — both confirm proxying works).
3. **Veil listens loopback-only** — `ss -tlnp` finds the webtunnel listener bound к `127.0.0.1:18443` (not `0.0.0.0`).

If any check fails, the playbook exits с the specific failure.  Common debug paths:

```bash
# Caddy status (cert-acquisition errors live here)
ssh root@<host> 'journalctl -u caddy --since "10 minutes ago" | tail -50'

# veil status
ssh root@<host> 'journalctl -u veil.service --since "5 minutes ago" | tail -50'

# Check the resolved DNS:
ssh root@<host> 'getent hosts <veil_host>'

# Manual cert-issuance test (от the host itself):
ssh root@<host> 'curl -fsS https://<veil_host>/.well-known/acme-challenge/foo'
```

## Rollback

The Caddy/Let's Encrypt path is а pure additive replacement of the old `deploy-webtunnel.yml`.  Rollback options:

* **К the old self-signed webtunnel**: re-run `deploy-webtunnel.yml` — it ignores the loopback config и puts а fresh `webtunnel-wss://0.0.0.0:8443` entry в the listen array.  The Caddy-Lefsy installation remains on disk но veil no longer requires Caddy.
* **К pre-webtunnel state**: drop the listen entries с id `0x00000003` (old playbook) и `0x00000007` (this playbook) от `/var/lib/veil/node.toml`; restart veil; optionally `apt remove caddy`.

## Composition с other anti-censorship layers

This playbook closes #15 (FakeTLS via active probe).  Compose с:

* **PoW-Gated Rendezvous** (`enable-stealth-canary.yml`) — closes #4/#6/#16/#17 (IP-discovery via scan).  Stealth listeners can run alongside webtunnel — they're orthogonal: one is для anti-scan, the other для anti-probe.
* **DoT/DoH bootstrap** (shipped в `crates/veil-bootstrap/src/dns.rs`) — closes #9–#12 (DNS-level manipulation).
* **obfs4-tcp listener** (from `deploy-obfs4.yml`) — closes #1/#19/#33 (wire-level fingerprinting via obfuscated framing).

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) для the full DPI threat-model + roadmap.
