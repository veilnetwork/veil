# Operations Guide

> **Companion docs:** [MONITORING.md](MONITORING.md) — what to watch and when to alert; [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom → cause → fix table.

## Quick Start

```bash
# Build (debug)
cargo build --release

# Generate identity (24-bit PoW mining — runs ≈30 s on a modern CPU)
veil-cli --config node.toml config init

# Start node (foreground; for systemd, use `node run --foreground`)
veil-cli --config node.toml node run
```

## Configuration

Config file: TOML format. Key sections:

| Section | Purpose | Key fields |
|---------|---------|------------|
| `identity` | Node keypair + PoW nonce | `algo`, `public_key`, `private_key`, `nonce`, `role` |
| `listen[]` | Transport listeners | `transport` (tcp/tls/quic/ws), `advertise`, `tls_*` |
| `peers[]` | Static peer list | `peer_id`, `public_key`, `transport`, `nonce` |
| `bootstrap_peers[]` | Discovery seeds (queried only when `peers` empty) | same as `peers[]` |
| `routing` | Gossip + cache tuning | `max_gossip_hops` (2), `reannounce_interval_secs` (30) |
| `session` | Session limits | `max_concurrent` (512), `tx_queue_depth` (4096), `idle_timeout_secs` (90) |
| `dht` | Kademlia tuning | `k` (20), `alpha` (3), `max_store_entries` (25K default, opt-up to 1M via cold tier), `shard_filtering` |
| `mailbox` | Offline storage | `enabled`, `quota_per_receiver_bytes`, `ttl_secs`, `require_capability_token` |
| `metrics` | Prometheus export | `listen` (e.g. `tcp://0.0.0.0:9090`), `path` |
| `[global].admin_socket` | Admin/CLI control plane endpoint | `unix:///path/to/admin.sock` or `tcp://127.0.0.1:0?runtime_dir=...` |
| `[ipc]` | Application-side IPC | `enabled`, `socket_uri` |

Full reference: [config-reference.md](config-reference.md).

## Common Operations

### Start / stop / reload

```bash
# Start
veil-cli -c node.toml node run

# Status (uses admin socket from config)
veil-cli -c node.toml node show
# → node_id, role, version, build_features, uptime, sessions/peers/listens count

# Reload config (apply changes without dropping sessions where possible)
veil-cli -c node.toml node reload

# Stop (SIGTERM); the runtime drains sessions for ≤5 s before exiting
kill <pid>          # or `systemctl stop veil-node`
```

### Inspect peers and sessions

```bash
veil-cli -c node.toml peers list             # configured peers
veil-cli -c node.toml peers banned           # active bans (manual + temp)
veil-cli -c node.toml sessions list          # short ids
veil-cli -c node.toml sessions list -v       # full 64-hex ids
veil-cli -c node.toml node dht routing       # Kademlia k-bucket contents
veil-cli -c node.toml node dht list          # DHT key-value store
veil-cli -c node.toml node metrics           # Prometheus-exporter snapshot
```

### Ban management

```bash
# Permanent ban (persisted in <config-dir>/bans.json)
veil-cli -c node.toml peers ban <NODE_ID_HEX>

# Lift a manual ban
veil-cli -c node.toml peers unban <NODE_ID_HEX>

# Kill a session by link_id (also installs a 30 s auto-ban to prevent immediate
# reconnect — use this for short-term mitigation; use `peers ban` for permanent)
veil-cli -c node.toml sessions kill <LINK_ID_HEX>
```

`peers ban` is symmetric on the wire — only one side needs to ban for new
connections to be rejected, but if both sides ban, neither will retry-loop.

### Binary upgrade

1. **Build new release:** `cargo build --release --features production-seeds`
2. **Stage on host:** copy new `veil-cli` next to old, e.g. `veil-cli.new`
3. **Atomic swap:** `mv veil-cli.new veil-cli`
4. **Restart:** `systemctl restart veil-node` (or kill + relaunch).
   Persisted state — bans, DHT values, identity, mailbox WAL — survives.
5. **Verify:** `veil-cli node show` → check `version:` matches expected build.

The wire protocol is OVL1 throughout the running stack.  Two binaries
that differ only in non-wire-format code (routing internals, log
formatting, defaults) are fully interoperable — no co-ordinated
fleet-wide upgrade is required.  When wire format changes (next major
version), follow the version-skew matrix in [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

## Seed Node Setup

A seed node is a long-lived public node whose `(public_key, transport, nonce)`
ships hard-coded in `node/bootstrap/seeds.rs::BUILTIN_SEEDS`.  Fresh nodes
with no `[[peers]]` and no `bootstrap_peers` configuration use these to
join the network.

### Pre-deploy checklist

1. **Provision host** — public IP, open inbound TCP port (default 7001),
   ≥2 CPU / ≥4 GB RAM / ≥10 Mbps sustained, ≥99 % uptime.
2. **Generate identity** locally on the seed host:
   ```bash
   veil-cli -c /etc/veil/seed.toml config init
   ```
   This mines a 24-bit PoW nonce (≈30 s).  Output `identity.public_key`,
   `identity.nonce`, computed `node_id` are all needed for the BUILTIN_SEEDS
   entry.
3. **Configure listener:**
   ```toml
   listen = [{ id = "0x00000001", transport = "tcp://0.0.0.0:7001" }]
   [identity]
   role = "core"
   ```
4. **Start in foreground for the first verification run:**
   ```bash
   veil-cli -c /etc/veil/seed.toml node run
   # watch logs for `listen.start`, no errors; Ctrl-C to stop
   ```

### Adding seeds to the binary

Edit `crates/veil-bootstrap/src/seeds.rs`:

```rust
const BUILTIN_SEEDS: &[BootstrapPeer] = &[
    BootstrapPeer {
        transport:    "tcp://seed-1.veil.example:7001",
        public_key:   "BASE64_PUBKEY_FROM_seed.toml",
        nonce:        "BASE64_NONCE_FROM_seed.toml",
        algo:         SignatureAlgorithm::Ed25519,
        tls_cert:     None,
        tls_ca_cert:  None,
    },
    // … 2 or 3 more, in different geographic zones / providers
];
```

Build all client/seed binaries with the production-seeds feature flag:

```bash
cargo build --release --features production-seeds
```

The release-build compile-error guard (`veil/Cargo.toml` + `seeds.rs`)
will fail the build if `BUILTIN_SEEDS` is empty AND neither
`production-seeds` nor `allow-empty-seeds` is enabled.

### Multi-seed redundancy

- Run **at least 3** seeds across **different network providers and
  geographic regions** — losing one seed must not break network bootstrap.
- Keep seed identities in offline cold storage (laptop + paper backup).
  Recovery from a lost seed is a fleet-wide rebuild, not a runtime concern.
- Rotate one seed at a time; never simultaneously.

### `.onion` bootstrap source (Tor) — last-resort censorship escape

When every clearnet bootstrap layer is blocked (the operator's CDN hostnames,
the whole CDN, and DNS), an operator can publish the **signed seed bundle** at a
Tor `.onion` address and have nodes fetch it over a local Tor SOCKS proxy
(deferred backlog 481.4). Tor's exit/rendezvous diversity defeats IP/SNI
blocking of the bootstrap fetch itself.

```toml
[global]
# Any .onion URL in this list is fetched over Tor; clearnet URLs are
# unaffected and still use the direct PKI-verified HTTPS path.
bootstrap_https_urls = [
  "https://cdn1.example/seeds.json",      # clearnet — tried directly
  "http://abcd…xyz.onion/seeds.json",     # fetched via Tor
]
# Local Tor SOCKS5 endpoint. Required for the .onion URL above; if unset, the
# .onion URL is skipped (logged) and clearnet URLs are unaffected.
bootstrap_tor_socks_proxy = "socks5://127.0.0.1:9050"
# Pin the bundle issuer (strongly recommended) — see "signed bootstrap bundles".
trusted_bundle_issuer_pubkey = "<base64 issuer pubkey>"
```

**Why plain `http://`, not `https://`.** A `.onion` address *is* the service's
public key — connecting to it proves (via Tor's rendezvous) you reached its
holder, and the Tor circuit is already encrypted. There is no public-CA
certificate to verify, so TLS would add nothing. Authenticity comes instead
from the **signed bundle**, which the `.onion` path requires
**unconditionally**: raw JSON is rejected even when
`legacy_allow_unsigned_bootstrap = true`. (`https://…onion` URLs are rejected.)

**Setup.**
1. Run Tor (`apt install tor`; default client SOCKS at `127.0.0.1:9050`). On the
   host serving the bundle, add a `HiddenServiceDir` + `HiddenServicePort 80`
   pointing at your static file server, and read the generated `hostname`.
2. Sign the seed bundle (`veil-cli` bundle-signing) and serve the signed
   bytes at `http://<onion>/seeds.json`.
3. Add the `.onion` URL, `bootstrap_tor_socks_proxy`, and
   `trusted_bundle_issuer_pubkey` to client configs.

**Verification.** `journalctl -u veil-node | grep bootstrap.https` — a working
`.onion` source logs `bootstrap.https.found N seed(s) from http://…onion…`; a
missing proxy logs `bootstrap.https.fetch_failed … set [global]
bootstrap_tor_socks_proxy`.

**Scope.** The `.onion` host is handed to the Tor proxy as a SOCKS5 domain
address and resolved by Tor — never locally (no DNS leak). The fetch is bounded
by the same 10 s timeout and 64 KiB response cap as the clearnet path.

### systemd unit example

```ini
[Unit]
Description=Veil seed node
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=veil
Group=veil
ExecStart=/usr/local/bin/veil-cli -c /etc/veil/seed.toml node run --foreground
Restart=always
RestartSec=5
LimitNOFILE=65536
# Allow the daemon to mlock secret-key allocations (session AEAD keys,
# session_kdf OKM, identity_sk).  Without this, key material may swap to
# disk under memory pressure — see the "Memory locking" section below.
LimitMEMLOCK=infinity
# Keep state writable
ReadWritePaths=/var/lib/veil /run/veil

[Install]
WantedBy=multi-user.target
```

`/etc/veil/seed.toml` should set `[global].admin_socket =
"unix:///run/veil/admin.sock"` so `veil-cli` invocations work
without `-c` (when the user has read access to the socket).

## Memory locking (RLIMIT_MEMLOCK / CAP_IPC_LOCK)

Since Stage 6, the daemon attempts to `mlock(2)` every secret-key
allocation — session AEAD keys, session_kdf intermediate OKM, and
(via follow-up slices) identity_sk / master_seed / peer_mlkem cache.
This closes the **swap-to-disk leak** vector: an attacker with
adversary-time physical disk access could otherwise recover keys
from swap minutes-to-days after the session closed.

The mlock'd regions are additionally tagged with `MADV_DONTDUMP`
(Linux) or `MADV_NOCORE` (FreeBSD / NetBSD), excluding them from
process core dumps that systemd-coredump or friends would
otherwise capture under `/var/lib/systemd/coredump/` on a panic.
macOS lacks an equivalent madvise advisory — operators concerned
about crash-time exposure on Darwin should run `launchctl limit
core 0` to suppress cores process-wide.

### Required limits

| Environment | What to set | Why |
|---|---|---|
| systemd unit | `LimitMEMLOCK=infinity` (or a large explicit cap, e.g. `268435456` for 256 MiB) | Default Linux ulimit is 64 KiB per process; the daemon needs more for sustained-traffic sessions |
| Shell-launched debug | `ulimit -l unlimited` before `veil-cli node run` | Same reason; per-shell |
| Docker / Podman | `--ulimit memlock=-1:-1` or `--cap-add=IPC_LOCK` in `docker run` | Containers drop `CAP_IPC_LOCK` by default; without it, mlock() fails with EPERM regardless of RLIMIT_MEMLOCK |
| Kubernetes | `securityContext.capabilities.add: ["IPC_LOCK"]` + matching ulimit kubelet config | Same rationale as Docker |

### Operational visibility

The daemon does NOT abort on mlock failure.  Instead it logs a
**once-per-process** warn:

```
WARN  veil_util.sensitive_bytes.mlock_fallback
      mlock failed on key allocation, falling back to zeroize-only
      (bytes are still wiped on drop, but pages may swap to disk).
      Raise RLIMIT_MEMLOCK or grant CAP_IPC_LOCK to close swap exposure.
```

Scrape this log line — its presence on a production node indicates
the security guarantee Stage 6 ships has been **silently degraded**
to the pre-Stage-6 baseline (zeroize-on-drop only, no swap protection).
The daemon continues operating correctly; the leak vector is
re-opened.

### Verification

Bring a node up and confirm the limit applied:

```sh
$ cat /proc/$(pgrep veil-cli)/limits | grep "Max locked memory"
Max locked memory       unlimited            unlimited            bytes
```

If you see a small numeric value (e.g. `65536`), revisit the
systemd unit / container limits and restart.

### Trade-offs

mlock'd pages cannot be evicted by the kernel page reclaimer — they
permanently count against the host's physical RAM budget.  For a
typical veil-relay carrying 100-1000 concurrent sessions, the
mlocked footprint is **96 B × session_count** for OKM derivation
intermediates (function-scope; released after the function returns)
plus future per-session AEAD key sites (Stage 6 follow-up slices).
A relay carrying 10000 sessions with full Stage 6 coverage would peg
roughly 1-2 MiB of memlock — negligible relative to the daemon's
overall RSS.

Do NOT set `LimitMEMLOCK=infinity` on memory-constrained hosts
(< 256 MiB total RAM, e.g. some Raspberry Pi Zero deployments).
On those hosts a tightly-capped explicit value (`LimitMEMLOCK=16384`
= 16 MiB) leaves headroom for the daemon's working set while still
covering most key allocations.

## Config signing (Stage 11)

Since Stage 11 slice 11a, the daemon supports operator-signed config
files.  Pre-signing, anyone with filesystem write access could flip
`legacy_allow_unsigned_bootstrap = true`, lower
`anycast.resolve_policy` from `signed_only` to `best_effort`, redirect
bootstrap peers, etc. — without restarting the daemon.  A signed
config makes byte-level tamper surface as a structured WARN log; a
pinned-issuer setup additionally surfaces "wrong issuer" tamper.

### Signing a config file

Use the active `[identity]` keypair to sign the file in place:

```sh
veil-cli -c /etc/veil/config.toml config sign
# → emits an INFO line with the issuer pubkey fingerprint and issued_at;
#   atomically rewrites the file with a `# VEIL_CONFIG_SIGNATURE_V1: …`
#   comment header at the top.
```

Re-signing the same file replaces the previous signature header
(idempotent).  Use `--issued-at <UNIX_SECS>` to embed a specific
timestamp (default: `SystemTime::now()`).  Use `--stdout` for a
dry-run (prints signed bytes without writing back).

The signing key is the operator's `[identity]` keypair — same one
used for `config publish` bundles.  No separate keypair management.

### Pinning the trusted issuer pubkey (production hard-fail)

When `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` is set, the daemon
verifies the signature against THIS exact pubkey:

```ini
[Service]
Environment=VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY=<base64-encoded-pubkey>
```

Or for shell-launched invocations:

```sh
VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY=<base64> veil-cli node run
```

Pinning closes a subtle gap: in unpinned mode, the daemon accepts
ANY signature provided the envelope is internally consistent — a
wholly attacker-issued config with a fresh-but-attacker-owned key
would still pass.  Pinning catches that vector.

Pinning lives in the env-var rather than in `config.toml` itself
because pinning inside the config is chicken-and-egg: a tampered
config could simply remove the pin.  Env vars live in the systemd
unit / Docker compose / Kubernetes manifest — a separate trust
boundary from the operator's config bytes.

### Operational visibility

Scrape these log lines to monitor the signed-config state:

```
INFO  veil_cfg.signed_config
      config '<path>' signature verified (issuer=<fingerprint>…,
      issued_at=<unix_secs>, pinned=true|false)

WARN  veil_cfg.unsigned_config
      config file '<path>' has no signature header; tamper protection
      is OFF.

WARN  veil_cfg.signed_config_verify_failed
      config '<path>' has a signature header but verification failed:
      <structured-error>.  Loading anyway (refusal is opt-in via a
      future `require_signed_config = true` global flag).
      Investigate immediately — possible tamper or stale env-var pin.
```

Alert on **both** `unsigned_config` (deployment-config drift; the
operator forgot to sign) and `signed_config_verify_failed` (active
tamper or a pin / key rotation in-flight without coordination).

### Phase 1 vs phase 2 enforcement

Current behaviour is **phase 1 warn-only**: tampered configs still
load with a WARN log.  Operators get a grace window to sign their
existing configs without breaking deployments.

Phase 2 (separate future slice) adds a `require_signed_config = true`
global flag that flips the warn-only path to refuse-on-failure.  Set
this after every machine in the fleet has been signed AND verified
via dry-run.

### Stage 11e migration: per-origin byte cap + unsigned-STORE hard-fail

Slice 11e (Stage 11e) adds two complementary hardening knobs to the DHT
storage path:

**1. `[dht] per_origin_max_bytes = N`** — per-signer byte budget.  When set,
the local `TieredStore` tracks bytes-stored-per-signer pubkey, and a STORE
that would push the signer past `N` bytes is rejected at the daemon with
`PerOriginByteCapExceeded`.  Honest signers normally hold a handful of
records (NameClaim + IdentityDocument + a small fan-out of
AppEndpointEntry) — 64 KiB is a comfortable ceiling that still leaves
headroom for legitimate growth.  Misbehaving / Sybil signers can no longer
fill the store unilaterally — they can only fill their own per-origin
slice.  Operators who have **explicitly re-enabled** the legacy
`allow_unsigned_store = true` path (it now defaults to `false` — see
below) should note that all unsigned legacy STOREs share a single
synthetic origin bucket, so they collectively cap out at the same
per-origin budget; size it generously (≥ 4 MiB) on such networks.
`None` (default) disables the cap entirely — only the global
`max_store_bytes` limit (if set) applies.

Recommended profiles:

| Deployment profile | `[dht] per_origin_max_bytes` | Rationale |
|---|---|---|
| Leaf clients | `None` | `max_store_entries = 0` already suppresses storage |
| Core nodes | `Some(65_536)` | Single signer's worst-case fan-out (NameClaim + IdentityDocument + ~5 AppEndpointEntry) ≈ 12 KiB; 64 KiB leaves 5× headroom |
| Dedicated DHT seeds | `Some(262_144)` | Higher per-origin tolerance — these nodes carry the network's authoritative storage |
| Networks with `allow_unsigned_store = true` (explicitly re-enabled) | `Some(4_194_304)` | Generous bucket for the unsigned shared-origin pattern. Only relevant if you have opted back into the legacy flag — the default is now `false` and unsigned raw STOREs are rejected outright |

Log scrape: hits show up as `[dht] STORE rejected: signer's per-origin
byte cap exceeded` — a sustained burst from a single peer is a strong
indicator of attempted store-exhaustion (the per-origin cap turns the
attack from "fill the store" into "fill your own slice").

**2. `[dht] allow_unsigned_store`** — the default is now `false`
(secure-by-default).  Raw unsigned STOREs are **rejected** at the daemon
with `STORE rejected: unsigned authenticator + allow_unsigned_store=false`.
This is **not** a wholesale block on legacy publishing: self-authenticating
records (NameClaim, IdentityDocument, InstanceRegistry, MlkemCert,
SignedBootstrap, and the AnnounceEndpoint / AnnounceAttachment magics) plus
PBAN bans carry their own signed envelopes inside the `value` blob and
continue to propagate via the dispatcher's validated
`store_with_origin` / gate-bypass path **regardless of this flag** — only
genuinely unsigned, non-self-authenticating raw STOREs are gated.

The flag exists as an **explicit opt-back-in** for operators who still run
truly unsigned legacy STOREs.  When set back to `true`, the first time a
node accepts an unsigned STORE via this path it logs (once per process):

```
[dht] accepted unsigned STORE via allow_unsigned_store=true (legacy path) —
plan migration to signed STOREs; see docs/OPERATIONS.md → 'Stage 11e migration'
```

Subsequent unsigned STOREs are silent to avoid log spam.  The
recommendation is to leave the flag at its `false` default: the inner-sig
path keeps working if every STORE adds an explicit
`(ed25519_pubkey, ed25519_sig)` authenticator tuple, which the standard
publish helpers do automatically.

Migration walkthrough:

```bash
# 1. Set a conservative per_origin cap (64 KiB) — accepts everything
#    today but bounds the blast radius if a signer misbehaves.
echo '[dht]'                                       >> /etc/veil/node.toml
echo 'per_origin_max_bytes = 65536'                >> /etc/veil/node.toml

# 2. Reload and watch the cleanup-tick output for the deprecation warn.
veil-cli -c /etc/veil/node.toml config reload
journalctl -u veil-node -f | grep 'allow_unsigned_store=true'

# 3. A fresh default config already hard-fails unsigned ingress
#    (allow_unsigned_store defaults to false). This sed step is only
#    needed for OLD configs that explicitly set `= true` — it flips them
#    back to the secure default after you confirm no unsigned STOREs land.
sed -i 's/allow_unsigned_store = true/allow_unsigned_store = false/' \
    /etc/veil/node.toml
veil-cli -c /etc/veil/node.toml config reload
```

The default for `allow_unsigned_store` **has already been flipped to
`false`** (audit cycle-6, secure-by-default) — it is no longer a future
v1.0 event.  A freshly-generated config rejects unsigned raw STOREs out of
the box; the deprecation warn fires only on configs that have explicitly
re-enabled the legacy `= true` path, giving those operators a signal to
audit and migrate.

## Post-quantum signature algorithms (Stage 10)

The runtime supports four signature algorithms (selected via
`[identity] algo = "<name>"` in `config.toml` or the equivalent CLI
flags):

| Algorithm | `algo = …` | wire byte | pk size | sig size | Use case |
|---|---|---|---|---|---|
| Ed25519 (default) | `ed25519` | 1 | 32 B | 64 B | Classical, fast — default for non-identity signing |
| Falcon-512 (standalone) | `falcon512` | 2 | 897 B | ≤ 666 B | PQ-only, NIST PQC Level 1 |
| Ed25519 + Falcon-512 hybrid | `ed25519+falcon512` / `hybrid` | 3 | 929 B | ≤ 732 B | Classical + PQ Level 1 — recommended for long-lived sovereign identities |
| Ed25519 + Falcon-1024 hybrid | `ed25519+falcon1024` / `hybrid1024` | 4 | 1825 B | ≤ 1528 B | Classical + PQ Level 5 — higher PQ margin (~270-bit classical-equivalent vs ~103-bit for Falcon-512); use for identities that must outlive the CRQC horizon by a wider margin |

**Falcon-1024 hybrid availability** (Stage 10, slice 1):
- ✅ **Available**: `veil-cli config sign` + `veil-crypto::sign_message`
  / `verify_message` / `generate_keypair` — sign-and-verify with
  `--algo ed25519+falcon1024`.
- ✅ **Available**: wire-format mappings throughout
  (`veil-anonymity::directory` / `rendezvous`, `veil-bootstrap`,
  `veil-update::manifest`, `veil-identity::network_cert`,
  `veil-discovery::directory`, `veil-cfg::signed_config`,
  `veil-types::SignatureAlgorithm`).  The decoder accepts wire byte
  `4` everywhere, encoder emits it for the new variant.
- ⏳ **Future slice**: sovereign-identity creation
  (`veil-cli identity create --algo ed25519+falcon1024`).  BIP-39
  master-seed derivation for the Falcon-1024 hybrid layout (1825-byte
  master_pubkey) needs its own dedicated freshness / rotation /
  recovery path before this can ship safely.  Until then, identity
  creation stays on `ed25519+falcon512` (the recommended default).

**Choosing between Falcon-512 and Falcon-1024 hybrid**: the canonical
NIST PQC Level 5 ≈ AES-256 ≈ Falcon-1024 mapping. Operators running
honest-and-correct identities for 50+ year horizons should choose
Falcon-1024 hybrid; everyone else gets sufficient margin from Falcon-512
hybrid (NIST PQC Level 1 ≈ AES-128) and benefits from the 4-5× smaller
signature + key sizes.

## TLS ECH (Stage 10 slice 2)

Encrypted Client Hello (ECH) — RFC 8744 + draft-ietf-tls-esni — encrypts
the SNI field in the ClientHello so middleboxes cannot fingerprint the
target hostname for a TLS connection.  Most veil traffic uses
node-id-bound peer transport (`tls://` with `set_verify(NONE)`) where SNI
is a node-id literal, not a public DNS name, so traditional DNS-published
ECH does not apply.  But the **public-PKI HTTPS bootstrap path**
(`veil-bootstrap::https` fetches signed seed bundles from CDN URLs)
**does** speak ordinary TLS to public DNS names, and that's the connection
a censor's middlebox would fingerprint to build a target list.

### Rollout phases

| Slice | Status | What ships |
|---|---|---|
| **2a** | ✅ shipped 2026-05-28 | `GlobalConfig.tls_ech_grease` flag + audit-trail comment at the integration site (`veil-transport::tls::connect_pki_verified_https_stream`) + this docs section.  Flag is a no-op in slice 2a — sets the foundation. |
| **2b + 2c** | ✅ shipped 2026-05-28 | Bundled.  Workspace migrated from `rustls-ring` to `rustls-aws-lc-rs` crypto provider (4 quinn feature flags + 4 `default_provider()` call sites switched from `crypto::ring` to `crypto::aws_lc_rs`).  Actual `EchMode::Grease(EchGreaseConfig::new(DH_KEM_X25519_HKDF_SHA256_AES_128, random_placeholder))` wiring at the call site when `TransportContext::tls_ech_grease == true`.  Default flag flipped to `true` (slice 2c) since the workspace gates passed under aws_lc_rs with no observed regressions — operators on TLS 1.2-only public CDNs can override to `false`.  Pins TLS 1.3 for the public-HTTPS path when enabled (ECH requires 1.3). |
| **3** | ✅ shipped 2026-05-28 | Real ECH with `EchMode::Enable(EchConfig::new(...))` driven from DNS HTTPS RR (RFC 9460) lookups.  New `veil-transport::ech_dns::query_https_ech(host)` helper resolves the host's HTTPS record and extracts the `ech` SvcParamKey (key 5).  `connect_pki_verified_https_stream` tries real ECH first and falls back to slice 2c's GREASE on any DNS-side failure (NXDOMAIN, no HTTPS record, no `ech` SvcParamKey, malformed bytes, no supported HPKE suite).  Soft-failure model: DNS errors are logged at DEBUG (`tls.ech.dns`) but never propagated as TLS errors — GREASE fallback is always available.  `DnsResolver` trait extended with `resolve_https_ech` (default impl returns `None`); `SystemDnsResolver` overrides to use a process-wide hickory `TokioResolver` built lazily from system config with a 3 s lookup timeout. |

### Why GREASE ECH matters

Without GREASE, a middlebox can distinguish "ECH-capable" connections
(rare today) from "non-ECH" connections (the bulk of Web traffic).  Once
ECH adoption crosses a threshold, censors are forced into a binary
choice:

- **Block ECH-capable traffic**: visible failure mode — users see broken
  websites and notice the censorship.
- **Allow all TLS through**: ECH-real users get private SNI; ECH-GREASE
  users get cover traffic.

GREASE is the **cover traffic** half of that equation — it makes
ECH-capable connections indistinguishable from non-ECH connections at the
TLS layer.  Even before any operator publishes a real ECH config,
flipping GREASE to default-on on every veil client adds these
connections to the broader cover-traffic pool.

### Operator config

```toml
[global]
# Slice 2c default — `true`.  GREASE ECH on every public-PKI HTTPS
# fetch (bootstrap bundle, signed-update manifest).  Override to
# `false` only if you're stuck on TLS 1.2-only CDNs.
tls_ech_grease = true
```

### Why TLS 1.3 pinning

rustls's `with_ech` builder forces TLS 1.3 only — ECH is a 1.3-era
extension and does not exist in the 1.2 handshake.  Modern public CDNs
(Cloudflare, Fastly, AWS CloudFront, Google Cloud CDN) all support
1.3 since ~2018, so this is a non-issue in practice.  If a very old
CDN refuses your bootstrap connection after the flip, override
`tls_ech_grease = false` to restore 1.2 + 1.3 negotiation.

### Dependency migration (slice 2b background)

Slice 2b switched the workspace from `rustls-ring` to `rustls-aws-lc-rs`.
rustls 0.23.x supports ECH only when built with the `aws_lc_rs` crypto
provider (HPKE — the ECH inner-encryption primitive — is implemented
there only).  Surface area touched: 4 quinn feature flags in Cargo.toml
(veil-nat, veil-node-runtime, veil-transport, veilcore) +
4 `rustls::crypto::ring::default_provider()` call sites switched to
`rustls::crypto::aws_lc_rs::default_provider()` (3 in veil-nat,
1 in veil-transport).  Net binary size delta: ~3 MB; compile time
delta: ~20-30 s on M2-class hardware.

### Publishing a real ECH config (slice 3 operator-side)

Slice 3 reads `EchConfigList` from the target host's DNS HTTPS record.
For an operator that wants real ECH for their bootstrap CDN, the steps
are:

1. **Generate an HPKE keypair** + EchConfig.  Use [ech](https://crates.io/crates/ech)
   CLI or [Cloudflare's ECH config generator](https://github.com/cloudflare/ech).
   Pick HPKE suite `DH_KEM_X25519_HKDF_SHA256_AES_128` (suite ID `0x0020,0x0001,0x0001`)
   — the canonical default rustls accepts under aws-lc-rs.

2. **Encode the EchConfigList** to base64 (the DNS-presentation form
   of the `ech` SvcParamValue).

3. **Publish an HTTPS RR** under the bootstrap CDN's apex domain:

   ```text
   bootstrap.veil.example.    300  IN  HTTPS  1 .  alpn="h2,http/1.1"  ech="AED+DQA8AAAgACAAAQABAAEAAABL..."
   ```

   * Priority `1` (preferred).
   * Target `.` (defer to the A/AAAA records on the same name).
   * `alpn` SvcParamKey reflects the protocols the CDN serves.
   * `ech` SvcParamKey carries the base64-encoded EchConfigList.

4. **Deploy server-side ECH support** at the CDN.  Cloudflare, Fastly,
   AWS CloudFront, Google Cloud CDN all expose ECH config knobs through
   their respective control planes.

5. **Verify**: from a fresh veil client, watch `journalctl -u veil-node`
   for `[tls.ech.dns]` INFO lines confirming `real ECH selected
   host=bootstrap.veil.example`.  If DEBUG-level `tls.ech.dns`
   logs show "no supported HPKE suite available", the published
   config used a suite outside aws-lc-rs's
   [ALL_SUPPORTED_SUITES](https://docs.rs/rustls/0.23/rustls/crypto/aws_lc_rs/hpke/static.ALL_SUPPORTED_SUITES.html) — pick a supported one and re-publish.

Until operators publish HTTPS records with the `ech` SvcParamKey, slice 3
is a silent no-op: every connect tries the DNS lookup, gets `None`
back (no HTTPS record exists for most domains today), and falls back to
slice 2c's GREASE.  Soft-failure model means slice 3 ships safely
even in zero-real-ECH networks.

## TLS ClientHello fingerprint rotation (tls-boring)

Outbound `tls://` / `wss://` connects can present a **browser-like TLS
ClientHello** (JA3/JA4) and **rotate to a different one when a handshake
fails** — so a censor that blocks one fingerprint class, even Chrome's with
collateral damage accepted, does not sever connectivity.

> **Enabled by default** (the `tls-boring` feature is in `veil-cli`'s
> default set). A normal `cargo build` / release build gets fingerprint
> rotation; the BoringSSL backend needs `cmake` + a C/C++ toolchain at build
> time. **Opt out** for pure-Rust / cross-compile targets (routers, embedded,
> no cmake):
>
> ```sh
> cargo build -p veil-cli --no-default-features --features rocksdb-cold
> ```
>
> The opt-out build uses the `rustls` stack, which cannot customise its
> ClientHello and **ignores** this config — it emits one fixed,
> rustls-identifiable fingerprint.

### Operator config

```toml
[transport.tls_fingerprint]
# "rotate" (default) | "pinned" | "random"
mode = "rotate"
# rotate mode: try these in order until one completes the handshake, then
# stick to the winner (sticky) until it later fails.
rotation = ["chrome", "firefox", "safari"]   # also: "ios", "android"
sticky = true
# pinned mode only — present exactly this profile, no rotation:
# mode = "pinned"
# profile = "firefox"
```

| Mode | Behaviour |
|---|---|
| `rotate` (default `[chrome, firefox, safari]`, `sticky=true`) | try each profile over a **fresh** connection until the TLS handshake completes; remember the winner and keep using it until it fails. The censorship-robust default. |
| `pinned` | always present `profile`; zero rotation overhead. |
| `random` | fresh randomised (but valid) ClientHello per connection. |

### Profiles

| Token | Fingerprint | Fidelity |
|---|---|---|
| `chrome` | Desktop Chrome | near-native (BoringSSL **is** Chrome's TLS stack) |
| `android` | Mobile Chrome | near-native |
| `firefox` | Desktop Firefox | JA3-*class* approximation¹ |
| `safari` | Desktop Safari | JA3-*class* approximation¹ |
| `ios` | Mobile Safari | JA3-*class* approximation¹ |
| `random` | randomised each connection | valid modern-client shape |

¹ Firefox/Safari/iOS native stacks (NSS / SecureTransport) order the TLS 1.3
cipher suites and some extensions differently, and BoringSSL fixes those — so
the bytes are **not** byte-identical, but the JA3 *class* (TLS 1.2 cipher
order, supported-groups, signature algorithms, GREASE, extension permutation)
**is** distinct. BoringSSL cannot offer Firefox's FFDHE groups (EC curves
only). All profiles enable GREASE (matches real browsers).

### Mode ↔ DPI type

| DPI behaviour | Best `mode` | Why |
|---|---|---|
| **Blocklist** — drop known-bad JA3 | `random` (or `rotate`) | a varied/random JA3 isn't on the bad list; nothing stable to match. |
| **Allowlist** — drop everything that is not a known-good browser JA3 | `rotate` real browsers | every attempt **is** a whitelisted browser; a random JA3 would be dropped as anomalous. |
| **One fingerprint banned** (e.g. Chrome) with collateral damage accepted | `rotate` | falls back to the next real browser the censor can't afford to block. |
| **No JA3 inspection / SNI-only** | `pinned` (or any) | fingerprint is irrelevant — see ECH + `default_sni` below. |

Rule of thumb: under **allowlist** DPI prefer `rotate` through *real* browsers
(a random/rare JA3 is itself anomalous and gets default-denied); under
**blocklist** DPI `random` maximises unpredictability.

### Layering with obfs4, ECH, SNI

Fingerprint rotation is one layer. Combine for defence-in-depth:

| Control | Protects | Config |
|---|---|---|
| Fingerprint rotation | *which client* you look like (JA3/JA4) | `[transport.tls_fingerprint]` |
| **obfs4** transport | presents **no TLS ClientHello at all** — uniformly-random stream, nothing to JA3-ban | dial peers over `obfs4://` (+ `[transport] obfs4_psk_file`) |
| **ECH** | *which host* (real SNI hidden) | `[global] tls_ech_grease = true` (default) |
| **SNI masquerade** | the advertised SNI on peer connects | `[transport] default_sni = "..."` |
| **Connection rotation** | flow *lifetime* fingerprinting | `[transport.rotation]` |

Suggested escalation as a censor tightens:

1. `rotate` desktop browsers (default).
2. add mobile: `rotation = ["chrome","firefox","safari","ios","android"]`.
3. ensure ECH on (default) + a plausible `default_sni`.
4. if *all* browser JA3s are blocked (full allowlist) → move peers to
   `obfs4://` (no fingerprint to ban) and/or `webtunnel` behind a must-allow
   CDN. JA3 rotation cannot win against an allowlist that excludes every
   browser — at that point the answer is "present no fingerprint", not
   "present a different one".

### Scope / limits

* **QUIC** (`quic://`) stays Chrome-shaped — `quinn-btls` does not expose
  cipher/curve control. Rotation covers `tls://` and `wss://` only.
* **Server side** (your listener's ServerHello) is not rotated; this targets
  the outbound ClientHello a censor inspects on *your* dials.
* **SOCKS-proxied** TLS (`[transport] outbound_socks_fallback_proxy`) uses the
  policy's preferred profile **without** rotation — the tunnel is already
  established, so re-dialing per fingerprint is the proxy layer's concern.
* Non-Chromium profiles are JA3-*class* approximations, not byte-exact (see
  the Profiles note). For byte-exact mimicry of a non-Chromium browser there is
  no BoringSSL-based option.

### Verification

A rotated handshake logs at DEBUG under target `tls.fingerprint`:

```text
[tls.fingerprint] fingerprint 'chrome' failed TLS handshake to peer:443, rotating: ...
```

Capture an outbound ClientHello (`tcpdump` / Wireshark, filter
`tls.handshake.type == 1`) and compute its JA3 to confirm the active profile
matches the intended browser class. To pin one profile for a controlled test:
`mode = "pinned"` + `profile = "firefox"`.

## Disaster Recovery

State that survives restart (lives next to `config.toml`):

| File | Contents | Critical |
|------|----------|----------|
| `bans.json` | Manual bans (persisted) | Yes — protects against rejoining attackers |
| `dht_values.json` | Local DHT shard values (sovereign identity records, name claims) | Yes — sovereign-name resolution |
| `peers_discovered.json` | PEX-learned peers | No — re-discovered via PEX |
| `identity_document.bin` | Sovereign identity | **Yes — back this up** |
| `device_identity_sk.bin` | Per-device Ed25519 secret seed | **Yes — back this up** |
| `instance_id` | Local instance UUID + label | **Yes** — tied to identity_keys[] |
| `mlkem.key` | Per-instance ML-KEM-768 keypair | Auto-regenerates if missing |
| `name_claims/*.bin` | Persisted sovereign name claims | Yes — re-publishable from disk |

### Crash + restart

```bash
# Hard kill
killall -9 veil-cli

# Restart picks up bans.json, dht_values.json, identity_document.bin etc.
veil-cli -c /etc/veil/node.toml node run

# Verify state restored
veil-cli -c /etc/veil/node.toml node show
veil-cli -c /etc/veil/node.toml peers banned
```

Logs at startup will show `dht.values.persist.restored restored N/N` and
similar; missing files are skipped silently (fresh-node behavior).

### Identity loss — restore from BIP-39

Sovereign identities are derived from a 24-word BIP-39 phrase
emitted by `identity create`.  If the host is destroyed but the phrase
survives, full identity recovery is possible:

```bash
# On a fresh host, re-create identity from the saved phrase
veil-cli identity import --phrase-file /path/to/phrase.txt --veil-dir /var/lib/veil/

# Verify identity_id matches the original
veil-cli identity show --veil-dir /var/lib/veil
```

The same `identity_id` is reproduced; sovereign name claims and the
DHT-published `IdentityDocument` are unchanged from peers' perspective.

### ML-KEM key rotation

If `mlkem.key` is suspected compromised:

```bash
# Stop the node, remove the file, restart — auto-regenerated.
systemctl stop veil-node
rm /var/lib/veil/mlkem.key
systemctl start veil-node

# Re-publish ML-KEM cert via DHT (happens automatically on first
# IdentityDocument re-publish; force via debug command if needed)
```

Sessions established before rotation are unaffected (their session keys
are not derived from `mlkem.key`); new E2E messages will use the fresh key.

### False-positive ban storm

If a misconfigured ban-pulse landed everyone in `bans.json` and you need
to wipe it without losing identity / DHT state:

```bash
systemctl stop veil-node
mv /var/lib/veil/bans.json /var/lib/veil/bans.json.bak
systemctl start veil-node
# Selectively re-ban specific node_ids if needed:
veil-cli peers ban <node_id_hex>
```

## Default Tuning Guidance

Defaults target a mid-size Core node (≥4 GB RAM, ≥100 Mbps).  For
**constrained seeds** (2 GB RAM, shared VM) or **hardened public
nodes**, several values warrant explicit override.  Pre-deployment
review of this section is **strongly recommended** — the wrong
default on public infra is the difference between a stable node and
an OOM loop.

### RAM budget

Steady-state memory is dominated by three structures:

| Structure | Per-unit cost | Default cap | Worst-case RAM |
|-----------|---------------|-------------|----------------|
| Session tx queues | `tx_queue_depth × avg_frame_size` ≈ 1024 × 1 KiB = 1 MiB | `max_concurrent = 65 536` | **~64 GiB** |
| DHT store | `key(32) + value(≤ MAX_DHT_VALUE_BYTES = 16384 ≈ 16 KiB)` ≈ 16 KiB | `max_store_entries = 25 000` (default; opt up to ~250K for dedicated DHT seeds — lift further to disk via the RocksDB cold tier, `[dht] cold_store_path`) | **~400 MiB** at default, **~4 GiB** at 250K × 16 KiB |
| Route cache | `~200 bytes` per (dst, hop) pair | `~ K × 256` typical | <100 MiB |
| Mailbox WAL | disk-backed; RAM only for hot index | bounded by TTL | <500 MiB |

Worst-case is pathological (every session's queue full, every DHT
slot occupied).  Realistic steady-state on a public seed with ~5 000
active sessions and partial DHT fill is **~1–2 GB** — but you must
cap `max_concurrent` and `max_store_entries` to get there from the
defaults.

### Recommended overrides by deployment profile

#### Small seed (2 GB RAM, public IP, serving clients)
```toml
[session]
max_concurrent = 4096            # 4K sessions × 1 MiB queue ≈ 4 GiB cap
max_per_ip = 256                 # allow CGNAT clusters (mobile / residential)
max_per_subnet = 512             # /24 with many NAT-ed hosts

[dht]
# 25K is the default; keep explicit for clarity.
# 25K × 16 KiB ≈ 400 MiB worst-case.
max_store_entries = 25_000

[capacity]
max_relay_sessions = 2048        # hard cap on relay load
max_inbound_bandwidth_kbps = 50_000   # 50 Mbit/s

[abuse]
pow_min_difficulty = 20          # reject low-PoW joiners; tighten post-incident
ban_max_secs = 86_400            # 24 h escalated ban (default 1 h is lenient)
```

#### Large seed / infra node (≥8 GB RAM, dedicated HW)
```toml
[session]
max_concurrent = 65_536          # default — OK at this RAM budget
max_per_ip = 512

[dht]
# Opt up from default (25K) to 1M for dedicated DHT infra (1M × 16 KiB
# far exceeds RAM — pair with the disk cold tier below).
max_store_entries = 1_000_000
# Disk-backed cold tier: values aged out of the in-memory hot tier are
# demoted to RocksDB at this path instead of a bounded in-memory map, so a
# node can serve **> 1M entries** without the RAM cost, and cold entries
# survive restarts.  Needs a binary built with the `rocksdb-cold` feature
# (on by default for veil-cli).  Without the feature — or if the open
# fails — the node logs and keeps running on the in-memory cold tier.
cold_store_path = "/var/lib/veil/dht-cold"

[capacity]
max_relay_sessions = 20_000
```

> **Hot tier stays RAM-only.** `cold_store_path` persists only the *cold*
> tier. To also restore hot-tier entries on restart, keep
> `values_persist_path` set (the periodic JSON snapshot) alongside it — the
> two are independent and complementary.

#### Leaf / end-user node (laptop, phone gateway)
```toml
[session]
max_concurrent = 256             # client doesn't need many
idle_timeout_secs = 180          # tolerate mobile sleep
keepalive_interval_secs = 60     # save battery

[dht]
participate = false              # leaf nodes opt out of DHT storage
max_store_entries = 0

[capacity]
max_relay_sessions = 0           # don't relay as client
```

### Per-field tradeoff table

| Field | Default | Raise when | Lower when |
|-------|---------|-----------|-----------|
| `session.max_concurrent` | 65 536 | Dedicated infra (>8 GB RAM) | Small seed / leaf (<4 GB) |
| `session.max_per_ip` | 32 | Serving mobile-NAT clients | Hardening against scanners |
| `session.idle_timeout_secs` | 90 | Mobile / flaky networks | Latency-sensitive / chat-only |
| `session.keepalive_interval_secs` | 30 | Battery-constrained clients (→120) | High-churn debug |
| `session.tx_queue_depth` | 1024 | Bulk-transfer workloads | High-concurrency RAM-lean |
| `dht.max_store_entries` | 1 000 000 | Dedicated DHT infra | **always for small seeds** (→100k) |
| `dht.cold_store_path` | `None` (all-in-memory) | Dedicated DHT infra serving > 1M entries (disk cold tier, needs `rocksdb-cold`) | Leaf / RAM-only nodes |
| `dht.k` | 20 | Never (affects wire) | Never |
| `dht.alpha` | 3 | Slow lookup convergence | High-cost link |
| `capacity.max_relay_sessions` | 0 (∞) | **set anything ≥ 0 for public nodes** | — |
| `capacity.max_inbound_bandwidth_kbps` | 100 000 | Enterprise infra | Residential / metered |
| `abuse.pow_min_difficulty` | 16 | Under attack / tighten | Dev / LAN |
| `abuse.rate_limit_fps` | 500 | High-volume legit peers | — |
| `abuse.ban_max_secs` | 3600 | Persistent abuse | Short-lived sandboxing |
| `routing.max_gossip_hops` | 2 | Never raise > 3 (wire) | Small / fully-meshed mesh |

Flags that should **always** be set for public infra:
- `capacity.max_relay_sessions > 0` — uncapped relay is DoS-vulnerable.
- `dht.max_store_entries` tuned to RAM — default will OOM a 2 GB node
  under worst-case.

## Core Node Deployment

All Core nodes are equal participants with DHT (K=20), relay/forwarding, mailbox,
and gateway functionality.

### Requirements
- **Hardware**: ≥2 CPU cores, ≥2 GB RAM, ≥50 Mbps bandwidth
- **PoW**: ≥24-bit difficulty (mine with `--difficulty 24`)
- **Uptime**: 99 %+ (systemd unit with `Restart=always`)

### Config snippet
```toml
[identity]
role = "core"

[dht]
k = 20                    # Kademlia bucket size (default)
alpha = 3                 # lookup parallelism
shard_filtering = true    # accept only local shards

[session]
max_concurrent = 512
tx_queue_depth = 4096

[gateway]
enabled = true            # default; set false to disable gateway

[routing]
max_gossip_hops = 2
```

### Post-deploy verification
```bash
# Role
veil-cli node show | grep -i role

# Routing table populated (after first PEX walk, ≤2 min)
veil-cli node dht routing | wc -l

# Metrics snapshot (incl. DHT / route-cache gauges)
veil-cli node metrics
```
