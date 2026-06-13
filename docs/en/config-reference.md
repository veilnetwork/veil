# OVL1 Configuration Reference

Every field in the `config.toml` file, described in one place.

The config is read at startup by `veil-cli node run`. Where it lives depends on your OS (XDG on Linux, `AppData` on Windows); to find the exact path, run `veil-cli config locate`.

---

## File format

The file is **TOML**. Most sections are optional — leave one out and its defaults apply. Two things are not optional: the `[Identity]` section, and at least one `[[peers]]` or `[[listen]]` entry. Without them a node has no identity and nowhere to connect.

```toml
# Minimal config example (leaf node)
persist_enabled = true

[Identity]
algo       = "ed25519"
role       = "leaf"
public_key = "BASE64..."
private_key = "BASE64..."
nonce      = "AAAAAA=="

[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "BASE64..."
nonce      = "AAAAAA=="
transport  = "tls://gateway.example.com:9443"
```

---

## Top level

### `persist_enabled`

| Type | Default |
|-----|-------------|
| `bool` | `true` |

The master switch for everything written to disk. When `false`, no `*_persist_path` is read at startup or written while running — handy for throwaway nodes, CI, and debugging.

---

## `[global]`

Tokio runtime and logging.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `runtime_flavor` | enum | `"multi_thread"` | Tokio runtime type. Values: `"multi_thread"`, `"current_thread"` |
| `worker_threads` | `u16` or absent | unset | Number of worker threads. Left unset, it follows `num_cpus`. Applies only to `multi_thread` |
| `max_blocking_threads` | `u16` or absent | unset | Size of the blocking-thread pool (for `spawn_blocking`). Left unset, the tokio default (512) applies |
| `thread_keep_alive_ms` | `u64` or absent | unset | How long an idle blocking thread sticks around, in ms |
| `thread_name` | `string` or absent | unset | Name prefix for worker threads, so they're easy to spot in `ps` or `top` |
| `thread_stack_size` | `usize` or absent | unset | Worker-thread stack size in bytes |
| `admin_socket` | `string` or absent | unset | Admin backend URI: `"unix:///abs/path/to/admin.sock"` (Linux/macOS), or `"tcp://127.0.0.1:0?runtime_dir=/abs/path"` on Windows or wherever domain sockets aren't available. With TCP, `admin.port` and `admin.token` are written to `runtime_dir` for clients to read; the validator refuses non-loopback hosts (`::1` and `localhost` are fine). |
| `logs` | enum | `"stderr"` | Where logs go. Values: `"stderr"`, `"file"` |
| `log_file` | `string` or absent | unset | Path to the log file. Only consulted when `logs = "file"` |
| `log_level` | enum | `"info"` | Minimum level to log. Values: `"debug"`, `"info"`, `"warn"`, `"error"` |
| `log_format` | enum | `"text"` | Log line format. Values: `"text"` (human-readable), `"json"` (NDJSON) |
| `admin_max_connections` | `usize` | `32` | Most admin-socket connections allowed at once |
| `require_signed_config` | `bool` | `false` | When `true`, the node refuses to load a config that isn't validly signed (Stage 11d) — see config signing in [OPERATIONS](OPERATIONS.md) |
| `tls_ech_grease` | `bool` | `true` | Send TLS **ECH GREASE** so middleboxes can't tell ECH-capable connections from the rest. Set `false` only for CDNs stuck on TLS 1.2 |
| `bootstrap_dns_domain` | `string` or absent | unset | DNS bootstrap domain — seeds delivered as TXT records, one more fallback layer for joining the network |
| `bootstrap_https_urls` | `[string]` | `[]` | HTTPS (and `.onion`) URLs that serve a **signed** seed bundle — the last resort when clearnet seeds are blocked |
| `bootstrap_tor_socks_proxy` | `string` or absent | unset | SOCKS5 proxy (e.g. `"socks5://127.0.0.1:9050"`) for fetching `.onion` `bootstrap_https_urls` over Tor |
| `trusted_bundle_issuer_pubkey` | `string` or absent | unset | Pinned issuer pubkey that every signed seed bundle must verify against |
| `legacy_allow_unsigned_bootstrap` | `bool` | `false` | Accept unsigned bootstrap bundles (legacy). Default `false`; `.onion` sources are always force-signed regardless |
| `discovered_peers_cache_path` | `string` or absent | unset | Cache of peers found in earlier runs — a fallback for joining if the known seed IPs are down |

**Example:**

```toml
[global]
runtime_flavor    = "multi_thread"
worker_threads    = 4
admin_socket      = "/var/run/veil/admin.sock"
logs              = "file"
log_file          = "/var/log/veil/node.log"
log_level         = "warn"
log_format        = "json"
```

---

## `[Identity]`

> The spelling `[identity]` (lowercase) is also accepted. Both variants are equivalent.

The node's cryptographic identity — the one section a node can't run without.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `algo` | enum | `"ed25519"` | Signature algorithm. Values: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (the last two are post-quantum hybrids) |
| `role` | enum | `"leaf"` | The node's role in the network. Values: `"leaf"`, `"core"` |
| `public_key` | `string` | — | Public key, base64-encoded. **Required** |
| `private_key` | `string` | — | Private key, base64-encoded. **Required** |
| `nonce` | `string` | `"AAAAAA=="` (4 zero bytes) | PoW nonce for `node_id = BLAKE3(pubkey \|\| nonce)`. Generated by `config init` |
| `node_id` | `string` or absent | computed | Explicit hex node_id (64 characters). Left unset, it's computed from `public_key` + `nonce` |
| `key_passphrase` | `string` or absent | unset | Passphrase to decrypt the encrypted private key, written inline. Discouraged — prefer the file or prompt variants below |
| `key_passphrase_file` | `string` or absent | unset | Path to a file holding the key passphrase (keep it mode `0600`) |
| `key_passphrase_prompt` | `bool` | `false` | When `true`, ask for the key passphrase interactively at startup |
| `lazy_mining` | `bool` | `false` | Mine the PoW nonce in the background instead of making `config init` wait for it |
| `max_lazy_difficulty` | `u8` | `64` | The highest difficulty the lazy miner will attempt |

> Names aren't config keys. Claim one with `veil-cli identity claim-name <name>`, and the running node republishes it to the DHT. See [Names](user-guide.md#names-name-system).

**Node roles:**

| Role | Description |
|------|----------|
| `leaf` | A mobile or lightweight node. Stays out of the DHT and works through core nodes and the mailbox |
| `core` | A full network participant: DHT (K=20), relay/forwarding, gateway (attachment records), and mailbox. Recommended PoW difficulty ≥ 24 (the `--difficulty` default is `16`; `MAX_POW_DIFFICULTY = 24` is the hard cap) |

The legacy values `"relay"`, `"gateway"`, `"core_router"` have been removed — the parser
now accepts only `"leaf"` or `"core"`.

**Example:**

```toml
[Identity]
algo        = "ed25519"
role        = "core"
public_key  = "MCowBQYDK2VwAyEA..."
private_key = "MC4CAQAwBQYDK2Vw..."
nonce       = "AAAAAA=="
```

---

## `[[peers]]`

Persistent peers the node keeps an outbound connection open to. One entry, one connection.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `peer_id` | `string` (hex u32) | — | Local peer identifier, e.g. `"0x00000001"`. **Required** |
| `public_key` | `string` | — | Peer public key (base64). **Required** |
| `nonce` | `string` | — | Peer PoW nonce (base64). **Required** |
| `transport` | `string` | — | Transport URI to dial (see [Transport URI format](#transport-uri-format)). **Required** |
| `algo` | enum | `"ed25519"` | Peer signature algorithm. Values: `"ed25519"`, `"falcon512"` |
| `tls_cert` | `string` or absent | unset | PEM certificate for mTLS (client side) |
| `tls_key` | `string` or absent | unset | Private key for mTLS (client side) |
| `tls_ca_cert` | `string` or absent | unset | CA certificate for checking the peer's certificate |

**Example:**

```toml
[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEA..."
nonce      = "AAAAAA=="
transport  = "tls://gateway.example.com:9443"

[[peers]]
peer_id    = "0x00000002"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEB..."
nonce      = "AAAAAA=="
transport  = "quic://core.example.com:9444"
```

---

## Transport URI format

The `transport` field shares one URI format across every section that has it (`[[peers]]`, `[[listen]]`, `[[bootstrap_peers]]`). Implementation: `crates/veil-transport/src/uri.rs`.

### Supported schemes

| Scheme | Direction | Description |
|-------|-------------|----------|
| `tcp://HOST:PORT` | outbound / inbound | Plain TCP, no encryption |
| `tls://HOST:PORT` | outbound / inbound | TCP + TLS 1.3 |
| `quic://HOST:PORT` | outbound / inbound | UDP + QUIC (TLS built in); supports bidirectional streams, substreams, and datagrams |
| `ws://HOST:PORT/PATH` | outbound / inbound | WebSocket over TCP; usable as a byte stream or a message stream |
| `wss://HOST:PORT/PATH` | outbound / inbound | WebSocket over TLS; usable as a byte stream or a message stream |
| `socks://PROXY:PORT/TARGET:PORT` | outbound only | TCP through a SOCKS5 proxy |
| `sockstls://PROXY:PORT/TARGET:PORT` | outbound only | TLS through a SOCKS5 proxy |
| `unix:///path/to/socket` | inbound only | Unix domain socket (IPC only) |

**Bind addresses for `[[listen]]`:** use `0.0.0.0` or `[::]` to accept connections on every interface; `127.0.0.1` or `unix://` to keep a listener local.  
**For `[[peers]]` / `[[bootstrap_peers]]`:** the DNS name or IP of the remote node.  
**IPv6:** wrap the address in square brackets — `tcp://[::1]:9000`, `tls://[2001:db8::1]:443`.

### Query parameters for TLS schemes

The `tls://`, `quic://`, `wss://`, and `sockstls://` schemes accept query parameters:

| Parameter | Repeat | Description |
|----------|--------|----------|
| `sni=NAME` | once | Override the SNI (Server Name Indication) for the TLS handshake. Defaults to `host`; for `sockstls://` it defaults to `target_host` |
| `alpn=PROTO` | many | Add an ALPN protocol. May be given more than once |

**Examples:**

```
# TLS with an explicit SNI (useful for IP connections or a reverse proxy)
tls://10.0.0.1:9443?sni=node.example.com

# TLS with multiple ALPNs
tls://example.com:443?alpn=h2&alpn=http/1.1

# QUIC with ALPN
quic://example.com:9443?sni=example.com&alpn=h3

# WebSocket Secure with an overridden SNI
wss://10.0.0.1:443/veil?sni=gateway.internal
```

### SOCKS5 proxy

Format: scheme `://proxy_host:proxy_port/target_host:target_port`

```
# TCP through a SOCKS5 proxy
socks://127.0.0.1:1080/remote.example.com:9000

# TLS through a SOCKS5 proxy (SNI automatically = target_host)
sockstls://127.0.0.1:1080/remote.example.com:9443

# TLS through SOCKS5 with an explicit SNI and ALPN
sockstls://127.0.0.1:1080/10.0.0.5:9443?sni=remote.example.com&alpn=h2
```

### TLS certificates

The `tls_cert`, `tls_key`, and `tls_ca_cert` parameters in `[[listen]]` / `[[peers]]` apply only to the `tls://`, `quic://`, and `wss://` schemes. For `tcp://`, `ws://`, and `unix://` they're ignored.

| Parameter | In `[[listen]]` | In `[[peers]]` |
|----------|---------------|--------------|
| `tls_cert` | Server certificate (PEM, leaf or fullchain) | Client certificate (mTLS) |
| `tls_key` | Server private key | Client private key |
| `tls_ca_cert` | CA for verifying clients (mTLS) | CA for verifying the server's certificate |

> Don't put a CA certificate in a listener's `tls_cert` field: rustls rejects a CA certificate used as an end-entity server certificate.

### Debugging transports

The `veil-cli debug transport` subcommand lets you test a connection by hand, without standing up a full node.

**Connection examples (client):**

```bash
veil-cli debug transport connect tcp://127.0.0.1:9001
veil-cli debug transport connect tls://example.com:443?sni=example.com&alpn=h2
veil-cli debug transport connect quic://example.com:443?alpn=h3
veil-cli debug transport connect unix:///tmp/veil.sock
veil-cli debug transport connect socks://127.0.0.1:1080/1.1.1.1:9001
veil-cli debug transport connect sockstls://127.0.0.1:1080/example.com:443?sni=example.com
veil-cli debug transport connect ws://127.0.0.1:8080/veil
veil-cli debug transport connect wss://example.com:443/veil?alpn=http/1.1
```

**Listener examples (server):**

```bash
veil-cli debug transport listen tcp://0.0.0.0:9001
veil-cli debug transport listen unix:///tmp/veil.sock
veil-cli debug transport listen tls://0.0.0.0:9443?sni=localhost&alpn=h2
veil-cli debug transport listen quic://0.0.0.0:9444?alpn=h3
veil-cli debug transport listen ws://0.0.0.0:8080/veil
veil-cli debug transport listen wss://0.0.0.0:8443/veil?alpn=http/1.1
```

For `listen` with a TLS scheme (`tls://`, `wss://`, `quic://`) a temporary self-signed certificate is generated for you. To test closer to production, pass real certificates:

```bash
# Listener with a real certificate
veil-cli debug transport listen tls://0.0.0.0:9443 \
  --tls-cert ssl/server-fullchain.pem \
  --tls-key ssl/server.key

# Client with a custom CA
veil-cli debug transport connect tls://127.0.0.1:9443 \
  --tls-ca-cert ssl/ca.pem

# Same for WSS and QUIC
veil-cli debug transport listen wss://0.0.0.0:8443/veil \
  --tls-cert ssl/server-fullchain.pem --tls-key ssl/server.key
veil-cli debug transport connect wss://127.0.0.1:8443/veil \
  --tls-ca-cert ssl/ca.pem
```

The `--tls-cert`, `--tls-key`, and `--tls-ca-cert` flags behave the same across `tls://`, `wss://`, and `quic://`.

---

## `[[listen]]`

Inbound listeners. Each one is a single port the node accepts connections on.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `id` | `string` (hex u32) | — | Local listener identifier, e.g. `"0x00000001"`. **Required** |
| `transport` | `string` | — | Transport URI to bind (see [Transport URI format](#transport-uri-format)). **Required** |
| `advertise` | `string` or absent | unset | Address advertised to peers in place of `transport`. Used behind a reverse proxy: bind to `localhost:9443`, advertise `wss://nginx.example.com:443/veil` |
| `relay` | `string` or absent | unset | Hex node_id of a relay node this listener can be reached through (for NAT). Included in `RouteResponsePayload.relay_ids` |
| `tls_cert` | `string` or absent | unset | PEM server certificate (TLS/WSS) |
| `tls_key` | `string` or absent | unset | Server private key |
| `tls_ca_cert` | `string` or absent | unset | CA certificate for verifying clients (mTLS) |
| `visibility` | enum | `"public"` | How visible the listener is. `"public"` — advertised via PEX + DHT; `"trusted"` — not advertised, reached by out-of-band invite; `"hidden"` — like trusted, but also enforces `allowlist_node_ids` at the handshake |
| `psk_file` | `string` (path) or absent | unset | Path to a file with the PSK (32 bytes, base64) for an `obfs4-tcp://` listener. Overrides the global `[transport].obfs4_psk_file`, so you can split PSKs by group — a public listener on a deployment-wide PSK plus a family listener on a private one |
| `allowlist_node_ids` | `[string]` | `[]` | Hex-encoded 32-byte node_ids allowed to authenticate against this listener. Required for `visibility = "hidden"`; optional reinforcement for `"trusted"`. Empty means no allowlist |
| `group_label` | `string` or absent | unset | A human-readable group tag (e.g. `"family"`, `"snowflake"`). The daemon doesn't act on it; it just shows up in logs and metrics |
| `ephemeral` | table or absent | unset | Random-port rotation, to avoid port clustering. See [`[listen.ephemeral]`](#listenephemeral) below |

**Example:**

```toml
[[listen]]
id        = "0x00000001"
transport = "tls://0.0.0.0:9443"
tls_cert  = "/etc/veil/server.crt"
tls_key   = "/etc/veil/server.key"
advertise = "tls://node.example.com:9443"

[[listen]]
id        = "0x00000002"
transport = "ws://0.0.0.0:8080/veil"

# trusted-only obfs4 listener for a family circle
[[listen]]
id          = "0x00000003"
transport   = "obfs4-tcp://0.0.0.0:5556"
visibility  = "trusted"
psk_file    = "/etc/veil/family.psk"
group_label = "family"
```

### `[listen.ephemeral]`

Rotates the listening port at random on a schedule, so ports don't cluster (snowflake-style).
The daemon rebinds to a fresh port from `range` every `rotation`, and peers pick up the new URI from a signed `TransportMigrationNotify` broadcast.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive port range, e.g. `[10000, 60000]`. A narrow range helps mimic a specific protocol (`[3306, 3306]` — MySQL-SSL). **Required** |
| `rotation` | `string` (duration spec) | — | How often to rotate: `"30s"`, `"5m"`, `"3h"`, `"7d"`. **Required** |
| `bind_retries` | `u32` | `64` | How many bind attempts to make on a collision (`EADDRINUSE`). 0 = single-shot |
| `grace_period` | `string` (duration spec) | `"30m"` | How long the old listener stays alive after rotation, finishing in-flight handshakes before it's dropped |

**Constraints:**

- Works only for `obfs4-tcp://` listeners (or another transport whose URI supports `with_host_port`).
- Needs an Ed25519 identity — the `TransportMigrationNotify` wire frame is signed with ed25519-dalek; the hybrid Falcon-512 + Ed25519 case isn't supported yet.
- If the rebind to the new port fails, a warning is logged and the old listener keeps serving. Peers whose caches already point at the new URI fall back through the DHT.

**Example:**

```toml
[[listen]]
id        = "0x00000004"
transport = "obfs4-tcp://0.0.0.0:5556"   # starting port (ignored after the first rotation)
psk_file  = "/etc/veil/ephemeral.psk"

[listen.ephemeral]
range         = [50000, 60000]
rotation      = "1h"
grace_period  = "30m"
bind_retries  = 64
```

**Logs and metrics:** on each rotation the daemon emits structured info-level logs:

- `listen.rotation.spawned` — at startup, confirms the rotator task came up
- `session.migration.notify.applied` — on the peer side, once it receives and applies the broadcast
- `listen.rotation.swap_sent` — on the rotating node, after a successful rebind
- `listen.swap` — the accept-loop has switched to the new listener
- `listen.rotation.rebind_failed` (warn) — the new bind failed; the old one keeps working
- `listen.rotation.bind_failed` (warn) — the rotator couldn't pick a port from the range

### `[listen.on_demand]`

An on-demand listener binds its port **only when asked**, not at startup.
Normally `ss -tlnp` shows nothing; the port opens only after a successful PoW
handshake, serves a capped number of sessions (or until a TTL), then closes on
its own.

**Requirements:**

- `visibility = "stealth"` is required (otherwise config validation errors out at startup)
- An Ed25519 node identity (hybrid Falcon-512 isn't supported at this layer)
- **Multiple stealth listeners** per node are supported (advertised round-robin; node-wide `pow_difficulty` / `rate_limit` / `max_concurrent` must be identical across them)

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive port range for the on-demand bind. **Required** |
| `pow_difficulty` | `u32` | — | Required PoW difficulty, in BLAKE3 leading-zero bits. Production: 24 (~16M attempts ≈ 0.5 sec CPU). Minimum 8. **Required** |
| `ttl` | `string` (duration) | — | Slot TTL: `"5m"`, `"300s"`. Once it expires the accept-task exits and the listener closes, even if no session ever arrived. **Required** |
| `max_concurrent` | `usize` | `16` | Most on-demand slots open at once. Keeps a PoW-funded burst from exhausting the FD table |
| `rate_limit` | `string` (`"N/period"`) | `"3/h"` | Per-requester rate limit: `"3/h"` (3 grants an hour per pubkey), `"1/m"`, `"10/30s"` |
| `max_accepts` | `usize` | `1` | How many sessions the slot takes before retiring. 1 = a one-shot rendezvous |
| `bind_retries` | `u32` | `64` | Bind attempts on EADDRINUSE |

**Example:**

```toml
[[listen]]
id        = "0x00000005"
transport = "obfs4-tcp://example.com:0"   # port ignored for stealth
visibility = "stealth"
advertise = "obfs4-tcp://example.com"      # advertise_host for composing the response URI

[listen.on_demand]
range          = [50000, 60000]
pow_difficulty = 24
ttl            = "5m"
max_concurrent = 16
rate_limit     = "3/h"
max_accepts    = 1
```

**Logs (info-level):**

- `rendezvous.controller.wired` — at startup, confirms the controller is wired to the dispatcher
- `rendezvous.request.rejected reason=<cat>` — request rejected (categories: decode, verify, not_our_target, rate_limited, concurrency_exhausted, bind_failed)
- `rendezvous.response.sent peer_id=<8 hex> new_port=<N>` — signed response sent to the initiator
- `rendezvous.on_demand.listener.spawned listen_id=<id> local_addr=<addr> ttl_remaining=<sec> accepts_remaining=<N>` — on-demand listener brought up
- `rendezvous.on_demand.scanner_dropped` — banned-IP connection dropped before the handshake
- `rendezvous.on_demand.budget_exhausted` — all `max_accepts` slots used up, the accept-task exits
- `rendezvous.on_demand.listener.ttl_or_shutdown` — TTL expired or runtime shutdown
- `rendezvous.on_demand.listener.exited` — final entry before dropping the listener

**Prometheus metrics (Slice 7):**

- `veil_rendezvous_requests_received_total` (counter) — total requests received
- `veil_rendezvous_requests_granted_total` (counter) — signed responses issued
- `veil_rendezvous_requests_rejected_decode_total` (counter)
- `veil_rendezvous_requests_rejected_verify_total` (counter)
- `veil_rendezvous_requests_rejected_not_our_target_total` (counter)
- `veil_rendezvous_requests_rejected_rate_limit_total` (counter)
- `veil_rendezvous_requests_rejected_concurrency_total` (counter)
- `veil_rendezvous_requests_rejected_bind_failed_total` (counter)
- `veil_rendezvous_slots_in_use` (gauge) — current number of active on-demand listeners

Grant rate is `granted / received`. A high `rejected_verify_total` with a low `granted` means one of two things: clients are mining too weak a PoW (raise `pow_difficulty`), or someone's forging requests (and the rate-limit and anti-abuse layers are doing their job). A high `rejected_concurrency_total` means `max_concurrent` is too tight for normal load.

**Mediator routing (shipped — Slice 6).** A requester with no open OVL1 session to the stealth target reaches it through a PEX/DHT mediator-relay (`RecursiveQuery`), so a stealth listener with no open port is reachable end-to-end — not merely hooked into the dispatch path.

**Still pending:**

- **End-to-end integration tests.** Slice 8.

---

## `[[bootstrap_peers]]`

Bootstrap peers seed the DHT routing table when the node first starts. They're used only at startup: the node runs FIND_NODE(self), then the session closes — unless that peer also appears in `[[peers]]`.

Unlike `[[peers]]`, bootstrap connections aren't kept open.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `transport` | `string` | — | Transport URI (see [Transport URI format](#transport-uri-format)). **Required** |
| `public_key` | `string` | — | Bootstrap node public key (base64). **Required** |
| `nonce` | `string` | `"AAAAAA=="` | Bootstrap node PoW nonce |
| `algo` | enum | `"ed25519"` | Signature algorithm. Values: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (the last two are post-quantum hybrids) |
| `tls_cert` | `string` or absent | unset | PEM certificate (for a TLS transport) |
| `tls_ca_cert` | `string` or absent | unset | CA certificate for verification |

**Example:**

```toml
[[bootstrap_peers]]
transport  = "tcp://bootstrap1.example.com:9000"
public_key = "MCowBQYDK2VwAyEA..."
nonce      = "AAAAAA=="

[[bootstrap_peers]]
transport  = "tcp://bootstrap2.example.com:9000"
public_key = "MCowBQYDK2VwAyEB..."
```

---

## `[metrics]`

Prometheus metrics exporter (HTTP). Optional — leave the section out and nothing is exported.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `listen` | `string` | — | Transport URI for the metrics HTTP server. A scheme is **required**, e.g. `"tcp://0.0.0.0:9090"` (a bare `host:port` is rejected). Required whenever the section is present |
| `path` | `string` or absent | `"/metrics"` | HTTP path to scrape |
| `auth_token` | `string` or absent | unset | Bearer token required to scrape. Set it, and requests without it are rejected |
| `allow_unauthenticated_remote_metrics` | `bool` | `false` | Allow non-loopback scrapes without a token. Default `false` — remote scrapes need `auth_token` |

**Example:**

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

---

## `[transport]`

Transport-layer settings and the censorship-circumvention tools (DPI evasion). Every key is optional.

> **TLS backend.** The `veil-cli` binary uses the BoringSSL backend by default
> (cargo feature `tls-boring`, part of `default = ["rocksdb-cold",
> "tls-boring"]`). It produces a Chrome-like JA3/JA4 fingerprint in the TLS
> ClientHello and can rotate it. The `rustls` backend is the fallback when you
> build with `--no-default-features`; it can't shape the ClientHello, so the
> `[transport.tls_fingerprint]` subsection is ignored there.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `default_sni` | `string` or absent | unset | Default SNI hostname in the TLS ClientHello, used when the outbound URI doesn't set `?sni=...` and the target isn't loopback. Set it to something like `"www.google.com"` and DPI on the path sees a popular domain instead of the node's real hostname. Left unset, the target host is used as the SNI |
| `obfs4_psk_file` | `string` (path) or absent | unset | Path to a file holding the obfs4 pre-shared key (32 bytes, base64 on one line). Setting it turns on the `obfs4-tcp://` transport: the server checks the MAC on incoming handshakes, the client adds one to outgoing handshakes. A single network-wide PSK. Left unset, the `obfs4-tcp` transport stays off |
| `webtunnel_secret_path` | `string` or absent | unset | Webtunnel secret path (e.g. `/_t/random-32-chars`). Turns on tunnel mode on the server side of the `webtunnel-wss://` transport |
| `webtunnel_auth_token_file` | `string` (path) or absent | unset | Webtunnel auth-token file (32 random bytes in base64). Sent in the `X-Veil-Auth` header alongside the secret path |
| `webtunnel_decoy_dir` | `string` (path) or absent | unset | Webtunnel decoy-content directory: static files served to probes that don't match the secret path or auth. A snapshot of some neutral site works well. Left unset, a minimal built-in HTML page is served |
| `webtunnel_response_floor_ms` | `int` (ms) or absent | absent ⇒ `40` (on) | Anti-probe response-timing floor. The server holds every response — the tunnel `101` upgrade and the decoy alike — until at least this many milliseconds have passed since the request was read, so a prober can't tell a real tunnel endpoint from a plain decoy by latency. **On by default at 40 ms since audit cycle-9** (absent ⇒ 40); set an explicit `0` to disable, or a larger value above the decoy's worst-case fetch time (for a proxy decoy, above the backend's latency) or the decoy can still overrun the floor. Costs up to this much added handshake latency |
| `outbound_socks_fallback_proxy` | `string` or absent | unset | URL of a SOCKS proxy to fall back on when a direct dial keeps failing (AS-level blocking, ISP route interception). Format `socks5://127.0.0.1:9050` (local Tor) or `socks5://proxy.example:1080`. Left unset, only direct connections are tried |
| `bandwidth_mimicry_enabled` | `bool` | `false` | Bandwidth-profile mimicry (P2 #7). For now this is a **placeholder**: the field is recognized, but the traffic-shaping layer isn't wired in yet. Setting it `true` without `experimental_allow_noop_mimicry` is a validation error (fail-closed) |
| `bandwidth_mimicry_profile` | `string` or absent | unset | Profile name for `bandwidth_mimicry_enabled`: `"chrome-browsing"`, `"cdn-download"`, `"interactive-chat"`. Still a placeholder |
| `experimental_allow_noop_mimicry` | `bool` | `false` | Acknowledges that `bandwidth_mimicry_enabled` is a no-op placeholder for now, and agrees to start the daemon without real mimicry. Required alongside `bandwidth_mimicry_enabled = true` |
| `obfs4_accept_variants` | `[string]` | `[]` | **Kill-switch, server side**: which obfs4 wire-format variants to accept, in priority order. Empty (resolves to `["v1"]`) keeps the pre-Phase-2 behavior. Values: `"v1"`, `"v2"` |
| `obfs4_client_variant` | `string` or absent | unset | **Kill-switch, client side**: the obfs4 wire-format variant for outbound `obfs4-tcp://`. Left unset, it resolves to `v1`. Values: `"v1"`, `"v2"`. Switch to `"v2"` only once every target server's `obfs4_accept_variants` includes `v2` |

### `[transport.rotation]`

Rotates transport connections on a schedule. It tears down and rebuilds each session's underlying TCP/TLS connection, so DPI can't classify a flow by how long it's lived (the "this HTTPS session has been up for 6 hours — must be a VPN" heuristic loses its signal). At the handshake, every session picks a random lifetime from the `[min_lifetime_secs, max_lifetime_secs]` range. The section is **always serialized** — as a censorship-circumvention tool, the operator should see it in their config.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `min_lifetime_secs` | `i64` | `1800` | Shortest session lifetime, in seconds (30 min). `-1` turns the whole rotation mechanism off. Positive values under 60 are rejected by validation |
| `max_lifetime_secs` | `i64` | `3600` | Longest session lifetime, in seconds (1 hour). `-1` turns rotation off. Must be `>= min_lifetime_secs` when both are positive |

### `[transport.tls_fingerprint]`

Controls the TLS ClientHello fingerprint on outbound `tls://` / `wss://`
connections. Active **only on builds with `tls-boring`** — the `rustls` backend
can't change the ClientHello and ignores this section. The section is **always
serialized**; like `[transport.rotation]`, it's a censorship-circumvention
control, so it stays visible in the config.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `mode` | enum | `"rotate"` | How the fingerprint is chosen: `"pinned"` (always `profile`), `"rotate"` (cycle through the profiles in `rotation` on fresh connections until one completes the handshake), `"random"` (a fresh randomized ClientHello every time). The default `"rotate"` rides out blocking — when one JA3 is blocked, the node moves to the next |
| `profile` | enum | `"chrome"` | Profile for `"pinned"` mode. Profile tokens: `chrome`, `firefox`, `safari`, `ios`, `android`, `random` |
| `rotation` | `[string]` | `["chrome", "firefox", "safari"]` | The ordered list of profiles to cycle through in `"rotate"` mode |
| `sticky` | `bool` | `true` | In `"rotate"` mode, stick with the last profile that completed a handshake instead of starting the cycle over |

### `[transport.tls_client]`

Trust store for the node's **outbound** TLS (HTTPS bootstrap, webtunnel). Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `connect_timeout_ms` | `u64` or absent | unset | Connect timeout for outbound TLS, in ms |
| `use_system_roots` | `bool` | `false` | Add Mozilla's webpki-roots CA bundle to the client trust store. Default `false` — veil trusts only the operator-pinned CAs in `trusted_ca_file`. Set `true` for mesh nodes that reach publicly-certified hosts |
| `trusted_ca_file` | `string` or absent | unset | PEM file of the operator-pinned CA(s) to trust |

**Example:**

```toml
[transport]
default_sni                    = "www.google.com"
obfs4_psk_file                 = "/etc/veil/obfs4.psk"
outbound_socks_fallback_proxy  = "socks5://127.0.0.1:9050"

[transport.rotation]
min_lifetime_secs = 1800
max_lifetime_secs = 3600

[transport.tls_fingerprint]
mode     = "rotate"
rotation = ["chrome", "firefox", "safari"]
sticky   = true
```

---

## `[mesh]`

Settings for the local UDP mesh — discovering neighbors within a single network segment. Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `bind_addr` | `string` | — | UDP address for the realm listener, e.g. `"0.0.0.0:9100"`. **Required** when the section is present |
| `realm_id` | `string` | — | 32 hex characters (16 bytes) — the realm identifier. **Required** |
| `beacon_addr` | `string` | `"255.255.255.255:9100"` | Broadcast/multicast address for beacon discovery. The **port** is the last remaining traffic-shape signal a beacon gives off (size and cadence are already hidden once `realm_psk` is set, C-03) — on a hostile LAN, pick a non-default port (every realm member must match) |
| `autodiscover_gateway` | `bool` | `true` | Automatically connect to gateway nodes found via mesh beacons |
| `autodiscover_max_concurrent` | `usize` | `3` | Most outbound sessions to auto-discovered gateways at once |
| `beacon_dedup_window_secs` | `u64` | `3` | How long to ignore repeat beacons from the same source, in seconds. `0` turns deduplication off |
| `autodiscover_persist_path` | `string` or absent | unset | Where to persist the `AutoDiscoveredPeers` table. Restored at startup, so the nearest gateways are known before the first beacon arrives |
| `require_signed_beacons` | `bool` | `true` | When `true` (default, C-03), only cryptographically-signed mesh beacons are accepted and unsigned ones are dropped, closing the on-link gateway-injection / neighbor-redirect hole. Set `false` only to interop with older deployments still sending unsigned beacons — turning signed-only on across a live unsigned network partitions those nodes, so roll signed beacons out fleet-wide first |
| `advertise_role_in_beacon` | `bool` | `false` | When `true`, the node advertises its role flags (`IS_GATEWAY` / `IS_RELAY` / `HAS_INTERNET`) in its mesh beacon — which `autodiscover_gateway` peers need in order to recognize it as a gateway. Default `false` (C-03): the beacon carries `role_flags = 0`, so a passive on-link observer can't pick the node out as a gateway/relay (a targeting/censorship signal). The stable `node_id` is broadcast either way |
| `realm_psk` | `string` or absent | unset | **Opt-in UDP obfuscation.** A base64-encoded pre-shared key (≥ 16 bytes decoded). When set, mesh **DATA** datagrams **and discovery beacons** are AEAD-wrapped (`veil-udp-obfs`: ChaCha20-Poly1305, a fresh random nonce + random padding per datagram), so a passive DPI/LAN observer sees only rotating ciphertext — the mesh framing **and the stable `node_id` / role flags / dial address inside beacons** are hidden (closes C-03; discovery then needs the PSK, as you'd expect for a protected realm). The key is realm-wide (HKDF-derived from the PSK and `realm_id`); **every realm member must share the same PSK**, handed out out-of-band. Left unset (default) → plaintext mesh + plaintext beacons, behavior byte-for-byte unchanged. A PSK that's set but invalid or too short **disables the mesh** rather than quietly falling back to plaintext |

**Example:**

```toml
[mesh]
bind_addr                  = "0.0.0.0:9100"
realm_id                   = "deadbeefcafebabedeadbeefcafebabe"
autodiscover_gateway       = true
autodiscover_max_concurrent = 5
autodiscover_persist_path  = "/var/lib/veil/autodiscover.bin"
# realm_psk                = "BASE64_PRESHARED_KEY"  # opt-in: AEAD-obfuscate DATA datagrams (≥16 bytes, shared realm-wide)
```

---

## `[mailbox]`

Mailbox settings — where messages wait for recipients who are offline.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Master switch — a node runs a mailbox only if you opt in |
| `quota_per_receiver_bytes` | `u64` | `0` (crate default) | Per-receiver storage quota in bytes. `0` = built-in default |
| `quota_global_bytes` | `u64` | `0` (crate default) | Global per-relay storage quota in bytes. `0` = built-in default |
| `quota_per_sender_bytes` | `u64` | `0` (crate default ≈ 10 MiB) | Per-sender byte quota. `0` = built-in default; `u64::MAX` effectively turns accounting off |
| `ttl_secs` | `u64` | `0` (crate default 7 days) | How long a stored blob lives, in seconds. `0` = built-in default |
| `rate_limit_per_minute` | `u32` | `0` (crate default) | Per-receiver PUT rate limit. `0` = built-in default |
| `require_capability_token` | `bool` | `false` | When `true`, PUTs without a token are rejected with `CapabilityRequired` |
| `[mailbox.push]` | table | absent | Push-provider credentials (FCM / APNs). Leave it out and you get a log-only dispatcher — puts are logged, with no provider API call |

**Example:**

```toml
[mailbox]
enabled                  = true
quota_per_receiver_bytes = 67108864   # 64 MiB
ttl_secs                 = 604800     # 7 days
require_capability_token = true
```

### `[mailbox.push]`

Push-notification provider credentials (FCM / APNs). Leave it empty and the daemon falls back to a log-only dispatcher — puts are logged, with no provider call.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `fcm_credentials_path` | `string` | `""` | Path to the Firebase Cloud Messaging service-account JSON |
| `apns_p8_path` | `string` | `""` | Path to the APNs `.p8` signing key |
| `apns_key_id` | `string` | `""` | APNs key ID |
| `apns_team_id` | `string` | `""` | Apple developer team ID |
| `apns_bundle_id` | `string` | `""` | App bundle ID (the APNs topic) |
| `apns_environment` | `string` | `"production"` | APNs environment: `"production"` or `"sandbox"` (empty ⇒ production) |
| `require_wake_hmac` | `bool` | `false` | Forbid the legacy **unauthenticated** wake-up push. A wake-up is authenticated (carries `ts ‖ content_id ‖ HMAC`) only when the receiver has uploaded a sealed `WakeHmacKey` envelope; otherwise the relay falls back to a "wake-only" push with an empty payload, which anyone who learns the push token (or can trigger a mailbox PUT) can forge to wake the device (battery-drain / nuisance). When `true`, the relay **drops** such pushes instead of sending an unauthenticated wake — so a receiver must opt into wake-HMAC to be woken. Default `false` for back-compat; operators who control their client fleet should enable it. With it off, the daemon logs a startup advisory |

---

## `[ipc]`

The IPC server, which lets local applications connect over a Unix socket.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Turn the IPC server on |
| `socket_uri` | `string` or absent | `~/.veil/app.sock` | IPC endpoint. Takes a Unix path / `unix:///abs/path`, or `tcp://127.0.0.1:0?runtime_dir=...` (TCP loopback — the Windows route) |
| `e2e_key_ttl_secs` | `u64` | `3600` | How long peers' ML-KEM-768 encapsulation keys stay cached, in seconds. Once they expire, a fresh `RouteRequest/RouteResponse` fetches a new key |
| `app_socket_dir` | `string` or absent | unset | Directory where the node opens an extra per-app Unix socket, `{app_socket_dir}/{hex(app_id)}.sock`, for app-scoped IPC |

**Example:**

```toml
[ipc]
enabled     = true
socket_uri = "/run/veil/app.sock"
e2e_key_ttl_secs = 1800
```

---

## `[priority_weights]`

Weighted Round Robin (WRR) weights for the four traffic classes in the outbound scheduler.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `realtime` | `u32` | `8` | Weight for REALTIME traffic (voice, hard-RT interactive) |
| `interactive` | `u32` | `4` | Weight for INTERACTIVE traffic (ordinary interactive) |
| `bulk` | `u32` | `2` | Weight for BULK traffic (file transfer) |
| `background` | `u32` | `1` | Weight for BACKGROUND traffic (background sync) |

For every `background` BACKGROUND frames the node sends, it sends `realtime` REALTIME-class frames.

**Example:**

```toml
[priority_weights]
realtime    = 16
interactive = 8
bulk        = 4
background  = 1
```

---

## `[proxy]`

The veil node's proxy features.

### `[proxy.socks5]`

SOCKS5 proxy: the node accepts SOCKS5 CONNECT and tunnels the TCP over veil to an exit node.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Turn the SOCKS5 listener on |
| `listen` | `string` | `"127.0.0.1:1080"` | TCP address for the SOCKS5 listener |
| `exit_node_id` | `string` or absent | unset | Pin the exit by hex node_id — SOCKS5 traffic is tunneled to this node. Left unset, an exit is picked dynamically |

### `[proxy.exit]`

Exit proxy: the node accepts veil proxy-connect streams and opens the outbound TCP connections for them.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Turn the exit proxy on. When `true`, this node forwards connections to external TCP addresses |
| `allow_private` | `bool` | `false` | Allow exit connections to private/RFC1918 ranges (10/8, 172.16/12, 192.168/16, loopback). Default `false` — blocked, as an SSRF guard |

**Example:**

```toml
[proxy.socks5]
enabled = true
listen  = "127.0.0.1:1080"

[proxy.exit]
enabled = true
```

---

## `[tun]`

> **Moved.** The TUN/TAP veil-VPN now lives in its own **`ogate`** binary,
> configured through its own `ogate.toml` (per-network `peers[]` allowlist,
> `iface_name`, `mode`, `mtu`, …). The main node config no longer has a `[tun]`
> section — see **[ogate.md](ogate.md)**.

---

## `[session]`

Session-layer settings: keepalive, idle timeout, queues.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `keepalive_interval_secs` | `u64` | `30` | How often to send keepalive frames, in seconds. `0` turns them off |
| `idle_timeout_secs` | `u64` | `90` | Close the session if no frame arrives within this window. Must be > `keepalive_interval_secs` |
| `max_concurrent` | `usize` | `512` | Most OVL1 sessions open at once |
| `max_per_ip` | `usize` | `32` | Most inbound sessions from a single IP address |
| `max_pending_responses` | `usize` | `256` | Most pending RPC responses per session. Anything beyond is dropped |
| `pending_response_ttl_ms` | `u64` | `30000` | How long a pending-response slot lives, in ms. Stale ones are evicted |
| `tx_queue_depth` | `usize` | `4096` | Size of the outbound-frame channel per session. On overflow, frames are dropped |
| `outbox_depth` | `usize` | `256` | Size of the RPC outbox per session. When the channel is full, `send_request()` returns `None` |
| `max_frame_body_bytes` | `u32` | 1 MiB | Largest allowed frame body; bigger frames are rejected. Hard ceiling: 16 MiB |
| `qos_weights` | `[u8; 4]` | `[8, 4, 2, 1]` | WRR weights for the classes `[RealTime, Interactive, Bulk, Background]` within a session |
| `rt_queue_len` | `usize` | `64` | Depth of the REALTIME queue per session. On overflow, frames are dropped |
| `bg_queue_len` | `usize` | `256` | Depth of the BACKGROUND queue per session. On overflow, frames are dropped |
| `rekey_bytes_threshold` | `u64` | 128 GiB (`137_438_953_472`) | Rekey once this many bytes have moved through the session |
| `rekey_time_threshold_secs` | `u64` | 32 days (`2_764_800`) | Rekey once this long has passed since the last rekey or the session start |
| `max_per_subnet` | `usize` | `64` | Most inbound sessions from a single /24 (IPv4) or /48 (IPv6) subnet |
| `battery_threshold_low` | `u8` | `20` | Battery % at or below which the "low" keepalive scaling kicks in |
| `battery_threshold_medium` | `u8` | `50` | Battery % at or below which the "medium" keepalive scaling kicks in |
| `battery_keepalive_scale_low` | `f32` | `4.0` | Keepalive-interval multiplier when battery ≤ `battery_threshold_low` |
| `battery_keepalive_scale_medium` | `f32` | `2.0` | Keepalive-interval multiplier when battery ≤ `battery_threshold_medium` |
| `battery_sync_threshold` | `u8` | `15` | Battery % below which background sync is held off |
| `allowed_peer_algos` | `[enum]` | `[]` | Allowlist of peer signature algorithms accepted at the handshake (`"ed25519"`, `"falcon512"`, hybrids). Empty = accept everything supported |

**Example:**

```toml
[session]
keepalive_interval_secs    = 15
idle_timeout_secs          = 60
max_concurrent             = 2048
max_per_ip                 = 64
tx_queue_depth             = 8192
max_frame_body_bytes       = 2097152        # 2 MiB
rekey_bytes_threshold      = 68719476736    # 64 GiB — rotate keys more often
rekey_time_threshold_secs  = 604800         # 7 days
```

### `[session.padding]`

Shapes outbound traffic to resist fingerprinting. Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `mode` | enum | `"adaptive"` | Padding mode: `"adaptive"` (pad to size buckets), `"none"` (off), `"full"` (maximum padding) |
| `jitter_ms` | `u32` | `0` | Largest random delay (ms) added to each outbound frame. `0` = no jitter |
| `cover_interval_ms` | `u32` | `0` | Gap (ms) between cover (dummy) frames while a session sits idle. `0` = no cover traffic |

---

## `[hot_standby]`

Keeps a second transport primed so a failing primary can be swapped out without dropping the session. Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Turn hot-standby transport swapping on |
| `handoff_timeout_secs` | `u64` | `5` | How long a handoff has to finish before it's aborted |
| `max_swaps_per_minute` | `u32` | `4` | Cap on transport swaps per minute, to stop flapping |
| `auto_trigger_after_write_errors` | `u32` | `3` | How many write errors in a row on the primary auto-trigger a swap |

---

## `[gateway]`

Gateway settings (attachment records for leaf nodes). Core nodes only.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Turn the gateway on (attachment records for leaf nodes). Can be switched off on a Core node |
| `attachment_lease_ttl_secs` | `u64` | `300` | How long an attachment lease survives without a keepalive, in seconds |
| `keepalive_interval_secs` | `u64` | `60` | How often a leaf sends its core keepalive, in seconds. `0` turns it off (not recommended in production) |

**Example:**

```toml
[gateway]
attachment_lease_ttl_secs = 600
keepalive_interval_secs   = 120
```

---

## `[nat]`

NAT traversal (hole punching, with a relay to fall back on).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Turn NAT traversal on. Set `false` only when every peer is directly reachable |
| `punch_timeout_ms` | `u64` | `3000` | How long to wait for a UDP hole-punch, in ms, before falling back to a relay |
| `stun_servers` | `[string]` | `[]` | External STUN servers (`"host:port"`, RFC 5389). Left empty, the address is found through veil itself — a core node reflects the source |
| `relay_enabled` | `bool` | `true` | Allow falling back to a relay when the hole-punch fails |

**Example:**

```toml
[nat]
enabled          = true
punch_timeout_ms = 5000
relay_enabled    = true
stun_servers     = ["stun.l.google.com:19302", "stun1.l.google.com:19302"]
```

---

## `[pow]`

The rate limiter for `PowChallenge` frames.

Only matters when `abuse.pow_min_difficulty > 0`.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `challenge_rate` | `f64` | `1.0` | Steady rate of PoW challenges issued, per peer per second |
| `challenge_burst` | `f64` | `1.0` | Burst the PoW rate limiter allows per peer. A burst of 1 is plenty for a legitimate `RouteRequest` flow |
| `challenge_window_secs` | `u64` | `300` | Sliding window the PoW rate-limiter state covers, in seconds |

---

## `[connection]`

Outbound reconnects and gateway failover.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `reconnect_backoff_min_ms` | `u64` | `1000` | Shortest reconnect interval, in ms |
| `reconnect_backoff_max_ms` | `u64` | `300000` | Longest reconnect interval, in ms (5 minutes) |
| `prefer_internet_gateway` | `bool` | `true` | Favor a gateway with the `HAS_INTERNET` flag when routing to global nodes. `false` uses the nearest gateway, internet access or not |
| `exit_diversification` | `bool` | `false` | Pick the exit gateway weighted-random from the top-K candidates instead of always the single best — cuts down statistical fingerprinting, since one fat flow to one IP stands out |
| `exit_diversification_top_k` | `u8` | `4` | Window for `exit_diversification`: choose from the top-K gateways by score |
| `reconnect_quiet_after_failures` | `u32` | `5` | After this many reconnect failures in a row, per-attempt logs drop from WARN to DEBUG (it keeps retrying, and emits `INFO peer.recovered` once it's back). `0` keeps them at WARN forever |

**Example:**

```toml
[connection]
reconnect_backoff_min_ms     = 500
reconnect_backoff_max_ms     = 60000
prefer_internet_gateway      = true
```

---

## `[capacity]`

Load-shedding limits for relay nodes. `0` means no limit.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `max_relay_sessions` | `usize` | `0` | Most relay sessions at once. `0` = no limit |
| `max_total_sessions` | `usize` | `0` | Most sessions of any kind (relay + direct). `0` = no limit |
| `tx_queue_high_watermark` | `f64` | `0.8` | TX-queue fill fraction at which the node counts as overloaded (0.0–1.0) |
| `congestion_high` | `f64` | `0.8` | Congestion-score threshold above which the node stops taking new relay sessions |
| `congestion_low` | `f64` | `0.6` | Congestion-score threshold below which it starts taking relay sessions again (the hysteresis) |
| `max_inbound_bandwidth_kbps` | `i64` | `10000000` | Per-node total inbound bandwidth cap in kbps (default 10 Gbit/s). `-1` = unlimited |
| `max_outbound_bandwidth_kbps` | `i64` | `10000000` | Per-node total outbound bandwidth cap in kbps. `-1` = unlimited |

**Example:**

```toml
[capacity]
max_relay_sessions      = 500
max_total_sessions      = 1000
tx_queue_high_watermark = 0.75
congestion_high         = 0.75
congestion_low          = 0.5
```

---

## `[abuse]`

Abuse protection: rate limiting, mailbox quotas, PoW, bans.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `rate_limit_fps` | `f64` | `200000.0` | Steady per-peer frame rate (frames/sec) |
| `rate_limit_burst` | `f64` | `400000.0` | Per-peer burst frame quota |
| `pow_min_difficulty` | `u32` | `16` | Leading-zero bits required in the `RouteRequest`/`PowChallenge` PoW (≈65k hashes, <1 ms). `0` turns it off (dev only); the hard cap is `MAX_POW_DIFFICULTY = 24` |
| `ban_threshold` | `u32` | `5` | How many protocol violations earn a temporary ban |
| `ban_initial_secs` | `u64` | `5` | Length of the first ban (seconds) |
| `ban_step_secs` | `u64` | `5` | Added to each later ban — it grows step by step: the Nth ban is `ban_initial_secs + N × ban_step_secs`, capped at `ban_max_secs` |
| `ban_max_secs` | `u64` | `3600` | Ceiling on the growing ban duration (seconds) |

**Example (production settings):**

```toml
[abuse]
rate_limit_fps     = 200000.0
rate_limit_burst   = 400000.0
pow_min_difficulty = 16
ban_threshold      = 3
ban_initial_secs   = 30
ban_step_secs      = 30
ban_max_secs       = 7200
```

---

## `[routing]`

Fine-tuning for the routing plane.

### Core parameters

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `route_probe_interval_secs` | `u64` | `30` | How often to send ROUTE_PROBE, in seconds |
| `reannounce_interval_secs` | `u64` | `30` | How often to re-announce routes, in seconds |
| `route_cache_ttl_secs` | `u64` | `120` | How long route-cache entries live |
| `route_request_backoff_ms` | `[u64; 3]` | `[500, 1000, 2000]` | Backoff between RouteRequest retries: [attempt0, attempt1, attempt2] ms |
| `partition_score_threshold` | `f64` | `0.2` | The `network_reachability_score` (0.0–1.0) below which a network partition is logged. `0.0` turns the check off |
| `route_seen_capacity` | `usize` | `4096` | Size of the route-deduplication cache |
| `route_seen_window_secs` | `u64` | `120` | Route-deduplication window, in seconds |
| `max_gossip_hops` | `u8` | `2` | Maximum TTL for gossip frames. Frames past this hop count are dropped |

### ECMP and redundant send

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `ecmp_score_band` | `f64` | `0.20` | How far a route's score may trail the best and still join the ECMP group. `0.0` turns ECMP off |
| `redundant_send` | `bool` | `false` | Send critical frames over the two best paths at once. Trims p99 latency, but doubles the traffic |

### Adaptive probe intervals

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `probe_min_interval_secs` | `u64` | `5` | Shortest ROUTE_PROBE interval on a shaky path |
| `probe_max_interval_secs` | `u64` | `120` | Longest ROUTE_PROBE interval on a steady path |
| `probe_stability_threshold` | `f64` | `0.05` | Stability threshold (`std_dev/mean` of RTT). Below it the path counts as stable and gets probed less often |

### Epidemic broadcast

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `epidemic_fanout` | `usize` | `3` | How many random neighbors an `EpidemicBroadcast` is forwarded to |
| `epidemic_max_payload` | `usize` | `4096` | Largest `EpidemicBroadcast` payload, in bytes |

### Battery-aware routing

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `battery_penalty_low` | `f64` | `3.0` | Penalty multiplier at critically low charge (< `battery_threshold_low` %) |
| `battery_penalty_medium` | `f64` | `0.5` | Penalty multiplier at medium charge (< `battery_threshold_medium` %) |
| `battery_threshold_low` | `u8` | `20` | Charge (%) at which `battery_penalty_low` applies |
| `battery_threshold_medium` | `u8` | `40` | Charge (%) at which `battery_penalty_medium` applies |

### Distributed tracing

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `trace_sample_rate` | `f64` | `0.01` | Share of outbound DELIVERY_FORWARD frames that get a `trace_id` injected (0.0 = none, 1.0 = all) |
| `trace_buffer_size` | `usize` | `10000` | Size of the per-node ring buffer of trace-hop records |

### Persistence

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `cache_persist_path` | `string` or absent | unset | Where to write a route-cache snapshot. `None` turns it off |
| `cache_persist_interval_secs` | `u64` | `30` | How often the route-cache snapshot is written |
| `cache_persist_max_age_secs` | `u64` | `3600` | Oldest a snapshot may be and still be loaded. Stale files are ignored |
| `rtt_persist_path` | `string` or absent | unset | Where to write an RTT-table snapshot |
| `rtt_persist_interval_secs` | `u64` | `60` | How often the RTT snapshot is written |
| `vivaldi_persist_path` | `string` or absent | unset | Where to persist Vivaldi coordinates |
| `gateway_persist_path` | `string` or absent | unset | Where to persist the (ranked) gateway list |
| `peer_pubkeys_persist_path` | `string` or absent | unset | Where to cache the public keys of known peers |
| `discovery_mode` | enum | `"public"` | Visibility advertised in the handshake. Values: `"public"`, `"contacts_only"` |
| `target_labels` | `[string]` | `[]` | Operator labels advertised for label-based routing/selection |
| `dht_fallback_timeout_ms` | `u64` | `10000` | How long to wait, in ms, before falling back to a DHT lookup when direct route discovery stalls |
| `dht_fallback_backpressure_threshold_pct` | `u8` | `75` | Queue-fill % above which DHT-fallback lookups are throttled |
| `dht_fallback_adaptive` | `bool` | `false` | Tune the DHT-fallback timeout on the fly from observed latencies |
| `dht_fallback_priority_mult` | `[u16; 2]` | `[50, 200]` | Priority multipliers `[floor, ceiling]` applied to DHT-fallback traffic |
| `multi_path_enabled` | `bool` | `false` | Send across several disjoint paths in parallel, for resilience |
| `max_parallel_paths` | `u8` | `2` | Most disjoint paths to use when `multi_path_enabled` |
| `multi_path_min_priority` | `u8` | `1` (INTERACTIVE) | Only multi-path traffic at this priority class or above |
| `relay_reputation_min_attempts` | `u32` | `10` | How many relay attempts to observe before reputation downweighting kicks in |
| `relay_reputation_threshold` | `f64` | `0.5` | Success rate below which a relay is downweighted |
| `relay_reputation_penalty` | `f64` | `2.0` | Score-penalty multiplier for low-reputation relays |
| `jitter_penalty_weight` | `f64` | `0.5` | Weight of the RTT-jitter penalty in path scoring |
| `jitter_threshold_ms` | `u64` | `20` | Jitter (ms) above which the jitter penalty applies |
| `narrow_bandwidth_bulk_penalty` | `f64` | `2.0` | Penalty multiplier for routing BULK traffic over narrow links |

**Example:**

```toml
[routing]
route_probe_interval_secs  = 20
reannounce_interval_secs   = 20
route_cache_ttl_secs       = 180
ecmp_score_band            = 0.15
redundant_send             = true
trace_sample_rate          = 0.05
cache_persist_path         = "/var/lib/veil/routes.bin"
rtt_persist_path           = "/var/lib/veil/rtt.bin"
vivaldi_persist_path       = "/var/lib/veil/vivaldi.bin"
gateway_persist_path       = "/var/lib/veil/gateways.bin"
peer_pubkeys_persist_path  = "/var/lib/veil/pubkeys.bin"
```

---

## `[dht]`

DHT (Kademlia) settings — background node lookup and value storage.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `republish_interval_secs` | `u64` | `1800` | How often DHT records are re-published (30 minutes) |
| `cleanup_interval_secs` | `u64` | `60` | How often expired DHT records are cleaned up |
| `participate` | `bool` | `true` | Take part in DHT storage (accept STORE/DELETE). `false` = routing only (FIND_NODE/FIND_VALUE) |
| `k` | `u8` | `20` | Kademlia k-bucket size — the number of contacts in a FIND_NODE response |
| `alpha` | `u8` | `3` | Kademlia α — parallel requests per round of the iterative lookup |
| `max_rounds` | `u8` | `20` | How many iterative-lookup rounds to try before giving up |
| `find_node_timeout_ms` | `u64` | `2000` | Timeout for a single FIND_NODE/FIND_VALUE RPC, in ms |
| `vivaldi_weight` | `f64` | `0.3` | How much the Vivaldi topology factor counts when ranking DHT nodes. `0.0` = pure XOR ordering |
| `routing_persist_path` | `string` or absent | unset | Where to persist the DHT k-bucket routing table |
| `values_persist_path` | `string` or absent | unset | Where to persist stored DHT values (a periodic JSON snapshot of the whole store) |
| `cold_store_path` | `string` or absent | unset | Directory for an on-disk **RocksDB cold tier** holding evicted DHT values. When set (and the binary is built with the `rocksdb-cold` feature — on by default for `veil-cli`), values evicted from the in-memory hot tier land in this on-disk RocksDB store instead of the bounded in-memory cold map. That moves the entry-count limit from RAM to disk (a dedicated DHT node then serves >1M entries), and cold records survive a restart. Unlike `values_persist_path` (a periodic JSON snapshot), the cold tier is a live DB, updated continuously. If the feature is missing or RocksDB won't open, it's ignored with a log line at startup and the node falls back to the in-memory cold tier |
| `allow_unsigned_store` | `bool` | `false` | Accept legacy **unsigned** raw STOREs. Default `false` (rejected outright). Turning it back on is a deploy footgun — see [OPERATIONS](OPERATIONS.md); a one-shot deprecation warning fires the first time one is accepted |
| `max_store_entries` | `usize` | `25000` | Hard cap on entries in the DHT store. Raise it for dedicated DHT seeds (e.g. `250000`); to go past RAM, page out through the `cold_store_path` RocksDB tier |
| `max_store_bytes` | `u64` or absent | unset | Optional byte-size cap on the DHT store, alongside `max_store_entries` |
| `per_origin_max_bytes` | `u64` or absent | `1048576` (1 MiB) | Per-signer byte cap (Stage 11e) — limits how much one origin can store, so a single signer can't fill the store. Absent ⇒ the 1 MiB default (audit cycle-9; was unset before). Set an explicit larger value on dedicated seeds (see OPERATIONS) |
| `shard_filtering` | `bool` | `false` | Opt-in: accept a STORE only when its key falls in this node's shard. Default `false`; meant to become default-on once the network grows past ~1M nodes |

**Example:**

```toml
[dht]
republish_interval_secs  = 3600
participate              = true
k                        = 20
alpha                    = 5
vivaldi_weight           = 0.5
routing_persist_path     = "/var/lib/veil/dht-routing.bin"
values_persist_path      = "/var/lib/veil/dht-values.bin"
cold_store_path          = "/var/lib/veil/dht-cold"
```

---

## `[pex]`

Peer Exchange — random-walk peer discovery. Optional, with sensible defaults.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Turn on PEX random-walk discovery |
| `max_peers` | `usize` | `32` | Most peers to keep from PEX discovery |
| `walk_parallelism` | `u8` | `3` | Parallel walk requests per round |
| `max_response_peers` | `u8` | `16` | Most peers returned in a single PEX response |

---

## `[anycast]`

How anycast service records are resolved. An anycast record maps a service tag
(e.g. a gateway/mailbox shard) to a candidate `node_id`; the record's `score`
is **peer-controlled**, so without admission control a Sybil could publish a
`score = 0` record to win traffic for a tag, or claim to be the canonical
provider of someone else's `node_id`.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `resolve_policy` | enum | `"signed_bound"` | Which anycast records to accept. Values: `"signed_bound"` (default — signed and owner-bound), `"signed_only"` (reject unsigned), `"best_effort"` (accept anything — legacy, not recommended) |

**Default lockdown.** `signed_bound` is secure-by-default: a record is accepted
only if it carries a valid owner signature **and** is bound to the advertising
node (`BLAKE3(owner_pubkey) == node_id`), so a node can advertise only for its
*own* id. This closes record forgery and node-id impersonation. (A signer can
still claim a dishonest `score` for its *own* record; the resolver additionally
mixes in resolver-specific XOR distance and a resolver-local reputation penalty
for candidates that later fail — both automatic, no config.)

Only drop to `best_effort` for discovery-only / non-trust-sensitive deployments
where unsigned legacy records must resolve; it disables the signature/binding
check and re-opens the Sybil-score and impersonation vectors above. Advertising
is local-app-driven over the (0600) IPC socket, so *who* may advertise a tag is
already gated by host access to that socket — `resolve_policy` governs which
*network-published* records a resolver will trust.

---

## `[mobile]`

Throttling that's aware of battery and background state, for mobile or battery-powered leaf nodes. Optional (the `mobile` profile fills it in for you).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `low_battery_threshold_pct` | `u8` or absent | unset | Battery % at or below which probe rates throttle. Left unset, battery awareness is off; a typical mobile value is `30` |
| `low_battery_multiplier` | `u32` | `4` | Probe-interval multiplier below the battery threshold (4 = 4× less often). Capped at a safe maximum |
| `background_keepalive_multiplier` | `u32` | `1` | Keepalive-interval multiplier when the runtime `background_mode` flag is set (it stacks with battery scaling). `1` = off; the `mobile` profile sets `60` (30 s → 30 min) |
| `low_battery_throttle_maintenance` | `bool` | `false` | Throttle background maintenance tasks too when the battery is low. Recommended for cellular/mobile |

---

## `[anonymity]`

Whether this node acts as an onion-routing relay for others. Optional. (The node always uses anonymity for its OWN sends; this only controls whether it carries OTHER peers' circuits.)

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `relay_capable` | `bool` | `false` | Advertise the `ANONYMITY_RELAY` capability and be eligible as a circuit hop. `false` = invisible to relay-directory lookups |
| `advertised_bps` | `u32` | `0` | Self-reported (UNVERIFIED) relay bandwidth in bytes/sec, used for load-balancing. Only meaningful when `relay_capable = true`. `0` = "don't know / lowest priority" |

---

## `[update]`

Self-update from signed manifests. Optional — nothing happens until `expected_issuer_pk` is set.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `manifest_urls` | `[string]` | `[]` | HTTPS URLs that serve the operator's signed update manifest. Spreading them across several providers guards against any one endpoint being taken down |
| `expected_issuer_pk` | `string` or absent | unset | Hex public key the manifest must be signed by. **Must be set** for the update mechanism to do anything |
| `installed_version_path` | `string` or absent | unset | File that records the installed binary's `release_unix`. Required for the apply path |
| `install_path` | `string` or absent | unset | Path to the binary itself (the atomic stage-and-rename target). Required for the apply path |
| `check_interval_secs` | `u64` or absent | unset | When set, poll `manifest_urls` every N seconds (hard floor of 60). Left unset, auto-poll is off |

---

## Complete configuration example (gateway node)

```toml
persist_enabled = true

[Identity]
algo        = "ed25519"
role        = "core"
public_key  = "MCowBQYDK2VwAyEA..."
private_key = "MC4CAQAwBQYDK2Vw..."
nonce       = "AAAAAA=="
name        = "mynode"

[global]
log_level  = "info"
log_format = "json"
logs       = "file"
log_file   = "/var/log/veil/node.log"
admin_socket = "/var/run/veil/admin.sock"

[[listen]]
id        = "0x00000001"
transport = "tls://0.0.0.0:9443"
advertise = "tls://gateway.example.com:9443"
tls_cert  = "/etc/veil/server.crt"
tls_key   = "/etc/veil/server.key"

[[peers]]
peer_id    = "0x00000001"
algo       = "ed25519"
public_key = "MCowBQYDK2VwAyEB..."
nonce      = "AAAAAA=="
transport  = "tls://core1.example.com:9443"

[[bootstrap_peers]]
transport  = "tcp://bootstrap.example.com:9000"
public_key = "MCowBQYDK2VwAyEC..."
nonce      = "AAAAAA=="

[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"

[mesh]
bind_addr                 = "0.0.0.0:9100"
realm_id                  = "deadbeefcafebabedeadbeefcafebabe"
autodiscover_gateway      = false
autodiscover_persist_path = "/var/lib/veil/autodiscover.bin"

[mailbox]
enabled                  = true
quota_per_receiver_bytes = 67108864
ttl_secs                 = 604800
require_capability_token = true

[ipc]
enabled     = true
socket_uri = "/run/veil/app.sock"

[session]
keepalive_interval_secs = 15
idle_timeout_secs       = 60
max_concurrent          = 2048
max_per_ip              = 64

[abuse]
pow_min_difficulty     = 16
ban_threshold          = 3
ban_initial_secs       = 30
ban_step_secs          = 30
ban_max_secs           = 7200

[routing]
cache_persist_path        = "/var/lib/veil/routes.bin"
rtt_persist_path          = "/var/lib/veil/rtt.bin"
gateway_persist_path      = "/var/lib/veil/gateways.bin"
peer_pubkeys_persist_path = "/var/lib/veil/pubkeys.bin"

[dht]
participate          = true
routing_persist_path = "/var/lib/veil/dht-routing.bin"
values_persist_path  = "/var/lib/veil/dht-values.bin"
```
