# OVL1 Configuration Reference

Complete description of all fields in the `config.toml` configuration file.

The config is read at startup by the `veil-cli node run` command. The default path depends on the OS (XDG on Linux, `AppData` on Windows); to find it: `veil-cli config locate`.

---

## File format

The file is in **TOML** format. Most sections are optional — if a section is omitted, default values are used. The exceptions: the `[Identity]` section and at least one `[[peers]]` or `[[listen]]` entry are required for a node to actually work.

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

The master switch for all on-disk persistence. When `false`, no `*_persist_path` is written or read at startup. Convenient for ephemeral nodes, CI, and debugging.

---

## `[global]`

Tokio runtime and logging settings.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `runtime_flavor` | enum | `"multi_thread"` | Tokio runtime type. Values: `"multi_thread"`, `"current_thread"` |
| `worker_threads` | `u16` or absent | unset | Number of worker threads. If unset — `num_cpus`. Only for `multi_thread` |
| `max_blocking_threads` | `u16` or absent | unset | Blocking-thread pool (for `spawn_blocking`). Absent — uses the tokio default (512) |
| `thread_keep_alive_ms` | `u64` or absent | unset | Lifetime of an idle blocking thread in ms |
| `thread_name` | `string` or absent | unset | Name prefix for worker threads (for `ps`, `top`) |
| `thread_stack_size` | `usize` or absent | unset | Worker-thread stack size in bytes |
| `admin_socket` | `string` or absent | unset | Admin backend URI: `"unix:///abs/path/to/admin.sock"` (Linux/macOS) or `"tcp://127.0.0.1:0?runtime_dir=/abs/path"` (Windows, or when domain sockets are unavailable). On TCP, `admin.port` and `admin.token` are written to `runtime_dir` and read by clients; the ban on non-loopback hosts is enforced in the validator (`::1`, `localhost` are allowed). |
| `logs` | enum | `"stderr"` | Where to write logs. Values: `"stderr"`, `"file"` |
| `log_file` | `string` or absent | unset | Path to the log file. Used only when `logs = "file"` |
| `log_level` | enum | `"info"` | Minimum log level. Values: `"debug"`, `"info"`, `"warn"`, `"error"` |
| `log_format` | enum | `"text"` | Log line format. Values: `"text"` (human-readable), `"json"` (NDJSON) |
| `admin_max_connections` | `usize` | `32` | Max concurrent admin-socket connections |
| `require_signed_config` | `bool` | `false` | When `true`, the node refuses to load a config that isn't validly signed (Этап 11d) — see config signing in [OPERATIONS](OPERATIONS.md) |
| `tls_ech_grease` | `bool` | `true` | Send TLS **ECH GREASE** so middleboxes can't distinguish ECH-capable from non-ECH connections. Set `false` only for TLS-1.2-only CDNs |
| `bootstrap_dns_domain` | `string` or absent | unset | DNS bootstrap domain (TXT-record seed source — a fallback bootstrap layer) |
| `bootstrap_https_urls` | `[string]` | `[]` | HTTPS (and `.onion`) URLs serving a **signed** seed bundle — last-resort bootstrap when clearnet seeds are blocked |
| `bootstrap_tor_socks_proxy` | `string` or absent | unset | SOCKS5 proxy (e.g. `"socks5://127.0.0.1:9050"`) for fetching `.onion` `bootstrap_https_urls` over Tor |
| `trusted_bundle_issuer_pubkey` | `string` or absent | unset | Pinned issuer pubkey that signed seed bundles must verify against |
| `legacy_allow_unsigned_bootstrap` | `bool` | `false` | Accept unsigned bootstrap bundles (legacy). Default `false`; `.onion` sources are always force-signed regardless |
| `discovered_peers_cache_path` | `string` or absent | unset | Cache of peers discovered in prior runs — a bootstrap fallback if known seed IPs go down |

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

The node's cryptographic identity. The only section required for operation.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `algo` | enum | `"ed25519"` | Signature algorithm. Values: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (the last two are post-quantum hybrids) |
| `role` | enum | `"leaf"` | The node's role in the network. Values: `"leaf"`, `"core"` |
| `public_key` | `string` | — | Public key, base64-encoded. **Required** |
| `private_key` | `string` | — | Private key, base64-encoded. **Required** |
| `nonce` | `string` | `"AAAAAA=="` (4 zero bytes) | PoW nonce for `node_id = BLAKE3(pubkey \|\| nonce)`. Generated by `config init` |
| `node_id` | `string` or absent | computed | Explicit hex node_id (64 characters). If unset — computed from `public_key` + `nonce` |
| `key_passphrase` | `string` or absent | unset | Passphrase to decrypt the encrypted private key inline (discouraged — prefer the file/prompt variants) |
| `key_passphrase_file` | `string` or absent | unset | Path to a file holding the key passphrase (keep it mode `0600`) |
| `key_passphrase_prompt` | `bool` | `false` | When `true`, prompt for the key passphrase interactively at startup |
| `lazy_mining` | `bool` | `false` | Mine the PoW nonce lazily in the background instead of blocking `config init` |
| `max_lazy_difficulty` | `u8` | `64` | Upper bound on the difficulty the lazy miner will attempt |

> Names are not config keys — claim a name with `veil-cli identity claim-name <name>`; the running node republishes it to the DHT. See [Names](user-guide.md#names-name-system).

**Node roles:**

| Role | Description |
|------|----------|
| `leaf` | Mobile/lightweight node. Does not participate in the DHT. Operates through core nodes and the mailbox |
| `core` | Full-fledged network participant. DHT (K=20), relay/forwarding, gateway (attachment records), mailbox. Recommended PoW difficulty ≥ 24 (the `--difficulty` default is `16`; `MAX_POW_DIFFICULTY = 24` is the hard cap) |

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

An array of persistent peers with which the node maintains an outbound connection. Each entry is one connection.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `peer_id` | `string` (hex u32) | — | Local peer identifier, e.g. `"0x00000001"`. **Required** |
| `public_key` | `string` | — | Peer public key (base64). **Required** |
| `nonce` | `string` | — | Peer PoW nonce (base64). **Required** |
| `transport` | `string` | — | Transport URI to connect to (see [Transport URI format](#transport-uri-format)). **Required** |
| `algo` | enum | `"ed25519"` | Peer signature algorithm. Values: `"ed25519"`, `"falcon512"` |
| `tls_cert` | `string` or absent | unset | PEM certificate for mTLS (client) |
| `tls_key` | `string` or absent | unset | Private key for mTLS (client) |
| `tls_ca_cert` | `string` or absent | unset | CA certificate for verifying the peer's certificate |

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

The `transport` field in all sections (`[[peers]]`, `[[listen]]`, `[[bootstrap_peers]]`) uses a single URI format. Implementation: `crates/veil-transport/src/uri.rs`.

### Supported schemes

| Scheme | Direction | Description |
|-------|-------------|----------|
| `tcp://HOST:PORT` | outbound / inbound | Direct TCP connection without encryption |
| `tls://HOST:PORT` | outbound / inbound | TCP + TLS 1.3 |
| `quic://HOST:PORT` | outbound / inbound | UDP + QUIC (built-in TLS); supports bidirectional streams, substreams, and datagrams |
| `ws://HOST:PORT/PATH` | outbound / inbound | WebSocket over TCP; available as a byte stream and a message stream |
| `wss://HOST:PORT/PATH` | outbound / inbound | WebSocket over TLS; available as a byte stream and a message stream |
| `socks://PROXY:PORT/TARGET:PORT` | outbound only | TCP through a SOCKS5 proxy |
| `sockstls://PROXY:PORT/TARGET:PORT` | outbound only | TLS through a SOCKS5 proxy |
| `unix:///path/to/socket` | inbound only | Unix Domain Socket (IPC only) |

**Bind addresses for `[[listen]]`:** use `0.0.0.0` or `[::]` to accept connections on all interfaces; `127.0.0.1` or `unix://` for local listeners.  
**For `[[peers]]` / `[[bootstrap_peers]]`:** the DNS name or IP of the remote node.  
**IPv6:** addresses are wrapped in square brackets: `tcp://[::1]:9000`, `tls://[2001:db8::1]:443`.

### Query parameters for TLS schemes

The `tls://`, `quic://`, `wss://`, `sockstls://` schemes support query parameters:

| Parameter | Repeat | Description |
|----------|--------|----------|
| `sni=NAME` | once | Override the SNI (Server Name Indication) for the TLS handshake. Defaults to `host`. For `sockstls://` the default is `target_host` |
| `alpn=PROTO` | many | Add an ALPN protocol. Can be specified multiple times |

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

The `tls_cert`, `tls_key`, `tls_ca_cert` parameters in `[[listen]]` / `[[peers]]` sections apply only to the `tls://`, `quic://`, `wss://` schemes. For `tcp://`, `ws://`, `unix://` they are ignored.

| Parameter | In `[[listen]]` | In `[[peers]]` |
|----------|---------------|--------------|
| `tls_cert` | Server certificate (PEM, leaf or fullchain) | Client certificate (mTLS) |
| `tls_key` | Server private key | Client private key |
| `tls_ca_cert` | CA for verifying clients (mTLS) | CA for verifying the server's certificate |

> Do not pass a CA certificate in the `tls_cert` field for a listener: rustls will reject a CA certificate used as an end-entity server certificate.

### Debugging transports

The `veil-cli debug transport` subcommand lets you manually test connections without launching a full node.

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

For `listen` with TLS schemes (`tls://`, `wss://`, `quic://`) a temporary self-signed certificate is generated automatically. For production testing, pass explicit certificates:

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

The `--tls-cert`, `--tls-key`, `--tls-ca-cert` flags work the same for `tls://`, `wss://`, and `quic://`.

---

## `[[listen]]`

An array of inbound listeners. Each listener is one port on which the node accepts connections.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `id` | `string` (hex u32) | — | Local listener identifier, e.g. `"0x00000001"`. **Required** |
| `transport` | `string` | — | Transport URI to bind on (see [Transport URI format](#transport-uri-format)). **Required** |
| `advertise` | `string` or absent | unset | Address advertised to peers instead of `transport`. Used behind a reverse proxy: bind to `localhost:9443`, advertise `wss://nginx.example.com:443/veil` |
| `relay` | `string` or absent | unset | Hex node_id of a relay node through which this listener can be reached (for NAT). Included in `RouteResponsePayload.relay_ids` |
| `tls_cert` | `string` or absent | unset | PEM server certificate (TLS/WSS) |
| `tls_key` | `string` or absent | unset | Server private key |
| `tls_ca_cert` | `string` or absent | unset | CA certificate for verifying clients (mTLS) |
| `visibility` | enum | `"public"` | Listener visibility level. `"public"` — advertised via PEX + DHT; `"trusted"` — not advertised (out-of-band invite); `"hidden"` — same as trusted plus enforces `allowlist_node_ids` at handshake |
| `psk_file` | `string` (path) or absent | unset | Path to a file containing the PSK (32 bytes, base64) for an `obfs4-tcp://` listener. Overrides the global `[transport].obfs4_psk_file`. Allows splitting PSKs by group — a public listener with a deployment-wide PSK + a family listener with a private one |
| `allowlist_node_ids` | `[string]` | `[]` | List of hex-encoded 32-byte node_ids permitted to authenticate against this listener. Required for `visibility = "hidden"`; optional reinforcement for `"trusted"`. Empty = no allowlist |
| `group_label` | `string` or absent | unset | Human-readable group tag (e.g. `"family"`, `"snowflake"`). Not used by daemon logic; surfaced in logs + metrics |
| `ephemeral` | table or absent | unset | Random-port rotation config (anti-port-clustering). See [`[listen.ephemeral]`](#listenephemeral) below |

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

Periodic random-port rotation for anti-port-clustering (snowflake-style).
The daemon rebinds to a fresh port from `range` every `rotation`; peers learn the new URI through a signed `TransportMigrationNotify` broadcast.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive port range, e.g. `[10000, 60000]`. A narrow range is useful for mimicry of a specific protocol (`[3306, 3306]` — MySQL-SSL). **Required** |
| `rotation` | `string` (duration spec) | — | Rotation interval: `"30s"`, `"5m"`, `"3h"`, `"7d"`. **Required** |
| `bind_retries` | `u32` | `64` | Number of bind attempts on collision (`EADDRINUSE`). 0 = single-shot |
| `grace_period` | `string` (duration spec) | `"30m"` | Window after rotation during which the old listener stays alive for in-flight handshakes before dropping |

**Constraints:**

- Works only for `obfs4-tcp://` listeners (or another transport whose URI supports `with_host_port`).
- Requires an Ed25519 identity — the `TransportMigrationNotify` wire frame is signed via ed25519-dalek; hybrid Falcon-512 + Ed25519 is not yet supported.
- On a failed rebind on the new port, a warn is logged + the old listener stays in service. Peers whose caches already point to the new URI fall back through the DHT.

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

**Logs and metrics:** on rotation the daemon emits structured info-level logs:

- `listen.rotation.spawned` — at startup, confirms the rotator task came up
- `session.migration.notify.applied` — on the peer side, on receiving and applying the broadcast
- `listen.rotation.swap_sent` — on the rotating node's side, after a successful rebind
- `listen.swap` — the accept-loop has switched to the new listener
- `listen.rotation.rebind_failed` (warn) — if the new bind failed; the old one keeps working
- `listen.rotation.bind_failed` (warn) — if the rotator couldn't pick a port from the range

### `[listen.on_demand]`

On-demand listener — a slot binds **on request** rather than at startup.
By default `ss -tlnp` shows no port at all; the port opens only after a
successful PoW handshake, serves a limited number of sessions (or a TTL), and
closes automatically.

**Requirements:**

- `visibility = "stealth"` is required (otherwise config validation throws an error at startup)
- Ed25519 node identity (hybrid Falcon-512 is not supported at this layer)
- **One stealth listener** per node (multi-stealth = TODO in Slice 6+)

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `range` | `[u16, u16]` | — | Inclusive port range for the on-demand bind. **Required** |
| `pow_difficulty` | `u32` | — | Required PoW difficulty in BLAKE3 leading-zero bits. Production: 24 (~16M attempts ≈ 0.5 sec CPU). Minimum 8. **Required** |
| `ttl` | `string` (duration) | — | Slot TTL: `"5m"`, `"300s"`. After the TTL the accept-task exits and the listener closes, even if no session arrived. **Required** |
| `max_concurrent` | `usize` | `16` | Maximum simultaneous on-demand slots. Protects the FD table from a PoW-funded burst |
| `rate_limit` | `string` (`"N/period"`) | `"3/h"` | Per-requester rate limit: `"3/h"` (3 grants per hour per pubkey), `"1/m"`, `"10/30s"` |
| `max_accepts` | `usize` | `1` | How many sessions the slot accepts before retiring. 1 = one-shot rendezvous |
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

Grant rate: `granted / received`. A high `rejected_verify_total` with a low `granted` = either clients are mining too weak a PoW (raise `pow_difficulty`), or forge-attempts (rate-limit and anti-abuse are working). A high `rejected_concurrency_total` = `max_concurrent` is too tight for normal load.

**What is not yet implemented (Slice 6+):**

- **Mediator routing**: at this layer only target-side handling of the request frame is implemented, which assumes the requester already has an OVL1 session with the target (which is nonsense for a stealth listener that has no port). Full integration via a PEX/DHT mediator-relay lands in Slice 6.
- **End-to-end integration tests**: Slice 8.

Until Slice 6 the stealth listener operates in "hooks into the dispatch path, but nobody can reach it through a mediator" mode — useful for unit-testing the controller and observing it through metrics during manual frame injection.

---

## `[[bootstrap_peers]]`

Bootstrap peers for the initial seeding of the DHT routing table. Used only at startup: the node performs FIND_NODE(self), then the session closes (unless the peer is also listed in `[[peers]]`).

Unlike `[[peers]]`, connections to bootstrap peers are **not maintained** persistently.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `transport` | `string` | — | Transport URI (see [Transport URI format](#transport-uri-format)). **Required** |
| `public_key` | `string` | — | Bootstrap node public key (base64). **Required** |
| `nonce` | `string` | `"AAAAAA=="` | Bootstrap node PoW nonce |
| `algo` | enum | `"ed25519"` | Signature algorithm. Values: `"ed25519"`, `"falcon512"`, `"ed25519+falcon512"`, `"ed25519+falcon1024"` (the last two are post-quantum hybrids) |
| `tls_cert` | `string` or absent | unset | PEM certificate (if a TLS transport) |
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

Prometheus metrics exporter (HTTP). The section is optional; if unset — metrics are not exported.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `listen` | `string` | — | Transport URI for the metrics HTTP server — a scheme is **required**, e.g. `"tcp://0.0.0.0:9090"` (a bare `host:port` is rejected). Required when the section is present |
| `path` | `string` or absent | `"/metrics"` | HTTP path for scraping |
| `auth_token` | `string` or absent | unset | Bearer token required to scrape. When set, requests without it are rejected |
| `allow_unauthenticated_remote_metrics` | `bool` | `false` | Allow non-loopback scrapes without a token. Default `false` — remote scrapes require `auth_token` |

**Example:**

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

---

## `[transport]`

Transport-layer settings and censorship-circumvention facilities (DPI evasion). All
keys are optional.

> **TLS backend.** For the `veil-cli` binary, the BoringSSL backend is
> enabled by default (cargo feature `tls-boring`, part of `default = ["rocksdb-cold",
> "tls-boring"]`). It produces a Chrome-like JA3/JA4 fingerprint in the TLS
> ClientHello and supports rotating it. The `rustls` backend is available as a fallback
> when building with `--no-default-features` and cannot substitute the ClientHello —
> the `[transport.tls_fingerprint]` subsection is ignored on it.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `default_sni` | `string` or absent | unset | Default SNI hostname in the TLS ClientHello, when the outbound URI does not set `?sni=...` and the target is not loopback. For example `"www.google.com"` — DPI on the path sees a popular domain instead of the node's real hostname. Unset — use the target host as the SNI |
| `obfs4_psk_file` | `string` (path) or absent | unset | Path to a file with the obfs4 pre-shared key (32 bytes, base64 on a single line). When set, enables the `obfs4-tcp://` transport: the server checks incoming MACs, the client adds a MAC to outgoing handshakes. A single network-wide PSK. Unset — the `obfs4-tcp` transport is disabled |
| `webtunnel_secret_path` | `string` or absent | unset | Webtunnel secret path (e.g. `/_t/random-32-chars`). Activates tunnel mode on the server side of the `webtunnel-wss://` transport |
| `webtunnel_auth_token_file` | `string` (path) or absent | unset | Webtunnel auth-token file (32 random bytes in base64). Passed in the `X-Veil-Auth` header alongside the secret path |
| `webtunnel_decoy_dir` | `string` (path) or absent | unset | Webtunnel decoy-content directory: static files served to probes that did not match the secret path / auth. A snapshot of a neutral site is recommended. Unset — a minimal built-in HTML page |
| `outbound_socks_fallback_proxy` | `string` or absent | unset | URL of a SOCKS proxy used as a **fallback** when a direct dial fails repeatedly (AS-level blocking, ISP route interception). Format `socks5://127.0.0.1:9050` (local Tor) or `socks5://proxy.example:1080`. Unset — direct connections only |
| `bandwidth_mimicry_enabled` | `bool` | `false` | Bandwidth profile mimicry (P2 #7). This is currently a **design landing-pad**: the field is recognized, but the traffic-shaping layer is not yet wired in. Setting it to `true` without `experimental_allow_noop_mimicry` causes a validation error (fail-closed) |
| `bandwidth_mimicry_profile` | `string` or absent | unset | Profile name for `bandwidth_mimicry_enabled`: `"chrome-browsing"`, `"cdn-download"`, `"interactive-chat"`. Still a pure landing-pad |
| `experimental_allow_noop_mimicry` | `bool` | `false` | Confirmation that `bandwidth_mimicry_enabled` is currently a no-op landing-pad, and consent to start the daemon without real mimicry. A required pairing with `bandwidth_mimicry_enabled = true` |
| `obfs4_accept_variants` | `[string]` | `[]` | **Kill-switch, server side**: list of accepted obfs4 wire-format variants in priority order. Empty (resolves to `["v1"]`) preserves pre-Phase-2 behavior. Values: `"v1"`, `"v2"` |
| `obfs4_client_variant` | `string` or absent | unset | **Kill-switch, client side**: obfs4 wire-format variant for outbound `obfs4-tcp://`. Unset — resolves to `v1`. Values: `"v1"`, `"v2"`. Switch to `"v2"` only after every target server's `obfs4_accept_variants` includes `v2` |

### `[transport.rotation]`

Transport-connection rotation policy. Periodically and forcibly
recreates the underlying TCP/TLS connection of each session, so that DPI
classification by flow lifetime (e.g. "this HTTPS session has been alive for 6 hours — that's a VPN")
loses its signal. Each session, at the handshake, picks a random lifetime from
the `[min_lifetime_secs, max_lifetime_secs]` range. The section is **always
serialized** (as a censorship-circumvention facility, the operator must see it in their
config).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `min_lifetime_secs` | `i64` | `1800` | Minimum session lifetime in seconds (30 min). `-1` — disable the entire rotation mechanism. Positive values < 60 are rejected by validation |
| `max_lifetime_secs` | `i64` | `3600` | Maximum session lifetime in seconds (1 hour). `-1` — disable rotation. Must be `>= min_lifetime_secs` when both are positive |

### `[transport.tls_fingerprint]`

TLS ClientHello fingerprint policy for outbound `tls://` / `wss://`
connections. Active **only on builds with `tls-boring`** (the `rustls` backend
cannot change the ClientHello and ignores this section). The section is **always
serialized** — like `[transport.rotation]`, it is a censorship-circumvention control,
discoverable by reading the config.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `mode` | enum | `"rotate"` | Mode: `"pinned"` (always `profile`), `"rotate"` (cycle through the profiles in `rotation` on fresh connections until one completes the handshake), `"random"` (a fresh randomized ClientHello on every connection). The default is `"rotate"` — resilient to blocking: when one JA3 is blocked, the node switches to another |
| `profile` | enum | `"chrome"` | Profile for `"pinned"` mode. Profile tokens: `chrome`, `firefox`, `safari`, `ios`, `android`, `random` |
| `rotation` | `[string]` | `["chrome", "firefox", "safari"]` | Ordered list of profiles to cycle through in `"rotate"` mode |
| `sticky` | `bool` | `true` | In `"rotate"` mode, keep using the last profile that completed the handshake instead of cycling again from the start |

### `[transport.tls_client]`

Trust store for the node's **outbound** TLS (HTTPS bootstrap, webtunnel). Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `connect_timeout_ms` | `u64` or absent | unset | Connect timeout for outbound TLS, in ms |
| `use_system_roots` | `bool` | `false` | Include Mozilla's webpki-roots CA bundle in the client trust store. Default `false` — veil trusts only operator-pinned CAs via `trusted_ca_file`. Set `true` for mesh nodes reaching publicly-certified hosts |
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

Configuration for the local UDP mesh network (neighbor discovery within a single segment). The section is optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `bind_addr` | `string` | — | UDP address for the realm listener, e.g. `"0.0.0.0:9100"`. **Required** when the section is present |
| `realm_id` | `string` | — | 32 hex characters (16 bytes) — the realm identifier. **Required** |
| `beacon_addr` | `string` | `"255.255.255.255:9100"` | Broadcast/multicast address for beacon discovery. The **port** here is the one remaining beacon traffic-shape signal (size and cadence are already hidden when `realm_psk` is set, C-03) — on a hostile LAN, set a non-default port (all realm members must match) |
| `autodiscover_gateway` | `bool` | `true` | Automatically connect to gateway nodes discovered via mesh beacons |
| `autodiscover_max_concurrent` | `usize` | `3` | Maximum simultaneous outbound sessions to auto-discovered gateways |
| `beacon_dedup_window_secs` | `u64` | `3` | Deduplication window for beacons from a single source, in seconds. `0` — disable deduplication |
| `autodiscover_persist_path` | `string` or absent | unset | Path for persisting the `AutoDiscoveredPeers` table. Restored at startup so the nearest gateways are known before the first beacon |
| `require_signed_beacons` | `bool` | `true` | When `true` (default, C-03), only cryptographically-signed mesh beacons are accepted; unsigned beacons are dropped, closing the on-link gateway-injection / neighbor-redirect vector. Set `false` only for legacy interop with deployments still emitting unsigned beacons — flipping signed-on across a live unsigned network partitions those nodes, so roll signed beacons out fleet-wide first |
| `advertise_role_in_beacon` | `bool` | `false` | When `true`, the node advertises its role flags (`IS_GATEWAY` / `IS_RELAY` / `HAS_INTERNET`) in its mesh beacon — required for `autodiscover_gateway` peers to recognise this node as a gateway. Default `false` (C-03): the beacon carries `role_flags = 0`, so a passive on-link observer cannot single the node out as a gateway/relay (a targeting/censorship signal). The stable `node_id` is still broadcast regardless |
| `realm_psk` | `string` or absent | unset | **Opt-in UDP obfuscation.** Base64-encoded pre-shared key (≥ 16 bytes decoded). When set, mesh **DATA** datagrams **and discovery beacons** are AEAD-wrapped (`veil-udp-obfs`: ChaCha20-Poly1305, fresh random nonce + random padding per datagram) so a passive DPI/LAN observer sees only rotating ciphertext — the mesh framing **and the stable `node_id` / role flags / dial address carried in beacons** are hidden (closes C-03; discovery then requires the PSK, expected for a protected realm). The key is realm-wide (HKDF-derived from the PSK and `realm_id`); **all realm members must share the same PSK**, distributed out-of-band. Unset (default) → plaintext mesh + plaintext beacons, byte-for-byte unchanged behaviour. A configured-but-invalid/too-short PSK **disables the mesh** rather than silently falling back to plaintext |

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

Mailbox configuration — message storage for offline recipients.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Master switch — a node only runs a mailbox if you opt in |
| `quota_per_receiver_bytes` | `u64` | `0` (crate default) | Per-receiver storage quota in bytes. `0` = built-in default |
| `quota_global_bytes` | `u64` | `0` (crate default) | Global per-relay storage quota in bytes. `0` = built-in default |
| `quota_per_sender_bytes` | `u64` | `0` (crate default ≈ 10 MiB) | Per-sender byte quota. `0` = built-in default; set `u64::MAX` to effectively disable accounting |
| `ttl_secs` | `u64` | `0` (crate default 7 days) | Stored-blob TTL in seconds. `0` = built-in default |
| `rate_limit_per_minute` | `u32` | `0` (crate default) | Per-receiver PUT rate limit. `0` = built-in default |
| `require_capability_token` | `bool` | `false` | When `true`, tokenless PUTs are rejected with `CapabilityRequired` |
| `[mailbox.push]` | table | absent | Push-provider credentials (FCM / APNs). Absent ⇒ log-only dispatcher (puts logged, no provider API call) |

**Example:**

```toml
[mailbox]
enabled                  = true
quota_per_receiver_bytes = 67108864   # 64 MiB
ttl_secs                 = 604800     # 7 days
require_capability_token = true
```

### `[mailbox.push]`

Push-notification provider credentials (FCM / APNs). When empty, the daemon uses a log-only dispatcher (puts are logged, no provider call).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `fcm_credentials_path` | `string` | `""` | Path to the Firebase Cloud Messaging service-account JSON |
| `apns_p8_path` | `string` | `""` | Path to the APNs `.p8` signing key |
| `apns_key_id` | `string` | `""` | APNs key ID |
| `apns_team_id` | `string` | `""` | Apple developer team ID |
| `apns_bundle_id` | `string` | `""` | App bundle ID (the APNs topic) |
| `apns_environment` | `string` | `"production"` | APNs environment: `"production"` or `"sandbox"` (empty ⇒ production) |

---

## `[ipc]`

Configuration of the IPC server for connecting local applications via a Unix socket.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Enable the IPC server |
| `socket_uri` | `string` or absent | `~/.veil/app.sock` | IPC endpoint. Accepts a Unix path / `unix:///abs/path`, or `tcp://127.0.0.1:0?runtime_dir=...` (TCP loopback — the Windows path) |
| `e2e_key_ttl_secs` | `u64` | `3600` | TTL of the cache of peers' ML-KEM-768 encapsulation keys, in seconds. After expiry — a new `RouteRequest/RouteResponse` for a fresh key |
| `app_socket_dir` | `string` or absent | unset | Directory where the node opens an additional per-app Unix socket `{app_socket_dir}/{hex(app_id)}.sock` for app-scoped IPC |

**Example:**

```toml
[ipc]
enabled     = true
socket_uri = "/run/veil/app.sock"
e2e_key_ttl_secs = 1800
```

---

## `[priority_weights]`

Weighted Round Robin (WRR) weights for the 4 traffic classes in the outbound scheduler.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `realtime` | `u32` | `8` | Weight for REALTIME traffic (voice, hard-RT interactive) |
| `interactive` | `u32` | `4` | Weight for INTERACTIVE traffic (ordinary interactive) |
| `bulk` | `u32` | `2` | Weight for BULK traffic (file transfer) |
| `background` | `u32` | `1` | Weight for BACKGROUND traffic (background sync) |

The node sends `realtime` REALTIME-class frames for every `background` BACKGROUND frames.

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

Proxy functionality of the veil node.

### `[proxy.socks5]`

SOCKS5 proxy: the node accepts SOCKS5 CONNECT and tunnels TCP over the veil to an exit node.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Enable the SOCKS5 listener |
| `listen` | `string` | `"127.0.0.1:1080"` | TCP address for the SOCKS5 listener |
| `exit_node_id` | `string` or absent | unset | Pin the exit by hex node_id — SOCKS5 traffic is tunneled to this node. If unset, an exit is chosen dynamically |

### `[proxy.exit]`

Exit proxy: the node accepts veil proxy-connect streams and establishes outbound TCP connections.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Enable the exit proxy. When `true`, this node forwards connections to external TCP addresses |
| `allow_private` | `bool` | `false` | Allow exit connections to private/RFC1918 ranges (10/8, 172.16/12, 192.168/16, loopback). Default `false` — blocked (SSRF guard) |

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

> **Moved.** The TUN/TAP veil-VPN was extracted into the separate **`ogate`**
> binary and is now configured in its own `ogate.toml` (per-network `peers[]`
> allowlist, `iface_name`, `mode`, `mtu`, …). The main node config no longer has
> a `[tun]` section — see **[ogate.md](ogate.md)**.

---

## `[session]`

Session-layer settings: keepalive, idle timeout, queues.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `keepalive_interval_secs` | `u64` | `30` | Interval for sending keepalive frames, in seconds. `0` — disable |
| `idle_timeout_secs` | `u64` | `90` | Close the session if no frame is received within this time. Must be > `keepalive_interval_secs` |
| `max_concurrent` | `usize` | `512` | Maximum simultaneous OVL1 sessions |
| `max_per_ip` | `usize` | `32` | Maximum inbound sessions from a single IP address |
| `max_pending_responses` | `usize` | `256` | Maximum pending RPC responses per session. Excess — dropped |
| `pending_response_ttl_ms` | `u64` | `30000` | TTL of a pending-response slot in ms. Stale ones are evicted |
| `tx_queue_depth` | `usize` | `4096` | Size of the outbound-frame channel per session. Overflow — dropped |
| `outbox_depth` | `usize` | `256` | Size of the RPC outbox per session. When the channel is full, `send_request()` returns `None` |
| `max_frame_body_bytes` | `u32` | 1 MiB | Maximum frame body size. Larger frames are rejected. Hard ceiling: 16 MiB |
| `qos_weights` | `[u8; 4]` | `[8, 4, 2, 1]` | WRR weights for the classes `[RealTime, Interactive, Bulk, Background]` within a session |
| `rt_queue_len` | `usize` | `64` | Depth of the REALTIME queue per session. Overflow — dropped |
| `bg_queue_len` | `usize` | `256` | Depth of the BACKGROUND queue per session. Overflow — dropped |
| `rekey_bytes_threshold` | `u64` | 128 GiB (`137_438_953_472`) | Initiate a rekey after this volume of bytes transferred per session |
| `rekey_time_threshold_secs` | `u64` | 32 days (`2_764_800`) | Initiate a rekey after this time since the last rekey or session start |
| `max_per_subnet` | `usize` | `64` | Maximum inbound sessions from a single /24 (IPv4) or /48 (IPv6) subnet |
| `battery_threshold_low` | `u8` | `20` | Battery % at or below which the "low" keepalive scaling applies |
| `battery_threshold_medium` | `u8` | `50` | Battery % at or below which the "medium" keepalive scaling applies |
| `battery_keepalive_scale_low` | `f32` | `4.0` | Keepalive-interval multiplier when battery ≤ `battery_threshold_low` |
| `battery_keepalive_scale_medium` | `f32` | `2.0` | Keepalive-interval multiplier when battery ≤ `battery_threshold_medium` |
| `battery_sync_threshold` | `u8` | `15` | Battery % below which background sync is suppressed |
| `allowed_peer_algos` | `[enum]` | `[]` | Allowlist of peer signature algorithms accepted at handshake (`"ed25519"`, `"falcon512"`, hybrids). Empty = accept all supported |

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

Outbound traffic shaping (anti-fingerprinting). Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `mode` | enum | `"adaptive"` | Padding mode: `"adaptive"` (size-bucket padding), `"none"` (off), `"full"` (maximum padding) |
| `jitter_ms` | `u32` | `0` | Maximum random delay (ms) added to each outbound frame. `0` = no jitter |
| `cover_interval_ms` | `u32` | `0` | Interval (ms) between cover (dummy) frames during idle sessions. `0` = no cover traffic |

---

## `[hot_standby]`

Warm-standby transport: keep a second transport primed so a failing primary can be swapped without dropping the session. Optional.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `false` | Enable hot-standby transport swapping |
| `handoff_timeout_secs` | `u64` | `5` | Deadline for completing a handoff before it is aborted |
| `max_swaps_per_minute` | `u32` | `4` | Rate cap on transport swaps (anti-flap) |
| `auto_trigger_after_write_errors` | `u32` | `3` | Consecutive write errors on the primary that auto-trigger a swap |

---

## `[gateway]`

Gateway-functionality settings (attachment records for leaf nodes).
Available only for Core nodes.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Enable the gateway (attachment records for leaf nodes). Can be disabled on a Core node |
| `attachment_lease_ttl_secs` | `u64` | `300` | Lifetime of an attachment lease without keepalive, in seconds |
| `keepalive_interval_secs` | `u64` | `60` | Interval for sending leaf→core keepalives, in seconds. `0` — disable (not recommended in production) |

**Example:**

```toml
[gateway]
attachment_lease_ttl_secs = 600
keepalive_interval_secs   = 120
```

---

## `[nat]`

NAT-traversal configuration (hole punching + relay fallback).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Enable NAT traversal. `false` — only if all peers are directly reachable |
| `punch_timeout_ms` | `u64` | `3000` | Maximum wait time for a UDP hole-punch, in ms. Then — relay fallback |
| `stun_servers` | `[string]` | `[]` | List of external STUN servers (`"host:port"`, RFC 5389). If empty — the address is determined via the veil (a core node reflects the source) |
| `relay_enabled` | `bool` | `true` | Allow relay fallback when hole-punch fails |

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

Settings for the PoW rate limiter for `PowChallenge` frames.

Relevant only when `abuse.pow_min_difficulty > 0`.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `challenge_rate` | `f64` | `1.0` | Sustained rate of issuing PoW challenges per peer per second |
| `challenge_burst` | `f64` | `1.0` | Permitted burst for the PoW rate limiter per peer. Burst=1 is enough for a legitimate `RouteRequest` flow |
| `challenge_window_secs` | `u64` | `300` | Sliding window of PoW rate-limiter state, in seconds |

---

## `[connection]`

Settings for outbound reconnects and gateway failover.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `reconnect_backoff_min_ms` | `u64` | `1000` | Minimum reconnect interval in ms |
| `reconnect_backoff_max_ms` | `u64` | `300000` | Maximum reconnect interval in ms (5 minutes) |
| `prefer_internet_gateway` | `bool` | `true` | Prefer a gateway with the `HAS_INTERNET` flag for routing to global nodes. `false` — use the nearest gateway regardless of internet access |
| `gateway_failover_delay_secs` | `u64` | `5` | Minimum gateway-unavailability time (sec) before switching. Short outages are ignored |
| `exit_diversification` | `bool` | `false` | Sample exit-gateway selection weighted-random from the top-K candidates instead of always the single best — reduces statistical fingerprinting (one fat flow to one IP is distinctive) |
| `exit_diversification_top_k` | `u8` | `4` | Window size for `exit_diversification`: pick from the top-K gateways by score |
| `reconnect_quiet_after_failures` | `u32` | `5` | Consecutive reconnect failures after which per-attempt logs drop WARN→DEBUG (keeps retrying; emits `INFO peer.recovered` on recovery). `0` keeps WARN forever |

**Example:**

```toml
[connection]
reconnect_backoff_min_ms     = 500
reconnect_backoff_max_ms     = 60000
prefer_internet_gateway      = true
gateway_failover_delay_secs  = 10
```

---

## `[capacity]`

Load-shedding limits for relay nodes. `0` = no limit.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `max_relay_sessions` | `usize` | `0` | Maximum simultaneous relay sessions. `0` — no limit |
| `max_total_sessions` | `usize` | `0` | Maximum of all sessions (relay + direct). `0` — no limit |
| `tx_queue_high_watermark` | `f64` | `0.8` | TX-queue fill fraction at which the node is considered overloaded (0.0–1.0) |
| `congestion_high` | `f64` | `0.8` | Congestion-score threshold above which the node drops new relay sessions |
| `congestion_low` | `f64` | `0.6` | Congestion-score threshold below which the node resumes accepting relay sessions (hysteresis) |
| `max_inbound_bandwidth_kbps` | `i64` | `10000000` | Per-node aggregate inbound bandwidth cap in kbps (10 Gbit/s default). `-1` — unlimited |
| `max_outbound_bandwidth_kbps` | `i64` | `10000000` | Per-node aggregate outbound bandwidth cap in kbps. `-1` — unlimited |

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
| `rate_limit_fps` | `f64` | `200000.0` | Per-peer sustained frame rate (frames/sec) |
| `rate_limit_burst` | `f64` | `400000.0` | Per-peer burst frame quota |
| `pow_min_difficulty` | `u32` | `16` | Leading-zero bits required in the `RouteRequest`/`PowChallenge` PoW (≈65k hashes, <1 ms). `0` disables (dev only); hard cap is `MAX_POW_DIFFICULTY = 24` |
| `ban_threshold` | `u32` | `5` | Protocol violations before a temporary ban |
| `ban_initial_secs` | `u64` | `5` | Duration of the first ban (seconds) |
| `ban_step_secs` | `u64` | `5` | Added per subsequent ban — progressive: Nth ban = `ban_initial_secs + N × ban_step_secs`, capped at `ban_max_secs` |
| `ban_max_secs` | `u64` | `3600` | Ceiling for the progressive ban duration (seconds) |

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

Fine-tuning of the routing plane.

### Core parameters

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `route_probe_interval_secs` | `u64` | `30` | Interval for sending ROUTE_PROBE in seconds |
| `reannounce_interval_secs` | `u64` | `30` | Interval for re-announcing routes in seconds |
| `route_cache_ttl_secs` | `u64` | `120` | TTL of entries in the route cache |
| `route_request_backoff_ms` | `[u64; 3]` | `[500, 1000, 2000]` | Backoff for RouteRequest retries: [attempt0, attempt1, attempt2] ms |
| `partition_score_threshold` | `f64` | `0.2` | Minimum `network_reachability_score` (0.0–1.0) before logging a network partition. `0.0` — disable |
| `route_seen_capacity` | `usize` | `4096` | Size of the route-deduplication cache |
| `route_seen_window_secs` | `u64` | `120` | Route-deduplication window in seconds |
| `max_gossip_hops` | `u8` | `2` | Maximum TTL of gossip frames. Frames with a higher hop count are dropped |

### ECMP and redundant send

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `ecmp_score_band` | `f64` | `0.20` | Maximum relative score difference for including a route in the ECMP group. `0.0` — disable ECMP |
| `redundant_send` | `bool` | `false` | Send critical frames simultaneously over the two best paths. Lowers p99 latency at the cost of doubling traffic |

### Adaptive probe intervals

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `probe_min_interval_secs` | `u64` | `5` | Minimum ROUTE_PROBE interval on an unstable path |
| `probe_max_interval_secs` | `u64` | `120` | Maximum ROUTE_PROBE interval on a stable path |
| `probe_stability_threshold` | `f64` | `0.05` | Stability threshold (`std_dev/mean` of RTT). Below it — the path is stable, probes are sent less often |

### Epidemic broadcast

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `epidemic_fanout` | `usize` | `3` | Number of random neighbors to forward an `EpidemicBroadcast` to |
| `epidemic_max_payload` | `usize` | `4096` | Maximum payload size for `EpidemicBroadcast` in bytes |

### Battery-aware routing

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `battery_penalty_low` | `f64` | `3.0` | Penalty multiplier at critically low charge (< `battery_threshold_low` %) |
| `battery_penalty_medium` | `f64` | `0.5` | Penalty multiplier at medium charge (< `battery_threshold_medium` %) |
| `battery_threshold_low` | `u8` | `20` | Threshold (%) for applying `battery_penalty_low` |
| `battery_threshold_medium` | `u8` | `40` | Threshold (%) for applying `battery_penalty_medium` |

### Distributed tracing

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `trace_sample_rate` | `f64` | `0.01` | Fraction of outbound DELIVERY_FORWARD frames with `trace_id` injection (0.0 = off, 1.0 = all) |
| `trace_buffer_size` | `usize` | `10000` | Size of the ring buffer of trace-hop records per node |

### Persistence

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `cache_persist_path` | `string` or absent | unset | Path for a route-cache snapshot. `None` — disable |
| `cache_persist_interval_secs` | `u64` | `30` | Interval for writing the route-cache snapshot |
| `cache_persist_max_age_secs` | `u64` | `3600` | Maximum snapshot age on load. Stale files are ignored |
| `rtt_persist_path` | `string` or absent | unset | Path for an RTT-table snapshot |
| `rtt_persist_interval_secs` | `u64` | `60` | Interval for writing the RTT snapshot |
| `vivaldi_persist_path` | `string` or absent | unset | Path for persisting Vivaldi coordinates |
| `gateway_persist_path` | `string` or absent | unset | Path for persisting the gateway list (ranked) |
| `peer_pubkeys_persist_path` | `string` or absent | unset | Path for the cache of public keys of known peers |
| `discovery_mode` | enum | `"public"` | Visibility advertised in the handshake. Values: `"public"`, `"contacts_only"` |
| `target_labels` | `[string]` | `[]` | Operator labels advertised for label-based routing/selection |
| `dht_fallback_timeout_ms` | `u64` | `10000` | Timeout before falling back to a DHT lookup when direct route discovery stalls, in ms |
| `dht_fallback_backpressure_threshold_pct` | `u8` | `75` | Queue-fill % above which DHT-fallback lookups are throttled |
| `dht_fallback_adaptive` | `bool` | `false` | Adaptively tune the DHT-fallback timeout from observed latencies |
| `dht_fallback_priority_mult` | `[u16; 2]` | `[50, 200]` | Priority multipliers `[floor, ceiling]` applied to DHT-fallback traffic |
| `multi_path_enabled` | `bool` | `false` | Send over multiple disjoint paths in parallel for resilience |
| `max_parallel_paths` | `u8` | `2` | Maximum disjoint paths when `multi_path_enabled` |
| `multi_path_min_priority` | `u8` | `1` (INTERACTIVE) | Only multi-path traffic at or above this priority class |
| `relay_reputation_min_attempts` | `u32` | `10` | Minimum relay attempts before reputation downweighting engages |
| `relay_reputation_threshold` | `f64` | `0.5` | Success-rate below which a relay is downweighted |
| `relay_reputation_penalty` | `f64` | `2.0` | Score-penalty multiplier applied to low-reputation relays |
| `jitter_penalty_weight` | `f64` | `0.5` | Weight of the RTT-jitter penalty in path scoring |
| `jitter_threshold_ms` | `u64` | `20` | Jitter (ms) above which the jitter penalty applies |
| `narrow_bandwidth_bulk_penalty` | `f64` | `2.0` | Penalty multiplier for routing BULK traffic over narrow-bandwidth links |

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
| `republish_interval_secs` | `u64` | `1800` | Interval for re-publishing DHT records (30 minutes) |
| `cleanup_interval_secs` | `u64` | `60` | Interval for cleaning up expired DHT records |
| `participate` | `bool` | `true` | Participate in DHT storage (accept STORE/DELETE). `false` — routing only (FIND_NODE/FIND_VALUE) |
| `k` | `u8` | `20` | Kademlia k-bucket size — contacts in a FIND_NODE response |
| `alpha` | `u8` | `3` | Kademlia α — parallel requests per round of the iterative lookup |
| `max_rounds` | `u8` | `20` | Maximum iterative-lookup rounds before giving up |
| `find_node_timeout_ms` | `u64` | `2000` | Timeout of a single FIND_NODE/FIND_VALUE RPC in ms |
| `vivaldi_weight` | `f64` | `0.3` | Weight of the Vivaldi topology factor in ranking DHT nodes. `0.0` — pure XOR ordering |
| `routing_persist_path` | `string` or absent | unset | Path for persisting the DHT k-bucket routing table |
| `values_persist_path` | `string` or absent | unset | Path for persisting stored DHT values (a periodic JSON snapshot of the entire store) |
| `cold_store_path` | `string` or absent | unset | Directory for an on-disk **RocksDB cold tier** for evicted DHT values. When set (and the binary is built with the `rocksdb-cold` feature — enabled by default for `veil-cli`), values evicted from the in-memory hot tier are written to this on-disk RocksDB store instead of the bounded in-memory cold map. Lifts the entry-count limit from RAM to disk (a dedicated DHT node serves >1M entries); cold records survive a restart. Differs from `values_persist_path` (a periodic JSON snapshot): the cold tier is a live, continuously-updated DB. If the feature is absent or RocksDB failed to open — it is ignored with a log line at startup, and the node falls back to the in-memory cold tier |
| `allow_unsigned_store` | `bool` | `false` | Accept legacy **unsigned** raw STOREs. Default `false` (rejected outright). Re-enabling is a deploy footgun — see [OPERATIONS](OPERATIONS.md); a one-shot deprecation warning fires on first acceptance |
| `max_store_entries` | `usize` | `25000` | Hard cap on entries in the DHT store. Lift for dedicated DHT seeds (e.g. `250000`); to exceed RAM, page out via the `cold_store_path` RocksDB tier |
| `max_store_bytes` | `u64` or absent | unset | Optional byte-size cap on the DHT store (complements `max_store_entries`) |
| `per_origin_max_bytes` | `u64` or absent | unset | Per-signer byte cap (Этап 11e) — bounds how much one origin can store so a single signer can't exhaust the store |
| `shard_filtering` | `bool` | `false` | Opt-in: only accept STOREs whose key falls in this node's shard. Default `false`; intended to become default-on once the network exceeds ~1M nodes |

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

Peer Exchange — random-walk peer discovery. Optional; sensible defaults.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `enabled` | `bool` | `true` | Enable PEX random-walk discovery |
| `max_peers` | `usize` | `32` | Max peers to keep from PEX discovery |
| `walk_parallelism` | `u8` | `3` | Parallel walk requests per round |
| `max_response_peers` | `u8` | `16` | Max peers returned per PEX response |

---

## `[anycast]`

Anycast service-resolution policy.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `resolve_policy` | enum | `"signed_bound"` | How anycast records are accepted. Values: `"signed_bound"` (default — signed + owner-bound), `"signed_only"` (reject unsigned), `"best_effort"` (accept any — legacy, not recommended) |

---

## `[mobile]`

Battery- and background-aware throttling for mobile / battery-powered leaf nodes. Optional (the `mobile` profile pre-fills it).

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `low_battery_threshold_pct` | `u8` or absent | unset | Battery % at or below which probe rates throttle. Unset disables battery awareness; typical mobile value `30` |
| `low_battery_multiplier` | `u32` | `4` | Probe-interval multiplier when below the battery threshold (4 = 4× less often). Capped at a safe max |
| `background_keepalive_multiplier` | `u32` | `1` | Keepalive-interval multiplier when the runtime `background_mode` flag is set (composes with battery scaling). `1` = off; the `mobile` profile sets `60` (30 s → 30 min) |
| `low_battery_throttle_maintenance` | `bool` | `false` | Also throttle background maintenance tasks under low battery. Recommended for cellular/mobile |

---

## `[anonymity]`

This node's participation as an onion-routing relay. Optional. (The node always uses anonymity for its OWN sends; this controls whether it carries OTHER peers' circuits.)

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `relay_capable` | `bool` | `false` | Advertise the `ANONYMITY_RELAY` capability and be selectable as a circuit hop. `false` = invisible to relay-directory lookups |
| `advertised_bps` | `u32` | `0` | Self-reported (UNVERIFIED) relay bandwidth in bytes/sec for load-balancing. Only meaningful when `relay_capable = true`. `0` = "don't know / lowest-priority" |

---

## `[update]`

Self-update via signed manifests. Optional — the mechanism engages only when `expected_issuer_pk` is set.

| Key | Type | Default | Description |
|------|-----|-------------|----------|
| `manifest_urls` | `[string]` | `[]` | HTTPS URLs serving the operator's signed update manifest. Multiple diverse providers defend against single-endpoint takedown |
| `expected_issuer_pk` | `string` or absent | unset | Hex public key the manifest must be signed by. **Must be set** for the update mechanism to engage |
| `installed_version_path` | `string` or absent | unset | File recording the installed binary's `release_unix`. Required for the apply path |
| `install_path` | `string` or absent | unset | Path of the binary itself (atomic stage + rename target). Required for the apply path |
| `check_interval_secs` | `u64` or absent | unset | When set, poll `manifest_urls` every N seconds (hard floor 60). Unset disables auto-poll |

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
