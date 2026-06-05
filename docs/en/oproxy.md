# oproxy: Veil-Network Proxy Bridge

Two-binary system that tunnels local proxy traffic (SOCKS5 / HTTP /
transparent) through an veil-network session to a remote exit node,
then on to the real internet.

```
[local app]
    │ SOCKS5  /  HTTP CONNECT  /  transparent (TPROXY)
    ▼
[oproxy-client]  ◀── connects to local veil daemon via IPC
    │
    │  veil session (E2E encrypted)
    │
    ▼
[veil daemon on the server]
    │
    │  bound endpoint → routed to oproxy-server
    ▼
[oproxy-server]
    │ TCP CONNECT to host:port
    ▼
[real internet]
```

`oproxy-client` and `oproxy-server` both connect to a **local veil
daemon** on their respective hosts; the proxy traffic flows over the
veil between those two daemons. Russian translation:
[oproxy.md](../ru/oproxy.md).

## Why veil instead of a plain HTTPS proxy

- **End-to-end veil encryption** — peers can't be impersonated
  even if a CA is compromised; identities are sovereign keypairs.
- **No exposed cleartext port on the server** — the server doesn't
  listen on any public IP for proxy traffic; all flow is veil-
  tunnelled. Public surface is the veil daemon itself.
- **Custom app names** — multiple proxy services can coexist on one
  daemon without port collisions (each gets a distinct `app_id`
  derived from its name).
- **`node_id` allowlist on the server** — drop unauthorized peers at
  the app layer; no firewall rules, no certs, no rotation hassles.

## Inbound modes

| Mode    | Use case                                    | Platforms |
|---------|---------------------------------------------|-----------|
| SOCKS5  | Browser SOCKS proxy, `curl --socks5`        | All (Linux / macOS / Windows / FreeBSD / Keenetic) |
| HTTP    | Browser HTTP/HTTPS proxy (`HTTP_PROXY=...`) | All |
| TProxy  | Transparent gateway (`iptables -j TPROXY`)  | Linux / Keenetic only |

Multiple inbound listeners can run concurrently on the same client.

---

## `oproxy-client`

Standalone binary. Connects to the local veil daemon, binds an
endpoint, listens locally for one or more inbound modes, and tunnels
each connection to the configured upstream `(server_node_id,
server_app_name)`.

```bash
oproxy-client --config /etc/oproxy/client.toml
```

### Bootstrap a config from scratch

```bash
# 1. Generate the template (writes to stdout — redirect to file).
sudo mkdir -p /etc/oproxy
sudo oproxy-client --gen-config | sudo tee /etc/oproxy/client.toml >/dev/null
sudo chmod 0640 /etc/oproxy/client.toml
sudo chown root:veil /etc/oproxy/client.toml

# 2. Edit it — at minimum: server_node_id, server_app_name, [[inbound]] listeners.
sudo vim /etc/oproxy/client.toml

# 3. Run it AS THE DAEMON'S USER (not root). The daemon drops any IPC
#    connection whose peer uid != its own (audit U9, no root exception),
#    so a root-owned client is silently dropped on the app socket.
sudo -u veil oproxy-client --config /etc/oproxy/client.toml
```

> **Run as the daemon user, never root.** The veil daemon enforces a
> kernel-level peer-uid match (`SO_PEERCRED` / `getpeereid`) on its IPC
> socket and drops any connection from a different uid — root included.
> Run `oproxy-client` as whatever user the daemon runs as (here
> `veil`). TProxy still needs `CAP_NET_ADMIN`; grant it to that user
> (e.g. `setcap cap_net_admin+ep`) instead of running as root.

### Minimal config

```toml
socket_path     = "/var/lib/veil/app.sock"
server_node_id  = "00112233445566778899001122334455667788990011223344556677889900aa"
server_app_name = "my-proxy"

[[inbound]]
kind   = "socks5"
listen = "127.0.0.1:1080"
```

### Full config

```toml
socket_path     = "/var/lib/veil/app.sock"
server_node_id  = "<64-hex node_id of oproxy-server's host>"
server_app_name = "my-proxy"

[[inbound]]
kind   = "socks5"
listen = "127.0.0.1:1080"

[[inbound]]
kind   = "http"
listen = "127.0.0.1:8080"

[[inbound]]
kind   = "tproxy"          # Linux / Keenetic only
listen = "0.0.0.0:12345"

# Optional. Per-target routing — proxy / direct / block.
# Default: all traffic via veil, no fallback (fail on veil down).
[routing]
default  = "veil"   # veil | direct | block
fallback = "fail"      # global default — overridden per rule below

[[routing.rules]]      # first match wins; AND within a rule
host_suffix = ".internal"
action      = "direct"

[[routing.rules]]
cidr     = "10.0.0.0/8"
action   = "veil"
fallback = "direct"    # per-rule override: try veil, then direct

[[routing.rules]]
cidr     = "172.16.0.0/12"
action   = "veil"
fallback = "fail"      # per-rule override: try veil, then return error

[[routing.rules]]
cidr   = "192.168.0.0/16"
action = "direct"      # never go through veil

# Optional. Tokio knobs — shared schema with veil-cli + ogate.
[runtime]
flavor               = "multi_thread"
worker_threads       = 4
max_blocking_threads = 64

# Optional. Log destination + level.
[logging]
level = "info"                       # off | error | warn | info | debug | trace
file  = "/var/log/oproxy-client.log" # optional — defaults to stderr
```

---

## `oproxy-server`

Standalone binary. Binds an veil app endpoint via IPC, accepts
incoming veil streams, and bridges each one to its requested TCP
destination.

```bash
oproxy-server --config /etc/oproxy/server.toml
```

### Bootstrap a config from scratch

```bash
# 1. Generate the template.
sudo mkdir -p /etc/oproxy
sudo oproxy-server --gen-config | sudo tee /etc/oproxy/server.toml >/dev/null
sudo chmod 0640 /etc/oproxy/server.toml
sudo chown root:veil /etc/oproxy/server.toml

# 2. Edit it — at minimum: app_name and either allowed_node_ids list
#    OR allow_all=true (explicit open-proxy opt-in).
sudo vim /etc/oproxy/server.toml

# 3. Run it AS THE DAEMON'S USER (not root). The daemon drops any IPC
#    connection whose peer uid != its own (audit U9, no root exception),
#    so a root-owned server is silently dropped on the app socket.
sudo -u veil oproxy-server --config /etc/oproxy/server.toml
```

### Config

```toml
socket_path = "/var/lib/veil/app.sock"
app_name    = "my-proxy"

# Optional allowlist by source node_id (hex). Empty = open proxy.
allowed_node_ids = [
  "0011223344556677889900112233445566778899001122334455667788990011",
]

# When false (default, recommended) the exit refuses outbound TCP to
# RFC1918 / loopback / multicast / link-local + cloud-metadata (169.254/16) /
# CGNAT (100.64/10) targets — including their IPv4-mapped/-compatible IPv6
# forms (`::ffff:a.b.c.d`, `::a.b.c.d`). Set true only for a deliberately
# LAN-facing exit.
allow_private = false

# Optional. Shared runtime + logging schema.
[runtime]
flavor         = "multi_thread"
worker_threads = 2

[logging]
level = "info"
file  = "/var/log/oproxy-server.log"
```

`app_id` is derived deterministically from the server's `node_id` +
`app_name`: clients with the matching `server_app_name` compute the
same bytes locally and dial that exact endpoint.

---

## Routing modes (client)

The `[routing]` section drives per-target dispatch. For each
`(host, port)` the client receives over its inbound listeners, the
routing engine walks `rules` in order (first match wins) and applies
the matched rule's `action`. If no rule matches, the global `default`
applies.

### Actions

| Action    | Behaviour |
|-----------|-----------|
| `veil` | Open an veil stream to `(server_node_id, server_app_name)` |
| `direct`  | Skip veil; TCP-connect directly from the local host |
| `block`   | Refuse with a SOCKS5 / HTTP error reply |

### Rule fields (all optional — empty = wildcard; rule is a conjunction)

| Field | Matches |
|---|---|
| `host_suffix` | hostname ends with this string (case-insensitive); e.g. `.internal` matches `db.internal` |
| `host_exact`  | hostname equals this (case-insensitive) |
| `cidr`        | host parses as IPv4/IPv6 literal AND falls inside this CIDR |
| `port_range`  | `"443"` (single) or `"1024-65535"` (inclusive range) |
| `action`      | (required) one of `veil` / `direct` / `block` |
| `fallback`    | per-rule override; one of `direct` / `fail` |

**Note**: `cidr` matches IP literals only — hostnames are not
DNS-resolved on the client. Use `host_suffix` for hostname-based
rules.

### Fallback semantics

Applies only when `action = "veil"` and the veil path fails
(server unreachable, timeout, denied, or rejected).

| `fallback` | On veil failure |
|---|---|
| `fail` | Return CONNECT failure to the inbound client (no recovery) |
| `direct` | Silently TCP-connect direct from the local host, then bridge |

The fallback opportunity exists only during phases 1–3 of the
veil handshake (open stream / write connect header / read status
reply). Once Phase 4 (bridge) starts, payload bytes are flowing on
both sides — the connection is committed and any failure passes
through to the inbound client.

Per-rule `fallback` overrides the global `[routing] fallback`. If
omitted on a rule, the global value applies.

### Example: RFC1918 split

```toml
[routing]
default  = "veil"   # everything else via veil
fallback = "fail"      # global default — fail when veil is down

[[routing.rules]]
cidr     = "10.0.0.0/8"
action   = "veil"
fallback = "direct"    # 10/8 — try veil, then direct on failure

[[routing.rules]]
cidr     = "172.16.0.0/12"
action   = "veil"
fallback = "fail"      # 172.16/12 — try veil, fail-closed (matches global)

[[routing.rules]]
cidr   = "192.168.0.0/16"
action = "direct"      # 192.168/16 — never use veil
```

Resulting per-target behaviour:

| Target          | mode    | on veil failure |
|-----------------|---------|---------------------|
| `10.x.x.x:*`    | veil | direct              |
| `172.16-31.x:*` | veil | fail                |
| `192.168.x.x:*` | direct  | n/a                 |
| anything else   | veil | fail (default)      |

---

## Runtime + logging configuration

Shared schema with `veil-cli` and `ogate`. Both sections are
optional; if omitted, sensible defaults apply.

### `[runtime]`

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "oproxy-client"
thread_stack_size    = 2097152
```

**Env-var overrides** (apply after config load, win over file):

| Env var | Effect |
|---|---|
| `OPROXY_RUNTIME` | `current_thread` or `multi_thread` |
| `OPROXY_WORKERS` | worker thread count |
| `OPROXY_MAX_BLOCKING_THREADS` | blocking pool cap |

### `[logging]`

```toml
[logging]
level = "info"                  # off | error | warn | info | debug | trace
file  = "/var/log/oproxy.log"   # optional — defaults to stderr
```

| Field | Default | Description |
|---|---|---|
| `level` | `info` | Min level emitted. `off` skips logger init entirely (zero log output, including warnings/errors). |
| `file` | (stderr) | Optional log file. Logs are appended (file created if absent). Parent directory must exist. |

`RUST_LOG` env var overrides `level`:

```bash
RUST_LOG=oproxy=debug oproxy-client --config client.toml
```

---

## Setting up TProxy on Linux / Keenetic

```bash
# Mark + route transit traffic to the listener:
iptables -t mangle -A PREROUTING -p tcp \
    --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 12345
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

oproxy-client --config client.toml
```

The listener accepts connections to any destination and retrieves the
original target via `SO_ORIGINAL_DST`. Requires `CAP_NET_ADMIN`.

---

## Wire protocol (oproxy-client ↔ oproxy-server)

After the veil stream is open, the client sends a connect header
and waits for a status reply:

```text
client → server:   [host_len u16 BE][host UTF-8][port u16 BE]
server → client:   [status u8]
```

| Status | Meaning |
|---|---|
| `0x00` | Connected; proceed with byte-pipe |
| `0x01` | Denied (node_id not in allowlist OR forbidden destination) |
| `0x02` | Connect failed (DNS / TCP error) |
| `0x03` | Bad request (malformed header) |

On non-OK status the server closes the stream after replying. The
client's `fallback` decision is based on this status (Denied / Connect
failed / Bad request all qualify as recoverable failures during
phases 1–3).

---

## Related code

- [`crates/oproxy/src/config.rs`](../../crates/oproxy/src/config.rs) — TOML schema
- [`crates/oproxy/src/routing.rs`](../../crates/oproxy/src/routing.rs) — per-target rule engine
- [`crates/oproxy/src/connector.rs`](../../crates/oproxy/src/connector.rs) — veil-side bridge + fallback
- [`crates/oproxy/src/inbound/`](../../crates/oproxy/src/inbound/) — SOCKS5 / HTTP / TProxy listeners
- [`crates/oproxy/src/logging.rs`](../../crates/oproxy/src/logging.rs) — logger init helper
- [`crates/oproxy/README.md`](../../crates/oproxy/README.md) — crate-level README

## Limitations / open work

- No UDP forwarding (TCP only).
- No DNS resolution on the client — hostnames are forwarded
  literally to the server, which does its own DNS lookup. This means
  `cidr`-based routing rules don't catch hostname targets (use
  `host_suffix` for those).
- FreeBSD TProxy support is currently stubbed (returns startup error);
  use SOCKS5 on FreeBSD instead.
