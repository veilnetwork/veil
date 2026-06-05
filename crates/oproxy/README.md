# oproxy — Veil-network proxy bridge

Two-binary system что tunnels local proxy traffic (SOCKS5 / HTTP / TProxy)
через an veil-network session к а remote exit node, then к the real
internet.

```
[local app]
    │ SOCKS5 / HTTP CONNECT / transparent redirect
    ▼
[oproxy-client] ◀── connects к local veil daemon via IPC
    │
    │ veil session (end-to-end encrypted)
    │
    ▼
[oproxy-server (standalone) on the server host]
    │ TCP CONNECT к target
    ▼
[real internet]
```

## Why оverlay instead of plain HTTPS proxy?

* **End-to-end veil encryption** — peers can't be impersonated
  even если а CA is compromised; identities ара sovereign keypairs.
* **Bootstrap-resistant** — works через censored DNS / blocked ISPs
  как long as one veil seed is reachable.
* **No exposed cleartext port** — the server doesn't listen на
  any public IP for the proxy traffic.  It's all veil-tunnelled.
* **Custom app names** — multiple proxy services can coexist на one
  daemon без port collisions (each gets а distinct app_id derived
  от its name).

## Binaries

### `oproxy-client`

Standalone binary.  Listens locally в one OR more modes и forwards
к an upstream veil exit:

```bash
oproxy-client --config /etc/oproxy/client.toml
```

Sample `client.toml`:

```toml
socket_path     = "/var/lib/veil/app.sock"
server_node_id  = "00112233445566778899001122334455667788990011223344556677889900aa"
server_app_name = "my-proxy"

[[inbound]]
kind   = "socks5"
listen = "127.0.0.1:1080"

[[inbound]]
kind   = "http"
listen = "127.0.0.1:8080"

[[inbound]]
kind   = "tproxy"        # Linux / FreeBSD / Keenetic only
listen = "0.0.0.0:12345"

# Per-target routing — veil / direct / block.  Optional; defaults
# к "veil for everything, fail если veil down".
[routing]
default  = "veil"
fallback = "fail"

[[routing.rules]]
cidr     = "10.0.0.0/8"
action   = "veil"
fallback = "direct"      # per-rule override

[[routing.rules]]
cidr   = "192.168.0.0/16"
action = "direct"
```

See [§ Routing modes](#routing-modes) ниже для full schema.

### `oproxy-server`

Standalone binary (Phase 6.51 — uses the SDK's inbound-stream accept
API).  Binds an endpoint via the local daemon, accepts incoming
veil streams, и bridges each one к the requested TCP destination.

```bash
oproxy-server --config /etc/oproxy/server.toml
```

Sample `server.toml`:

```toml
socket_path = "/var/lib/veil/app.sock"
app_name    = "my-proxy"
# Empty / omitted = allow ALL callers. Non-empty = strict allowlist.
allowed_node_ids = [
  "0011223344556677889900112233445566778899001122334455667788990011",
]
allow_private = false   # block RFC1918 / loopback / metadata
```

## Server architecture (Phase 6.51 — standalone)

`oproxy-server` runs as **а normal user-space daemon** alongside the
veil daemon.  Both processes share the local IPC socket
(`/var/lib/veil/app.sock`); the proxy server binds its own
endpoint via the SDK's `bind()` API, then accepts incoming veil
streams через the **new `AppHandle::accept_stream()` API** (Phase
6.51, closes the inbound-stream SDK gap).

Wire flow:

1. Operator starts `veil-cli node run` (or whatever launches the
   daemon) — the daemon comes up, binds к the public IP, joins the
   veil mesh.
2. Operator starts `oproxy-server --config server.toml` — connects к
   the daemon's app socket, binds an endpoint c app_id derived от
   `app_name`.
3. The daemon now routes incoming veil streams targeted at that
   app_id к `oproxy-server` via `AppMessage::StreamOpen` → IPC's
   new `StreamOpenInbound` notification.
4. `oproxy-server` calls `accept_stream()` к pull each incoming
   stream, checks the source `node_id` against the allowlist, reads
   the connect header, и bridges к the requested target.

Restart-independence: stopping `oproxy-server` does NOT take down the
daemon; only the proxy endpoint goes away.  Clients dialling в while
the server is offline get а graceful refusal.

## Inbound modes

| Mode       | Use case                                      | Platforms                            |
| ---------- | --------------------------------------------- | ------------------------------------ |
| SOCKS5     | Browser SOCKS proxy, curl `--socks5`          | All (Win / Linux / macOS / FreeBSD)  |
| HTTP       | Browser HTTP/HTTPS proxy (`HTTP_PROXY=...`)   | All (Win / Linux / macOS / FreeBSD)  |
| TProxy     | Transparent gateway (`iptables -j TPROXY`)    | Linux / Keenetic (Linux kernel) / FreeBSD (partial) |

### Setting up TProxy на Linux / Keenetic

```bash
# Mark + route transit traffic к the listener.
iptables -t mangle -A PREROUTING -p tcp \
  --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 12345
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# Run the client.
oproxy-client --config client.toml
```

The listener will accept connections к ANY destination и retrieve
the original target address via `SO_ORIGINAL_DST`.

## Wire protocol

Reused от the existing `veil-proxy::exit`:

```text
[host_len u16 BE][host UTF-8][port u16 BE]
```

Server replies with а single status byte:

| Byte   | Meaning                                              |
| ------ | ---------------------------------------------------- |
| `0x00` | Connected; proceed с byte-pipe                       |
| `0x01` | Denied (node_id not в allowlist OR forbidden dest)   |
| `0x02` | Connect failed (DNS / TCP errors)                    |
| `0x03` | Bad request (malformed header)                       |

## Cross-platform support matrix

| Platform   | SOCKS5 | HTTP   | TProxy            | Build verified |
| ---------- | ------ | ------ | ----------------- | -------------- |
| Linux      | ✓      | ✓      | ✓ (full)          | ✓              |
| Keenetic   | ✓      | ✓      | ✓ (Linux kernel)  | (cross-compile)|
| FreeBSD    | ✓      | ✓      | partial           | (cross-compile)|
| macOS      | ✓      | ✓      | ✗ (use SOCKS)     | ✓              |
| Windows    | ✓      | ✓      | ✗ (use SOCKS)     | ✓              |

## Routing modes

Per-target policy для each `(host, port)` arriving via SOCKS5 / HTTP /
TProxy.  Configured under `[routing]` в `client.toml`:

```toml
[routing]
default  = "veil"   # veil | direct | block
fallback = "fail"      # direct | fail  (global default, per-rule override possible)

[[routing.rules]]      # rules evaluated в order; first match wins
host_suffix = ".internal"
action      = "direct"

[[routing.rules]]
cidr   = "10.0.0.0/8"
action = "veil"
fallback = "direct"    # per-rule override: try veil → if fails, direct

[[routing.rules]]
cidr     = "172.16.0.0/12"
action   = "veil"
fallback = "fail"      # per-rule override: try veil → if fails, return error

[[routing.rules]]
port_range = "443"
action     = "veil"
```

### Action semantics

| `action`  | Behaviour |
|---|---|
| `veil` | Open veil stream к the server (default behaviour) |
| `direct`  | Skip veil entirely; TCP-connect direct от local host |
| `block`   | Refuse the connection с а SOCKS5/HTTP error |

### Rule matching

A rule is а **conjunction**: every supplied field must match для the
action к fire.  Empty fields are wildcards.

| Field | Matches |
|---|---|
| `host_suffix` | hostname ends с this string (case-insensitive) |
| `host_exact`  | hostname equals this (case-insensitive) |
| `cidr`        | host parses as IPv4/IPv6 literal и falls в this subnet |
| `port_range`  | `"443"` (single) or `"1024-65535"` (inclusive range) |

**Note**: `cidr` does NOT do DNS resolution.  Hostname targets are
matched against `host_suffix`/`host_exact` only.  For DNS-resolved
CIDR matching, do the resolve client-side (browser → SOCKS5
with IP) или add equivalent `host_suffix` rules.

### Fallback semantics

When `action = "veil"` and the veil path fails (server
unreachable, timeout, denied), the per-rule `fallback` (or, if
unset, the global `[routing] fallback`) decides:

| `fallback` | On veil failure |
|---|---|
| `fail` | Return CONNECT failure к the inbound client (no recovery) |
| `direct` | Silently TCP-connect direct, bridge those bytes |

Fallback only applies к phases 1-3 of the connect handshake (open
stream / write header / read status).  Once Phase 4 (bridging) starts,
any failure passes through к the client — it's the point-of-no-return.

## Runtime + logging

Same shared schema as `veil-cli` and `ogate`.  Optional sections.

### `[runtime]` — tokio knobs

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "oproxy-client"
thread_stack_size    = 2097152
```

Env-var overrides (set after config load — wins over file):

| Env var | Effect |
|---|---|
| `OPROXY_RUNTIME` | `current_thread` or `multi_thread` |
| `OPROXY_WORKERS` | worker thread count |
| `OPROXY_MAX_BLOCKING_THREADS` | blocking pool cap |

### `[logging]` — output knobs

```toml
[logging]
level = "info"                 # off | error | warn | info | debug | trace
file  = "/var/log/oproxy.log"  # optional — defaults to stderr
```

| Field | Default | Description |
|---|---|---|
| `level` | `info` | Min level emitted; `off` disables the logger entirely (zero log output, including warnings) |
| `file` | (stderr) | Optional path; logs are *appended* (created if absent). Parent directory must exist. |

`RUST_LOG` env var overrides `level`.  Apply to either binary:

```bash
RUST_LOG=oproxy=debug oproxy-client --config client.toml
```

**Examples:**

```toml
# Silent operation
[logging]
level = "off"

# Append logs к а file, ready для shipping
[logging]
level = "info"
file  = "/var/log/oproxy-client.log"
```

## Testing

```bash
cargo test -p oproxy --lib
```

Covers:
* Wire-format roundtrip (encode/decode connect headers + status replies)
* SOCKS5 / HTTP parsers (authority + absolute-URI)
* Node-id allowlist guard (allow-all vs strict-allowlist)
* Config parsing (TOML schema, runtime, logging, routing)
* Routing-policy resolution (rule matching, port ranges, CIDR, ordering,
  per-rule fallback overrides)
* Logger init smoke (off-level skip, file writer)
