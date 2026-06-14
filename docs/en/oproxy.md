# oproxy: Veil-Network Proxy Bridge

oproxy lets an app on your machine reach the internet *through* Veil.
A **proxy** is just a middleman: your app hands it a request, and the
proxy fetches the answer on your behalf. Here the proxy isn't a single
server — it's two small programs joined by a Veil session, so your
traffic travels the network end to end before it surfaces.

The app speaks one of three common proxy dialects — **SOCKS5**, **HTTP**,
or **transparent** (explained under [Inbound modes](#inbound-modes)).
oproxy carries that traffic over a Veil session to a remote **exit
node** — the point where your traffic leaves Veil and steps onto the
open internet — and from there to the real site.

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

The two halves are `oproxy-client` (next to your app) and
`oproxy-server` (out at the exit). Each one talks to a **local Veil
daemon** — the background program that keeps your node on the network —
running on its own host. The proxy traffic flows over Veil between
those two daemons, so neither program ever opens a connection straight
across the open internet. Russian translation:
[oproxy.md](../ru/oproxy.md).

## Why Veil instead of a plain HTTPS proxy

A normal proxy listens on a public port and leans on TLS certificates
to prove who it is. Running it over Veil sidesteps the usual headaches:

- **End-to-end Veil encryption.** A peer can't be impersonated, even
  if a certificate authority (the company that vouches for a site's
  identity) is compromised. Each identity is its own keypair, owned
  by no one else.
- **No open port on the server.** The server never listens on a public
  IP for proxy traffic — it all rides inside the Veil tunnel. The only
  thing exposed to the world is the Veil daemon itself.
- **Custom app names.** Several proxy services can share one daemon
  without fighting over ports. Each gets its own `app_id`, derived
  from its name.
- **A `node_id` allowlist on the server.** You decide which peers are
  allowed and turn the rest away right at the app — no firewall rules,
  no certificates, no rotation to babysit.

## Inbound modes

An **inbound mode** is simply how a local app hands its traffic to
`oproxy-client`. Pick whichever your app already speaks:

- **SOCKS5** — a widely supported proxy protocol. The app says "connect
  me to this host and port," and the proxy does it. Most browsers and
  tools like `curl` understand it out of the box.
- **HTTP** — the proxy mode built into web browsers and the
  `HTTP_PROXY` environment variable. Good when an app only knows how to
  talk to an HTTP proxy.
- **Transparent** (TProxy) — no per-app setting at all. You point a
  whole machine or network through oproxy and it captures the traffic
  invisibly. Handy as a gateway, but it needs Linux and some firewall
  rules (see [below](#setting-up-tproxy-on-linux--keenetic)).

| Mode    | Use case                                    | Platforms |
|---------|---------------------------------------------|-----------|
| SOCKS5  | Browser SOCKS proxy, `curl --socks5`        | All (Linux / macOS / Windows / FreeBSD / Keenetic) |
| HTTP    | Browser HTTP/HTTPS proxy (`HTTP_PROXY=...`) | All |
| TProxy  | Transparent gateway (`iptables -j TPROXY`)  | Linux / Keenetic only |

You can run several inbound modes at once on the same client — say
SOCKS5 and HTTP side by side — each on its own port.

---

## `oproxy-client`

This is the half that runs next to your app. It's a single standalone
binary. On startup it connects to the local Veil daemon, claims an
endpoint on it, and listens locally for one or more of the inbound
modes above. Every connection it accepts gets tunnelled to the
**upstream** server you configured — "upstream" just meaning the next
hop toward the internet, here named by `(server_node_id,
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

> **Run as the daemon user, never root.** The Veil daemon checks, down
> in the kernel, that whoever connects to its IPC socket has the same
> user id as the daemon itself (`SO_PEERCRED` / `getpeereid`). Anyone
> else is dropped — root included. So run `oproxy-client` as the same
> user the daemon runs as (here, `veil`). Transparent mode still needs
> the `CAP_NET_ADMIN` capability; grant just that one capability to the
> user (e.g. `setcap cap_net_admin+ep`) rather than reaching for root.

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

This is the exit half — the program that actually reaches the internet
for you. It's a single standalone binary too. It claims a Veil app
endpoint through the local daemon, accepts the incoming Veil streams
from clients, and for each one opens a plain TCP connection to the host
and port the client asked for, then ferries bytes between the two.

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

# Optional allowlist by source node_id (hex).
# Empty list requires `allow_all = true` (explicit open-proxy opt-in).
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

There's no shared secret to copy around. The `app_id` is computed
straight from the server's `node_id` plus its `app_name`, and the same
inputs always give the same result. A client that knows the server's
`node_id` and sets a matching `server_app_name` works out that same
`app_id` on its own and dials that exact endpoint.

---

## Routing modes (client)

By default every connection goes through Veil. But you don't always
want that — local addresses, for instance, are quicker to reach
directly. **Routing** is the client deciding, per destination, *which
way* a connection should go. The optional `[routing]` section in the
config is where you set those decisions.

It works like a short checklist. For each `(host, port)` an app asks
for, the client runs down your `rules` from top to bottom and stops at
the first one that matches, then does what that rule's `action` says.
If nothing matches, it falls back to the global `default`.

### Actions

There are three things a rule (or the default) can do with a connection:

| Action    | Behaviour |
|-----------|-----------|
| `veil` | Open a Veil stream to `(server_node_id, server_app_name)` |
| `direct`  | Skip veil; TCP-connect directly from the local host |
| `block`   | Refuse with a SOCKS5 / HTTP error reply |

In plain terms: `veil` sends it through the tunnel, `direct` connects
straight from this machine without Veil, and `block` refuses the
connection outright.

### Rule fields

A rule is a set of conditions plus an action. Every field below except
`action` is optional, and a field you leave out matches anything. When
a rule lists several conditions, **all** of them must hold for it to
match — they're combined with AND, not OR.

| Field | Matches |
|---|---|
| `host_suffix` | hostname ends with this string (case-insensitive); e.g. `.internal` matches `db.internal` |
| `host_exact`  | hostname equals this (case-insensitive) |
| `cidr`        | host parses as IPv4/IPv6 literal AND falls inside this CIDR |
| `port_range`  | `"443"` (single) or `"1024-65535"` (inclusive range) |
| `action`      | (required) one of `veil` / `direct` / `block` |
| `fallback`    | per-rule override; one of `direct` / `fail` |

A **CIDR** is a way to write a whole block of IP addresses at once —
for example `10.0.0.0/8` covers every address starting with `10.`.

**Note:** `cidr` only matches when the host is written as a literal IP
address. The client never looks up hostnames in DNS — the internet's
phone book that turns a name like `example.com` into an IP — so a
`cidr` rule won't catch a target given by name. For name-based rules,
reach for `host_suffix` instead.

### What happens when Veil is down (fallback)

**Fallback** is the backup plan for when a `veil` action can't get
through — the server is unreachable, the request times out, or it gets
turned away. It only comes into play for `action = "veil"`; `direct`
and `block` have nothing to fall back from.

| `fallback` | On veil failure |
|---|---|
| `fail` | Return CONNECT failure to the inbound client (no recovery) |
| `direct` | Silently TCP-connect direct from the local host, then bridge |

So `fail` gives up and reports the error to your app, while `direct`
quietly retries the connection straight from this machine instead.

There's a catch on timing. The backup plan is only available while
Veil is still setting the connection up — the first three steps of the
handshake (open the stream, send the connect header, read back the
status reply). Once step four begins and real data is moving in both
directions, the connection is committed: nothing can be retried, and
any later failure is passed straight back to your app.

A `fallback` written on a rule overrides the global `[routing]
fallback` for that rule. Leave it off and the rule uses the global
value.

### Example: send LAN traffic direct, everything else via Veil

"RFC1918" is the standard that set aside the private address ranges
your home and office networks use — `10.x`, `172.16–31.x`, and
`192.168.x`. This example treats each of those a little differently
while routing everything else through Veil.

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

Reading that back, here's where each kind of target ends up:

| Target          | mode    | on veil failure |
|-----------------|---------|---------------------|
| `10.x.x.x:*`    | veil | direct              |
| `172.16-31.x:*` | veil | fail                |
| `192.168.x.x:*` | direct  | n/a                 |
| anything else   | veil | fail (default)      |

---

## Runtime + logging configuration

These two sections tune the engine and the logs. They use the same
format as `veil-cli` and `ogate`, so settings carry over if you've
configured those. Both are optional — skip them and reasonable defaults
take over.

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

You can also set these from the environment. An environment variable
is read after the config file and wins over it, which makes it handy
for a one-off override without editing the file:

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

The `RUST_LOG` environment variable overrides `level` when you need
more detail for a single run:

```bash
RUST_LOG=oproxy=debug oproxy-client --config client.toml
```

---

## Setting up TProxy on Linux / Keenetic

Transparent mode needs a hand from the kernel: a few firewall rules to
nudge passing traffic over to oproxy's listener. `iptables` is the
Linux tool for those rules. This set marks TCP traffic to port 80 and
sends it to the listener on port 12345:

```bash
# Mark + route transit traffic to the listener:
iptables -t mangle -A PREROUTING -p tcp \
    --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 12345
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

oproxy-client --config client.toml
```

With that in place, the listener takes connections aimed at any
destination and recovers where each one was really headed via
`SO_ORIGINAL_DST` (a kernel feature that remembers the original target
after the firewall redirects a connection). This needs the
`CAP_NET_ADMIN` capability.

---

## Wire protocol (oproxy-client ↔ oproxy-server)

This part is for the curious — you don't need it to use oproxy. It's
the little handshake the two halves speak once a Veil stream is open,
before any of your app's data flows. The client sends a short header
naming the host and port it wants, and the server answers with a
one-byte status:

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

If the status is anything but `0x00`, the server sends it and then
closes the stream. That status is what the client's `fallback` decision
hangs on: Denied, Connect failed, and Bad request all count as
recoverable failures during the first three steps, so a `direct`
fallback can still step in.

---

## Related code

- [`crates/oproxy/src/config.rs`](../../crates/oproxy/src/config.rs) — TOML schema
- [`crates/oproxy/src/routing.rs`](../../crates/oproxy/src/routing.rs) — per-target rule engine
- [`crates/oproxy/src/connector.rs`](../../crates/oproxy/src/connector.rs) — veil-side bridge + fallback
- [`crates/oproxy/src/inbound/`](../../crates/oproxy/src/inbound/) — SOCKS5 / HTTP / TProxy listeners
- [`crates/oproxy/src/logging.rs`](../../crates/oproxy/src/logging.rs) — logger init helper
- [`crates/oproxy/README.md`](../../crates/oproxy/README.md) — crate-level README

## Limitations / open work

A few things oproxy doesn't do yet — worth knowing before you lean on it:

- **TCP only.** There's no UDP forwarding, so anything that relies on
  UDP (some games and video calls) won't go through.
- **The client doesn't resolve names.** It forwards hostnames as-is to
  the server, which does its own DNS lookup. That's why a `cidr`
  routing rule never matches a target given by name — use `host_suffix`
  for those.
- **No transparent mode on FreeBSD.** TProxy there is just a stub and
  exits with an error at startup; use SOCKS5 on FreeBSD instead.
