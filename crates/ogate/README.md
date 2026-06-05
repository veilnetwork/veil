# ogate

Veil-network TUN bridge. Bind two or more machines into a virtual
private LAN over the veil, with optional `node_id` authorization.

## What it does

`ogate` is a user-space app that:

1. Connects to the local veil daemon over IPC.
2. Binds a named application endpoint (`namespace = "ogate.<network>"`,
   `name = <app>`).
3. Opens a TUN device with a configured virtual IPv4/IPv6 address.
4. Forwards IP packets between the TUN device and veil peers based
   on a configured peer table.

Two access modes:

* `open` — any peer that knows the network/app pair can send packets in.
* `authorized` — only peers whose `node_id` is in `peers[]` are accepted,
  AND their source IP must match the peer's declared virtual IP.

## Platforms

| Platform | TUN backend | Address setup |
|---|---|---|
| Linux | `tun` crate (`/dev/net/tun`, IFF_NO_PI) | crate handles ipv4; ipv6 via `ip -6` |
| macOS | `tun` crate (utun) | crate handles ipv4; ipv6 via `ifconfig` |
| Windows | `tun` crate (WinTun) | crate handles ipv4; ipv6 via `netsh` |
| FreeBSD | raw `/dev/tunN` + `TUNSIFHEAD` ioctl | `ifconfig inet ... up` |

FreeBSD requires `iface_name = "tunN"` (kernel-assigned). Rename later
with `ifconfig tunN name myiface` if you want a friendlier label.

## Quick start (two hosts)

### 1. Configure both hosts

Get each host's `node_id` from its veil daemon:

```bash
# Host A:
veil-cli node identity   # prints node_id_hex
# Host B:
veil-cli node identity
```

### 2. `/etc/ogate/ogate.toml` on host A

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/run/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.1"
prefix_v4     = 24
local_addr_v6 = "fd00:1::1"
prefix_v6     = 64

[[peers]]
node_id = "<host B node_id hex>"
addr_v4 = "10.99.0.2"
addr_v6 = "fd00:1::2"
name    = "host-b"
```

### 3. Mirror config on host B

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/run/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.2"
prefix_v4     = 24
local_addr_v6 = "fd00:1::2"
prefix_v6     = 64

[[peers]]
node_id = "<host A node_id hex>"
addr_v4 = "10.99.0.1"
addr_v6 = "fd00:1::1"
name    = "host-a"
```

### 4. Run on both hosts (needs CAP_NET_ADMIN — run as the daemon user, NOT root)

The IPC peer-uid gate (audit U9) drops any connection whose uid differs from the
daemon's — including root. Grant the TUN capability to the binary and run as a
dedicated unprivileged user:

```bash
sudo setcap cap_net_admin+ep "$(command -v ogate)"
sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

### 5. Ping across

```bash
# From host A:
ping 10.99.0.2
ping6 fd00:1::2
```

## CLI subcommands

```
ogate up    --config <path>     Bring up TUN + bridge, run until SIGINT/SIGTERM.
ogate show  --config <path>     Print resolved config + computed app_ids.
ogate app-id --network <net> --node-id <hex>
                                Compute one peer's app_id (handy for bootstrap).
ogate reload --pid <pid>        Send SIGHUP to a running ogate to reload its
                                peer table without restart.
```

Flags:
* `-v` — debug logging, `-vv` — trace.
* `RUST_LOG=ogate=debug` — env-filter override.

## Runtime + logging configuration

Both can be tuned per-config (introduced in audit batch 2026-05-24
along with the same schema in `veil-cli` and `oproxy`).

### `[runtime]` — tokio knobs

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4                # multi_thread only
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "ogate"
thread_stack_size    = 2097152
```

`flavor` accepts both `flavor` and the legacy alias `runtime_flavor`.
All fields are optional — defaults match tokio's. Zero values for
`worker_threads` / `max_blocking_threads` are treated as "leave unset"
(tokio panics on 0, the factory clamps).

**Env-var overrides** (set after config load — wins over file):

| Env var | Effect |
|---|---|
| `OGATE_RUNTIME` | `current_thread` or `multi_thread` |
| `OGATE_WORKERS` | worker thread count |
| `OGATE_MAX_BLOCKING_THREADS` | blocking pool cap |

Backward-compat with pre-`[runtime]` systemd units.

### `[logging]` — output knobs

```toml
[logging]
level  = "info"              # off | error | warn | info | debug | trace
format = "text"              # text | json
file   = "/var/log/ogate.log"   # optional — defaults to stderr
```

| Field | Default | Description |
|---|---|---|
| `level` | `info` | Min level emitted; `off` disables logging entirely (no subscriber registered) |
| `format` | `text` | `text` = human-readable single-line; `json` = structured (one event per line) |
| `file` | (stderr) | Optional path; logs are *appended* (created if absent). Parent directory must exist. Uses a non-blocking writer — concurrent log calls do not stall on disk I/O. |

**Precedence** (high → low):

1. `RUST_LOG` env var (always wins when set)
2. CLI `-v` / `-vv` flags (when > 0)
3. config `[logging] level`
4. baked default (`info`)

**Examples:**

```toml
# Silent operation (no log output anywhere)
[logging]
level = "off"

# JSON logs to a file, ready for log-shipping (Promtail / Vector / etc.)
[logging]
level  = "info"
format = "json"
file   = "/var/log/ogate.json"

# Verbose debugging via env var (overrides config level)
# RUST_LOG=ogate=debug,veilclient=info sudo ogate up --config /etc/ogate/ogate.toml
```

## App-id derivation

The IPC layer assigns each binding `app_id = BLAKE3(node_id || namespace || name)`.
`ogate` uses:

* `namespace = "ogate." + network`
* `name      = app`

Both peers can pre-compute each other's app_ids locally — no peer-list
harvest step needed. `ogate app-id` exposes the derivation for manual
verification:

```bash
$ ogate app-id --network homenet --node-id $(cat host-a.nodeid)
namespace = ogate.homenet
name      = ogate
app_id    = 3c4e9f...
```

## Auth modes in detail

### `mode = "open"`

* Accept all incoming packets, regardless of `src_node_id`.
* Egress: drop only if dst IP is not in the peer table.
* Useful for testing or for networks where the veil's P-Net
  membership cert is already the access boundary.

### `mode = "authorized"`

* Ingress: drop unless `src_node_id` ∈ `peers[]`.
* Ingress: drop unless the packet's claimed source IP matches the
  peer's recorded virtual IP (anti-spoof).
* Egress: drop unless dst IP is in the peer table.
* Stacks on top of P-Net handshake gate — if you're already running
  a private veil, this is per-app isolation within it.

## Layering vs P-Net

`ogate` access mode is independent of veil P-Net mode:

| Veil mode | ogate mode | Effect |
|---|---|---|
| public | open | any veil peer can join the LAN |
| public | authorized | only listed node_ids form the LAN |
| private (P-Net) | open | any P-Net member can join the LAN |
| private (P-Net) | authorized | two-level allowlist (P-Net + ogate) |

## Hot reload (SIGHUP)

Edit `ogate.toml`, then signal the running daemon:

```bash
# Either: directly
sudo kill -HUP "$(pidof ogate)"
# Or: via the CLI helper
sudo ogate reload --pid "$(pidof ogate)"
```

The bridge re-reads the config and atomically swaps the routing state.
Egress/ingress tasks pick up the new table on the very next packet —
no in-flight packet is dropped.

**Reloadable**: `mode`, `peers[]`. **Not reloadable** (require restart):
`network`, `app`, `endpoint_id`, `iface_name`, `mtu`, `local_addr_v4`,
`local_addr_v6`, `prefix_v4`, `prefix_v6`, `socket_path`. Attempts to
change them via SIGHUP are rejected with a warning and the current
state is kept.

Reload errors (parse / validate / unsupported field change) are logged
and the previous state stays active — there is no broken-state window.

## Limitations / open work

* No route management beyond the implicit subnet route — host routes
  through peers must be added manually with `ip route` / `route add`.
* No NAT / forwarding — `ogate` is endpoint-only; if you want gateway
  semantics, set `net.ipv4.ip_forward=1` (Linux) and add NAT rules
  yourself.
* Performance not benchmarked yet. Each packet does take an IPC
  round-trip (TUN read → unix-socket write → daemon crypto → wire →
  daemon decrypt → unix-socket → TUN write), but on Linux unix-domain
  IPC handles 100k+ small messages/sec and the bottleneck is more
  likely to be the daemon's crypto / network than ogate itself.
  Measure before optimizing.

## Related code

* [`src/config.rs`](src/config.rs) — config schema + validation
* [`src/app_id.rs`](src/app_id.rs) — IPC app_id derivation helper
* [`src/routing.rs`](src/routing.rs) — virtual-IP ↔ node_id table
* [`src/tun/`](src/tun/) — platform TUN abstraction
* [`src/bridge.rs`](src/bridge.rs) — egress/ingress runtime
