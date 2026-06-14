# ogate: an IP bridge over Veil

`ogate` lets a group of machines talk to each other over Veil as if they
shared an ordinary office network — a **virtual LAN** (Local Area
Network). Each machine gets a private IP address, and from then on you
can `ping` it, SSH into it, or run any normal IP app, even though the
machines are scattered across the internet.

It works through a **TUN device**: a virtual network card the operating
system hands to a program instead of to real hardware. Anything the
machine sends to that card, `ogate` picks up and forwards to the right
Veil peer; anything that arrives from a peer, `ogate` writes back to the
card. Each host opens one TUN device with a configured IPv4/IPv6
address, and `ogate` routes IP packets between it and the other peers
using a peer table you supply.

There are two ways to decide who is allowed in:

* **`open`** — any peer that knows the `(network, app)` pair can send
  packets in.
* **`authorized`** — only peers whose `node_id` is on the network's
  `peers[]` allowlist get through. On top of that, a packet's source IP
  must match the virtual IP that peer is supposed to use. This stops a
  peer from impersonating someone else's address (anti-spoofing).

`ogate` is an ordinary *application* that sits on top of the Veil daemon
and talks to it — it is **not** part of the daemon. One daemon can serve
several `ogate` instances at once: each `(network, app)` pair gets its
own private channel to the daemon.

## How it layers with P-Net

`ogate`'s access mode is a separate decision from how you've set up
[P-Net](p-net.md) (Veil's network-level membership). The two combine
like this:

| Veil mode | ogate mode | Effect |
|---|---|---|
| public | open | any veil peer joins the LAN |
| public | authorized | only listed `node_id`s form the LAN |
| private (P-Net) | open | any P-Net member joins the LAN |
| private (P-Net) | authorized | two-level allowlist (P-Net + ogate) |

If untrusted peers might be on the Veil network, use `authorized`.

## Platforms

| Platform | TUN backend | Address setup |
|---|---|---|
| Linux | `tun` crate (`/dev/net/tun`, IFF_NO_PI) | crate handles ipv4; ipv6 via `ip -6` |
| macOS | `tun` crate (utun) | crate handles ipv4; ipv6 via `ifconfig` |
| Windows | `tun` crate (WinTun) | crate handles ipv4; ipv6 via `netsh` |
| FreeBSD | raw `/dev/tunN` + `TUNSIFHEAD` ioctl | `ifconfig inet ... up` |

On FreeBSD `iface_name` must start with `tun` — the kernel assigns the
number. Want a friendlier label? Rename it after startup with
`ifconfig tunN name myiface`.

## Configuration

`/etc/ogate/ogate.toml`:

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/var/lib/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.1"
prefix_v4     = 24
local_addr_v6 = "fd00:1::1"
prefix_v6     = 64
endpoint_id   = 1

[[peers]]
node_id = "<64-hex peer node_id>"
addr_v4 = "10.99.0.2"
addr_v6 = "fd00:1::2"
name    = "host-b"

[[peers]]
node_id = "<another 64-hex peer node_id>"
addr_v4 = "10.99.0.3"
name    = "host-c"
```

You need at least one of `local_addr_v4` or `local_addr_v6`, plus a
peers list to match.

### How subnets and IPs get assigned

You assign them by hand, in this config file. (A **subnet** is just the
block of addresses your virtual LAN uses — for example `10.99.0.0/24`.)
You pick the subnet, then pick one virtual IP for each peer. Two rules
keep everyone in sync:

* **Every peer in a network shares the same subnet.**
* **The peer tables mirror each other.** Host A's `local_addr_v4` is
  host B's `peers[A].addr_v4`, and the other way around.

In `authorized` mode, a packet whose source IP doesn't match the table
is dropped as a spoofed address.

Want addresses handed out automatically — say, derived from each
`node_id` — instead of by hand? The design notes in
[`../../crates/ogate/README.md`](../../crates/ogate/README.md) sketch
some options, but there's no automated registry today.

## How the app_id is derived

Every ogate channel has an `app_id` that identifies it. It's computed as
`app_id = BLAKE3(node_id || "ogate.<network>" || <app>)`. Because it's
pure math, each peer can work out the other's `app_id` on its own — no
need to fetch a peer list from anywhere.

```bash
$ ogate app-id --network homenet --node-id $(cat host-a.nodeid)
namespace = ogate.homenet
name      = ogate
app_id    = 3c4e9f...
```

## Quick start (two hosts)

### 1. Get each host's veil `node_id`

```bash
sudo -u veil veil-cli --config /var/lib/veil/node.toml \
    node show
```

### 2. `/etc/ogate/ogate.toml` on host A

```toml
network       = "homenet"
app           = "ogate"
mode          = "authorized"
socket_path   = "/var/lib/veil/app.sock"
iface_name    = "ogate0"
mtu           = 1280
local_addr_v4 = "10.99.0.1"
prefix_v4     = 24

[[peers]]
node_id = "<host B node_id hex>"
addr_v4 = "10.99.0.2"
name    = "host-b"
```

### 3. Mirror it on host B

Set `local_addr_v4 = "10.99.0.2"`, and add a peer entry for host A at
`10.99.0.1`.

### 4. Run it on both hosts (as the daemon user, with CAP_NET_ADMIN)

Two things decide which user `ogate` runs as.

First, `ogate` connects to the daemon over a local channel, and the
daemon's peer-uid gate (U9) **drops any connection coming from a
different user than its own — root included, no exceptions.** So `ogate`
has to run as the *same* user as the Veil daemon (say, `veil`), not as
root.

Second, opening a TUN device normally needs root. You don't have to run
as root, though: grant just the one capability that allows it,
`CAP_NET_ADMIN` (the Linux permission to manage network interfaces), to
that same user.

```bash
# One-time: let the daemon user open TUN without root.
sudo setcap cap_net_admin+ep "$(command -v ogate)"

# Run as the daemon's user (matches the uid the daemon runs as):
sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

### 5. Ping across

```bash
ping 10.99.0.2   # from host A
```

## Reloading without a restart (SIGHUP)

You can change some settings on a running bridge without stopping it.
Edit the config, then send the process a SIGHUP signal:

```bash
sudo kill -HUP "$(pidof ogate)"
# Or via the helper subcommand:
sudo ogate reload --pid "$(pidof ogate)"
# Or under systemd:
sudo systemctl reload ogate
```

The bridge re-reads the config and swaps in the new routing in one
atomic step. Packets already in flight aren't dropped.

**Can be reloaded:** `mode`, `peers[]`.

**Needs a full restart:** `network`, `app`, `endpoint_id`,
`iface_name`, `mtu`, `local_addr_v4`, `local_addr_v6`, `prefix_v4`,
`prefix_v6`, `socket_path`. If you try to change one of these with a
SIGHUP, the bridge warns you and keeps running as it was.

If a reload fails for any reason — a typo in the file, a value that
doesn't validate, or an attempt to change a restart-only field — it's
logged and the old config stays live. There's never a moment where the
bridge is left in a broken state.

## CLI

```
ogate up         --config <path>      Bring up TUN + bridge, run until SIGINT/SIGTERM.
ogate show       --config <path>      Print resolved config + computed app_ids
                                      (no TUN / IPC opened).
ogate reload     --pid <pid>          Send SIGHUP to a running instance.
ogate app-id     --network <net> --node-id <hex>
                                      Compute one peer's app_id (handy
                                      when bootstrapping config files).
ogate gen-config [-o <path>]          Emit a commented default-config TOML template.
                                      No -o ⇒ stdout (pipe to less / your editor).
                                      With -o ⇒ writes the file (refuses to overwrite
                                      an existing one).
```

Flags: `-v` debug, `-vv` trace. Or `RUST_LOG=ogate=debug` env override.

### Bootstrap a config from scratch

```bash
# 1. Generate the template (refuses to overwrite if file already exists).
sudo -u veil ogate gen-config -o /etc/ogate/ogate.toml

# 2. Edit it — at minimum: network name, local_addr_v4, [[peers]] entries.
#    The template's inline `#` comments explain each knob.
sudo vim /etc/ogate/ogate.toml

# 3. (Optional) Sanity-check the resolved config without opening any device.
sudo -u veil ogate show --config /etc/ogate/ogate.toml

# 4. Bring it up (as the daemon user — see Quick start step 4).
sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

## Runtime and logging configuration

You can tune both of these in the config file. The same settings work in
`veil-cli` and `oproxy` too.

### `[runtime]` — async runtime settings

These control the async runtime (tokio) that `ogate` runs on — mostly
how many threads it uses.

```toml
[runtime]
flavor               = "multi_thread"   # | "current_thread"
worker_threads       = 4                # multi_thread only
max_blocking_threads = 64
thread_keep_alive_ms = 10000
thread_name          = "ogate"
thread_stack_size    = 2097152
```

Every field is optional. `flavor` also accepts the old name
`runtime_flavor`. Setting `worker_threads` or `max_blocking_threads` to
zero means "leave it unset" — this guards against a tokio panic that a
literal `0` would otherwise cause.

**Environment-variable overrides** — applied after the config is loaded,
so they win over the file:

| Env var | Effect |
|---|---|
| `OGATE_RUNTIME` | `current_thread` or `multi_thread` |
| `OGATE_WORKERS` | worker thread count |
| `OGATE_MAX_BLOCKING_THREADS` | blocking pool cap |

These exist mainly so older systemd units — written before the
`[runtime]` section existed — keep working when they pass tuning through
the environment.

### `[logging]` — log output settings

These control what gets logged and where it goes.

```toml
[logging]
level  = "info"                    # off | error | warn | info | debug | trace
format = "text"                    # text | json
file   = "/var/log/ogate.log"      # optional — defaults to stderr
```

| Field | Default | Description |
|---|---|---|
| `level` | `info` | The lowest level that gets logged. `off` turns the logger off completely — nothing is registered, so it costs nothing and stays totally silent. |
| `format` | `text` | `text` = easy to read by eye; `json` = one structured event per line, for machines. |
| `file` | (stderr) | Optional log file. New lines are *appended* (the file is created if it doesn't exist), and the parent directory has to exist already. Writing is non-blocking, so logging never stalls on slow disk I/O. |

**Which setting wins** (highest to lowest):

1. `RUST_LOG` env var (always wins when set)
2. CLI `-v` / `-vv` flags (when > 0)
3. config `[logging] level`
4. baked default (`info`)

**Examples:**

```toml
# Completely silent operation
[logging]
level = "off"

# JSON logs to a file for log-shipping (Promtail / Vector / Fluent Bit)
[logging]
level  = "info"
format = "json"
file   = "/var/log/ogate.json"

# Verbose stderr (default for systemd → journald)
[logging]
level  = "debug"
format = "text"
```

```bash
# Per-invocation override via env var:
RUST_LOG="ogate=debug,veilclient=info" sudo -u veil ogate up --config /etc/ogate/ogate.toml
```

## Rolling it out with Ansible

The repo ships two playbooks: `ansible/deploy-ogate.yml` to roll `ogate`
out, and `ansible/remove-{chat,chaos-ban}.yml` to clean up some older
test workloads. The deploy goes one host at a time (`serial: 1`), and
each host's config is rendered from `manifest.json` plus an
`host_to_ogate_addr` map declared in the playbook.

```bash
# Roll out:
ansible-playbook -i inventory.yml deploy-ogate.yml

# Reload peers without restart (after editing /etc/ogate/ogate.toml):
ansible all -i inventory.yml -m systemd \
    -a "name=ogate state=reloaded" --become

# Stop everywhere:
ansible all -i inventory.yml -m systemd \
    -a "name=ogate state=stopped enabled=no" --become
```

The current test network runs `mode=authorized` over `192.168.0.0/16`:
* bootstraps: `192.168.0.1`–`.3`
* leaf nodes: `192.168.0.11`–`.15`

## How it works under the hood

* **Transport**: every IP packet coming off the TUN device is wrapped in
  an `AppIpcSend` message, handed to the daemon, and sent out as an
  ordinary Veil datagram. `ogate` does **not** use the old, deprecated
  `Tunnel` message family on the daemon side.
* **What each packet costs**: read from TUN → write to the local socket
  → daemon encrypts it end to end → onto the wire → daemon decrypts →
  back over the socket → write to TUN. That local socket handles well
  over 100,000 small messages a second on Linux, so if anything is the
  bottleneck it's far more likely the daemon's crypto or the network
  itself than `ogate`.
* **Authorization** happens in `ogate` itself, as packets arrive. In
  `authorized` mode every incoming packet is checked twice: that its
  `src_node_id` is in the peer table, AND that its `src_ip` matches
  `peers[src_node_id].addr_*`.
* **Anti-spoofing**: because of that second check, in `authorized` mode
  a peer can't slip in packets pretending to come from a virtual IP that
  isn't theirs.

## Limitations and open work

* It doesn't manage routes beyond the one subnet route it sets up for
  you. If you need a route to a specific host through a peer, add it by
  hand with `ip route` / `route add`.
* No NAT or forwarding. `ogate` is an endpoint, not a **gateway** (a
  machine that passes traffic on to other networks). If you want it to
  behave like one, turn on forwarding yourself — `net.ipv4.ip_forward=1`
  on Linux — and add your own NAT rules.
* Performance hasn't been benchmarked. Measure with `iperf3` before you
  reach for any optimizations.

## Related code

* [`crates/ogate/src/config.rs`](../../crates/ogate/src/config.rs)
* [`crates/ogate/src/app_id.rs`](../../crates/ogate/src/app_id.rs)
* [`crates/ogate/src/routing.rs`](../../crates/ogate/src/routing.rs)
* [`crates/ogate/src/tun/`](../../crates/ogate/src/tun/)
* [`crates/ogate/src/bridge.rs`](../../crates/ogate/src/bridge.rs)
* [`ansible/deploy-ogate.yml`](../../ansible/deploy-ogate.yml)
