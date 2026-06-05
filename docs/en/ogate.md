# ogate: Veil-Network TUN Bridge

`ogate` is a user-space app that turns the veil network into a virtual
private LAN. Each host opens a TUN device with a configured IPv4/IPv6
address; ogate forwards IP packets between that TUN and veil peers
based on a per-network peer table.

Two access modes:

* **`open`** — any peer that knows the (network, app) pair can send
  packets in.
* **`authorized`** — only peers whose `node_id` is in the per-network
  `peers[]` allowlist are accepted, AND their packet's source IP must
  match the peer's declared virtual IP (anti-spoof).

`ogate` is an *application* layered on top of the veil daemon's IPC
(it is NOT part of the daemon itself). One veil daemon can serve
multiple `ogate` instances simultaneously — different `(network, app)`
pairs give different IPC bindings.

## Layering vs P-Net

`ogate`'s access mode is independent of the veil's [P-Net](p-net.md)
membership mode:

| Veil mode | ogate mode | Effect |
|---|---|---|
| public | open | any veil peer joins the LAN |
| public | authorized | only listed `node_id`s form the LAN |
| private (P-Net) | open | any P-Net member joins the LAN |
| private (P-Net) | authorized | two-level allowlist (P-Net + ogate) |

Use `authorized` for any LAN where untrusted peers might exist on the
veil.

## Platforms

| Platform | TUN backend | Address setup |
|---|---|---|
| Linux | `tun` crate (`/dev/net/tun`, IFF_NO_PI) | crate handles ipv4; ipv6 via `ip -6` |
| macOS | `tun` crate (utun) | crate handles ipv4; ipv6 via `ifconfig` |
| Windows | `tun` crate (WinTun) | crate handles ipv4; ipv6 via `netsh` |
| FreeBSD | raw `/dev/tunN` + `TUNSIFHEAD` ioctl | `ifconfig inet ... up` |

FreeBSD requires `iface_name = "tunN"` (kernel-assigned). Rename later
with `ifconfig tunN name myiface` if you want a friendlier label.

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

Required: at least one of `local_addr_v4` or `local_addr_v6`, plus a
matching peers list.

### How subnets / IPs are assigned

Statically, via this config file. The operator picks the subnet and
each peer's virtual IP. **All peers in a network must share the same
subnet** and **must mirror each other's IP assignments** — host A's
`local_addr_v4` is host B's `peers[A].addr_v4` and vice versa. Mismatches
in authorized mode are dropped as spoofed source IP.

For dynamic / deterministic assignment (e.g. derive IP from `node_id`),
the design notes in [`../../crates/ogate/README.md`](../../crates/ogate/README.md)
list alternatives but no automated registry is shipped today.

## App-id derivation

Each ogate binding is `app_id = BLAKE3(node_id || "ogate.<network>" || <app>)`.
Both peers can pre-compute each other's app_ids locally — no peer-list
harvest is needed.

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
    node identity
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

### 3. Mirror on host B

`local_addr_v4 = "10.99.0.2"` and a peer entry for host A at `10.99.0.1`.

### 4. Run on both hosts (as the daemon user, with CAP_NET_ADMIN)

ogate connects to the daemon's app socket over IPC. The daemon's
peer-uid gate (U9) **drops any IPC connection whose peer uid differs
from the daemon's uid — there is no root exception** — so ogate must run
as the *same* user as the veil daemon (e.g. `veil`), NOT as root.
Opening the TUN device needs `CAP_NET_ADMIN`; grant it to that user
instead of running as root:

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

## Hot reload (SIGHUP)

Edit the config, then signal the running process:

```bash
sudo kill -HUP "$(pidof ogate)"
# Or via the helper subcommand:
sudo ogate reload --pid "$(pidof ogate)"
# Or under systemd:
sudo systemctl reload ogate
```

The bridge re-reads the config and atomically swaps the routing state.
No in-flight packets are dropped.

**Reloadable**: `mode`, `peers[]`.

**Not reloadable** (restart required): `network`, `app`, `endpoint_id`,
`iface_name`, `mtu`, `local_addr_v4`, `local_addr_v6`, `prefix_v4`,
`prefix_v6`, `socket_path`. Attempts to change them via SIGHUP are
rejected with a warning and the current state is kept.

Reload errors (parse / validate / unsupported field change) are logged
and the previous state stays active — there is no broken-state window.

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

## Runtime + logging configuration

Both can be tuned per config (the same schema is also available in
`veil-cli` and `oproxy`).

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

All fields optional. `flavor` accepts the legacy alias
`runtime_flavor`. Zero values for `worker_threads` /
`max_blocking_threads` are treated as "leave unset" (the factory
guards against the tokio-internal panic on `0`).

**Env-var overrides** (set after config load — wins over file):

| Env var | Effect |
|---|---|
| `OGATE_RUNTIME` | `current_thread` or `multi_thread` |
| `OGATE_WORKERS` | worker thread count |
| `OGATE_MAX_BLOCKING_THREADS` | blocking pool cap |

Backward-compat path for pre-`[runtime]` systemd units that pass
tuning via env.

### `[logging]` — output knobs

```toml
[logging]
level  = "info"                    # off | error | warn | info | debug | trace
format = "text"                    # text | json
file   = "/var/log/ogate.log"      # optional — defaults to stderr
```

| Field | Default | Description |
|---|---|---|
| `level` | `info` | Min level emitted. `off` disables the logger entirely (no subscriber registered — zero overhead, completely silent). |
| `format` | `text` | `text` = human-readable; `json` = one structured event per line. |
| `file` | (stderr) | Optional log file. Logs are *appended* (created if absent). Parent directory must exist. Writer is non-blocking so concurrent log calls do not stall on disk I/O. |

**Precedence** (high → low):

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

## Ansible rollout

The repo ships `ansible/deploy-ogate.yml` (rollout) and
`ansible/remove-{chat,chaos-ban}.yml` (cleanup of older test workloads).
Rolling deploy (`serial: 1`), per-host config rendered from
`manifest.json` + an `host_to_ogate_addr` map declared in the playbook.

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

The current testnet runs `mode=authorized` over `192.168.0.0/16`:
* bootstraps: `192.168.0.1`–`.3`
* leaf nodes: `192.168.0.11`–`.15`

## Architecture notes

* **Transport**: each TUN-side IP packet is wrapped in an `AppIpcSend`
  message via the IPC handle and forwarded by the daemon as a normal
  veil datagram. ogate does NOT use the deprecated daemon-side
  `Tunnel` family.
* **Cost per packet**: TUN read → unix socket write → daemon E2E
  encrypt → wire → daemon decrypt → unix socket → TUN write. Unix
  domain IPC handles 100k+ small messages/sec on Linux, so the
  per-packet bottleneck is more likely the daemon's crypto or the
  network than ogate itself.
* **Authorization**: enforced at app layer on ingress. In `authorized`
  mode each received packet is checked against the peer table for both
  `src_node_id` membership AND `src_ip` ≡ `peers[src_node_id].addr_*`.
* **Anti-spoof**: in `authorized` mode a peer cannot inject packets
  claiming a virtual IP that is not theirs.

## Limitations / open work

* No route management beyond the implicit subnet route — host routes
  through peers must be added manually with `ip route` / `route add`.
* No NAT / forwarding — `ogate` is endpoint-only; if you want gateway
  semantics, set `net.ipv4.ip_forward=1` (Linux) and add NAT rules
  yourself.
* Performance not benchmarked yet. Measure with `iperf3` before
  optimising.

## Related code

* [`crates/ogate/src/config.rs`](../../crates/ogate/src/config.rs)
* [`crates/ogate/src/app_id.rs`](../../crates/ogate/src/app_id.rs)
* [`crates/ogate/src/routing.rs`](../../crates/ogate/src/routing.rs)
* [`crates/ogate/src/tun/`](../../crates/ogate/src/tun/)
* [`crates/ogate/src/bridge.rs`](../../crates/ogate/src/bridge.rs)
* [`ansible/deploy-ogate.yml`](../../ansible/deploy-ogate.yml)
