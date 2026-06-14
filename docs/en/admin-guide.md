# Administrator Guide

## Overview

You run a Veil node by configuring it through a single TOML file (a plain-text
settings file). One file holds everything the node needs to know.

There are two ways to manage a running node. You can use the `veil-cli` command,
or you can talk to the node directly over its admin protocol — a simple
request/response channel that sends JSON over a local socket. (Don't confuse this
with the OVL1 *wire protocol*, the compact binary format nodes use to talk to
each other. The admin protocol is for you and your tools; the wire protocol is
for the nodes.)

### How the admin protocol connects

The node listens for admin commands on a local channel. You pick which kind with
`global.admin_socket`. There are two choices.

The first is a *Unix domain socket* — a special file on disk that programs on the
same machine use to talk to each other. This is the default on Linux and macOS:
`unix:///path/to/admin.sock`.

The second is *TCP-loopback* — a network connection that never leaves your own
machine (it stays on `127.0.0.1`, the address every computer uses for itself):
`tcp://127.0.0.1:0?runtime_dir=/abs/path`. This is the only option on Windows,
because Unix domain sockets aren't available there.

| Backend | Config | Where the files live | UID equality check |
|--------|--------|-----------------|------------------------|
| Unix | `unix:///abs/admin.sock` | The socket file itself (mode `0o600`) | `SO_PEERCRED` / `getpeereid` |
| TCP-loopback | `tcp://127.0.0.1:0?runtime_dir=…` | `admin.port` + `admin.token` in `runtime_dir` | 32-byte token (`subtle::ct_eq`) |

The TCP backend binds to `127.0.0.1` and nothing else. `localhost` and `::1`
(the same loopback address, written other ways) are allowed too; any other host
is rejected by the validator. Serving admin commands on a public port is unsafe
even behind a token, so the node simply won't do it.

Clients — `veil-cli` and any direct connection — find the right channel through a
single helper, `admin_socket_path(config)`. For TCP it hands back a stand-in path,
`runtime_dir/admin.anchor`. The real connection is then made by
`connect_admin_client_any`, which looks next to that anchor for `admin.port` and
`admin.token`, connects over TCP if it finds them, and otherwise falls back to
the Unix socket.

---

## Configuration file

By default, the node looks for its config file here:
- Linux: `~/.config/veil/config.toml`
- macOS: `~/Library/Application Support/veil/config.toml`
- Windows: `%APPDATA%\veil\config.toml`

To point it somewhere else, pass the path yourself: `veil-cli --config /etc/veil/config.toml node run`

> Want every section and field — types, defaults, and what each one does? The
> **[Configuration Reference](config-reference.md)** is the full list.

---

## Node identity and key management

Every node has an *identity*: a pair of cryptographic keys (a public one everyone
may see, and a private one only you hold). The node's address is computed from
the public key, so the identity *is* the node. Guard the private key carefully —
lose it and the node is gone.

### Signature algorithms

| Algorithm | Wire byte | Pub key | Priv key | Signature | Note |
|----------|-----------|---------|---------|---------|-----------|
| Ed25519 | 0 | 32 bytes | 32 bytes | 64 bytes | Default |
| Falcon512 | 2 | 897 bytes | 1281 bytes | 666 bytes | Post-quantum |

Each algorithm has a one-byte tag, the `algo` *wire byte*, that travels on the
network so the other side knows which algorithm to expect. The same value is used
in `IdentityPayload`, `DeletePayload`, the mesh beacon, and the PEX signature.
One exception: the session handshake (`SessionMsg::KeyAgreement`) numbers them
differently — 1 = Ed25519, 2 = Falcon512 (see
`node/session/handshake.rs::algo_to_u8`).

### Key generation

```bash
veil-cli key gen
veil-cli key gen --algo falcon512
```

**Creating an identity with a proof-of-work nonce** (recommended when you first
set up a node):

```bash
veil-cli config init --difficulty 16
```

*Proof of work* is a small puzzle the node solves to earn its identity — cheap
for an honest user, costly for a spammer churning out fakes. The answer to the
puzzle is a number called the *nonce*. The `difficulty` sets how hard the puzzle
is: it's the number of leading zero bits the BLAKE3 hash of the nonce must have.
At `difficulty=16`, expect about 65K tries — under a millisecond on modern
hardware.

### Key security

- Keep the config file readable by its owner alone: `chmod 600 ~/.config/veil/config.toml`
- The private key sits in the file as plain text. For a production node, protect
  it with filesystem encryption or a hardware security module (HSM — a dedicated
  device that stores keys and never lets them out).
- **Never** publish the `private_key`.

### Key rotation

Replacing a node's key changes its `node_id`, so as far as the network is
concerned you've created a brand-new node:

```bash
veil-cli key gen --output > new_keys.txt   # prints the pair to stdout without touching the config
# Update public_key, private_key, recompute the nonce
veil-cli config init --force
```

---

## Managing listeners and peers

A *listener* is an address your node opens so others can connect *in* to it. A
*peer* is another node yours reaches *out* to. Listeners are how people find you;
peers are who you talk to.

### CLI for listeners

```bash
veil-cli listen add tcp://0.0.0.0:9000
veil-cli listen del LISTEN_ID
veil-cli listen list
```

A few more flags for `listen add`: `--advertise URI` lets you announce a different
address than the one you bind to — handy when your node sits behind a reverse
proxy (a front-end server that relays connections to it). There's also
`--relay NODE_ID_BASE64`, and `--tls-cert`, `--tls-key`, `--tls-ca-cert` for the
encrypted `tls://` and `wss://` listeners.

### Transports

A *transport* is simply how the bytes physically travel — plain TCP, encrypted
TLS, QUIC, and so on. You pick one by the scheme at the front of a listener
address (the `tcp://` part). Here's the menu:

| Scheme | Protocol | Security | Notes |
|-------|----------|--------------|-------------|
| `tcp` | TCP | None (OVL1 encryption on top) | Simple, fast |
| `tls` | TCP + TLS 1.3 | TLS certificate | Recommended for public nodes |
| `quic` | UDP + QUIC | TLS inside QUIC | Fast handshake, multiplexing |
| `ws` | HTTP WebSocket | None | For bypassing firewalls via port 80/443 |
| `wss` | HTTPS WebSocket | TLS | WebSocket with TLS |
| `unix` | Unix domain socket | File permissions | Local IPC connections only |

### CLI for peers

```bash
# Add a peer: PUBLIC_KEY, NONCE, and TRANSPORT are positional arguments
veil-cli peers add \
  --algo ed25519 \
  "BASE64_PUBLIC_KEY==" \
  "BASE64_POW_NONCE==" \
  "tls://core.example.com:9443"

# Remove (by peer_id from `peers list`, or --by-node-id / --by-public-key)
veil-cli peers del PEER_ID
veil-cli peers del --by-node-id HEX_NODE_ID

# List
veil-cli peers list
```

---

## Mailbox — message storage

When someone you're messaging is offline, their node can't receive anything. A
*mailbox* fixes that: a core node holds the message until the recipient comes
back online and fetches it. The mailbox is off by default, and you turn it on
with a single flag:

```toml
[mailbox]
enabled = true
```

There's nothing to choose about where it stores things. With `enabled = true`,
the node always opens its built-in redb store at one fixed path,
`<veil_dir>/mailbox/blobs.db`. (redb is a small embedded database; *durable*
means data survives a crash, *transactional* means each change happens all-or-
nothing.) The `[mailbox]` section has no `backend`, `data_dir`, or
`strict_backend` fields — those don't exist.

What you *can* tune is the quotas, the TTL, the rate limit, and push
notifications. (A *quota* caps how much can be stored; *TTL*, "time to live," is
how long a message is kept before it's dropped; the *rate limit* caps how fast
new messages may arrive.) Leave a value at zero and the node uses the
`veil-mailbox` crate's own default:

| Field | Purpose | Default |
|------|------------|--------------|
| `enabled` | Master switch | `false` |
| `quota_per_receiver_bytes` | Per-receiver quota (bytes) | 100 MiB |
| `quota_global_bytes` | Global per-node quota (bytes) | 10 GiB |
| `quota_per_sender_bytes` | Per-sender quota (bytes) | 10 MiB |
| `ttl_secs` | Blob storage TTL (sec) | 7 days |
| `rate_limit_per_minute` | Limit on puts per minute per receiver | 60 |
| `require_capability_token` | Require a capability token on PUT | `false` |
| `[mailbox.push]` | Push provider credentials (FCM/APNs) | empty (log only) |

For more on the fields in the `[mailbox]` section, see the [Configuration Reference](config-reference.md#mailbox).

---

## Metrics

*Metrics* are running counts and gauges the node keeps about itself — how many
sessions are open, how many bytes have flowed, and so on. They let you watch the
node's health over time.

### Configuring the exporter

The `[metrics]` section switches on an *exporter*: a small built-in web page that
publishes those numbers for Prometheus, the popular monitoring tool, to read.

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

`listen` is a TransportUri and must start with the `tcp://` scheme, or the config
won't pass validation.

### Retrieving metrics

```bash
# Via CLI
veil-cli node metrics

# Via HTTP (Prometheus scrape)
curl http://127.0.0.1:9090/metrics
```

### Available counters

The complete list lives in the code, in `NodeMetrics::render_prometheus`
([observability.rs](../../crates/veil-observability/src/lib.rs)). Every name
carries the `veil_` prefix. The main groups are below. (A *counter* only ever
climbs — a total since startup; a *gauge* goes up and down to show a value right
now.)

| Group | Metric | Type | Description |
|--------|---------|-----|----------|
| Transport | `veil_configured_peers` | gauge | Number of `[[peers]]` in the config |
| Transport | `veil_active_sessions` | gauge | Currently active sessions |
| Transport | `veil_inbound_sessions_total` | counter | Inbound sessions established |
| Transport | `veil_outbound_connect_attempts_total` | counter | Outbound connect attempts |
| Transport | `veil_outbound_connect_failures_total` | counter | Failed outbound connects |
| Transport | `veil_transport_bytes_rx_total` | counter | Bytes received on the transport |
| Transport | `veil_transport_bytes_tx_total` | counter | Bytes sent on the transport |
| Session | `veil_session_handshake_failures_total` | counter | Handshake rejections |
| Delivery | `veil_mailbox_fetches_total` | counter | MAILBOX_FETCH operations |
| Delivery | `veil_delivery_rejects_total` | counter | Rejected Delivery frames |
| Delivery | `veil_chunks_reassembled_total` | counter | Reassembled chunked transfers |
| Delivery | `veil_multi_path_sends_total` | counter | Parallel multi-path sends |
| DHT | `veil_dht_store_total` | counter | STORE operations in DHT |
| DHT | `veil_dht_lookup_total` | counter | LOOKUP operations in DHT |
| Crypto | `veil_decrypt_failures_total` | counter | E2E decryption errors |
| Storage | `veil_storage_evictions_total` | counter | Evictions from storage |
| Routing | `veil_route_miss_total` | counter | Cache misses in the route cache |
| Routing | `veil_discovery_triggered_total` | counter | Route-discovery runs |
| Routing | `veil_route_recovery_total` | counter | Route recoveries after a miss |
| Routing | `veil_route_cache_hits_total` | counter | Cache hits during forwarding |
| Routing | `veil_network_reachability_score` | gauge | Fraction of successful recoveries in the window (0.0–1.0) |
| Routing | `veil_route_selection_avg_rtt_ms` | gauge | Average RTT of selected routes (ms) |
| Routing | `veil_vivaldi_prediction_error_ms` | gauge | Average Vivaldi prediction error (ms) |
| Routing | `veil_vivaldi_coord_x` / `_y` / `_height` / `_error` | gauge | Local Vivaldi coordinate (synthetic, meaningful only as distances) |
| Mesh | `veil_mesh_relay_hops_total` | counter | Hops through the mesh relay |
| Mesh | `veil_gossip_announces_rx_total` | counter | ROUTE_ANNOUNCE received |
| DHT-routing | `veil_recursive_relay_initiated_total` | counter | RecursiveRelay initiated |
| DHT-routing | `veil_recursive_relay_forwarded_total` | counter | RecursiveRelay transit hops |
| DHT-routing | `veil_recursive_relay_delivered_total` | counter | RecursiveRelay delivered |
| Abuse | `veil_rate_limit_drops_total` | counter | Frames dropped by the rate limiter |
| Abuse | `veil_backpressure_received_total` | counter | BACKPRESSURE received |
| Abuse | `veil_ban_actions_total` | counter | Bans applied |
| RT | `veil_rt_frames_total` / `_rx_total` / `_tx_total` | counter | Real-time frames (total / RX / TX) |
| RT | `veil_rt_seq_gaps_total` | counter | Sequence-number gaps in RT |
| App | `veil_app_msg_channel_full_total` | counter | IPC channel overflows |
| App | `veil_app_msg_channel_closed_total` | counter | Deliveries to a closed channel |
| Session-queue | `veil_session_tx_drops_total` | counter | Dropped from the per-session TX queue |
| Session-queue | `veil_session_outbox_drops_total` | counter | Dropped from SessionOutbox |
| IPC | `veil_ipc_delivery_drops_total` | counter | Dropped into the client IPC channel |
| Sleep | `veil_sleeping_recipients` | gauge | Recipients in sleep state on the host |
| Sleep | `veil_sleep_advertisements_accepted_total` | counter | SleepAdvertisement accepted |
| Sleep | `veil_sleep_advertisements_emitted_total` | counter | SleepAdvertisement emitted |
| Sleep | `veil_wakeup_fetches_total` | counter | Wake-up MAILBOX_FETCH on session open |

> **Mailbox depth.** One number is missing from Prometheus: how many blobs the
> mailbox currently holds. To see it, read the `mailbox_entries` field in the
> admin HTTP API's state dump.

---

## Admin API — the administrative socket

**Address.** A Unix domain socket (the default on Linux and macOS), or
TCP-loopback guarded by a token (the only choice on Windows, where Unix sockets
don't exist). You set the path or URI with `global.admin_socket`; the
"How the admin protocol connects" section above covers both.

**Protocol.** Plain request/response: the client sends a line of JSON, the node
sends one back, each ended by a newline. On the TCP backend there's one extra
step first. The client sends a 32-byte token — read from `runtime_dir/admin.token`
— as its opening message. The node compares it in *constant time* (a check that
takes the same time whether the token is right or wrong, so an attacker can't
learn anything from timing). Only on a match does the node start answering;
otherwise it hangs up.

### Node inspection

```bash
# Node state
veil-cli node show

# Active sessions
veil-cli sessions list

# Routes (route cache)
veil-cli node routes

# DHT
veil-cli node dht list
veil-cli node dht get HEX_KEY         # KEY is a positional argument, 64 hex characters
veil-cli node dht routing             # Kademlia routing table

# Discovery entries
veil-cli node discovery-list

# Gateway: connected leaf nodes
veil-cli node gateway-list
```

### Diagnostics

```bash
# Ping a remote node through the veil
veil-cli debug ping HEX_NODE_ID --count 5 --interval 1000 --timeout 5000

# Traceroute
veil-cli debug trace HEX_NODE_ID --max-hops 16 --timeout 5000

# Frame capture (for debugging)
veil-cli debug capture --limit 100
veil-cli debug capture --node-id HEX --family 3   # Delivery frames only

# Test connection to a specific peer (peer_id from `peers list`)
veil-cli debug peers connect PEER_ID

# Test accepting on a listener (listen_id from `listen list`)
veil-cli debug node accept LISTEN_ID
```

### Managing blocks

```bash
# Ban a node (NODE_ID — 64 hex characters)
veil-cli peers ban NODE_ID

# Unban
veil-cli peers unban NODE_ID

# List active bans
veil-cli peers banned
```

The very same commands also live under `veil-cli sessions ban/unban/banned` —
both names act on the same shared state.

### Hot config reload

You can change a node's config without restarting it. This is a *hot reload* —
the running node re-reads its config file on the fly.

```bash
# Via the admin API (recommended — addresses exactly the running daemon)
veil-cli node reload

# Or SIGHUP directly: under systemd
systemctl reload veil        # see ExecReload in the unit below
```

A quick warning about `pkill -HUP veil-cli`: it only does the right thing if
exactly one copy of the binary is running and that copy is the node, not a CLI
client. That's too fragile to trust in production — use one of the two commands
above instead.

---

## Configuring the systemd service

On Linux you'll usually want the node to start at boot and restart itself if it
ever crashes. *systemd* — the service manager built into most Linux distributions
— handles that. You describe the service in a small file called a *unit*, like
this one:

```ini
# /etc/systemd/system/veil.service
[Unit]
Description=OVL1 Veil Node
After=network.target

[Service]
Type=simple
User=veil
Group=veil
ExecStart=/usr/local/bin/veil-cli --config /etc/veil/config.toml node run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable veil
systemctl start veil
systemctl status veil
journalctl -u veil -f
```

---

## Troubleshooting

When something's off, work through the symptom that matches. Each one starts with
the most common cause.

### The node won't start

Usually the config has a problem. Check it first, then watch the logs as the node
comes up:

```bash
# Validate the config
veil-cli config validate

# View the logs
veil-cli --config /etc/veil/config.toml node run
# or via journalctl if using systemd
```

### No inbound connections

Nobody can reach you. Check, in order:

1. Is the firewall open on the ports you're using?
2. Is there a `[[listen]]` block in the config?
3. What does the listener say? Run `veil-cli listen list`.

### No outbound connections

You can't reach anyone. Check, in order:

1. Have you added any `[[peers]]` blocks?
2. Is the transport URI good? Try `veil-cli debug transport connect URI`.
3. Can you reach the peer at all? Try `veil-cli debug peers connect PEER_ID`.

### High memory use

Look at the limits in `[capacity]` and `[abuse]`. On a gateway that's carrying
too much, tightening them helps:

```toml
[capacity]
max_relay_sessions = 512

[abuse]
rate_limit_fps = 20.0
```

### The node isn't visible in the DHT

The DHT is the network's shared address book, the way other nodes find you. If
you're not in it:

- Make sure at least one Core node is listed in `[[peers]]`.
- The node needs a `[[listen]]` address others can actually reach from the
  public internet.
- Check the routing table: `veil-cli node dht routing`.

---

## Running as a service

You don't want to babysit the node by hand. Better to hand it to whatever your
operating system uses to keep background programs running — and to restart them
after a reboot or a crash.

### Linux / macOS — systemd / launchd

On Unix systems the node runs as an ordinary background program (a *daemon*). You
hook it into the system's service manager — systemd on Linux, or launchd on macOS
(its equivalent, configured with a small file called a *plist*). Here's a
template systemd unit:

```ini
[Unit]
Description=Veil Node
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veil-cli --config /etc/veil/config.toml node run --foreground
Restart=on-failure
User=veil

[Install]
WantedBy=multi-user.target
```

### Windows — Service Control Manager

On Windows the node can register itself as a native service through the Service
Control Manager (SCM), the part of Windows that runs and supervises background
services. Once registered, it starts automatically at boot, stops at shutdown,
and shows up in `services.msc` and `Get-Service VeilNode`.

**Installation** (needs administrator rights):

```powershell
# From an administrator PowerShell.
veil-cli service install --config C:\ProgramData\veil\config.toml

# The service is installed as AutoStart. Start it immediately:
sc start VeilNode

# Or via PowerShell:
Start-Service VeilNode
```

**Control:**

```powershell
Get-Service VeilNode         # Status check
Stop-Service VeilNode        # Graceful stop (SCM sends ServiceControl::Stop)
Start-Service VeilNode
```

**Uninstallation** (stops the service if running):

```powershell
veil-cli service uninstall
```

**A few details worth knowing:**

- By default the service runs as `LocalSystem`, a powerful built-in account. To
  run it under a less privileged user instead, edit it after install:
  ```powershell
  sc config VeilNode obj= ".\veil_user" password= "..."
  ```
- The config path is baked into the service's `ImagePath` when you install it. So
  if you ever move the config, uninstall and reinstall the service.
- `service run` is the entry point the SCM calls; it's hidden from `--help`. Don't
  run it yourself — use `install` followed by `Start-Service`.
- Shutting down cleanly: on `Stop-Service`, the SCM sends a `ServiceControl::Stop`
  signal. The service marks itself `StopPending`, waits for the node to wind down
  (including flushing bans, discovered peers, and the like to disk so nothing is
  lost), and only then reports `Stopped`.
