# Administrator Guide

## Overview

An OVL1 node is configured through a single TOML file. Administrative management is performed via `veil-cli` or directly through the JSON-over-socket admin protocol (not to be confused with the binary OVL1 wire protocol between nodes).

### Admin protocol transport

Epic 451 added a TCP-loopback backend: `global.admin_socket` can be
`unix:///path/to/admin.sock` (the default on Linux/macOS) or
`tcp://127.0.0.1:0?runtime_dir=/abs/path` (mandatory on Windows — Unix
domain sockets are unavailable there).

| Backend | Config | Where the files live | UID equality check |
|--------|--------|-----------------|------------------------|
| Unix | `unix:///abs/admin.sock` | The socket file itself (mode `0o600`) | `SO_PEERCRED` / `getpeereid` |
| TCP-loopback | `tcp://127.0.0.1:0?runtime_dir=…` | `admin.port` + `admin.token` in `runtime_dir` | 32-byte token (`subtle::ct_eq`) |

The TCP backend binds `127.0.0.1` and only `127.0.0.1`: `localhost`, `::1` are
also allowed, any other host is rejected by the validator (admin over a public
port is insecure even with a token).

Clients (`veil-cli`, direct connections) obtain both forms through a single
`admin_socket_path(config)` — for TCP it returns a synthetic
`runtime_dir/admin.anchor`; the actual connection is made via
`connect_admin_client_any`, which looks for `admin.port` + `admin.token`
next to the anchor and goes over TCP, or falls back to the Unix socket.

---

## Configuration file

The configuration file is located by default at:
- Linux: `~/.config/veil/config.toml`
- macOS: `~/Library/Application Support/veil/config.toml`
- Windows: `%APPDATA%\veil\config.toml`

To set the path explicitly: `veil-cli --config /etc/veil/config.toml node run`

> An exhaustive reference of all config sections and fields with types, default values, and a description of each parameter — see the **[Configuration Reference](config-reference.md)**.

---

## Node identity and key management

### Signature algorithms

| Algorithm | Wire byte | Pub key | Priv key | Signature | Note |
|----------|-----------|---------|---------|---------|-----------|
| Ed25519 | 0 | 32 bytes | 32 bytes | 64 bytes | Default |
| Falcon512 | 2 | 897 bytes | 1281 bytes | 666 bytes | Post-quantum |

The `algo` wire byte matches the values in `IdentityPayload`, `DeletePayload`, the mesh beacon,
and the PEX signature. The session handshake (`SessionMsg::KeyAgreement`) uses a separate
convention: 1 = Ed25519, 2 = Falcon512 (see `node/session/handshake.rs::algo_to_u8`).

### Key generation

```bash
veil-cli key gen
veil-cli key gen --algo falcon512
```

**Creating an identity with a PoW nonce** (recommended during initial setup):

```bash
veil-cli config init --difficulty 16
```

The `difficulty` is the number of leading zero bits in the BLAKE3 hash of the nonce. At `difficulty=16`, expect ~65K iterations (< 1 ms on modern hardware).

### Key security

- The config file must be accessible only to its owner: `chmod 600 ~/.config/veil/config.toml`
- The private key is stored in plaintext — use filesystem encryption or an HSM for production
- **Never** publish the `private_key`

### Key rotation

Rotating a key changes the `node_id`, which is equivalent to creating a new node:

```bash
veil-cli key gen --output > new_keys.txt   # prints the pair to stdout without touching the config
# Update public_key, private_key, recompute the nonce
veil-cli config init --force
```

---

## Managing listeners and peers

### CLI for listeners

```bash
veil-cli listen add tcp://0.0.0.0:9000
veil-cli listen del LISTEN_ID
veil-cli listen list
```

Additional `listen add` flags: `--advertise URI` (the address advertised when behind a reverse proxy),
`--relay NODE_ID_BASE64`, as well as `--tls-cert/--tls-key/--tls-ca-cert` for `tls://`/`wss://` listeners.

### Transports

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

Core nodes can store messages for offline recipients. The mailbox is disabled by default and is enabled with a single flag:

```toml
[mailbox]
enabled = true
```

There is no backend choice: when `enabled = true`, the runtime always opens the built-in redb store at the fixed path `<veil_dir>/mailbox/blobs.db` (durable, transactional). No `backend`, `data_dir`, or `strict_backend` fields exist in the `[mailbox]` section.

Only quotas, TTL, the rate limit, and push notifications are configurable (with zero values, the `veil-mailbox` crate's defaults are used):

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

For more on the `[mailbox]` section fields — see the [Configuration Reference](config-reference.md#mailbox).

---

## Metrics

### Configuring the exporter

The `[metrics]` section enables the HTTP exporter in Prometheus format:

```toml
[metrics]
listen = "tcp://0.0.0.0:9090"
path   = "/metrics"
```

`listen` is a TransportUri (must contain the `tcp://` scheme), otherwise the config will fail validation.

### Retrieving metrics

```bash
# Via CLI
veil-cli node metrics

# Via HTTP (Prometheus scrape)
curl http://127.0.0.1:9090/metrics
```

### Available counters

The full list is built in `NodeMetrics::render_prometheus`
([observability.rs](../../crates/veil-observability/src/lib.rs)). All names
are exported with the `veil_` prefix. Below are the main groups.

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

> **Mailbox depth.** The current number of blobs in the mailbox is not
> exported to Prometheus — it is available only through the admin HTTP API
> state dump in the `mailbox_entries` field.

---

## Admin API — the administrative socket

**Address:** Unix domain socket (the default on Linux/macOS) or TCP-loopback with
token authentication (mandatory on Windows, since Unix sockets are unavailable).
The path/URI is set by `global.admin_socket`; see the "Admin protocol transport"
section above.

**Protocol:** JSON request/response over the socket, newline-terminated. For the TCP backend,
the client sends a 32-byte binary token as its first frame, read from
`runtime_dir/admin.token` — only after a successful constant-time
check does the server begin serving the admin protocol; otherwise the connection
is dropped.

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

These same subcommands are also available under `veil-cli sessions ban/unban/banned` — they share one backend state.

### Hot config reload

```bash
# Via the admin API (recommended — addresses exactly the running daemon)
veil-cli node reload

# Or SIGHUP directly: under systemd
systemctl reload veil        # see ExecReload in the unit below
```

`pkill -HUP veil-cli` will only work if there is a single running process of
the binary in the system and it is not a CLI client — do not rely on this in production.

---

## Configuring the systemd service

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

### The node does not start

```bash
# Validate the config
veil-cli config validate

# View the logs
veil-cli --config /etc/veil/config.toml node run
# or via journalctl if using systemd
```

### No inbound connections

1. Check that the firewall is open on the required ports
2. Make sure a `[[listen]]` block exists in the config
3. Check the listener status: `veil-cli listen list`

### No outbound connections

1. Check that `[[peers]]` blocks have been added
2. Check the transport URI: `veil-cli debug transport connect URI`
3. Check connectivity: `veil-cli debug peers connect PEER_ID`

### High memory consumption

Check the limits in `[capacity]` and `[abuse]`. On an overloaded gateway:

```toml
[capacity]
max_relay_sessions = 512

[abuse]
rate_limit_fps = 20.0
```

### The node is not visible in the DHT

- Make sure at least one Core node is added to `[[peers]]`
- The node must have a publicly reachable `[[listen]]` address
- Check: `veil-cli node dht routing`

---

## Running as a service

### Linux / macOS — systemd / launchd

On Unix systems, veil runs as an ordinary daemon; integration with
the system supervisor is done through a systemd unit (Linux) or a
launchd plist (macOS). Template unit:

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

On Windows, veil can register itself as a native service through the
SCM. The service starts automatically at boot, stops at
shutdown, and is visible in `services.msc` / `Get-Service VeilNode`.

**Installation** (requires admin privileges):

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

**Implementation details:**

- The service logs in as `LocalSystem` by default. To run under a
  less privileged account, edit after install:
  ```powershell
  sc config VeilNode obj= ".\veil_user" password= "..."
  ```
- The config path is baked into the service `ImagePath` at install time. If
  the config is later moved — uninstall and reinstall the service.
- `service run` — the entry invoked by SCM, hidden from `--help`. Operators
  must not invoke it directly; use `install` +
  `Start-Service`.
- Graceful shutdown: on `Stop-Service`, SCM sends `ServiceControl::Stop`,
  the service flips its status to `StopPending`, waits for the node runtime to stop
  (including the fsync persist of bans/peers_discovered/etc), then `Stopped`.
