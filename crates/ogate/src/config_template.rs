//! Default-config template emitted by `ogate gen-config`.
//!
//! The template is a complete TOML file documenting every public
//! field in [`crate::config::OgateConfig`] with inline `#` comments
//! explaining what each field does, what the default is, and when
//! you'd want to change it.
//!
//! Operators run `ogate gen-config -o /etc/ogate/ogate.toml`, then
//! fill in the placeholder bits (network name, peer node_ids, virtual
//! IPs) for their deployment.

pub const OGATE_DEFAULT_CONFIG: &str = r#"# ogate.toml — veil-network TUN bridge configuration
#
# Generate this file with:
#     ogate gen-config -o /etc/ogate/ogate.toml
#
# Then edit the placeholders below — at minimum:
#   * `network` — must match across all peers in your deployment
#   * `local_addr_v4` — your virtual IPv4 inside the subnet
#   * `[[peers]]` entries — one per other peer in the network
#
# Bring up with:
#     ogate up --config /etc/ogate/ogate.toml
#
# Permissions: chmod 0640 ogate.toml and chown root:veil (or whatever
# group your daemon runs as).  The file lists peer node_ids — keep it
# readable only by the daemon's uid.

# ─── identity ─────────────────────────────────────────────────────────

# Network name.  Must match exactly across all peers.  Two peers with
# different `network` values cannot communicate even if both are on the
# same veil; the value is mixed into the app_id derivation, which
# changes the IPC binding namespace.  Required.
network = "REPLACE-WITH-YOUR-NETWORK-NAME"

# Application name within the network.  Multiple apps can share one
# network with different virtual-IP plans (e.g. ogate, voip, file-share).
# Default: "ogate".
app = "ogate"

# ─── access mode ──────────────────────────────────────────────────────

# Access mode:
#   "authorized" — only peers listed in [[peers]] below are accepted on
#                   ingress AND allowed as egress destinations
#                   (fail-closed; default; recommended).
#   "open"       — any peer that knows (network, app) can talk in.
#                   Use only for testing / fully-open networks.
mode = "authorized"

# **P-Net admission gate**.  When `true`, ogate queries the daemon's
# verified-cert cache at startup and on SIGHUP, filtering out any
# [[peers]] entry whose peer hasn't presented a valid MembershipCert.
# Combine with mode = "authorized" for defence-in-depth: peer must BOTH
# have a verified cert AND be in the [[peers]] list.
#
# Requires the daemon to be running in P-Net mode (`[network]` block
# in node.toml + `veil-cli network sign-member`-issued certs).
# Default: false (backward-compatible).
pnet_required = false

# ─── S2.B app-layer cert authority (optional) ───────────────────────
#
# Independent from the daemon's P-Net gate.  When all three server-side
# fields ARE set, ogate's ingress path drops IP packets from peers that
# haven't presented a valid MembershipCert signed by a trusted owner.
# The cert exchange happens via a dedicated out-of-band message protocol
# (see crates/ogate/src/cert_message.rs) and a per-peer verified cache.
#
# Use case: ogate operator wants a narrower trust domain than the
# veil daemon's overall membership (e.g. daemon in public mode but
# ogate restricts to a specific cluster).
#
# Operator flow:
#   1. veil-cli network gen-owner --pub-out owner.pub --priv-out owner.priv
#   2. veil-cli network gen-network-id    # → save the hex string
#   3. Issue per-peer certs: `veil-cli network sign-member ...`
#   4. Plug owner.pub contents + network_id below.
#
# app_cert_trusted_owner_pubkey = "<base64 ed25519 owner pubkey>"
# app_cert_owner_algo = "ed25519"
# app_cert_network_id = "948b97b51b...ea87"

# Sender-side: path to a signed MembershipCert blob (output of
# `veil-cli network sign-member`).  When set, ogate emits the cert
# to each configured peer at startup and every 5 min thereafter.  Peers
# with the matching `app_cert_trusted_owner_pubkey` configuration cache
# the verified node_id and admit subsequent IP packets.
#
# app_cert_path = "/etc/ogate/my-cert.bin"

# ─── runtime / daemon ─────────────────────────────────────────────────

# Path to the veil daemon's IPC socket.  Must match the daemon's
# `[ipc] socket_uri` (minus the `unix://` scheme).
# Default: /run/veil/app.sock
socket_path = "/run/veil/app.sock"

# Endpoint id for the IPC binding.  Must match across all peers in the
# same (network, app).  Default: 0 (a single endpoint per app).
endpoint_id = 0

# ─── virtual interface ────────────────────────────────────────────────

# TUN interface name.  OS-dependent: Linux honours this verbatim,
# macOS auto-assigns `utunN`, Windows uses a GUID under the hood.
# Default: "ogate0".
iface_name = "ogate0"

# MTU for the TUN device.  1280 keeps room for veil AEAD overhead +
# typical L3 path MTU.  Raise only if you're certain the path MTU is
# higher (jumbo frames, dedicated tunnels).
# Default: 1280.
mtu = 1280

# ─── virtual addressing ───────────────────────────────────────────────

# Local IPv4 address inside the virtual subnet.  REQUIRED — the TUN
# backend cannot bring the interface up without it (Linux TUNSETIFF,
# macOS utun, Windows WinTun all need an IPv4 address).
# Pick a private RFC1918 range — e.g. 10.99.0.X, 172.31.X.Y, 192.168.99.Z.
local_addr_v4 = "10.99.0.1"
prefix_v4 = 24

# Local IPv6 address (optional — IPv6 stack on the TUN if set).
# Use ULA fd00::/8 unless you know what you're doing.
# local_addr_v6 = "fd00:ogate:1::1"
# prefix_v6 = 64

# ─── peers ────────────────────────────────────────────────────────────

# Per-peer virtual-IP table.  Required for mode = "authorized";
# optional but recommended for mode = "open" (still resolves dst → IP).
#
# Each entry needs `node_id` (64-char hex of the peer's veil node_id)
# AND at least one of `addr_v4` / `addr_v6` (the virtual IP that maps to
# that peer inside the subnet).  `name` is an optional human label that
# shows up in logs.
#
# Get a peer's node_id with `veil-cli node show | grep node_id` on their box.
#
# [[peers]]
# node_id = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
# addr_v4 = "10.99.0.2"
# addr_v6 = "fd00:ogate:1::2"
# name    = "alice-laptop"
#
# [[peers]]
# node_id = "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d"
# addr_v4 = "10.99.0.3"
# name    = "bob-server"

# ─── egress batching (Phase E27) ──────────────────────────────────────

[batch]
# Coalesce small IP packets into 0xB1-prefixed batch envelopes for
# better throughput on bulk transfer.  ALL peers must run an E27-or-
# newer build for this to work — legacy peers silently drop batch
# envelopes (manifests as a blackhole).
#
# Recommended:
#   * `false` during rolling upgrades from a pre-E27 cluster.
#   * `true`  (or omit) after every peer in the network is on E27+.
#
# Default: true.
enabled = true

# ─── logging ──────────────────────────────────────────────────────────

[logging]
# Minimum log level emitted: `off` | `error` | `warn` | `info` |
# `debug` | `trace`.  Default `info`.  Overridden by `RUST_LOG` env var
# when set (so `RUST_LOG=debug ogate up …` works without touching this file).
level = "info"

# Output format: `text` (default, human-readable) or `json` (machine-
# parseable structured logs — ship via fluent-bit etc.).
format = "text"

# Optional log file path.  Omit to log to stderr (default; systemd captures
# to journald).  When set, logs are appended (file created if absent);
# parent directory must exist.
# file = "/var/log/ogate/ogate.log"

# ─── tokio runtime ────────────────────────────────────────────────────

[runtime]
# Tokio runtime flavour: `current_thread` (single-thread executor) or
# `multi_thread` (default; work-stealing pool).  Use `current_thread`
# for memory-constrained boxes (<= 256 MiB RAM).
flavor = "multi_thread"

# Worker thread count for multi_thread.  Omit (or set 0) to use tokio's
# default (= num_cpus).  Lower this to limit ogate's CPU footprint on
# busy hosts.
# worker_threads = 4

# Cap for `spawn_blocking` thread pool.  Defaults to tokio's 512 — only
# change if profiling shows blocking-pool saturation.
# max_blocking_threads = 512

# Env-var overrides (still honoured after loading this file):
#   OGATE_RUNTIME             ⇒ flavor
#   OGATE_WORKERS             ⇒ worker_threads
#   OGATE_MAX_BLOCKING_THREADS ⇒ max_blocking_threads
"#;
