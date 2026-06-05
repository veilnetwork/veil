//! Default-config templates emitted by `oproxy-server --gen-config`
//! and `oproxy-client --gen-config`.
//!
//! Hand-written TOML templates с inline `#`-comments на every field +
//! sensible defaults.  Operators run the flag once, then fill in the
//! placeholders (server node_id, allowed_node_ids, listener ports).

/// Default-config template для `oproxy-server`.
pub const SERVER_DEFAULT_CONFIG: &str = r#"# oproxy-server.toml — veil-network exit proxy server
#
# Generate this file с:
#     oproxy-server --gen-config > /etc/oproxy/server.toml
#
# Then fill in:
#   * `app_name`        — must match the client's `server_app_name`
#   * `allowed_node_ids` — list of clients allowed к connect
#                          (or set `allow_all = true` для an open proxy)
#
# Run с:
#     oproxy-server --config /etc/oproxy/server.toml
#
# Permissions: chmod 0640, chown root:veil.  Lists allowed peer node_ids —
# не leak в world-readable storage.

# ─── veil daemon ──────────────────────────────────────────────────

# Path к the local veil daemon's IPC socket (Unix) or named-pipe
# (Windows).  Must match the daemon's `[ipc] socket_uri` (without the
# `unix://` scheme).
socket_path = "/run/veil/app.sock"

# App-name used to derive the app_id.  The client must publish the same
# `server_app_name` к match — both sides compute
# `app_id(server_node_id, "oproxy", app_name)` independently.
app_name = "exit"

# ─── admission ──────────────────────────────────────────────────────

# Strict allowlist by source node_id (64-char hex).  Only listed peers
# can connect.  Get а peer's node_id с `veil-cli node show | grep
# node_id` on their box.
#
# Empty list ⇒ open proxy (requires `allow_all = true` below as explicit
# opt-in, otherwise startup fails).
allowed_node_ids = [
  # "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  # "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d",
]

# Explicit acknowledgement that this server is an **open proxy** (no
# allowlist).  Without this flag, an empty `allowed_node_ids` is rejected
# at startup — silent open-proxy was а footgun where operators thought
# "empty = nothing" but actually meant "all veil peers".
# Default: false.
allow_all = false

# **P-Net admission gate**.  When `true`, every incoming veil stream's
# source node_id is checked against the daemon's verified-cert cache
# (LocalAppMsg::PnetStatusQuery).  Streams от peers без а valid
# MembershipCert are rejected с `Denied`.
#
# Combine с allowed_node_ids для defence-in-depth: peer must BOTH have
# а verified cert AND be в the static list.  An empty allowed_node_ids
# + pnet_required = true means "trust whoever the daemon's P-Net gate
# admitted".
#
# Requires the daemon к be running in P-Net mode (`[network]` block
# в node.toml + `veil-cli network sign-member`-issued certs).
# Default: false (backward-compatible).
pnet_required = false

# ─── S2.B app-layer cert authority (optional) ───────────────────────
#
# Independent от the daemon's P-Net gate.  When all three fields are
# set, oproxy-server requires every incoming stream к present а signed
# MembershipCert preamble (см. wire-format в crates/oproxy/src/wire.rs),
# verifies it against THIS server's own trusted owner pubkey, и admits
# only on success.  Use case: daemon в public mode но oproxy specifically
# wants к admit а narrower set of clients (separate authority per app).
#
# Leave all three unset (the default) к skip the app-cert gate.  Setting
# only а subset fails startup.
#
# Operator flow:
#   1. veil-cli network gen-owner --pub-out owner.pub --priv-out owner.priv
#   2. veil-cli network gen-network-id        # → save the hex string
#   3. Each client gets а cert via `veil-cli network sign-member ...`
#   4. Plug owner.pub contents + network_id below.
#
# app_cert_trusted_owner_pubkey = "<base64 ed25519 owner pubkey>"
# app_cert_owner_algo = "ed25519"
# app_cert_network_id = "948b97b51b...ea87"

# ─── egress destination policy ──────────────────────────────────────

# Permit outbound TCP к RFC1918 / loopback / metadata addresses
# (169.254.169.254, link-local).  Default `false` — recommended.
# Enable only если the proxy is intended as а bastion для internal
# network access.
allow_private = false

# ─── connection limits ──────────────────────────────────────────────

[limits]
# Max concurrent inbound veil streams the server bridges. When at
# capacity, accept_stream() blocks; the daemon backpressures upstream
# peers via the standard stream-window mechanism.
# Default: 1024.
max_concurrent_streams = 1024

# ─── logging ────────────────────────────────────────────────────────

[logging]
# Minimum log level: `off` | `error` | `warn` | `info` | `debug` |
# `trace`.  Overridden by `RUST_LOG` env var when set.
# Default: "info".
level = "info"

# Optional log file path.  Omit к log к stderr (default; systemd captures
# к journald).  Parent directory must exist.
# file = "/var/log/oproxy/server.log"

# ─── tokio runtime ──────────────────────────────────────────────────

[runtime]
# Runtime flavour: `current_thread` или `multi_thread` (default).
flavor = "multi_thread"

# Worker threads (multi_thread only).  Omit для tokio default (num_cpus).
# worker_threads = 4

# Cap для spawn_blocking pool.  Defaults к tokio's 512.
# max_blocking_threads = 512

# Env-var overrides (still honoured post-load):
#   OPROXY_RUNTIME             ⇒ flavor
#   OPROXY_WORKERS             ⇒ worker_threads
#   OPROXY_MAX_BLOCKING_THREADS ⇒ max_blocking_threads
"#;

/// Default-config template для `oproxy-client`.
pub const CLIENT_DEFAULT_CONFIG: &str = r#"# oproxy-client.toml — veil-network proxy client
#
# Generate с:
#     oproxy-client --gen-config > /etc/oproxy/client.toml
#
# Then fill in:
#   * `server_node_id`   — 64-char hex node_id of the oproxy-server box
#   * `server_app_name`  — must match the server's `app_name`
#   * `[[inbound]]`       — at least one listener (SOCKS5 / HTTP / Tproxy)
#
# Run с:
#     oproxy-client --config /etc/oproxy/client.toml
#
# Permissions: chmod 0640, chown root:veil.

# ─── veil daemon ──────────────────────────────────────────────────

# Path к the local veil daemon's IPC socket.  Must match the daemon's
# `[ipc] socket_uri` (without the `unix://` scheme).
socket_path = "/run/veil/app.sock"

# ─── upstream server ────────────────────────────────────────────────

# 64-char hex of the upstream server's veil node_id.  Get it с
# `veil-cli node show | grep node_id` on the server box.
server_node_id = "REPLACE-WITH-64-HEX-CHARS"

# Must match the server's `app_name`.  Both sides derive the same
# app_id from this string.
server_app_name = "exit"

# ─── inbound listeners ───────────────────────────────────────────────

# One или more local listeners.  All run concurrently — you can mix
# SOCKS5 + HTTP + transparent proxy if needed.

# SOCKS5 ingress (RFC 1928) — most common.
[[inbound]]
kind = "socks5"
# host:port для the local listener.  127.0.0.1 для loopback-only access.
listen = "127.0.0.1:1080"

# HTTP/1.1 forward proxy (CONNECT + absolute-URI rewriting).
# [[inbound]]
# kind = "http"
# listen = "127.0.0.1:8080"

# Transparent proxy via Linux IP_TRANSPARENT / SO_ORIGINAL_DST.  Requires
# CAP_NET_ADMIN + matching iptables/nftables rules.  Linux / Keenetic only.
# [[inbound]]
# kind = "tproxy"
# listen = "0.0.0.0:1081"

# ─── connection limits ──────────────────────────────────────────────

[limits]
# Max concurrent SOCKS5 / HTTP / TProxy sessions PER LISTENER.  When at
# capacity, accept() blocks — TCP backpressure к the local client.
# Default: 1024.
max_concurrent_per_listener = 1024

# ─── routing policy ─────────────────────────────────────────────────

[routing]
# Default action when no rule matches:
#   "veil" — tunnel через veil → server (default)
#   "direct"  — open а direct TCP socket from client host
#   "block"   — refuse the connection с а proxy-error response
default = "veil"

# What к do if `default = "veil"` AND the veil path fails:
#   "fail"   — return CONNECT failure к the inbound client (default)
#   "direct" — silently fall back к а direct TCP connect
fallback = "fail"

# ─── S2.B app-layer cert (optional) ─────────────────────────────────
#
# Path к а signed `MembershipCert` blob (output of `veil-cli network
# sign-member`).  When set, oproxy-client prepends an app-cert preamble
# к every outbound stream open; the server verifies it against its own
# configured trusted owner pubkey (`app_cert_trusted_owner_pubkey` в
# server.toml) before accepting the connection.
#
# Set this если the server requires app-cert authority (see server's
# config).  Leaving it unset keeps the client backward-compatible с
# servers що don't enforce app-cert.
#
# app_cert_path = "/etc/oproxy/client.cert"

# Per-target rules — evaluated в order, first match wins.  Omit для
# "everything через veil".  Each rule needs at least one match field
# (`host_suffix` | `host_exact` | `cidr` | `port_range`) and an `action`.
#
# Example: send only internal DNS suffixes через the veil, everything
# else direct:
#
# [[routing.rules]]
# host_suffix = ".internal"
# action      = "veil"
#
# [[routing.rules]]
# host_suffix = ".example.com"
# action      = "direct"

# ─── logging ────────────────────────────────────────────────────────

[logging]
# Minimum log level: `off` | `error` | `warn` | `info` | `debug` |
# `trace`.  Overridden by `RUST_LOG` env var when set.
# Default: "info".
level = "info"

# Optional log file path.  Omit к log к stderr.
# file = "/var/log/oproxy/client.log"

# ─── tokio runtime ──────────────────────────────────────────────────

[runtime]
flavor = "multi_thread"
# worker_threads = 4
# max_blocking_threads = 512

# Env-var overrides (still honoured post-load):
#   OPROXY_RUNTIME             ⇒ flavor
#   OPROXY_WORKERS             ⇒ worker_threads
#   OPROXY_MAX_BLOCKING_THREADS ⇒ max_blocking_threads
"#;
