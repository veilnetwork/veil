//! `ogate` — veil-network TUN bridge library.
//!
//! Wraps the local veil daemon IPC into a virtual TUN interface so two
//! or more machines can exchange IPv4/IPv6 packets over the veil as if
//! they were on a private LAN. Two access modes:
//!
//! * `open` — any veil peer that knows the (network, app) pair
//!   can send traffic in.
//! * `authorized` — only peers whose `node_id` is in the per-network
//!   allowlist are accepted (drop-at-app-layer).
//!
//! Use the `ogate` binary; the library is mostly internal but exposed for
//! integration testing.

pub mod app_cert_gate;
pub mod app_id;
pub mod batch;
// `bridge` pulls в `veilclient::VeilClient`, which is itself
// `#[cfg(unix)]`-gated (Unix-domain-socket IPC).  Skip it on Windows
// cross-compile к keep the workspace `cargo check --target
// x86_64-pc-windows-gnu` gate green — the `ogate` binary as а whole
// is а daemon that requires UDS, so Windows builds are CI-only.
#[cfg(unix)]
pub mod bridge;
pub mod cert_message;
pub mod cli;
pub mod config;
pub mod config_template;
pub mod routing;
pub mod tun;

pub use app_id::{derive_app_id, namespace_for};
pub use config::{AccessMode, OgateConfig, PeerEntry};
pub use routing::{Decision, RoutingTable};
