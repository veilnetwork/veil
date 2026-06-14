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

/// Maximum obfs4 single-packet (solo) egress payload, in bytes. A solo packet
/// above this would make `wrap_frame` return `OversizedFrame`, exit the writer
/// task, and tear down the whole session; the bridge drops just that packet
/// instead, and `config::validate` rejects an MTU above the ceiling up front
/// (diff-audit H6 — the old default 16000 sat ABOVE this, silently dropping
/// every full-size packet). Operators should keep the tunnel MTU at or below
/// this. (audit cycle-8 H10.)
///
/// Lives at crate root (not in the `#[cfg(unix)]` `bridge` module) because
/// `config::validate` consumes it on ALL platforms — a unix-only home broke
/// the Windows release build (E0433: `crate::bridge` absent on Windows).
pub(crate) const MAX_OBFS4_SOLO_PAYLOAD_BYTES: usize = 15_231;

// Compile-time invariant: the solo ceiling must stay strictly below the obfs4
// frame ciphertext cap (`veil_obfs4::MAX_FRAME_CIPHERTEXT_BYTES = 16 * 1024`),
// otherwise a solo packet at the ceiling could still trip OversizedFrame and
// tear down the session the H10 guard exists to protect.
const _: () = assert!(MAX_OBFS4_SOLO_PAYLOAD_BYTES < 16 * 1024);

pub mod app_cert_gate;
pub mod app_id;
pub mod batch;
// `bridge` pulls in `veilclient::VeilClient`, which is itself
// `#[cfg(unix)]`-gated (Unix-domain-socket IPC).  Skip it on Windows
// cross-compile to keep the workspace `cargo check --target
// x86_64-pc-windows-gnu` gate green — the `ogate` binary as a whole
// is a daemon that requires UDS, so Windows builds are CI-only.
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
