//! Shared veil-stream bridge tables for cross-node IPC stream forwarding.
//!
//! When an IPC SDK client opens a stream to a **remote** node
//! (`STREAM_OPEN { dst_node_id != local }`), the IPC server bridges it onto the
//! wire-level `AppOpen`/`AppData`/`AppClose` machinery — the same machinery
//! [`veil_proxy::VeilConnector`] already uses for the SOCKS5/HTTP proxy
//! paths. These tables are the shared rendezvous between the IPC server, the
//! `VeilConnector`, and the frame dispatcher.
//!
//! The two map aliases are intentionally **transparent type synonyms** for the
//! same concrete types `veil_proxy::veil_connector` exposes. Because Rust
//! type aliases are structural (not nominal), the daemon can pass its existing
//! `VeilConnector`-typed `Arc`s straight into the IPC server's API without
//! any dependency edge between `veil-ipc` and `veil-proxy` (which would
//! otherwise be a new cross-crate coupling).

use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

/// `(dst_node_id, wire_stream_id)` → inbound-data sender.
///
/// The frame dispatcher routes an inbound `AppData` frame whose
/// `(src_node_id, header.stream_id)` matches a registered entry into this
/// `mpsc`, where a per-stream bridge task picks it up and forwards it to the
/// owning surface (the IPC client's delivery channel, or the proxy socket).
pub type VeilStreamRxMap = Arc<Mutex<HashMap<([u8; 32], u32), mpsc::Sender<Vec<u8>>>>>;

/// `wire_stream_id` → one-shot receipt waiter.
///
/// Completed by the dispatcher with the `AppReceipt` status byte when the
/// remote peer accepts (or rejects) a freshly-sent `AppOpen`.
pub type PendingReceiptMap = Arc<Mutex<HashMap<u32, oneshot::Sender<u8>>>>;

/// Daemon-supplied shared state that enables the IPC server's cross-node
/// stream-forwarding path. Cloned into the [`crate::server::IpcServer`] at
/// construction via [`crate::server::IpcServer::with_stream_bridge`].
///
/// `None` on the server (tests / setups without a full `NodeRuntime`) keeps the
/// remote `STREAM_OPEN` path returning `REMOTE_NOT_IMPLEMENTED` — the local
/// same-node pair path is unaffected either way.
#[derive(Clone)]
pub struct IpcStreamBridge {
    /// `(node_id, wire_stream_id)` → inbound-data sender (shared with the
    /// dispatcher and `VeilConnector`).
    pub veil_stream_rx: VeilStreamRxMap,
    /// `wire_stream_id` → receipt waiter (shared with the dispatcher).
    pub pending_receipts: PendingReceiptMap,
    /// Monotonic wire stream-id allocator, shared across **every** surface that
    /// opens wire streams on this node (the IPC remote path and
    /// `VeilConnector`) so `(node_id, wire_stream_id)` keys never collide
    /// between surfaces. Allocate with `fetch_add(1, Relaxed)`.
    pub wire_stream_counter: Arc<AtomicU32>,
}
