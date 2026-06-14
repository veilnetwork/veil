//! `LocalLink` — the abstract interface for a single local-mesh link.
//!
//! A link is a point-to-point or broadcast medium connecting two mesh nodes
//! within the same realm. Concrete implementations are:
//!
//! * `InMemoryLink` — used by `InMemoryRealm` for in-process testing.
//! * (future) `UdpLink`, `BleLink`, `WifiDirectLink`

use veil_proto::mesh::MeshFrame;
use veil_util::lock;

/// Outcome of a send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendResult {
    Ok,
    /// The remote end is gone or the link is broken.
    Disconnected,
}

/// A single directed local-mesh link.
///
/// The trait is intentionally *synchronous* at the `LocalLink` level — buffering
/// and async I/O are the responsibility of the caller (`MeshForwarder`).
pub trait LocalLink: Send + Sync {
    /// Node ID of the remote end of this link.
    fn remote_node_id(&self) -> [u8; 32];

    /// Send a frame on this link. Must not block indefinitely.
    fn send(&self, frame: &MeshFrame) -> SendResult;

    /// Send a pre-encoded frame (wire bytes) on this link.
    ///
    /// Links that work with raw bytes (e.g. UDP) should override this to avoid
    /// re-encoding. The default decodes and calls `send`.
    fn send_encoded(&self, encoded: &Arc<[u8]>) -> SendResult {
        match MeshFrame::decode(encoded) {
            Ok(frame) => self.send(&frame),
            Err(_) => SendResult::Disconnected,
        }
    }

    /// True if the link is still considered live.
    fn is_alive(&self) -> bool;
}

// ── InMemoryLink ──────────────────────────────────────────────────────────────

use std::sync::{Arc, Mutex};

/// In-process link backed by a shared `Vec<MeshFrame>` inbox.
///
/// Used by `InMemoryRealm` to wire up simulated nodes.
#[derive(Debug, Clone)]
pub struct InMemoryLink {
    pub(crate) remote_id: [u8; 32],
    /// Frames delivered to the remote end are pushed here.
    pub(crate) inbox: Arc<Mutex<Vec<MeshFrame>>>,
    pub(crate) alive: Arc<Mutex<bool>>,
}

impl InMemoryLink {
    /// Create a new link pair: (link for A→B, inbox for B).
    pub fn pair(remote_id: [u8; 32]) -> (InMemoryLink, Arc<Mutex<Vec<MeshFrame>>>) {
        let inbox = Arc::new(Mutex::new(Vec::new()));
        let alive = Arc::new(Mutex::new(true));
        let link = InMemoryLink {
            remote_id,
            inbox: Arc::clone(&inbox),
            alive,
        };
        (link, inbox)
    }

    /// Disconnect the link (simulate link failure).
    pub fn disconnect(&self) {
        *lock!(self.alive) = false;
    }
}

impl LocalLink for InMemoryLink {
    fn remote_node_id(&self) -> [u8; 32] {
        self.remote_id
    }

    fn send(&self, frame: &MeshFrame) -> SendResult {
        if !*lock!(self.alive) {
            return SendResult::Disconnected;
        }
        lock!(self.inbox).push(frame.clone());
        SendResult::Ok
    }

    fn is_alive(&self) -> bool {
        *lock!(self.alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::mesh::{MeshFrame, RealmId};

    fn frame() -> MeshFrame {
        MeshFrame::new(
            RealmId([0u8; 16]),
            [1u8; 32],
            [2u8; 32],
            4,
            b"test".to_vec(),
        )
    }

    #[test]
    fn send_delivers_to_inbox() {
        let (link, inbox) = InMemoryLink::pair([2u8; 32]);
        assert_eq!(link.send(&frame()), SendResult::Ok);
        assert_eq!(inbox.lock().unwrap().len(), 1);
    }

    #[test]
    fn disconnected_link_returns_error() {
        let (link, _inbox) = InMemoryLink::pair([2u8; 32]);
        link.disconnect();
        assert_eq!(link.send(&frame()), SendResult::Disconnected);
        assert!(!link.is_alive());
    }

    #[test]
    fn remote_node_id() {
        let (link, _) = InMemoryLink::pair([7u8; 32]);
        assert_eq!(link.remote_node_id(), [7u8; 32]);
    }
}
