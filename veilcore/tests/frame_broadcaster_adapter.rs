//! Smoke test for the `FrameBroadcaster` trait inversion.
//!
//! Verifies that veilcore's `Arc<RwLock<SessionTxRegistry>>` can be
//! passed through the `veil_types::FrameBroadcaster` trait surface
//! end-to-end:
//!
//! 1. Construct a real `SessionTxRegistry`.
//! 2. Wrap it in `SessionTxBroadcaster`.
//! 3. Coerce to `Arc<dyn FrameBroadcaster>`.
//! 4. Call `send_to_all` through the trait — must not panic, must
//!    route through the registry's existing eviction logic for
//!    empty-receiver-set.
//!
//! This is the integration check that future extractions of pex / proxy /
//! ipc / miss_handler will rely on when they accept
//! `Arc<dyn FrameBroadcaster>` instead of importing the concrete type.

use std::sync::{Arc, RwLock};

use veil_session::glue::SessionTxBroadcaster;
use veil_session::tx_registry::SessionTxRegistry;
use veil_types::FrameBroadcaster;

#[test]
fn frame_broadcaster_smoke_through_session_tx_adapter() {
    let inner = Arc::new(RwLock::new(SessionTxRegistry::new()));
    let adapter = SessionTxBroadcaster::new(Arc::clone(&inner));
    let broadcaster: Arc<dyn FrameBroadcaster> = Arc::new(adapter);

    // No registered sessions — `send_to_all` must be a silent no-op.
    let frame: Arc<[u8]> = Arc::from(b"smoke".to_vec());
    broadcaster.send_to_all(Arc::clone(&frame));
    broadcaster.send_to_all_with_priority(0, Arc::clone(&frame));

    // Nonexistent peer — `send_to` must return false, not panic.
    let peer = [0xAAu8; 32];
    let sent = broadcaster.send_to(&peer, 1, b"unicast".to_vec());
    assert!(!sent, "send_to to nonexistent peer must return false");
}
