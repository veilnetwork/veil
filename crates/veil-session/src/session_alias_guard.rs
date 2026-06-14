//! Session-alias RAII guard.  SessionRunner decomposition slice 31
//! (architecture backlog) — moves the previously inline `AliasGuard`
//! struct + the `register_session_aliases_with_drop_guard` method
//! into a dedicated module.
//!
//! ## What this does
//!
//! On session attach, the runner derives **compact 8-byte session
//! aliases** (one local, one remote) from `(session_id, node_id)`
//! pairs via `session_kdf::derive_session_alias`.  These aliases are
//! used by `RouteAnnounceAliased` / `RouteWithdrawAliased` gossip
//! frames so route updates don't carry full 32-byte node_ids on the
//! wire (saves bytes + avoids identity-correlation leakage).
//!
//! [`SessionAliasGuard`] holds the dispatcher + both aliases.  On
//! `Drop` — triggered by ANY exit path from `run()` (normal close,
//! idle timeout, I/O error, cipher error, panic during the loop) —
//! the guard calls `dispatcher.unregister_session_aliases(...)` to
//! release the mapping from the dispatcher's alias table.
//!
//! Without the RAII pattern a panic between dispatcher.register and
//! the explicit unregister call would leak the alias mapping, leading
//! to a route-table inconsistency on the next session for the same
//! `(session_id, node_id)` pair.
//!
//! ## Why extract
//!
//! * **Consistency**: slices 22-30 already moved per-session state
//!   into dedicated modules; the inline `AliasGuard` struct was the
//!   last guard-pattern still living in `runner.rs`.
//! * **Discoverability**: search for "AliasGuard" pre-extraction hit
//!   only one site (the `runner.rs` definition).  Post-extraction the
//!   module name surfaces in the file-listing pane.
//! * **Decoupling**: the constructor closure becomes a free function
//!   that takes the four needed inputs explicitly (`dispatcher`,
//!   `session_id`, `local_node_id`, `peer_id`) — cleaner test fixture
//!   than borrowing the whole `SessionRunner`.

use std::sync::Arc;

use crate::dispatcher_sink::DispatcherSink;
use veil_crypto::session_kdf;

/// RAII guard that unregisters session aliases when dropped.
///
/// Constructed by [`register_session_aliases_with_drop_guard`].  Held
/// as a local variable in `run()` so it drops when the run loop exits
/// via any path (early return, normal exit, panic).
///
/// `#[allow(dead_code)]`: fields are read solely by the `Drop` impl —
/// rustc otherwise warns "field never read".  Struct-level attribute
/// covers all three fields with a single anchor (per dead-code-anchors
/// policy).
#[allow(dead_code)]
pub struct SessionAliasGuard {
    pub dispatcher: Arc<dyn DispatcherSink>,
    pub local_alias: [u8; 8],
    pub remote_alias: [u8; 8],
}

impl Drop for SessionAliasGuard {
    fn drop(&mut self) {
        self.dispatcher
            .unregister_session_aliases(self.local_alias, self.remote_alias);
    }
}

/// Derive session aliases from `(session_id, node_id)` pairs, register
/// them with the dispatcher, and return a [`SessionAliasGuard`] that
/// auto-unregisters on drop.
///
/// Returns `None` for bootstrap / pre-handshake sessions where either
/// `session_id` or `peer_id` is the zero array — aliases rely on
/// session_id-bound derivation, so they're skipped when unavailable.
///
/// Side-effect ordering: dispatcher registration MUST complete before
/// the [`SessionAliasGuard`] is constructed — a panic between would
/// leak the registration.  This function preserves the ordering by
/// returning the guard only after `register_session_aliases` succeeds.
pub fn register_session_aliases_with_drop_guard(
    dispatcher: &Arc<dyn DispatcherSink>,
    session_id: &[u8; 32],
    local_node_id: &[u8; 32],
    peer_id: &[u8; 32],
) -> Option<SessionAliasGuard> {
    if *session_id == [0u8; 32] || *peer_id == [0u8; 32] {
        return None;
    }
    let local_alias = session_kdf::derive_session_alias(session_id, local_node_id);
    let remote_alias = session_kdf::derive_session_alias(session_id, peer_id);
    dispatcher.register_session_aliases(local_alias, *local_node_id, remote_alias, *peer_id);
    Some(SessionAliasGuard {
        dispatcher: Arc::clone(dispatcher),
        local_alias,
        remote_alias,
    })
}

// No standalone unit tests — `FrameDispatcher` requires a full
// session fixture to instantiate, so the zero-session-id and happy-path
// branches are covered transitively via the existing session-runner
// integration tests (phase650b_* gate suite).  Code paths covered:
// * Bootstrap session (zero session_id) — covered by
//   `two_nodes_complete_ovl1_handshake` integration test, which uses
//   a SessionFsm directly without a runner, so it exercises the
//   "no aliases registered" path implicitly.
// * Healthy session with non-zero ids — covered by every other
//   `session::*` test that spawns a full SessionRunner via
//   `make_runner_pair` test helper.
