//! H10 stage-B decomposition: PEX-domain runtime state collapsed into
//! one owned struct on [`crate::node::NodeRuntime`].
//!
//! ## Why a dedicated struct (and why not `Arc<...>`)
//!
//! Pre-stage-B, `NodeRuntime` carried four PEX-related fields side-by-
//! side with unrelated session/handoff/mailbox state:
//!
//! 1. `pex_state: Arc<Mutex<PexState>>` — shared with the initiator task.
//! 2. `pex_event_rx: Option<Receiver<PexEvent>>` — consumed once
//!    when `spawn_pex_initiator` fires.
//! 3. `pex_connect_tx: Option<PexConnectTx>` — cloned into the
//!    initiator task on spawn.
//! 4. `pex_connect_rx: Option<Receiver<Vec<PexPeer>>>` — consumed
//!    once by the PEX connector task.
//!
//! The other H10 bundles (`MailboxState`, `MobileState`, `RoutingState`,
//! `ResumptionState`) are `Arc<XState>`-shared, but PEX cannot use
//! that pattern: `tokio::mpsc::Receiver` is not `Clone`, and the
//! receivers must be `.take()`-d via `&mut self` at task-spawn time.
//! Wrapping in `Arc<Mutex<_>>` just to satisfy take-once semantics
//! would add a lock that nobody contends on. Instead, `PexRuntime`
//! is a plain owned struct embedded directly in `NodeRuntime`;
//! NodeServices never carries PEX state, so there is no propagation
//! surface to worry about.
//!
//! Net effect: 4 sibling fields → 1 typed bundle. Same migration
//! pattern as the Arc-shared bundles but with an explicit comment
//! explaining the shape divergence.

use std::sync::{Arc, Mutex};

use veil_proto::pex::PexPeer;

/// PEX-domain runtime state owned exclusively by
/// [`crate::node::NodeRuntime`]. Populated once at construction; the
/// `Option<Receiver>` fields are `.take()`-d when the PEX
/// initiator / connector tasks spawn.
pub struct PexRuntime {
    /// PEX shared state — Arc-wrapped mutex so multiple tasks can
    /// read while the initiator task mutates.
    pub state: Arc<Mutex<veil_pex::PexState>>,

    /// PEX event receiver. Consumed once by `spawn_pex_initiator`; on
    /// subsequent reloads this is `None` and the initiator does not
    /// re-spawn (it picks up config changes via its own shutdown_rx).
    pub event_rx: Option<tokio::sync::mpsc::Receiver<veil_pex::PexEvent>>,

    /// PEX connect sender. Cloned into the initiator task on spawn.
    pub connect_tx: Option<veil_pex::PexConnectTx>,

    /// PEX connect receiver, consumed once by the PEX connector task
    /// that reads discovered peers and initiates outbound connections.
    pub connect_rx: Option<tokio::sync::mpsc::Receiver<Vec<PexPeer>>>,
}

impl PexRuntime {
    pub fn new(
        state: Arc<Mutex<veil_pex::PexState>>,
        event_rx: tokio::sync::mpsc::Receiver<veil_pex::PexEvent>,
        connect_tx: veil_pex::PexConnectTx,
        connect_rx: tokio::sync::mpsc::Receiver<Vec<PexPeer>>,
    ) -> Self {
        Self {
            state,
            event_rx: Some(event_rx),
            connect_tx: Some(connect_tx),
            connect_rx: Some(connect_rx),
        }
    }
}

/// Build the inbound `PexDispatcher` (the handler that turns incoming PEX
/// frames into [`veil_pex::PexEvent`]s pushed down `event_tx`).
///
/// Audit M2: extracted so BOTH the cold-start path (`NodeRuntime::start`) and
/// the reload path (`build_reload_dispatcher`) construct the dispatcher the
/// same way. On reload the channel pair is recreated and a fresh dispatcher is
/// built here pointing at the new `event_tx`; without that, the dispatcher
/// (Arc-cloned across reload) kept pushing into the original channel whose
/// receiver had been consumed by the now-aborted initiator — leaving PEX
/// peer-exchange permanently dead after the first reload.
///
/// Returns `None` when PEX is disabled (the caller drops `event_tx`).
pub(crate) fn build_pex_dispatcher(
    config: &veil_cfg::Config,
    local_node_id: [u8; 32],
    logger: Arc<dyn veil_pex::PexLogger>,
    event_tx: tokio::sync::mpsc::Sender<veil_pex::PexEvent>,
) -> Option<Arc<veil_pex::PexDispatcher>> {
    if !config.pex.enabled {
        return None;
    }
    let (local_pk_bytes, local_nonce_u64, local_diff) = config
        .identity
        .as_ref()
        .and_then(|id| {
            let di = veil_cfg::identity::DomainIdentity::from_config(id).ok()?;
            // Cap local_difficulty at MAX_POW_DIFFICULTY — random identities
            // can land at zero_bits 26..31, above the session-layer ceiling
            // that PEX walkers refuse to solve, which would make every walk to
            // this node fail with `pex.pow.unsolvable`.
            let raw_score = di.pow_score().ok()?.zero_bits as u8;
            let score = raw_score.min(veil_proto::budget::MAX_POW_DIFFICULTY);
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let pk = STANDARD.decode(&id.public_key).ok()?;
            let nonce_bytes = STANDARD.decode(&id.nonce).unwrap_or_default();
            let nonce_val = if nonce_bytes.len() >= 4 {
                u32::from_be_bytes([
                    nonce_bytes[0],
                    nonce_bytes[1],
                    nonce_bytes[2],
                    nonce_bytes[3],
                ]) as u64
            } else {
                0u64
            };
            Some((pk, nonce_val, score))
        })
        .unwrap_or_default();
    Some(Arc::new(veil_pex::PexDispatcher::new(
        local_node_id,
        local_pk_bytes,
        local_nonce_u64,
        local_diff,
        &config.pex,
        event_tx,
        logger,
    )))
}
