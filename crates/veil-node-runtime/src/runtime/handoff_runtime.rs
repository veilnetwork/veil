//! H10 stage-B decomposition: hot-standby handoff-domain state
//! extracted into а dedicated [`Arc<HandoffRuntime>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-stage-B, three structs (`NodeRuntime`, `NodeServices`,
//! `SessionRuntimeContext`) each held five sibling handoff fields
//! — four `Arc<...>` registries + one `u32` policy knob — scattered
//! between the resumption и session-defaults groups:
//!
//! 1. `handoff_registry` — pending `HandoffInit` state, consulted by
//!    the accept-side peek-and-dispatch helper к bind warm sockets back
//!    into the matching runner's `swap_rx`.
//! 2. `swap_registry` — session_id → swap-channel sender map; auto-
//!    cleared via `SwapRegistryGuard::drop` at session exit.
//! 3. `handoff_ack_waiters` — session_id → HandoffAck-nonce sender map;
//!    warm-probe tasks register here before sending `HandoffInit`.
//! 4. `hot_standby_controller` — auto-swap controller (alt-URI map
//!    + flap damping).
//! 5. `auto_trigger_after_write_errors` — consecutive-error threshold
//!    that fires the controller. Logically part of the same handoff
//!    domain even though it's а pure `u32` config value.
//!
//! Five fields × three structs = fifteen field slots; bundle-then-Arc
//! collapses them к three (one `Arc<HandoffRuntime>` per struct).
//! Same pattern as the established `MailboxState`/`MobileState`/
//! `RoutingState`/`ResumptionState` decompositions.
//!
//! ## Migration surface
//!
//! Every callsite reading `self.handoff_registry` / `self.swap_registry`
//! / `self.handoff_ack_waiters` / `self.hot_standby_controller` /
//! `self.auto_trigger_after_write_errors` now reads
//! `self.handoff.<field>`. Boundary clones collapse from five
//! `Arc::clone` / value-copy calls к one `Arc::clone(&self.handoff)`.
//! No behaviour change.

use std::sync::Arc;

use super::handoff::{HandoffAckWaiters, HandoffRegistry, SessionSwapRegistry};
use super::hot_standby::HotStandbyController;

/// Hot-standby handoff-domain state owned by
/// [`crate::node::NodeRuntime`] и cloned (Arc) into `NodeServices` /
/// `SessionRuntimeContext` at boundary builds.
pub struct HandoffRuntime {
    /// stage (d) Task 3: hot-standby handoff registry. Shared
    /// с every `SessionRunner` this runtime spawns so inbound
    /// `HandoffInit` frames register а `PendingHandoff` here; the
    /// accept-side then consults it к bind warm sockets back into the
    /// matching runner's `swap_rx`.
    pub registry: Arc<HandoffRegistry>,

    /// stage (d) Task 4a: session_id → swap-channel sender map.
    /// Populated automatically when а `SessionRunner` is spawned и
    /// auto-cleared via `SwapRegistryGuard::drop` at session exit, so
    /// accept-side lookups на а dead session fail fast.
    pub swap_registry: Arc<SessionSwapRegistry>,

    /// stage (b): session_id → HandoffAck nonce-sender map.
    /// Warm-probe tasks register here before sending `HandoffInit`;
    /// runners look up на incoming `HandoffAck` и forward the nonce.
    pub ack_waiters: Arc<HandoffAckWaiters>,

    /// stage (c): auto-swap controller (alt_uri map + flap damping).
    pub controller: Arc<HotStandbyController>,

    /// stage (c): consecutive write-error threshold for auto-swap.
    /// Sourced от `config.hot_standby.auto_trigger_after_write_errors`.
    /// Pure value — included в the bundle because it's the same
    /// configuration domain (hot-standby) and bundling avoids а
    /// five-vs-four asymmetry that would force callsites к read
    /// the `u32` separately.
    pub auto_trigger_after_write_errors: u32,
}

impl HandoffRuntime {
    pub fn new(
        registry: Arc<HandoffRegistry>,
        swap_registry: Arc<SessionSwapRegistry>,
        ack_waiters: Arc<HandoffAckWaiters>,
        controller: Arc<HotStandbyController>,
        auto_trigger_after_write_errors: u32,
    ) -> Self {
        Self {
            registry,
            swap_registry,
            ack_waiters,
            controller,
            auto_trigger_after_write_errors,
        }
    }
}
