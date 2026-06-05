//! IPC → runtime adapter for mobile-lifecycle events.
//!
//! Implements [`veil_ipc::MobileEventSink`] over the runtime's
//! process-global mobile-mode atomic and the gateway-failover notify
//! handle. Constructed in `spawn_ipc_server` and handed to
//! [`veil_ipc::IpcServer::with_mobile_event_sink`].

use std::sync::{Arc, RwLock};

use veil_ipc::{EventBus, MobileEventSink};
use veil_proto::{EventPayload, MobileBackgroundMode, NetworkChangedPayload, event_kind};

use veil_observability::NodeLogger;
use veil_session::SessionTxRegistry;

/// Bridges mobile-lifecycle IPC events to the daemon runtime.
pub struct MobileEventForwarder {
    logger: Arc<NodeLogger>,
    /// Same handle the gateway-failover loop awaits on — we kick it on
    /// `NetworkChanged` so failover tries IMMEDIATELY rather than
    /// waiting for its periodic poll (typically 5-10 s).
    gateway_failover_notify: Arc<tokio::sync::Notify>,
    /// outbound-connector wake handle. Fired alongside
    /// `gateway_failover_notify` on `NetworkChanged` so every reconnect
    /// loop short-circuits its sleep AND tries fresh handshake (with
    /// SESSION_TICKET fast-resume if available).
    force_reconnect_notify: Arc<tokio::sync::Notify>,
    /// registry of active peer sessions. On NetworkChanged
    /// we unregister every entry — drops the sender channel so the
    /// `SessionRunner` exits via channel-closed branch (clean shutdown
    /// of the now-stale TCP) и `has_session` pre-check returns false
    /// for the connector's next iteration.
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    /// Optional push-event bus. When set, we publish
    /// `MOBILE_TIER_CHANGED` events on every background-tier
    /// transition so connected apps can reactively redraw their
    /// "power-saving" UI без polling `GetMobileStatus`.
    event_bus: Option<Arc<EventBus>>,
}

impl MobileEventForwarder {
    pub fn new(
        logger: Arc<NodeLogger>,
        gateway_failover_notify: Arc<tokio::sync::Notify>,
        force_reconnect_notify: Arc<tokio::sync::Notify>,
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    ) -> Self {
        Self {
            logger,
            gateway_failover_notify,
            force_reconnect_notify,
            session_tx_registry,
            event_bus: None,
        }
    }

    /// Attach the push-event bus so tier transitions publish a
    /// `MOBILE_TIER_CHANGED` event.
    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }
}

impl MobileEventSink for MobileEventForwarder {
    fn set_mobile_background_mode(&self, mode: MobileBackgroundMode) {
        // follow-up: 3-tier API directly. Previously this
        // sink mapped the wire enum to a single-bit flag, which lost
        // the Active middle tier. Now the runtime keepalive scaler
        // honours all three tiers + suppresses background maintenance
        // on LowPower.
        let tier = mode.to_wire();
        veil_session::runner::set_mobile_background_tier(tier);
        self.logger.info(
            "ipc.mobile.background_mode",
            format!("mode={:?} tier={}", mode, tier),
        );
        // notify all connected apps that the tier changed.
        // Best-effort — zero subscribers is the steady state and never
        // an error.
        if let Some(bus) = &self.event_bus {
            bus.publish(EventPayload {
                kind: event_kind::MOBILE_TIER_CHANGED,
                payload: vec![tier],
            });
        }
    }

    fn network_changed(&self, payload: NetworkChangedPayload) {
        self.logger.info(
            "ipc.mobile.network_changed",
            format!("kind={:?} mtu_hint={}", payload.kind, payload.mtu_hint),
        );
        // Wake the gateway-failover loop so it retries gateway connect
        // attempts immediately instead of waiting for its periodic poll.
        self.gateway_failover_notify.notify_waiters();
        // full session-teardown + force-reconnect. Walk
        // session_tx_registry, unregister every active peer (drops
        // sender channel → SessionRunner exits cleanly on next select
        // poll → stale TCP closes), then notify every outbound-connector
        // loop to retry IMMEDIATELY на the new local interface.
        // SESSION_TICKET carries fast-resume data so the
        // re-handshake is ~1 RT instead of full Noise + IdentityProof.
        // Recovery latency on WiFi ↔ Cellular flip drops from
        // ~30-90 s (TCP keepalive timeout + 30 s pre-check sleep) к
        // ~1-3 s (new TCP RT + resume RT).
        let count = {
            let mut reg = self
                .session_tx_registry
                .write()
                .unwrap_or_else(|p| p.into_inner());
            let active: Vec<[u8; 32]> = reg.active_node_ids().into_iter().collect();
            for pid in &active {
                reg.unregister(pid);
            }
            active.len()
        };
        if count > 0 {
            self.logger.info(
                "ipc.mobile.network_changed.force_reconnect",
                format!("unregistered={count} (network-change recovery)"),
            );
        }
        self.force_reconnect_notify.notify_waiters();
    }
}
