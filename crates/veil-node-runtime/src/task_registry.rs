//! Runtime service registry —.
//!
//! Exhaustive enum of every background task that `NodeRuntime` spawns, plus an
//! ordered `ALL` list that both `start` and `apply_reload_after_stop` walk.
//!
//! # Why this exists
//!
//! Before, start-up and reload-up each carried their own explicit
//! list of spawn calls. The reload list drifted out of sync with start-up —
//! six background tasks (IPC server, SOCKS5, exit proxy, discovery initiator
//! pending-ACK ticker, name autoclaim) never respawned after a `node.reload`
//! leaving the daemon silently degraded. See.
//!
//! By routing both flows through `RuntimeService::ALL` + [`NodeRuntime::spawn_service`]
//! the compiler's exhaustive-match check makes forgetting a new service a
//! **compile error**, not a runtime regression.

/// Every background task `NodeRuntime` needs to keep alive during its lifetime.
///
/// Order in `ALL` reflects the startup dependency chain — listeners first so
/// outbound connectors see the bind, persist tasks last so the dht/route
/// snapshots reflect the steady-state caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeService {
    // ── Core transport / session plane ────────────────────────────────────
    Listeners,
    OutboundPeers,
    PinnedRelays,

    // ── Observability / health ────────────────────────────────────────────
    MetricsExporter,
    HealthWatchdog,

    // ── Maintenance / GC ──────────────────────────────────────────────────
    /// periodic runtime-maintenance loop (renamed from
    /// `MailboxCleanup` after the mailbox subsystem was removed).
    /// Drives memory-budget eviction, secondary-cache GC, and
    /// runtime-summary refresh.
    MaintenanceTick,
    PowPendingCleanup,
    GatewayEviction,
    /// Periodic prune of expired `HandoffRegistry` entries. The registry
    /// auto-prunes on `insert`/`consume` but а quiet session may accumulate
    /// stale entries between operations; this background tick guarantees
    /// bounded steady-state memory usage. See `services::spawn_handoff_prune`.
    HandoffPrune,
    /// Periodic prune of closed-channel entries в `SessionTxRegistry`.
    /// Audit batch 2026-05-24 (M4): `prune_closed` previously fired only
    /// on the `&mut self` register/unregister paths.  Pure broadcast
    /// workloads (mesh-hub nodes без new session churn) could accumulate
    /// closed entries indefinitely.  This tick guarantees bounded growth.
    TxRegistryPrune,

    // ── Routing / DHT ─────────────────────────────────────────────────────
    RouteProbe,
    RouteRefresh,
    CongestionWithdraw,
    Mesh,
    DhtRepublish,
    RouteMissHandler,
    Bootstrap,
    /// Partition-recovery watchdog (post-cascade-failure).
    ///
    /// `Bootstrap` is one-shot at startup (bootstrap_only peers
    /// don't reconnect — the connector task terminates when the session
    /// ends). When the cluster fragments at runtime (e.g. 4+ hosts
    /// simultaneously ban the same bootstrap peer), the affected nodes
    /// log `dht.republish.under_count fan-out=0` indefinitely without
    /// ever re-dialing the operator-curated bootstrap list. This
    /// watchdog samples `live_sessions.len` every 30 s and, after a
    /// configurable streak of zero-session ticks (with cool-down between
    /// retries), respawns outbound connectors for `config.bootstrap_peers`.
    BootstrapWatchdog,

    // ── Sovereign identity ──────────────────────────────────
    /// Periodic re-publish of the node's sovereign `IdentityDocument`
    /// to the DHT — keeps the record reachable against TTL expiry.
    /// No-op on nodes without a loaded sovereign identity.
    SovereignIdentityRepublish,

    // ── P-Net (private veil network) ──────────────────────────────────
    /// Periodic poll of the local DHT store для PBAN-prefixed records,
    /// verifying and applying them to the local `BanList`. Spawned only
    /// when `[network].mode = "private"` and the membership cert loads
    /// successfully at startup — public-mode nodes get no-op behaviour.
    PNetBanSync,

    // ── Self-update ──────────────────────────────────
    /// Periodic poll of the operator's signed update-manifest URLs.
    /// No-op when `[update]` config is not opt-in. Emits structured
    /// `update.check.*` log events that GUI wrappers / admin dashboards
    /// can scrape to surface "update available" without polling the
    /// admin socket.
    UpdateCheck,

    // ── Proxy / IPC / discovery ──────────────────────────────────────────
    DiscoveryInitiator,
    Socks5,
    ExitProxy,
    IpcServer,
    PendingAckTick,
    GatewayFailover,
    LazyMiner,
    PexInitiator,

    // ── Persist snapshots (gated on `config.persist_enabled` except
    // RouteCache and Rtt, which only require their own `*_persist_path`) ──
    PersistRouteCache,
    PersistRtt,
    PersistVivaldi,
    PersistDhtRouting,
    PersistDhtValues,
    PersistAutodiscover,
    PersistGatewayList,
    PersistPeerPubkeys,
    ///periodic snapshot of peer transport
    /// announcements to disk so a restart can immediately serve
    /// `ResolveTransport` for previously-handshaked peers.
    PersistTransportAnnouncements,
}

impl RuntimeService {
    /// Ordered list driving both start-up and reload. Adding a new variant
    /// requires adding it here AND handling it in
    /// [`crate::runtime::NodeRuntime::spawn_service`] — otherwise the compiler
    /// will flag the missing match arm.
    pub const ALL: &'static [RuntimeService] = &[
        // Core transport + session plane.
        Self::Listeners,
        Self::OutboundPeers,
        Self::PinnedRelays,
        // Observability.
        Self::MetricsExporter,
        // Maintenance.
        Self::MaintenanceTick,
        Self::PowPendingCleanup,
        Self::GatewayEviction,
        Self::HandoffPrune,
        Self::TxRegistryPrune,
        Self::HealthWatchdog,
        // Routing / DHT.
        Self::RouteProbe,
        Self::RouteRefresh,
        Self::CongestionWithdraw,
        Self::Mesh,
        Self::DhtRepublish,
        Self::RouteMissHandler,
        Self::Bootstrap,
        Self::BootstrapWatchdog,
        Self::SovereignIdentityRepublish,
        Self::PNetBanSync,
        Self::UpdateCheck,
        // Proxy / IPC / discovery.
        Self::DiscoveryInitiator,
        Self::Socks5,
        Self::ExitProxy,
        Self::IpcServer,
        Self::PendingAckTick,
        Self::GatewayFailover,
        Self::LazyMiner,
        Self::PexInitiator,
        // Persist (skipped internally when the relevant config path is unset).
        Self::PersistRouteCache,
        Self::PersistRtt,
        Self::PersistVivaldi,
        Self::PersistDhtRouting,
        Self::PersistDhtValues,
        Self::PersistAutodiscover,
        Self::PersistGatewayList,
        Self::PersistPeerPubkeys,
        Self::PersistTransportAnnouncements,
    ];
}
