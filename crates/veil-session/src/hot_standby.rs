//! Hot-standby auto-trigger controller).
//!
//! Owned by [`super::NodeRuntime`]. The session runner calls
//! [`HotStandbyController::try_auto_trigger`] when it observes enough
//! consecutive write errors on the primary transport to suggest the
//! pipe is failing. The controller:
//!
//! 1. Checks whether the peer has an `alt_uri` registered (populated
//!    [`veil_cfg::PeerConfig::alt_uri`] at runtime init). No
//!    alt_uri → no swap; fall back to legacy reconnect-with-handshake.
//! 2. Applies flap damping: at most
//!    [`veil_cfg::HotStandbyConfig::max_swaps_per_minute`] successful
//!    auto-swaps per peer within a rolling 60-second window.
//! 3. Spawns a one-shot [`crate::warm_probe::WarmProbe`]
//!    to dial the alt_uri and run the three-frame handoff protocol
//!    from stage (d). The spawn is fire-and-forget — the runner
//!    doesn't block waiting for the swap to complete; if the swap
//!    succeeds the runner's `swap_rx` will pick up the new transport
//!    at the next `await_next_input` tick.
//!
//! The manual admin command (stage (b) B5) also runs through the same
//! probe code path but drives `initiate_handoff` synchronously for a
//! clean operator-facing result. This controller is the *asynchronous*
//! entry point for runner-driven triggers.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use crate::SessionTxRegistry;
use crate::handoff::{HandoffAckWaiters, SessionSwapRegistry};
use crate::warm_probe::{WarmProbeConfig, spawn_warm_probe};
use veil_cfg::HotStandbyConfig;
use veil_cfg::NodeId;
use veil_transport::{TransportContext, TransportRegistry, TransportUri};
use veil_types::NodeIdBytes;

pub struct HotStandbyController {
    /// Per-peer alt transport URI, populated from config at startup.
    /// When a peer is not present (or its value is `None`) the
    /// controller refuses to auto-trigger for that peer.
    alt_uris: Mutex<HashMap<NodeIdBytes, String>>,
    /// Per-peer alt transport URI auto-discovered from the peer's
    /// advertised listener set at handshake time.
    /// Consulted by `alt_uri_for` only when the operator-configured
    /// `alt_uris` map has no entry for the peer — explicit config
    /// always wins. Learned values survive until a fresh handshake
    /// replaces them.
    auto_alt_uris: Mutex<HashMap<NodeIdBytes, String>>,
    /// Per-peer ring of swap-attempt timestamps used for flap damping.
    /// Entries older than 60 seconds are pruned on every read.
    swap_history: Mutex<HashMap<NodeIdBytes, VecDeque<Instant>>>,
    transport_registry: Arc<TransportRegistry>,
    transport_ctx: Arc<TransportContext>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    handoff_ack_waiters: Arc<HandoffAckWaiters>,
    swap_registry: Arc<SessionSwapRegistry>,
    hot_standby: HotStandbyConfig,
    /// Logger — owned by `NodeLogger` (Arc-wrapped). Used only for
    /// info/warn lines so the logger trait's dynamic dispatch cost is
    /// incurred only on auto-trigger events.
    logger: Arc<veil_observability::NodeLogger>,
}

impl HotStandbyController {
    /// Rolling window for flap damping. Picked to match the
    /// `max_swaps_per_minute` semantics [`HotStandbyConfig`].
    pub const FLAP_WINDOW: Duration = Duration::from_secs(60);

    /// Cap on distinct peers tracked in `swap_history`. Past this, a single GC
    /// sweep drops peers whose flap window has fully aged out, so a churn of
    /// one-shot swappers can't grow the map unboundedly (the per-peer prune only
    /// runs when that peer is revisited). (audit cycle-3.)
    const MAX_TRACKED_SWAP_PEERS: usize = 4096;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport_registry: Arc<TransportRegistry>,
        transport_ctx: Arc<TransportContext>,
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        handoff_ack_waiters: Arc<HandoffAckWaiters>,
        swap_registry: Arc<SessionSwapRegistry>,
        hot_standby: HotStandbyConfig,
        logger: Arc<veil_observability::NodeLogger>,
    ) -> Self {
        Self {
            alt_uris: Mutex::new(HashMap::new()),
            auto_alt_uris: Mutex::new(HashMap::new()),
            swap_history: Mutex::new(HashMap::new()),
            transport_registry,
            transport_ctx,
            session_tx_registry,
            handoff_ack_waiters,
            swap_registry,
            hot_standby,
            logger,
        }
    }

    /// Master switch (`[hot_standby] enabled`). When `false`, the runner
    /// suppresses automatic warm-probe triggers (rotation / write-error /
    /// stall / keepalive). The accept side (responding to a peer-driven
    /// handoff) and the manual `node swap-transport` admin command are
    /// unaffected — only auto-initiation consults this flag.
    pub fn enabled(&self) -> bool {
        self.hot_standby.enabled
    }

    /// Populate/replace the alt_uri entry for a peer. Called at
    /// runtime init for every `PeerConfig` with `alt_uri.is_some`
    /// and by `config reload` handlers when peer records change.
    pub fn set_alt_uri(&self, peer_id: NodeId, uri: String) {
        self.alt_uris
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*peer_id.as_bytes(), uri);
    }

    /// Remove a peer's alt_uri — e.g. after config reload dropped the
    /// field. Returns the old value for logging. audit
    /// cleanup: only test-side caller exists today; if
    /// reload-pipeline ever wires this, drop the cfg + add the call
    /// site in the same commit so production-compile signal goes live.
    pub fn clear_alt_uri(&self, peer_id: &NodeId) -> Option<String> {
        self.alt_uris
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(peer_id.as_bytes())
    }

    pub fn alt_uri_for(&self, peer_id: &NodeId) -> Option<String> {
        if let Some(v) = self
            .alt_uris
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(peer_id.as_bytes())
            .cloned()
        {
            return Some(v);
        }
        // Fall back to the auto-discovered entry.
        self.auto_alt_uris
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(peer_id.as_bytes())
            .cloned()
    }

    /// stage c.3: record an auto-discovered alt URI from the
    /// peer's advertised transports (received via the AttachPayload TLV).
    /// Picks the first advertised transport that is not byte-identical
    /// to `primary_uri`. This is intentionally permissive: operators
    /// who stand up two TCP listeners on different ports (or the same
    /// scheme on different hosts) clearly want failover between them
    /// so we accept both same-scheme-different-port and cross-scheme
    /// alternates. The only case we reject is the primary URI itself
    /// since swapping to that is a no-op.
    ///
    /// Parses every candidate through `TransportUri::parse` and skips
    /// malformed entries to stop a misbehaving peer from planting junk
    /// in the map. On success the entry is inserted into `auto_alt_uris`
    /// — `alt_uri_for` will fall back to it when no operator-configured
    /// alt URI exists. Returns the chosen URI for observability.
    pub fn auto_set_alt_uri_from_transports(
        &self,
        peer_id: NodeId,
        transports: &[String],
        primary_uri: &str,
    ) -> Option<String> {
        for candidate in transports {
            let Ok(uri) = TransportUri::parse(candidate) else {
                continue;
            };
            if candidate == primary_uri {
                continue;
            }
            // Skip transports this node can't actually dial as a client.
            // Otherwise hot-standby auto-swap picks an alt it will only fail
            // to reach — e.g. a peer's `webtunnel-wss` endpoint when we have
            // no local `webtunnel_secret_path` — wasting the rotation and
            // logging a `swap_failed`.
            if !self.local_can_dial(&uri) {
                continue;
            }
            self.auto_alt_uris
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(*peer_id.as_bytes(), candidate.clone());
            return Some(candidate.clone());
        }
        None
    }

    /// Whether this node can dial `uri` as a client given its local transport
    /// config. Used to filter hot-standby alt-URI candidates so auto-swap
    /// never selects a transport the dial would reject outright. Currently the
    /// only constraint is `webtunnel-wss`, whose client side needs a locally
    /// configured `webtunnel_secret_path` (see veil-transport's webtunnel
    /// dialer); without it the dial fails immediately.
    fn local_can_dial(&self, uri: &TransportUri) -> bool {
        if matches!(uri, TransportUri::WebtunnelWss { .. })
            && self.transport_ctx.webtunnel_secret_path.is_none()
        {
            return false;
        }
        true
    }

    /// Observability hook: how many swap attempts have been registered
    /// for `peer_id` inside the current flap-damping window.
    /// audit cleanup: all callers live in `runner.rs`
    /// `#[cfg(test)]` — production code observes attempts only via the
    /// internal `swap_history` map. When a metrics counter wires this
    /// in, drop the cfg AND add the wire-up in the same commit so the
    /// production-compile signal goes live, not silently dead.
    pub fn swap_attempts_in_window(&self, peer_id: &NodeId) -> usize {
        let now = Instant::now();
        self.swap_history
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(peer_id.as_bytes())
            .map(|q| {
                q.iter()
                    .filter(|&&t| now.duration_since(t) <= Self::FLAP_WINDOW)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Check whether a fresh swap for `peer_id` would fit inside the
    /// flap-damping budget. On `true` the attempt is also *recorded*
    /// — the caller should only tell the controller "yes, go" once
    /// so this method has a side effect by design. Returns the
    /// current count within the window for logging.
    fn register_swap_attempt(&self, peer_id: &NodeId) -> Option<usize> {
        let now = Instant::now();
        let mut history = self.swap_history.lock().unwrap_or_else(|p| p.into_inner());
        // Opportunistic GC: when the map grows past the cap, prune every peer's
        // window and drop those that have fully aged out, bounding memory under
        // one-shot-swapper churn (the per-peer prune below only runs for the
        // peer being revisited).
        if history.len() > Self::MAX_TRACKED_SWAP_PEERS {
            history.retain(|_, dq| {
                while dq.front().is_some_and(|&t| now.duration_since(t) > Self::FLAP_WINDOW) {
                    dq.pop_front();
                }
                !dq.is_empty()
            });
        }
        let entry = history.entry(*peer_id.as_bytes()).or_default();
        // Prune entries older than the flap window.
        while let Some(&t) = entry.front() {
            if now.duration_since(t) > Self::FLAP_WINDOW {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= self.hot_standby.max_swaps_per_minute as usize {
            return None;
        }
        entry.push_back(now);
        Some(entry.len())
    }

    /// Runner-facing entry point. Called when the session has observed
    /// enough consecutive write errors on the primary transport to
    /// warrant an auto-swap. Returns `true` iff a warm-probe task was
    /// spawned; `false` means either no alt_uri is known, or flap
    /// damping rejected the attempt, or the alt_uri failed URI parsing.
    ///
    /// Non-blocking: the probe runs in the background and drops itself
    /// after one handoff attempt. Completion (or failure) is observable
    /// in logs: `session.hot_standby.auto_swap_complete` /
    /// `session.hot_standby.auto_swap_failed`.
    pub fn try_auto_trigger(
        &self,
        peer_id: NodeId,
        session_id: [u8; 32],
        tx_key: [u8; 32],
    ) -> bool {
        let Some(uri_str) = self.alt_uri_for(&peer_id) else {
            return false;
        };
        self.spawn_handoff_probe(peer_id, session_id, tx_key, uri_str, "auto_swap")
    }

    /// Rotation-trigger entry point (Q.7 audit batch).  Called when
    /// the session's lifetime deadline expires and we want to make-before-
    /// break swap to a fresh underlying TCP+TLS connection (defeats DPI
    /// flow-lifetime fingerprinting).
    ///
    /// Prefers `alt_uri_for(peer_id)` if registered — gives true
    /// transport-diversity (e.g. swap from webtunnel-wss to obfs4-tcp).
    /// Falls back to the caller-supplied `primary_uri` for **same-URI
    /// rotation**: the probe dials a new TCP+TLS connection to the same
    /// host:port the session is currently on.  From DPI's view, the old
    /// flow ends + a new HTTPS handshake starts to the same server —
    /// indistinguishable from a browser tab being closed and a new one
    /// opened to the same site.  The session keys + AEAD counter survive
    /// intact (see `warm_probe.rs` doc on 3-frame handoff protocol),
    /// so app traffic flows continuously across the swap.
    ///
    /// Same non-blocking + flap-damping semantics as `try_auto_trigger`.
    pub fn try_rotation_trigger(
        &self,
        peer_id: NodeId,
        primary_uri: &str,
        session_id: [u8; 32],
        tx_key: [u8; 32],
    ) -> bool {
        // Prefer alt_uri when available — true transport-diversity
        // beats same-URI rotation for anti-DPI even though both
        // achieve TCP-level rotation.
        let uri_str = self
            .alt_uri_for(&peer_id)
            .unwrap_or_else(|| primary_uri.to_string());
        self.spawn_handoff_probe(peer_id, session_id, tx_key, uri_str, "rotation")
    }

    /// Internal helper: validate URI, register swap attempt with flap
    /// damping, spawn a warm probe and one-shot handoff task.  Shared
    /// by `try_auto_trigger` (failure-driven) and `try_rotation_trigger`
    /// (timer-driven) — they only differ in how the URI is chosen.
    fn spawn_handoff_probe(
        &self,
        peer_id: NodeId,
        session_id: [u8; 32],
        tx_key: [u8; 32],
        uri_str: String,
        kind: &'static str,
    ) -> bool {
        let alt_uri = match TransportUri::parse(&uri_str) {
            Ok(u) => u,
            Err(e) => {
                self.logger.warn(
                    "session.hot_standby.bad_alt_uri",
                    format!(
                        "peer={} uri={uri_str:?} err={e}",
                        veil_util::hex_short(peer_id.as_bytes())
                    ),
                );
                return false;
            }
        };
        let Some(swap_count) = self.register_swap_attempt(&peer_id) else {
            self.logger.warn(
                "session.hot_standby.flap_damped",
                format!(
                    "peer={} — {} swaps within the last minute, deferring",
                    veil_util::hex_short(peer_id.as_bytes()),
                    self.hot_standby.max_swaps_per_minute
                ),
            );
            return false;
        };

        self.logger.info(
            "session.hot_standby.swap_trigger",
            format!(
                "peer={} kind={kind} uri={uri_str} swap_count_in_window={swap_count}",
                veil_util::hex_short(peer_id.as_bytes())
            ),
        );

        let cfg = WarmProbeConfig {
            session_id,
            peer_id,
            tx_key,
            alt_uri,
            transport_registry: Arc::clone(&self.transport_registry),
            transport_ctx: Arc::clone(&self.transport_ctx),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            handoff_ack_waiters: Arc::clone(&self.handoff_ack_waiters),
            swap_registry: Arc::clone(&self.swap_registry),
            hot_standby: self.hot_standby.clone(),
        };
        let logger = Arc::clone(&self.logger);
        let handle = spawn_warm_probe(cfg);
        tokio::spawn(async move {
            match handle.initiate_handoff().await {
                Ok(()) => logger.info(
                    "session.hot_standby.swap_complete",
                    format!(
                        "peer={} kind={kind}",
                        veil_util::hex_short(peer_id.as_bytes())
                    ),
                ),
                Err(e) => logger.warn(
                    "session.hot_standby.swap_failed",
                    format!(
                        "peer={} kind={kind} error={e}",
                        veil_util::hex_short(peer_id.as_bytes())
                    ),
                ),
            }
        });
        true
    }
}

impl std::fmt::Debug for HotStandbyController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let uri_count = self
            .alt_uris
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        f.debug_struct("HotStandbyController")
            .field("alt_uri_count", &uri_count)
            .field(
                "max_swaps_per_minute",
                &self.hot_standby.max_swaps_per_minute,
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal fixture: a controller without real transport plumbing is
    // enough to exercise alt_uri set/get + flap-damping. For try_auto_trigger
    // integration we rely on warm_probe's own tests to prove the probe
    // spawn path works.

    fn test_controller(max_swaps: u32) -> HotStandbyController {
        HotStandbyController::new(
            Arc::new(TransportRegistry::with_defaults()),
            Arc::new(TransportContext::for_debug().expect("debug ctx")),
            Arc::new(RwLock::new(SessionTxRegistry::new())),
            Arc::new(HandoffAckWaiters::new()),
            Arc::new(SessionSwapRegistry::new()),
            HotStandbyConfig {
                max_swaps_per_minute: max_swaps,
                ..HotStandbyConfig::default()
            },
            Arc::new(veil_observability::NodeLogger::new_noop()),
        )
    }

    #[test]
    fn enabled_reflects_config() {
        // test_controller builds with HotStandbyConfig::default() → enabled=false.
        assert!(!test_controller(4).enabled());
        let on = HotStandbyController::new(
            Arc::new(TransportRegistry::with_defaults()),
            Arc::new(TransportContext::for_debug().expect("debug ctx")),
            Arc::new(RwLock::new(SessionTxRegistry::new())),
            Arc::new(HandoffAckWaiters::new()),
            Arc::new(SessionSwapRegistry::new()),
            HotStandbyConfig {
                enabled: true,
                ..HotStandbyConfig::default()
            },
            Arc::new(veil_observability::NodeLogger::new_noop()),
        );
        assert!(on.enabled());
    }

    #[test]
    fn auto_fire_gated_by_enabled_and_reason() {
        use crate::runner::hot_standby_should_auto_fire;
        // Master switch off → never fire, whatever the reason.
        for r in ["rotation_deadline", "rx_stall", "primary_closed"] {
            assert!(!hot_standby_should_auto_fire(false, r));
        }
        // Enabled + any reason except `primary_closed` → fire. `writer_closed`
        // and the write-error reasons stay eligible (the half-dead
        // "outbound blocked, inbound alive" case hot-standby rescues).
        for r in [
            "rotation_deadline",
            "rx_stall",
            "write_error_threshold",
            "keepalive_probe_timeout",
            "writer_closed",
        ] {
            assert!(hot_standby_should_auto_fire(true, r));
        }
        // Enabled but `primary_closed` (read-EOF, peer gone) → suppressed: a
        // handoff over the dead primary is futile; reconnect recovers instead.
        assert!(!hot_standby_should_auto_fire(true, "primary_closed"));
    }

    #[test]
    fn set_and_get_alt_uri_roundtrips() {
        let c = test_controller(4);
        let peer = NodeId::from([0x11u8; 32]);
        assert!(c.alt_uri_for(&peer).is_none());
        c.set_alt_uri(peer, "tls://peer.example:9906".to_owned());
        assert_eq!(
            c.alt_uri_for(&peer).as_deref(),
            Some("tls://peer.example:9906")
        );
    }

    #[test]
    fn clear_alt_uri_removes_entry() {
        let c = test_controller(4);
        let peer = NodeId::from([0x22u8; 32]);
        c.set_alt_uri(peer, "tcp://x:1".to_owned());
        let prev = c.clear_alt_uri(&peer);
        assert_eq!(prev.as_deref(), Some("tcp://x:1"));
        assert!(c.alt_uri_for(&peer).is_none());
    }

    #[test]
    fn flap_damping_caps_swap_attempts() {
        // With max=2, the first two attempts succeed; the third within
        // the same minute must be rejected.
        let c = test_controller(2);
        let peer = NodeId::from([0x33u8; 32]);
        assert_eq!(c.register_swap_attempt(&peer), Some(1));
        assert_eq!(c.register_swap_attempt(&peer), Some(2));
        assert_eq!(
            c.register_swap_attempt(&peer),
            None,
            "third attempt within the window must be flap-damped"
        );
    }

    #[test]
    fn flap_damping_is_per_peer() {
        // A saturated quota on peer A must not affect peer B.
        let c = test_controller(1);
        let a = NodeId::from([0xAAu8; 32]);
        let b = NodeId::from([0xBBu8; 32]);
        assert!(c.register_swap_attempt(&a).is_some());
        assert!(c.register_swap_attempt(&a).is_none(), "A damped");
        assert!(
            c.register_swap_attempt(&b).is_some(),
            "B has independent budget"
        );
    }

    #[test]
    fn auto_set_alt_uri_from_transports_picks_different_scheme() {
        let c = test_controller(4);
        let peer = NodeId::from([0x55u8; 32]);
        // Primary is TCP; peer advertises both TCP (same as primary
        // — skip) and TLS (different — pick).
        let advertised = [
            "tcp://10.0.0.5:9100".to_owned(),
            "tls://10.0.0.5:9200".to_owned(),
        ];
        let picked = c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://10.0.0.5:9100");
        assert_eq!(picked.as_deref(), Some("tls://10.0.0.5:9200"));
        assert_eq!(
            c.alt_uri_for(&peer).as_deref(),
            Some("tls://10.0.0.5:9200"),
            "alt_uri_for must fall back to the auto-discovered entry"
        );
    }

    #[test]
    fn auto_set_alt_uri_picks_same_scheme_different_port() {
        // Operator stood up two TCP listeners — failover between ports
        // must work. The only URI we reject is the primary itself.
        let c = test_controller(4);
        let peer = NodeId::from([0x56u8; 32]);
        let advertised = [
            "tcp://10.0.0.5:9310".to_owned(), // same as primary
            "tcp://10.0.0.5:9311".to_owned(), // different port — pick
        ];
        let picked = c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://10.0.0.5:9310");
        assert_eq!(picked.as_deref(), Some("tcp://10.0.0.5:9311"));
    }

    #[test]
    fn auto_set_alt_uri_returns_none_when_only_primary_uri() {
        // Peer's advertised list contains only the URI we're already
        // using — nothing to fail over to.
        let c = test_controller(4);
        let peer = NodeId::from([0x66u8; 32]);
        let advertised = ["tcp://10.0.0.5:9310".to_owned()];
        assert!(
            c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://10.0.0.5:9310")
                .is_none()
        );
        assert!(c.alt_uri_for(&peer).is_none());
    }

    #[test]
    fn auto_set_alt_uri_skips_undialable_webtunnel() {
        // The test controller's TransportContext has no `webtunnel_secret_path`,
        // so this node can't dial a peer's webtunnel-wss endpoint. Auto-
        // discovery must skip it and pick a dialable alt instead of selecting a
        // swap target the dial would reject.
        let c = test_controller(4);
        let peer = NodeId::from([0x77u8; 32]);
        let advertised = [
            "webtunnel-wss://10.0.0.5:8443".to_owned(), // undialable here — skip
            "tls://10.0.0.5:9200".to_owned(),           // dialable — pick
        ];
        let picked = c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://10.0.0.5:9000");
        assert_eq!(picked.as_deref(), Some("tls://10.0.0.5:9200"));
    }

    #[test]
    fn auto_set_alt_uri_none_when_only_undialable_webtunnel() {
        // If the only alt is an undialable webtunnel-wss, return None rather
        // than a swap target that would fail.
        let c = test_controller(4);
        let peer = NodeId::from([0x78u8; 32]);
        let advertised = ["webtunnel-wss://10.0.0.5:8443".to_owned()];
        assert!(
            c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://10.0.0.5:9000")
                .is_none()
        );
    }

    #[test]
    fn auto_set_alt_uri_skips_malformed_entries() {
        let c = test_controller(4);
        let peer = NodeId::from([0x77u8; 32]);
        let advertised = ["::::not-a-uri".to_owned(), "tls://good:9000".to_owned()];
        let picked = c.auto_set_alt_uri_from_transports(peer, &advertised, "tcp://primary:1");
        assert_eq!(picked.as_deref(), Some("tls://good:9000"));
    }

    #[test]
    fn manual_alt_uri_takes_precedence_over_auto() {
        let c = test_controller(4);
        let peer = NodeId::from([0x88u8; 32]);
        c.auto_set_alt_uri_from_transports(peer, &["tls://auto:1".to_owned()], "tcp://primary:1");
        c.set_alt_uri(peer, "tls://manual:2".to_owned());
        assert_eq!(
            c.alt_uri_for(&peer).as_deref(),
            Some("tls://manual:2"),
            "operator config must override auto-discovery"
        );
    }

    #[test]
    fn try_auto_trigger_without_alt_uri_returns_false() {
        // Empty alt_uris map → no known target → returns false without
        // spawning anything. Safe to call in non-tokio context since
        // the early return happens before `tokio::spawn`.
        let c = test_controller(4);
        let peer = NodeId::from([0x44u8; 32]);
        let ok = c.try_auto_trigger(peer, [0u8; 32], [0u8; 32]);
        assert!(!ok);
    }

    // ── Q.7 audit batch: try_rotation_trigger ─────────────────────
    //
    // The rotation trigger differs from try_auto_trigger in that it
    // accepts a `primary_uri` fallback — when no alt_uri is set, it
    // dials the SAME URI the session is currently on (same-URI
    // rotation).  Tests below cover that fallback + the alt_uri
    // precedence.  We need a tokio runtime for these because the
    // spawn_handoff_probe path enters `tokio::spawn` once URI parsing
    // and flap damping succeed.

    #[tokio::test]
    async fn try_rotation_trigger_uses_alt_uri_when_set() {
        let c = test_controller(4);
        let peer = NodeId::from([0x77u8; 32]);
        c.set_alt_uri(peer, "tcp://10.1.1.1:9000".to_owned());
        // alt_uri takes precedence over the primary_uri fallback.
        let ok = c.try_rotation_trigger(peer, "tcp://10.2.2.2:9000", [0u8; 32], [0u8; 32]);
        assert!(ok, "must spawn a probe when alt_uri OR primary_uri parses");
    }

    #[tokio::test]
    async fn try_rotation_trigger_falls_back_to_primary_uri() {
        // No alt_uri registered → fall back to primary_uri (same-URI
        // rotation).  This is the main Q.7 codepath since most peers
        // don't configure a separate alt_uri.
        let c = test_controller(4);
        let peer = NodeId::from([0x88u8; 32]);
        assert!(c.alt_uri_for(&peer).is_none());
        let ok = c.try_rotation_trigger(peer, "tcp://10.3.3.3:9000", [0u8; 32], [0u8; 32]);
        assert!(ok, "must spawn a probe via primary_uri fallback");
    }

    #[tokio::test]
    async fn try_rotation_trigger_rejects_malformed_primary_uri() {
        // Bad URI → URI parse fails → returns false without spawning.
        let c = test_controller(4);
        let peer = NodeId::from([0x99u8; 32]);
        let ok = c.try_rotation_trigger(peer, "not a valid uri at all", [0u8; 32], [0u8; 32]);
        assert!(!ok);
    }
}
