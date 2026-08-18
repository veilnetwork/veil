//! RAII guard ensuring session teardown invariants run regardless of how
//! the owning struct (`AttachedDebugSession`) is dropped — normal close,
//! panic, or async cancellation.
//!
//! ## Canonical lock-acquisition order
//!
//! All paths that need more than one of these MUST acquire them in this
//! exact order; deviation risks a runtime deadlock under load.
//!
//! 1. `route_cache`                  (RwLock)
//! 2. `live_sessions`                (Mutex)
//! 3. `session_registry`             (Mutex)
//! 4. `session_tx_registry`          (Mutex)
//! 5. `peer_sovereign_identities`    (Mutex)
//! 6. `peer_pubkeys` / `peer_roles`  (LRU caches; per-call lock, never held over await)
//! 7. `sessions_per_ip`              (Mutex)
//! 8. `reputation`                   (Mutex; admin paths)
//!
//! One more edge, outside the numbered chain: the session-resumption
//! `ticket_issuer` mutex is acquired BEFORE `peer_sovereign_identities` (#5),
//! because the issuer's instance oracle reads that map to decide whether an
//! instance-less ticket is ambiguous. Nothing may take them the other way
//! round.
//!
//! `SessionGuard::drop` follows a strict subset:
//! `live_sessions → session_registry → session_tx_registry → sessions_per_ip
//! → reputation`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::watch;
use veil_util::{lock, wlock};

use crate::types::{LinkId, SessionInfo};
use veil_reputation::ReputationTracker;
use veil_session::{SessionRegistry, SessionTxRegistry};

use super::ip_slot::IpSlotTable;
use super::{NodeLogger, NodeMetrics};

/// Per-node-id outbound-connector refresh slots (the map
/// `spawn_outbound_peers` claims from) — aliased for the guard's
/// optional handle below.
pub type ConnectorRefreshMap = Arc<Mutex<std::collections::HashMap<[u8; 32], watch::Sender<u64>>>>;

pub struct SessionGuard {
    live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
    link_id: LinkId,
    logger: Arc<NodeLogger>,
    metrics: Option<Arc<NodeMetrics>>,
    /// OVL1 session_id — always present after a successful OVL1 handshake.
    /// Removed from the `SessionRegistry` on drop.
    session_id: [u8; 32],
    session_registry: Arc<Mutex<SessionRegistry>>,
    /// Source IP address (inbound connections only).  Used to decrement
    /// the per-IP session counter when this session ends.
    source_ip: Option<IpAddr>,
    /// Shared per-IP session counter map.
    sessions_per_ip: Arc<IpSlotTable>,
    /// Peer node_id for reputation tracking on session close. Also the key
    /// under which this session's outbox sender lives in `session_tx_registry`.
    peer_node_id: [u8; 32],
    /// Per-session outbox registry (node_id-keyed). On drop we remove only the
    /// sender whose owner token equals this guard's `session_id`. A reconnect
    /// may already have installed a newer sender under the same stable node id;
    /// owner-aware removal makes late old-runner teardown harmless.
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    /// Shared reputation tracker — `session_closed` called on drop.
    reputation: Option<Arc<Mutex<ReputationTracker>>>,
    /// Shared push-event bus — publish `SESSIONS_CHANGED` on drop so
    /// connected apps see live counts decrement in real time.
    event_bus: Arc<veil_ipc::EventBus>,
    /// P2P mobility slice: per-node-id outbound-connector refresh slots
    /// (same map `spawn_outbound_peers` claims from). On drop, if a
    /// connector loop exists for this peer we bump its refresh
    /// generation — a loop parked in its 30 s `has_session` pre-check
    /// sleep (its session was inbound-owned) re-evaluates IMMEDIATELY
    /// and re-dials, instead of riding out the poll interval while the
    /// peer's `admitted` status sits false. `watch` coalesces repeated
    /// closes into one wake. `None` in unit fixtures.
    connector_refresh: Option<ConnectorRefreshMap>,
}

impl SessionGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
        link_id: LinkId,
        logger: Arc<NodeLogger>,
        metrics: Option<Arc<NodeMetrics>>,
        session_id: [u8; 32],
        session_registry: Arc<Mutex<SessionRegistry>>,
        source_ip: Option<IpAddr>,
        sessions_per_ip: Arc<IpSlotTable>,
        peer_node_id: [u8; 32],
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        reputation: Option<Arc<Mutex<ReputationTracker>>>,
        event_bus: Arc<veil_ipc::EventBus>,
        connector_refresh: Option<ConnectorRefreshMap>,
    ) -> Self {
        Self {
            live_sessions,
            link_id,
            logger,
            metrics,
            session_id,
            session_registry,
            source_ip,
            sessions_per_ip,
            peer_node_id,
            session_tx_registry,
            reputation,
            event_bus,
            connector_refresh,
        }
    }
}

/// Borrowed handles a finished session runner needs to release what it
/// owns. Bundled so [`release_session`] stays under the argument cap.
pub struct SessionRelease<'a> {
    pub session_tx_registry: &'a Arc<RwLock<SessionTxRegistry>>,
    pub session_outbox: &'a Arc<veil_session::SessionOutbox>,
    pub session_close_generations: &'a Arc<Mutex<std::collections::HashMap<[u8; 32], u64>>>,
    pub identity: &'a Arc<super::identity_state::IdentityState>,
    pub dispatcher: &'a Arc<veil_dispatcher::FrameDispatcher>,
    pub logger: &'a Arc<NodeLogger>,
}

/// Compare-and-remove this session's tx registration, and report whether
/// **another** session has taken the peer over.
///
/// Both halves happen under one write lock, so nothing can register
/// between them.
///
/// The answer is deliberately not `!unregister_owned(..)`. That would
/// conflate "someone replaced us" with "our entry was already gone" —
/// and the entry is also gone after `prune_closed` reaps a dead channel
/// or `force_reconnect_all_peers` clears it, with no successor. Reading
/// that as "superseded" would skip the peer-wide teardown for a peer
/// that genuinely has no session left, stranding its ML-KEM key, its
/// reflectors, its rendezvous subscriptions and its routes until the
/// process exits. What matters is not whether we removed anything, but
/// whether anyone still holds the peer afterwards.
pub(crate) fn unregister_and_check_superseded(
    tx_registry: &RwLock<SessionTxRegistry>,
    peer_id: &[u8; 32],
    session_id: &[u8; 32],
) -> bool {
    // Unregister the tx channel BEFORE the caller notifies the
    // dispatcher. The reverse order left a window where dispatcher
    // close-handlers could look up `session_tx_registry` for the closing
    // peer, find a still-live channel, and enqueue frames nobody would
    // ever drain.
    let mut reg = wlock!(tx_registry);
    reg.unregister_owned(peer_id, session_id);
    reg.has_session(peer_id)
}

/// Record that a session runner for `peer_id` exited.
///
/// Never returns to 0 once bumped (`max(1)`), so a handle that sampled
/// the pre-first-close value of 0 still sees a change. The map is
/// cleared wholesale past 4096 distinct peers rather than evicted
/// one-by-one: a forgotten generation reads back as 0, which every
/// sampler treats as "changed", so the failure mode is a spurious
/// rebuild rather than a missed one.
fn bump_close_generation(
    generations: &Mutex<std::collections::HashMap<[u8; 32], u64>>,
    peer_id: &[u8; 32],
) {
    let mut generations = lock!(generations);
    if generations.len() >= 4096 && !generations.contains_key(peer_id) {
        generations.clear();
    }
    let next = generations
        .get(peer_id)
        .copied()
        .unwrap_or(0)
        .wrapping_add(1)
        .max(1);
    generations.insert(*peer_id, next);
}

/// Release everything a finished session runner owns: its own
/// registrations always, the **peer-wide** state only when no other
/// session has taken the peer over.
///
/// ## Why the peer-wide half is conditional
///
/// A session's own registrations are keyed by `session_id`, so removing
/// them is unambiguous. Everything else a session installs is keyed by
/// *peer* — the peer's ML-KEM key and per-session DK, its observed
/// address and UDP reflectors, its relay tunnels, its rendezvous
/// subscriptions, and the routes that run through it. One peer, one set,
/// no matter how many sessions have come and gone.
///
/// That is fine until a peer reconnects. A NAT'd client re-dialing
/// evicts the stale session's tx entry and installs its own
/// (`evict_stale_on_dedup` in `peer_handshake.rs`), and its
/// `on_session_opened` repopulates the peer-wide state. The *old*
/// runner then notices its channel is gone and exits — and its teardown
/// used to run unconditionally, deleting the live session's ML-KEM key,
/// dropping its rendezvous subscriptions and its reflectors, and
/// broadcasting `ROUTE_WITHDRAW` to the whole mesh
/// for a peer that was, at that moment, connected. The peer stayed
/// reachable but unreachable-looking, until something re-announced it.
///
/// So the peer-wide half runs only after a compare-and-remove of the
/// current owner: `unregister_owned` drops the tx entry only if it is
/// still ours, and — under the same lock — a remaining live entry means
/// someone else now owns the peer and everything above is theirs.
///
/// Returns whether the peer-wide state was released.
///
/// **Residual race.** A reconnect that registers after this function
/// releases the registry lock but before `on_session_closed` runs is
/// still torn down. Closing that fully would need a peer-wide lock held
/// across `on_session_closed`, which itself takes the tx-registry write
/// lock to broadcast — a deadlock. The window is microseconds against
/// the whole-runner-lifetime window it replaces.
pub fn release_session(
    h: SessionRelease<'_>,
    peer_id: veil_cfg::NodeId,
    session_id: &[u8; 32],
    was_referral: bool,
) -> bool {
    let superseded =
        unregister_and_check_superseded(h.session_tx_registry, peer_id.as_bytes(), session_id);
    // Owner-checked too, so a newer session's outbox is never removed.
    h.session_outbox.unregister_owned(peer_id, session_id);

    // Bump on EVERY runner exit, superseded or not — and note this is
    // deliberately OUTSIDE the owner check. The consumer is a long-lived
    // circuit handle asking "did the session I built this route on go
    // away", and a replacement is exactly that: the old session's keys
    // are gone, so frames for a circuit pinned to it are undeliverable
    // even though the peer itself is reachable again through the new
    // session. Suppressing the bump on a replacement would leave those
    // handles believing a dead first hop was live.
    bump_close_generation(h.session_close_generations, peer_id.as_bytes());

    if superseded {
        h.logger.debug(
            "session.close.superseded",
            format!(
                "peer={} — a newer session owns this peer; leaving its keys, \
                 reflectors, subscriptions and routes in place",
                veil_util::hex_short(peer_id.as_bytes()),
            ),
        );
        return false;
    }

    // Evict the peer's ML-KEM key and per-session ephemeral DK so stale
    // keys don't persist.
    wlock!(h.identity.peer_mlkem_keys).remove(peer_id.as_bytes());
    lock!(h.identity.per_session_mlkem_dk).remove(peer_id.as_bytes());
    // Now safe to notify the dispatcher: any `session_tx_registry`
    // lookup in the close-handler path returns None.
    h.dispatcher.on_session_closed(peer_id, was_referral);
    true
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Snapshot-then-publish: take each lock briefly to mutate its
        // map, then release before doing observable side-effects
        // (event_bus.publish, reputation notify, log).  Keeps the
        // teardown latency tail bounded: a slow event-bus subscriber or
        // a panic in reputation cannot stall live_sessions /
        // session_registry / sessions_per_ip past the snapshot point.

        // ── state mutations under locks (canonical order) ──────

        // live_sessions: remove this entry and observe the new total for the
        // SESSIONS_CHANGED publish below.
        let new_count = {
            let mut sessions = lock!(self.live_sessions);
            sessions.remove(&self.link_id);
            sessions.len()
        };

        // session_registry: resolve sovereign identity for reputation
        // BEFORE removing the session entry — the registry is the only
        // holder of the peer→identity binding, and the reputation tracker
        // keys on node_id (rotation-stable), not the per-device peer_id.
        // Legacy peers without a sovereign identity fall back to peer_id
        // as a degenerate identifier so legacy reputation behaviour is
        // unchanged.  Single lock acquisition.
        let identity_for_rep = {
            let mut reg = lock!(self.session_registry);
            let id = reg
                .node_id_for_peer(&self.peer_node_id.into())
                .unwrap_or(self.peer_node_id);
            reg.remove(&self.session_id);
            id
        };

        // session_tx_registry: remove THIS session's sender, but never a fresh
        // reconnect that has already replaced it under the same node id.
        // Canonical order slot 4 (after session_registry, before sessions_per_ip).
        wlock!(self.session_tx_registry).unregister_owned(&self.peer_node_id, &self.session_id);

        // sessions_per_ip: decrement counter for inbound connections.
        // Released via IpSlotTable::release which atomically decrements
        // both per_ip and per_subnet maps under one Mutex.
        if let Some(ip) = self.source_ip {
            self.sessions_per_ip.release(ip);
        }

        // ── side-effects (no session-state locks held) ─────────

        if let Some(metrics) = &self.metrics {
            metrics.dec_active_sessions();
        }

        // event_bus.publish is `tokio::sync::broadcast::send` — non-
        // blocking, drops to slow subscribers rather than backpressuring
        // us.  Still, keep it outside the map locks so a subscriber
        // observation re-entering our locks via a handler sees a
        // consistent state.
        let count_u16 = new_count.min(u16::MAX as usize) as u16;
        self.event_bus.publish(veil_proto::EventPayload {
            kind: veil_proto::event_kind::SESSIONS_CHANGED,
            payload: count_u16.to_be_bytes().to_vec(),
        });

        // P2P mobility slice: wake this peer's outbound-connector loop
        // (if one is claimed) so it re-evaluates `has_session` NOW and
        // re-dials immediately — this is the fast half of the
        // "admitted flips false → direct session re-established" loop
        // on the side that did not own the session task. Placed with
        // the side-effects (no session-state locks held).
        if let Some(map) = &self.connector_refresh
            && let Some(tx) = lock!(map).get(&self.peer_node_id)
        {
            tx.send_modify(|generation| *generation = generation.wrapping_add(1));
        }

        // Reputation tracker keys on sovereign node_id (rotation-stable).
        // Last so a panic inside `session_closed` poisons only the
        // reputation mutex, not the more critical state mutexes above.
        if let Some(ref rep) = self.reputation {
            lock!(rep).session_closed(identity_for_rep.into());
        }

        self.logger
            .info("session.close", format!("link_id={}", self.link_id));
    }
}

#[cfg(test)]
mod superseded_tests {
    use super::*;

    const LOCAL: [u8; 32] = [0x10; 32];
    const PEER: [u8; 32] = [0x90; 32];
    const OLD: [u8; 32] = [1; 32];
    const NEW: [u8; 32] = [2; 32];

    fn registry() -> RwLock<SessionTxRegistry> {
        RwLock::new(SessionTxRegistry::new())
    }

    /// The plain close: this session is the only one, so it is not
    /// superseded and its caller goes on to release the peer-wide state.
    #[tokio::test]
    async fn a_lone_session_closing_is_not_superseded() {
        let reg = registry();
        let _rx = wlock!(reg)
            .try_register_directional(PEER, &LOCAL, false, true, false, OLD)
            .expect("first inbound accepted");

        assert!(!unregister_and_check_superseded(&reg, &PEER, &OLD));
        assert!(!wlock!(reg).has_session(&PEER));
    }

    /// The reconnect the finding is about: a learned client re-dials,
    /// evicting the stale session's channel, and the old runner then
    /// exits. Its teardown must report superseded and leave the
    /// replacement — and everything keyed on the peer — alone.
    #[tokio::test]
    async fn a_replaced_session_closing_is_superseded() {
        let reg = registry();
        let mut rx_old = wlock!(reg)
            .try_register_directional(PEER, &LOCAL, false, true, false, OLD)
            .expect("first inbound accepted");
        let _rx_new = wlock!(reg)
            .try_register_directional(PEER, &LOCAL, false, true, true, NEW)
            .expect("learned reconnect evicts the open session");
        // Evicting closed the old channel — this is what makes the stale
        // runner exit and reach its teardown in the first place.
        assert!(matches!(
            rx_old.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));

        assert!(
            unregister_and_check_superseded(&reg, &PEER, &OLD),
            "the replacement owns the peer now"
        );
        assert!(
            wlock!(reg).has_session(&PEER),
            "the late teardown must not unregister the replacement"
        );

        // And when the replacement itself closes, it is the last one out.
        assert!(!unregister_and_check_superseded(&reg, &PEER, &NEW));
        assert!(!wlock!(reg).has_session(&PEER));
    }

    /// The case that separates this predicate from `!unregister_owned(..)`:
    /// the entry is already gone with no successor (`prune_closed`,
    /// `force_reconnect_all_peers`). We removed nothing, yet nobody
    /// replaced us — the peer-wide state is stale and must still be
    /// released.
    #[tokio::test]
    async fn an_already_pruned_entry_is_not_superseded() {
        let reg = registry();
        // Never registered at all — the strongest form of "already gone".
        assert!(!unregister_and_check_superseded(&reg, &PEER, &OLD));

        // And after a registration is dropped by someone else.
        {
            let mut g = wlock!(reg);
            let _rx = g
                .try_register_directional(PEER, &LOCAL, false, true, false, OLD)
                .expect("accepted");
            g.unregister_owned(&PEER, &OLD);
        }
        assert!(!unregister_and_check_superseded(&reg, &PEER, &OLD));
    }

    /// A closed-channel straggler is not a live owner: the peer has no
    /// usable session, so the teardown must proceed rather than defer to
    /// a corpse.
    #[tokio::test]
    async fn a_dead_channel_does_not_count_as_a_successor() {
        let reg = registry();
        {
            // Drop the receiver immediately so the sender is closed.
            let _rx = wlock!(reg)
                .try_register_directional(PEER, &LOCAL, false, true, false, NEW)
                .expect("accepted");
        }
        assert!(
            !unregister_and_check_superseded(&reg, &PEER, &OLD),
            "a closed successor channel must not suppress the teardown"
        );
    }
}

#[cfg(test)]
mod close_generation_tests {
    use super::*;

    const PEER: [u8; 32] = [7; 32];

    /// A handle samples the generation at circuit-open time and compares
    /// later. The first close must therefore move it off its unsampled
    /// value, and every close after that must move it again.
    #[test]
    fn every_close_changes_the_value_a_handle_sampled() {
        let gens = Mutex::new(std::collections::HashMap::new());
        let sampled = lock!(gens).get(&PEER).copied().unwrap_or(0);

        bump_close_generation(&gens, &PEER);
        let after_first = lock!(gens).get(&PEER).copied().unwrap_or(0);
        assert_ne!(after_first, sampled, "first close must be observable");

        bump_close_generation(&gens, &PEER);
        assert_ne!(
            lock!(gens).get(&PEER).copied().unwrap_or(0),
            after_first,
            "a second close must be observable too"
        );
    }

    /// `wrapping_add` would land on 0 exactly once per u64 cycle, and 0 is
    /// the value an absent entry reads back as — a handle comparing
    /// against 0 would then miss that close. `max(1)` skips it.
    #[test]
    fn the_counter_never_lands_on_the_absent_value() {
        let gens = Mutex::new(std::collections::HashMap::new());
        lock!(gens).insert(PEER, u64::MAX);
        bump_close_generation(&gens, &PEER);
        assert_eq!(lock!(gens).get(&PEER).copied(), Some(1));
    }

    /// The map is bounded: a churn of distinct peers cannot grow it
    /// without limit, and the peer being bumped survives the clear.
    #[test]
    fn the_map_stays_bounded_across_peer_churn() {
        let gens = Mutex::new(std::collections::HashMap::new());
        for i in 0..5000u32 {
            let mut peer = [0u8; 32];
            peer[..4].copy_from_slice(&i.to_be_bytes());
            bump_close_generation(&gens, &peer);
        }
        let g = lock!(gens);
        assert!(g.len() <= 4096, "map grew to {}", g.len());
        let mut last = [0u8; 32];
        last[..4].copy_from_slice(&4999u32.to_be_bytes());
        assert_eq!(
            g.get(&last).copied(),
            Some(1),
            "the peer that triggered the clear must still be recorded"
        );
    }
}
