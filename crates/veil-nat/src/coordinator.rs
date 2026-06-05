//! NAT traversal coordinator.
//!
//! [`NatCoordinator`] orchestrates the full NAT traversal state machine for a
//! single peer-to-peer connection attempt:
//!
//! ```text
//! Idle ──► Discovering ──► Exchanging ──► Punching ──► Connected
//! │ ▲
//! └──► Relaying ───┘
//! └──► Failed
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! let mut coord = NatCoordinator::new(config, session_outbox, local_node_id, peer_id);
//! match coord.run.await {
//! NatResult::Direct(conn) => { /* use QUIC connection */ }
//! NatResult::Relay => { /* traffic routed via core */ }
//! NatResult::Failed(msg) => { /* give up */ }
//! }
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use veil_proto::control::NatCandidate;
use veil_types::NatConfig;

use super::puncher::{CandidateList, NatPuncher, PunchResult};

// ── NatState ─────────────────────────────────────────────────────────────────

/// Internal state of the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatState {
    /// Not yet started.
    Idle,
    /// Collecting local candidates (host + srflx via STUN echo).
    Discovering,
    /// Waiting for the peer's `NatProbeReply` carrying their candidates.
    Exchanging,
    /// Concurrently attempting QUIC connects to all peer candidates.
    Punching,
    /// Hole-punch timed out; traffic is routed through a core relay.
    Relaying,
    /// A direct QUIC connection was established.
    Connected,
    /// All attempts exhausted without a usable path.
    Failed,
}

// ── NatResult ────────────────────────────────────────────────────────────────

/// Outcome of a completed [`NatCoordinator::run`] call.
#[derive(Debug)]
pub enum NatResult {
    /// A direct QUIC connection was successfully established.
    Direct(quinn::Connection),
    /// Hole-punch failed; relay tunnel via core is now active.
    Relay,
    /// All traversal strategies failed.
    Failed(String),
}

// ── NatCoordinator ───────────────────────────────────────────────────────────

/// Async state machine for NAT traversal toward a single peer.
pub struct NatCoordinator {
    config: NatConfig,
    local_node_id: [u8; 32],
    session_token: u32,
    state: NatState,
    /// stored so `terminal_result` can surface the original
    /// `fail` message instead of the old lossy "traversal failed"
    /// placeholder. Populated only when `state == Failed`.
    fail_reason: Option<String>,
    /// Optional local-mesh Gateway used as a fallback signaling server when
    /// no global Core is reachable.
    ///
    /// When set, `preferred_signal_peer` returns this node_id instead of the
    /// caller-supplied `core_peer`. This allows an isolated mesh (no internet)
    /// to perform NAT hole-punching through a local Gateway with `IS_RELAY` set.
    pub local_relay: Option<[u8; 32]>,
}

impl NatCoordinator {
    /// Create a new coordinator for the given peer.
    ///
    /// `session_token` is a caller-chosen nonce that ties probe requests to
    /// their replies and the eventual relay tunnel.
    pub fn new(config: NatConfig, local_node_id: [u8; 32], session_token: u32) -> Self {
        Self {
            config,
            local_node_id,
            session_token,
            state: NatState::Idle,
            fail_reason: None,
            local_relay: None,
        }
    }

    /// Set the local-mesh relay Gateway.
    ///
    /// When set, [`preferred_signal_peer`] will return this node_id rather than
    /// the caller-supplied global `core_peer`, allowing NAT traversal in
    /// internet-isolated mesh segments.
    pub fn with_local_relay(mut self, relay: [u8; 32]) -> Self {
        self.local_relay = Some(relay);
        self
    }

    /// Return the preferred signaling peer for this traversal attempt.
    ///
    /// Priority order:
    /// 1. `local_relay` — a nearby Gateway with `IS_RELAY` flag (no internet needed)
    /// 2. `core_peer` — a global Core reachable over the internet
    /// 3. `None` — no signaling server available
    pub fn preferred_signal_peer(&self, core_peer: Option<[u8; 32]>) -> Option<[u8; 32]> {
        self.local_relay.or(core_peer)
    }

    /// Current state of the coordinator.
    pub fn state(&self) -> &NatState {
        &self.state
    }

    /// Build the local candidate list from known local and server-reflexive addresses.
    ///
    /// Callers should populate `host_addrs` with all local interface addresses
    /// and `srflx_addr` with the externally-observed address returned by the core's
    /// `NatProbeReply` (STUN echo).
    pub fn build_candidates(
        host_addrs: &[SocketAddr],
        srflx_addr: Option<SocketAddr>,
        relay_addr: Option<SocketAddr>,
    ) -> Vec<NatCandidate> {
        let mut list = CandidateList::new();
        for &addr in host_addrs {
            list.add_host(addr);
        }
        if let Some(addr) = srflx_addr {
            list.add_srflx(addr);
        }
        if let Some(addr) = relay_addr {
            list.add_relay(addr);
        }
        list.into_sorted()
    }

    /// Attempt hole-punch against `peer_candidates` using the given `endpoint`.
    ///
    /// Transitions the state machine through `Punching → Connected` on success
    /// or `Punching → Relaying` on timeout. Returns the QUIC connection or
    /// `None` if punching timed out (caller should activate relay).
    pub async fn punch(
        &mut self,
        endpoint: quinn::Endpoint,
        peer_candidates: &[NatCandidate],
        server_name: &str,
        client_config: quinn::ClientConfig,
    ) -> Option<quinn::Connection> {
        self.state = NatState::Punching;
        let timeout = Duration::from_millis(self.config.punch_timeout_ms);
        let puncher = NatPuncher::new(self.local_node_id, self.session_token, endpoint, vec![]);
        match puncher
            .punch(peer_candidates, server_name, client_config, timeout)
            .await
        {
            PunchResult::Direct(conn) => {
                self.state = NatState::Connected;
                Some(conn)
            }
            PunchResult::TimedOut => {
                self.state = NatState::Relaying;
                None
            }
        }
    }

    /// Mark the state machine as using the relay path.
    pub fn activate_relay(&mut self) {
        self.state = NatState::Relaying;
    }

    /// Mark the traversal as failed with a diagnostic message.
    pub fn fail(&mut self, reason: impl Into<String>) -> NatResult {
        let reason: String = reason.into();
        self.state = NatState::Failed;
        // retain the message so `terminal_result` can return
        // the actual failure, not the old placeholder "traversal failed".
        self.fail_reason = Some(reason.clone());
        NatResult::Failed(reason)
    }

    /// `true` when the state machine has reached a terminal state
    /// (Connected / Relaying / Failed). Callers can poll this to decide
    /// whether further driving is needed.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            NatState::Connected | NatState::Relaying | NatState::Failed,
        )
    }

    /// the original `fail` reason if the coordinator terminated
    /// in `Failed` state; `None` otherwise (including for non-terminal and
    /// successful states). Prior impl in `result` returned a generic
    /// "traversal failed" string — the real reason is now preserved.
    pub fn fail_reason(&self) -> Option<&str> {
        self.fail_reason.as_deref()
    }

    /// Produce a `NatResult` from terminal states that don't carry a
    /// `quinn::Connection` (Relaying / Failed). Returns `None` for
    /// `Connected` — the caller [`Self::run`] already owns the
    /// connection directly — and for non-terminal states.
    pub fn terminal_result(&self) -> Option<NatResult> {
        match self.state {
            NatState::Relaying => Some(NatResult::Relay),
            NatState::Failed => Some(NatResult::Failed(
                // Prefer the stored reason; fall back only for the
                // degenerate case where `state` was set to Failed
                // without going through `fail`.
                self.fail_reason
                    .clone()
                    .unwrap_or_else(|| "traversal failed".to_owned()),
            )),
            NatState::Connected => None, // caller retains connection
            _ => None,
        }
    }

    /// ICE priority helper: compute RFC 8445 §5.1.2 priority.
    ///
    /// `type_pref`: 126 = host, 100 = srflx, 0 = relay.
    /// `local_pref`: 65535 for a single interface.
    /// `component_id`: 1 for RTP, 2 for RTCP (use 1 for OVL1 data).
    pub fn ice_priority(type_pref: u32, local_pref: u32, component_id: u32) -> u32 {
        // RFC 8445: type_pref is 7 bits (0..=127); local_pref is 16 bits.
        // Use saturating arithmetic to avoid overflow panic in debug builds
        // and silent wraparound in release builds.
        let a = (2u32.pow(24)).saturating_mul(type_pref.min(127));
        let b = (2u32.pow(8)).saturating_mul(local_pref & 0xFFFF);
        let c = 256u32.saturating_sub(component_id);
        a.saturating_add(b).saturating_add(c)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> NatConfig {
        NatConfig {
            enabled: true,
            punch_timeout_ms: 100,
            stun_servers: vec![],
            relay_enabled: true,
        }
    }

    #[test]
    fn initial_state_is_idle() {
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 42);
        assert_eq!(coord.state(), &NatState::Idle);
    }

    #[test]
    fn build_candidates_sorted_by_priority() {
        use std::net::{IpAddr, Ipv4Addr};
        use veil_proto::control::candidate_type;
        let host = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000);
        let srflx = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 7000);
        let relay = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

        let candidates = NatCoordinator::build_candidates(&[host], Some(srflx), Some(relay));
        assert_eq!(candidates.len(), 3);
        // Sorted by descending priority: host > srflx > relay
        assert_eq!(candidates[0].candidate_type, candidate_type::HOST);
        assert_eq!(candidates[1].candidate_type, candidate_type::SRFLX);
        assert_eq!(candidates[2].candidate_type, candidate_type::RELAY);
        assert!(candidates[0].priority > candidates[1].priority);
        assert!(candidates[1].priority > candidates[2].priority);
    }

    #[test]
    fn ice_priority_host_formula() {
        // RFC 8445 §5.1.2: host type_pref=126, local_pref=65535, component=1
        // priority = (2^24 * 126) + (2^8 * 65535) + 255 = 2_130_706_431
        let p = NatCoordinator::ice_priority(126, 65535, 1);
        assert_eq!(p, 2_130_706_431);
    }

    #[test]
    fn ice_priority_srflx_formula() {
        // srflx: type_pref=100 → (2^24 * 100) + (2^8 * 65535) + 255 = 1_694_498_815
        let p = NatCoordinator::ice_priority(100, 65535, 1);
        assert_eq!(p, 1_694_498_815);
    }

    #[test]
    fn activate_relay_transitions_state() {
        let mut coord = NatCoordinator::new(make_config(), [1u8; 32], 0);
        coord.activate_relay();
        assert_eq!(coord.state(), &NatState::Relaying);
        assert!(matches!(coord.terminal_result(), Some(NatResult::Relay)));
        assert!(coord.is_terminal());
        assert!(coord.fail_reason().is_none());
    }

    #[test]
    fn fail_transitions_state() {
        let mut coord = NatCoordinator::new(make_config(), [1u8; 32], 0);
        let r = coord.fail("timeout");
        assert_eq!(coord.state(), &NatState::Failed);
        assert!(matches!(r, NatResult::Failed(_)));
    }

    /// the original fail reason must survive through
    /// `terminal_result` — the prior impl lost it and returned a generic
    /// "traversal failed" placeholder.
    #[test]
    fn terminal_result_preserves_fail_reason() {
        let mut coord = NatCoordinator::new(make_config(), [1u8; 32], 0);
        coord.fail("stun echo timed out after 5s");
        assert_eq!(coord.fail_reason(), Some("stun echo timed out after 5s"));
        assert!(coord.is_terminal());
        match coord.terminal_result() {
            Some(NatResult::Failed(msg)) => {
                assert_eq!(msg, "stun echo timed out after 5s");
            }
            other => panic!("expected Failed with original reason, got {other:?}"),
        }
    }

    #[test]
    fn is_terminal_returns_false_for_intermediate_states() {
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 0);
        assert!(!coord.is_terminal(), "Idle is not terminal");
    }

    // ── local relay preference ───────────────────────────────────

    #[test]
    fn preferred_signal_peer_prefers_local_relay_over_core() {
        let local_relay = [0xAAu8; 32];
        let core_peer = [0xBBu8; 32];
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 1).with_local_relay(local_relay);
        // When both are available, local_relay wins.
        assert_eq!(
            coord.preferred_signal_peer(Some(core_peer)),
            Some(local_relay)
        );
    }

    #[test]
    fn preferred_signal_peer_falls_back_to_core_when_no_relay() {
        let core_peer = [0xBBu8; 32];
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 1);
        // No local_relay set → falls back to Core.
        assert_eq!(
            coord.preferred_signal_peer(Some(core_peer)),
            Some(core_peer)
        );
    }

    #[test]
    fn preferred_signal_peer_returns_none_when_neither_available() {
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 1);
        assert_eq!(coord.preferred_signal_peer(None), None);
    }

    #[test]
    fn with_local_relay_sets_field() {
        let relay = [0xCCu8; 32];
        let coord = NatCoordinator::new(make_config(), [1u8; 32], 0).with_local_relay(relay);
        assert_eq!(coord.local_relay, Some(relay));
    }
}
