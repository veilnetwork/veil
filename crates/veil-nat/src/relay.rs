//! Relay fallback when hole punching fails.
//!
//! If [`NatPuncher::punch`] returns [`PunchResult::TimedOut`], the initiating
//! node sends `NAT_RELAY_REQUEST` to a core node. The core creates a
//! bidirectional `FORWARD` tunnel between the two leaf nodes; traffic flows
//! through the core's `ForwardPayload` dispatch path.
//!
//! ## Relay decision
//!
//! ```text
//! Alice ---NAT_RELAY_REQUEST--> Core
//! Core ---FORWARD_OPEN------> Alice (token = session_token)
//! Core ---FORWARD_OPEN------> Bob (token = session_token)
//! Alice <---data via FORWARD--> Core <---data via FORWARD---> Bob
//! ```
//!
//! The core node simply forwards `DeliveryMsg::Forward` frames between Alice
//! and Bob keyed by `session_token`.

use veil_proto::NatRelayRequestPayload;

// ── RelayFallback ─────────────────────────────────────────────────────────────

/// How long (in seconds) to wait for a response from the local-mesh relay
/// before falling back to the global Core.
pub const LOCAL_RELAY_TIMEOUT_SECS: u64 = 3;

/// Handles the relay-request side of NAT fallback.
pub struct RelayFallback;

impl RelayFallback {
    /// Build a `NAT_RELAY_REQUEST` payload to send to a core node.
    pub fn build_relay_request(
        node_a: [u8; 32],
        node_b: [u8; 32],
        session_token: u32,
    ) -> NatRelayRequestPayload {
        NatRelayRequestPayload {
            node_a,
            node_b,
            session_token,
        }
    }

    /// Determine whether the core should accept a relay request.
    ///
    /// A core node accepts relay requests from any authenticated peer.
    /// A gateway may also accept them. Leaf nodes must decline.
    pub fn core_should_relay(role: veil_types::NodeRole) -> bool {
        matches!(role, veil_types::NodeRole::Core)
    }

    /// Select the best relay peer for a failed hole-punch.
    ///
    /// Priority order:
    /// 1. `local_relay` — a Gateway discovered via mesh beacon (`IS_RELAY` flag
    ///    set); no internet connectivity required.
    /// 2. `core_peer` — a global Core node reachable over the internet.
    /// 3. `None` — no relay available; caller should return
    ///    `NatError::NoRelayAvailable` and route via mailbox.
    ///
    /// The caller should first attempt `local_relay` and wait up to
    /// [`LOCAL_RELAY_TIMEOUT_SECS`] for a `NAT_RELAY_REQUEST` ack before
    /// retrying with `core_peer`.
    pub fn select_relay_peer(
        local_relay: Option<[u8; 32]>,
        core_peer: Option<[u8; 32]>,
    ) -> Option<[u8; 32]> {
        local_relay.or(core_peer)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use veil_types::NodeRole;

    // ── 32.4: relay request payload roundtrip ────────────────────────────────

    #[test]
    fn relay_request_roundtrip() {
        let req = RelayFallback::build_relay_request([0xAAu8; 32], [0xBBu8; 32], 0xDEAD_BEEF);
        let encoded = req.encode();
        let decoded = NatRelayRequestPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.node_a, [0xAAu8; 32]);
        assert_eq!(decoded.node_b, [0xBBu8; 32]);
        assert_eq!(decoded.session_token, 0xDEAD_BEEF);
    }

    // ── 32.6: only Core should relay ─────────────────────────────────────────

    #[test]
    fn core_should_relay() {
        assert!(RelayFallback::core_should_relay(NodeRole::Core));
    }

    #[test]
    fn leaf_should_not_relay() {
        assert!(!RelayFallback::core_should_relay(NodeRole::Leaf));
    }

    // ── relay peer selection ─────────────────────────────────────

    #[test]
    fn select_relay_peer_prefers_local_over_core() {
        let local = [0xAAu8; 32];
        let core = [0xBBu8; 32];
        assert_eq!(
            RelayFallback::select_relay_peer(Some(local), Some(core)),
            Some(local)
        );
    }

    #[test]
    fn select_relay_peer_falls_back_to_core() {
        let core = [0xBBu8; 32];
        assert_eq!(
            RelayFallback::select_relay_peer(None, Some(core)),
            Some(core)
        );
    }

    #[test]
    fn select_relay_peer_returns_none_when_neither() {
        assert_eq!(RelayFallback::select_relay_peer(None, None), None);
    }

    #[test]
    fn local_relay_timeout_is_3s() {
        assert_eq!(LOCAL_RELAY_TIMEOUT_SECS, 3);
    }

    // ── 32.6: symmetric NAT fallback flow simulation ─────────────────────────
    //
    // Simulates the decision tree: punch attempt times out → relay activated.

    #[tokio::test]
    async fn symmetric_nat_triggers_relay_fallback() {
        use super::super::puncher::{NatPuncher, PunchResult};
        use std::time::Duration;
        use veil_proto::NatCandidate;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Client endpoint — will try to reach an unreachable address.
        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

        // Minimal dummy ClientConfig (no trusted roots → handshake will fail fast).
        let root_store = rustls::RootCertStore::empty();
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));

        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];

        let puncher = NatPuncher::new(alice, 99, client_ep, vec![]);

        // Symmetric NAT: Bob's "candidate" is an unreachable address → timeout.
        let bobs_candidate = NatCandidate {
            atyp: 4,
            candidate_type: veil_proto::control::candidate_type::HOST,
            priority: 2_130_706_431,
            addr: vec![127, 0, 0, 1],
            port: 2, // port 2 is never open
        };

        let result = puncher
            .punch(
                &[bobs_candidate],
                "localhost",
                client_config,
                Duration::from_millis(50),
            )
            .await;

        // Punching timed out → activate relay.
        assert!(matches!(result, PunchResult::TimedOut));

        let relay_req = RelayFallback::build_relay_request(alice, bob, 99);
        assert_eq!(relay_req.node_a, alice);
        assert_eq!(relay_req.node_b, bob);
        assert_eq!(relay_req.session_token, 99);
        assert!(RelayFallback::core_should_relay(NodeRole::Core));
    }
}
