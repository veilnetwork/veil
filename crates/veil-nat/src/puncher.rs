//! UDP hole punching.
//!
//! ## Protocol
//!
//! 1. Alice sends `NAT_PROBE_REQUEST` (with her candidates) through the veil
//!    signalling channel to Bob. Core relays it.
//! 2. Bob receives the request, sends back `NAT_PROBE_REPLY` (with his candidates).
//! 3. Both sides call [`NatPuncher::punch`] simultaneously: each side fires UDP
//!    probe packets at all of the peer's candidates. When the peer's NAT sees
//!    an outbound packet to Alice, it creates a pin-hole; Alice's subsequent
//!    packet arrives and the QUIC handshake begins.
//! 4. The first successful `quinn::Connection` is returned as [`PunchResult::Direct`].
//! 5. If the deadline expires, the caller should invoke relay fallback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use veil_proto::budget::MAX_HOLE_PUNCH_CANDIDATES;
use veil_proto::control::candidate_type;
use veil_proto::{NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload};

use super::discovery::{candidate_to_socket_addr, socket_addr_to_candidate};

// ── CandidateList ─────────────────────────────────────────────────────────────

/// Builder for a prioritised list [`NatCandidate`]s.
///
/// Priority values follow RFC 8445 §5.1.2:
/// `priority = (2^24 × type_pref) + (2^8 × local_pref) + (256 − component_id)`
///
/// | Type | type_pref | priority (local_pref=65535, component=1) |
/// |-------|-----------|------------------------------------------|
/// | host | 126 | 2 130 706 431 |
/// | srflx | 100 | 1 694 498 815 |
/// | relay | 0 | 16 777 215 |
pub struct CandidateList {
    inner: Vec<NatCandidate>,
}

impl CandidateList {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Add a host candidate (directly reachable interface address).
    pub fn add_host(&mut self, addr: SocketAddr) {
        let mut c = socket_addr_to_candidate(addr);
        c.candidate_type = candidate_type::HOST;
        c.priority = 2_130_706_431;
        self.inner.push(c);
    }

    /// Add a server-reflexive candidate (external address learned from a STUN echo).
    pub fn add_srflx(&mut self, addr: SocketAddr) {
        let mut c = socket_addr_to_candidate(addr);
        c.candidate_type = candidate_type::SRFLX;
        c.priority = 1_694_498_815;
        self.inner.push(c);
    }

    /// Add a relay candidate (address provided by a relay/TURN node).
    pub fn add_relay(&mut self, addr: SocketAddr) {
        let mut c = socket_addr_to_candidate(addr);
        c.candidate_type = candidate_type::RELAY;
        c.priority = 16_777_215;
        self.inner.push(c);
    }

    /// Return the candidates sorted by descending priority (host first).
    pub fn into_sorted(mut self) -> Vec<NatCandidate> {
        self.inner.sort_by_key(|c| std::cmp::Reverse(c.priority));
        self.inner
    }
}

impl Default for CandidateList {
    fn default() -> Self {
        Self::new()
    }
}

// ── PunchResult ───────────────────────────────────────────────────────────────

/// Outcome of a hole-punch attempt.
#[derive(Debug)]
pub enum PunchResult {
    /// A direct QUIC connection was established.
    Direct(quinn::Connection),
    /// Punching timed out — caller should fall back to relay.
    TimedOut,
}

// ── NatPuncher ────────────────────────────────────────────────────────────────

/// Manages candidate exchange and UDP hole punching for one NAT traversal
/// session.
pub struct NatPuncher {
    local_node_id: [u8; 32],
    session_token: u32,
    /// QUIC endpoint bound to the local NAT-mapped port.
    endpoint: quinn::Endpoint,
    /// Local candidates advertised to the peer.
    local_candidates: Vec<NatCandidate>,
}

impl NatPuncher {
    /// Create a `NatPuncher` wrapping an already-bound `quinn::Endpoint`.
    ///
    /// `local_candidates` should include both the LAN address and the
    /// externally-observed address (from `ExternalAddrDiscovery`).
    pub fn new(
        local_node_id: [u8; 32],
        session_token: u32,
        endpoint: quinn::Endpoint,
        local_candidates: Vec<SocketAddr>,
    ) -> Self {
        Self {
            local_node_id,
            session_token,
            endpoint,
            local_candidates: local_candidates
                .into_iter()
                .map(socket_addr_to_candidate)
                .collect(),
        }
    }

    /// Build a relay-mode `NAT_PROBE_REQUEST` addressed at `target_node_id`.
    ///
    /// when sent through a coordinator, the coordinator
    /// forwards to `target_node_id` over an existing session. Pass
    /// `[0u8; 32]` to fall back to the legacy STUN-echo path (the
    /// coordinator responds locally with its observed srflx address
    /// for THIS sender).
    pub fn build_probe_request(&self, target_node_id: [u8; 32]) -> NatProbeRequestPayload {
        NatProbeRequestPayload {
            initiator_node_id: self.local_node_id,
            target_node_id,
            session_token: self.session_token,
            candidates: self.local_candidates.clone(),
        }
    }

    /// Build the `NAT_PROBE_REPLY` in response to a received request.
    ///
    /// The reply echoes the request's `session_token` so the initiator can
    /// match it. : if the request was relay-forwarded
    /// (`request.target_node_id == self`), the reply must carry the
    /// original initiator's id in `final_target_node_id` so the
    /// coordinator can route it back. For legacy STUN-echo path the
    /// caller passes `[0u8; 32]` (direct response to sender).
    pub fn build_probe_reply(
        responder_node_id: [u8; 32],
        final_target_node_id: [u8; 32],
        request: &NatProbeRequestPayload,
        local_candidates: Vec<SocketAddr>,
    ) -> NatProbeReplyPayload {
        NatProbeReplyPayload {
            responder_node_id,
            final_target_node_id,
            session_token: request.session_token,
            candidates: local_candidates
                .into_iter()
                .map(socket_addr_to_candidate)
                .collect(),
        }
    }

    /// Attempt UDP hole punching against `peer_candidates`.
    ///
    /// Sends a QUIC connect attempt to each candidate concurrently. Returns
    /// the first successful connection, or [`PunchResult::TimedOut`] if none
    /// succeed within `timeout`.
    ///
    /// The `client_config` must be set up to trust the peer's certificate (or
    /// use a shared-trust mechanism like the veil identity handshake).
    pub async fn punch(
        self,
        peer_candidates: &[NatCandidate],
        server_name: &str,
        client_config: quinn::ClientConfig,
        timeout: Duration,
    ) -> PunchResult {
        // cap candidate count to bound work per
        // hole-punch attempt. We sort by priority first, then take only
        // the top `MAX_HOLE_PUNCH_CANDIDATES` — preserves "host first
        // srflx next" semantics while preventing a misbehaving peer
        // (or attacker-controlled response) from forcing an O(N) clone +
        // O(N log N) sort + O(N) task fan-out for an arbitrarily-large N.
        let mut sorted: Vec<NatCandidate> = peer_candidates.to_vec();
        sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));
        sorted.truncate(MAX_HOLE_PUNCH_CANDIDATES);

        let endpoint = Arc::new(self.endpoint);
        let mut tasks = tokio::task::JoinSet::new();

        for candidate in &sorted {
            let Some(addr) = candidate_to_socket_addr(candidate) else {
                continue;
            };
            let ep = Arc::clone(&endpoint);
            let cfg = client_config.clone();
            let sn = server_name.to_string();
            tasks.spawn(async move {
                let connecting = match ep.connect_with(cfg, addr, &sn) {
                    Ok(c) => c,
                    Err(e) => return Err(e.to_string()),
                };
                connecting.await.map_err(|e| e.to_string())
            });
        }

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    tasks.abort_all();
                    return PunchResult::TimedOut;
                }
                result = tasks.join_next() => {
                    match result {
                        None => return PunchResult::TimedOut,
                        Some(Ok(Ok(conn))) => {
                            tasks.abort_all();
                            return PunchResult::Direct(conn);
                        }
                        Some(_) => {} // task error or connection error — try next
                    }
                }
            }
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Set up a QUIC pair for testing hole punch connection (in-process, no NAT).

    async fn make_server_endpoint() -> (quinn::Endpoint, quinn::ClientConfig) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert);
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_crypto.alpn_protocols = vec![b"ovl1".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap(),
        ));

        let server_ep =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

        // Client config trusting the server cert.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"ovl1".to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));

        (server_ep, client_config)
    }

    // ── 32.2: candidate exchange protocol ────────────────────────────────────

    #[test]
    fn probe_request_reply_exchange() {
        let alice_id = [0xAAu8; 32];
        let bob_id = [0xBBu8; 32];
        let token = 0x1234_5678u32;

        let alice_candidate: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        let bob_candidate: SocketAddr = "203.0.113.2:6000".parse().unwrap();

        // Alice builds a request.
        let req = NatProbeRequestPayload {
            initiator_node_id: alice_id,
            target_node_id: bob_id, // relay-mode (legacy: [0u8; 32])
            session_token: token,
            candidates: vec![socket_addr_to_candidate(alice_candidate)],
        };

        // Bob builds a reply. : pass alice_id as
        // final_target so the reply can route back through the
        // coordinator.
        let reply = NatPuncher::build_probe_reply(bob_id, alice_id, &req, vec![bob_candidate]);

        assert_eq!(reply.session_token, token);
        assert_eq!(reply.responder_node_id, bob_id);
        assert_eq!(
            candidate_to_socket_addr(&reply.candidates[0]).unwrap(),
            bob_candidate
        );
    }

    // ── 32.3: punch succeeds in-process (no actual NAT) ──────────────────────

    #[tokio::test]
    async fn punch_succeeds_direct_connection() {
        let (server_ep, client_config) = make_server_endpoint().await;
        let server_addr = server_ep.local_addr().unwrap();

        // Spawn server accept task.
        let server_task =
            tokio::spawn(async move { server_ep.accept().await.unwrap().await.unwrap() });

        // Client endpoint for the "puncher".
        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let puncher = NatPuncher::new([0u8; 32], 42, client_ep, vec![client_ep_addr()]);

        let candidate = NatCandidate {
            atyp: 4,
            candidate_type: veil_proto::control::candidate_type::HOST,
            priority: 2_130_706_431,
            addr: vec![127, 0, 0, 1],
            port: server_addr.port(),
        };

        let result = puncher
            .punch(
                &[candidate],
                "localhost",
                client_config,
                Duration::from_millis(500),
            )
            .await;

        assert!(
            matches!(result, PunchResult::Direct(_)),
            "expected Direct, got TimedOut"
        );
        server_task.await.unwrap();
    }

    // ── 32.5 (simulated): no valid candidates → timeout ──────────────────────

    #[tokio::test]
    async fn punch_times_out_no_reachable_candidates() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();

        // Build a dummy client config (won't actually connect).
        let root_store = rustls::RootCertStore::empty();
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));

        let puncher = NatPuncher::new([0u8; 32], 1, client_ep, vec![]);

        // Port 1 is never open — timeout expected quickly.
        let candidate = NatCandidate {
            atyp: 4,
            candidate_type: veil_proto::control::candidate_type::HOST,
            priority: 2_130_706_431,
            addr: vec![127, 0, 0, 1],
            port: 1,
        };

        let result = puncher
            .punch(
                &[candidate],
                "localhost",
                client_config,
                Duration::from_millis(50),
            )
            .await;

        assert!(matches!(result, PunchResult::TimedOut));
    }

    fn client_ep_addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }
}
