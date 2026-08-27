//! PEX frame dispatcher — handles Walk, Challenge, Response, Result.
//!
//! returns [`PexDispatchOutcome`] instead of veilcore's
//! `DispatchResult`; the central `FrameDispatcher` translates the three
//! variants at the boundary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use veil_proto::{family::PexMsg, header::TrafficClass, pex::*};
use veil_types::{FrameBroadcaster, PexConfig, SignatureAlgorithm};

use crate::{PexDispatchOutcome, PexEvent, PexLogger, encode_pex_frame};

const WALK_RATE_LIMIT_SECS: u64 = 60;
const CHALLENGE_TTL_SECS: u64 = PEX_CHALLENGE_TTL_SECS;
const MAX_ACTIVE_CHALLENGES: usize = 64;

/// Pending challenge awaiting a PoW response.
struct PendingChallenge {
    walk: PexWalk,
    challenge_nonce: [u8; 32],
    difficulty: u8,
    issued_at: Instant,
}

/// PEX dispatcher state, shared across sessions.
pub struct PexDispatcher {
    local_node_id: [u8; 32],
    local_pubkey: Vec<u8>,
    local_nonce: u64,
    local_difficulty: u8,
    max_response_peers: u8,
    pending_challenges: Mutex<HashMap<u64, PendingChallenge>>,
    /// Walks this node FORWARDED, and the two peers each sits between.
    ///
    /// A walk travels away from its origin, but everything that answers it —
    /// the challenge, the solved response, the result — has to travel back
    /// along the same path. Nothing recorded that path, so the terminal node
    /// addressed the ORIGIN directly and a node two hops out has no session
    /// with it: the frame was handed to `send_to`, refused, and dropped in
    /// silence. Multi-hop discovery therefore never completed — only walks
    /// that happened to terminate at a direct neighbour of the origin did
    /// (report14 V14-M11).
    forwarded_walks: Mutex<HashMap<u64, ForwardedWalk>>,
    walk_rate: Mutex<HashMap<[u8; 32], Instant>>,
    /// Channel to forward Challenge/Result events to the PEX initiator task.
    event_tx: tokio::sync::mpsc::Sender<PexEvent>,
    logger: Arc<dyn PexLogger>,
}

/// One walk this node relayed: which way is back, and which way is on.
struct ForwardedWalk {
    /// The hop the walk arrived from — the way back toward the origin.
    prev: [u8; 32],
    /// The hop it was forwarded to — the way on toward the terminal node.
    next: [u8; 32],
    at: Instant,
}

/// Walks this node will remember the path of at once.
///
/// Same shape of bound as `MAX_ACTIVE_CHALLENGES`, and for the same reason:
/// every entry is created by somebody else's traffic. A walk that is not
/// answered inside the challenge TTL is a walk nobody is waiting on.
const MAX_FORWARDED_WALKS: usize = 256;

/// The peers we may hand to a stranger who asks.
///
/// `PexState::discovered_peers` is filled straight from received results —
/// hearsay we have never contacted — and serving it verbatim turns every node
/// into a relay for addresses it cannot reach. A production seed ended up
/// advertising transports on another network's port, which its own PSK can
/// never complete; deleting them by hand brought them back within two hours,
/// because the neighbours were still handing them out.
///
/// A live session is the one claim we can actually make about a peer, and it
/// is also the filter another network can never pass. This is a newtype rather
/// than a filter at the call site so the rule cannot be forgotten: `dispatch`
/// takes nothing else, and the only way to build one is to name the sessions.
/// The walk pool is untouched — this is about what we EMIT.
pub struct VouchedPeers(Vec<PexPeer>);

impl VouchedPeers {
    pub fn from_sessions(
        known: &[(PexPeer, Instant)],
        live: &std::collections::HashSet<[u8; 32]>,
    ) -> Self {
        Self(
            known
                .iter()
                .filter(|(p, _)| live.contains(&p.node_id))
                .map(|(p, _)| p.clone())
                .collect(),
        )
    }

    pub fn as_slice(&self) -> &[PexPeer] {
        &self.0
    }
}

impl PexDispatcher {
    pub fn new(
        local_node_id: [u8; 32],
        local_pubkey: Vec<u8>,
        local_nonce: u64,
        local_difficulty: u8,
        config: &PexConfig,
        event_tx: tokio::sync::mpsc::Sender<PexEvent>,
        logger: Arc<dyn PexLogger>,
    ) -> Self {
        Self {
            local_node_id,
            local_pubkey,
            local_nonce,
            local_difficulty,
            max_response_peers: config.max_response_peers,
            pending_challenges: Mutex::new(HashMap::new()),
            forwarded_walks: Mutex::new(HashMap::new()),
            walk_rate: Mutex::new(HashMap::new()),
            event_tx,
            logger,
        }
    }

    pub fn dispatch(
        &self,
        msg_type: u16,
        body: &[u8],
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
        advertise_uris: &[String],
        known_peers: &VouchedPeers,
    ) -> PexDispatchOutcome {
        let msg = match PexMsg::try_from(msg_type) {
            Ok(m) => m,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
        match msg {
            PexMsg::Walk => self.handle_walk(body, peer_id, broadcaster),
            PexMsg::Challenge => self.handle_challenge_incoming(body, peer_id, broadcaster),
            PexMsg::Response => {
                self.handle_response(body, peer_id, broadcaster, advertise_uris, known_peers)
            }
            PexMsg::Result => self.handle_result(body, peer_id, broadcaster),
        }
    }

    fn handle_walk(
        &self,
        body: &[u8],
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
    ) -> PexDispatchOutcome {
        let walk = match PexWalk::decode(body) {
            Ok(w) => w,
            Err(e) => return PexDispatchOutcome::Violation(format!("bad PexWalk: {e}")),
        };

        // Rate limit: max 1 walk per authenticated peer per minute.
        // Keyed by peer_id (session-authenticated), NOT walk.origin_node_id
        // (attacker-controlled field that could be spoofed to bypass the limit).
        {
            let mut rate = self.walk_rate.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            if let Some(last) = rate.get(&peer_id)
                && now.duration_since(*last).as_secs() < WALK_RATE_LIMIT_SECS
            {
                return PexDispatchOutcome::NoResponse;
            }
            rate.insert(peer_id, now);
            // Evict old entries.
            rate.retain(|_, t| now.duration_since(*t).as_secs() < WALK_RATE_LIMIT_SECS * 2);
        }

        // Authenticate the stamped origin ONCE; gates both the LearnedPeer
        // fan-out below and the PoW-difficulty reduction in `emit_challenge`.
        let origin_authenticated = verify_walk_origin(&walk);

        // Learn the walk's ORIGIN as a dialable contact (if it advertised an
        // address and it isn't us). Every node a walk traverses thus records
        // the origin → an under-connected / keyspace-isolated origin (which
        // peers would otherwise never learn an address for, leaving it stuck on
        // outbound-only sessions) becomes discoverable cluster-wide and the mesh
        // fills. Rate-limited above (1 walk/peer/min). Gated on
        // `origin_authenticated` so a forged/unsigned origin can't inject a
        // spoofed (node_id, transport) contact; the initiator additionally
        // re-checks the binding and drops wildcard addresses before dialing.
        if origin_authenticated
            && !walk.origin_transport.is_empty()
            && walk.origin_node_id != self.local_node_id
        {
            let _ = self.event_tx.try_send(PexEvent::LearnedPeer(PexPeer {
                node_id: walk.origin_node_id,
                transport: walk.origin_transport.clone(),
                public_key: walk.origin_pubkey.clone(),
                nonce: walk.origin_nonce,
            }));
        }

        // Should we terminate the walk here?
        let should_terminate = walk.ttl <= 1
            || xor_distance(&self.local_node_id, &walk.target_node_id)
                < xor_distance(&peer_id, &walk.target_node_id);

        if should_terminate {
            return self.emit_challenge(&walk, peer_id, broadcaster, origin_authenticated);
        }

        // Forward the walk to the peer closest to target.
        if let Some(b) = broadcaster {
            let mut forwarded = walk.clone();
            forwarded.ttl = forwarded.ttl.saturating_sub(1);
            let frame = encode_pex_frame(PexMsg::Walk, &forwarded.encode());
            let active = b.active_node_ids();
            let exclude = [peer_id, walk.origin_node_id];
            if let Some(next_hop) = find_closest_peer(&active, &walk.target_node_id, &exclude)
                && b.send_to(&next_hop, TrafficClass::Background as u8, frame)
            {
                // The path, so the answers can come back along it. Recorded
                // only when the walk actually LEFT: a path to a hop that
                // refused the frame is a path nothing will ever travel.
                self.remember_path(walk.walk_id, peer_id, next_hop);
            }
        }
        PexDispatchOutcome::NoResponse
    }

    /// Remember which way is back and which way is on for a walk we relayed.
    ///
    /// Bounded and aged like the pending-challenge table: every entry is
    /// created by somebody else's traffic, and a walk unanswered inside the
    /// challenge TTL is a walk nobody is waiting on.
    fn remember_path(&self, walk_id: u64, prev: [u8; 32], next: [u8; 32]) {
        let mut paths = self
            .forwarded_walks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        paths.retain(|_, p| now.duration_since(p.at).as_secs() < CHALLENGE_TTL_SECS * 2);
        if paths.len() >= MAX_FORWARDED_WALKS {
            return;
        }
        paths.insert(
            walk_id,
            ForwardedWalk {
                prev,
                next,
                at: now,
            },
        );
    }

    /// Where a frame for `walk_id` goes next, given who it came from.
    ///
    /// `None` means this node is not a relay for that walk — it is the origin,
    /// or the terminal node, or it never saw the walk at all — and the frame is
    /// ours to handle. The direction check is what keeps a frame from being
    /// bounced back where it came from.
    fn relay_hop(&self, walk_id: u64, from: [u8; 32], toward_origin: bool) -> Option<[u8; 32]> {
        let paths = self
            .forwarded_walks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let path = paths.get(&walk_id)?;
        if Instant::now().duration_since(path.at).as_secs() >= CHALLENGE_TTL_SECS * 2 {
            return None;
        }
        if toward_origin {
            (from == path.next).then_some(path.prev)
        } else {
            (from == path.prev).then_some(path.next)
        }
    }

    fn emit_challenge(
        &self,
        walk: &PexWalk,
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
        origin_authenticated: bool,
    ) -> PexDispatchOutcome {
        // Only an AUTHENTICATED origin earns a PoW discount. An unsigned /
        // forged origin gets src_difficulty=0 → the full anti-amplification
        // challenge (no reduction), closing the grind-a-low-difficulty path.
        let origin_difficulty = if origin_authenticated {
            compute_origin_difficulty(walk)
        } else {
            0
        };
        let difficulty = compute_pex_challenge_difficulty(origin_difficulty, self.local_difficulty);

        let mut challenge_nonce = [0u8; 32];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut challenge_nonce);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let challenge = PexChallenge {
            walk_id: walk.walk_id,
            challenge_nonce,
            timestamp,
            difficulty,
        };

        // Store pending challenge.
        {
            let mut pending = self
                .pending_challenges
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            // Evict old challenges.
            let now = Instant::now();
            pending
                .retain(|_, c| now.duration_since(c.issued_at).as_secs() < CHALLENGE_TTL_SECS * 2);
            if pending.len() >= MAX_ACTIVE_CHALLENGES {
                return PexDispatchOutcome::NoResponse;
            }
            pending.insert(
                walk.walk_id,
                PendingChallenge {
                    walk: walk.clone(),
                    challenge_nonce,
                    difficulty,
                    issued_at: now,
                },
            );
        }

        // Toward the origin: directly when we have a session with it, and
        // otherwise BACK ALONG THE PATH the walk came down.
        //
        // Only the direct attempt existed, under a comment claiming it went
        // "via the session to the forwarding peer" — it did not, it named the
        // origin. A terminal node two hops out has no session with the origin,
        // so `send_to` refused and the challenge was dropped in silence
        // (report14 V14-M11). The direct attempt is kept and tried FIRST
        // because it is one hop instead of several, and because a peer running
        // an older build relays nothing.
        if let Some(b) = broadcaster {
            let frame = encode_pex_frame(PexMsg::Challenge, &challenge.encode());
            let direct = b.send_to(
                &walk.origin_node_id,
                TrafficClass::Interactive as u8,
                frame.clone(),
            );
            if !direct && !b.send_to(&peer_id, TrafficClass::Interactive as u8, frame) {
                self.logger.warn(
                    "pex.challenge.undeliverable",
                    &format!(
                        "walk_id={} — no session with the origin and none back \
                         along the path; the walk ends here",
                        walk.walk_id
                    ),
                );
            }
        }

        self.logger.info(
            "pex.challenge.sent",
            &format!(
                "walk_id={} origin={:02x}{:02x}{:02x}{:02x} difficulty={}",
                walk.walk_id,
                walk.origin_node_id[0],
                walk.origin_node_id[1],
                walk.origin_node_id[2],
                walk.origin_node_id[3],
                difficulty
            ),
        );

        PexDispatchOutcome::NoResponse
    }

    fn handle_challenge_incoming(
        &self,
        body: &[u8],
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
    ) -> PexDispatchOutcome {
        let challenge = match PexChallenge::decode(body) {
            Ok(c) => c,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
        // A walk WE relayed: this challenge is not ours to answer, it is ours
        // to pass back toward the origin (report14 V14-M11).
        if let Some(hop) = self.relay_hop(challenge.walk_id, peer_id, true)
            && let Some(b) = broadcaster
        {
            let frame = encode_pex_frame(PexMsg::Challenge, &challenge.encode());
            b.send_to(&hop, TrafficClass::Interactive as u8, frame);
            return PexDispatchOutcome::NoResponse;
        }
        // Forward to the PEX initiator task for PoW solving.
        let _ = self.event_tx.try_send(PexEvent::Challenge {
            challenge,
            from_peer: peer_id,
        });
        PexDispatchOutcome::NoResponse
    }

    fn handle_response(
        &self,
        body: &[u8],
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
        advertise_uris: &[String],
        known_peers: &VouchedPeers,
    ) -> PexDispatchOutcome {
        let response = match PexResponse::decode(body) {
            Ok(r) => r,
            Err(e) => return PexDispatchOutcome::Violation(format!("bad PexResponse: {e}")),
        };
        // Travelling the other way: a solved response for a walk WE relayed
        // belongs to the node that challenged, further along.
        if let Some(hop) = self.relay_hop(response.walk_id, peer_id, false)
            && let Some(b) = broadcaster
        {
            let frame = encode_pex_frame(PexMsg::Response, &response.encode());
            b.send_to(&hop, TrafficClass::Interactive as u8, frame);
            return PexDispatchOutcome::NoResponse;
        }

        // Look up pending challenge.
        let pending = {
            let mut map = self
                .pending_challenges
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.remove(&response.walk_id)
        };
        let Some(pending) = pending else {
            return PexDispatchOutcome::NoResponse;
        };

        // Verify freshness.
        if pending.issued_at.elapsed().as_secs() > CHALLENGE_TTL_SECS {
            return PexDispatchOutcome::NoResponse;
        }

        // Verify PoW.
        if !verify_pex_pow(&response, &pending.challenge_nonce, pending.difficulty) {
            self.logger
                .warn("pex.pow.invalid", &format!("walk_id={}", response.walk_id));
            return PexDispatchOutcome::NoResponse;
        }

        // Verify origin signature.
        if !verify_origin_sig(&pending.walk, &response) {
            self.logger
                .warn("pex.sig.invalid", &format!("walk_id={}", response.walk_id));
            return PexDispatchOutcome::NoResponse;
        }

        self.logger.info(
            "pex.verified",
            &format!("walk_id={} sending peers", response.walk_id),
        );

        // Build peer list from our known connections.
        let mut peers: Vec<PexPeer> = Vec::new();

        // Add ourselves if we have public URIs.
        for uri in advertise_uris {
            if peers.len() >= self.max_response_peers as usize {
                break;
            }
            peers.push(PexPeer {
                node_id: self.local_node_id,
                transport: uri.clone(),
                public_key: self.local_pubkey.clone(),
                nonce: self.local_nonce,
            });
        }

        // Add known peers.
        for peer in known_peers.as_slice() {
            if peers.len() >= self.max_response_peers as usize {
                break;
            }
            if peer.node_id == pending.walk.origin_node_id {
                continue;
            }
            peers.push(peer.clone());
        }

        let result = PexResult {
            walk_id: response.walk_id,
            peers,
            // Echoed from the WALK this node terminated. Only a node that read
            // the walk knows it; the relay in between sees the walk_id and
            // could compose a Result, but not this (report16 V16-M3).
            //
            // Zeros when the walk carried none — an origin too old to mint
            // one — and zeros are never proof of anything on the other side.
            walk_nonce: pending.walk.walk_nonce,
        };

        // Send result back to origin.
        PexDispatchOutcome::Response(encode_pex_frame(PexMsg::Result, &result.encode()))
    }

    fn handle_result(
        &self,
        body: &[u8],
        peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
    ) -> PexDispatchOutcome {
        let result = match PexResult::decode(body) {
            Ok(r) => r,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
        // The last leg of the same round trip: a result for a walk WE relayed
        // is the origin's, not ours, and absorbing it here is how a relay
        // quietly ate the answer to somebody else's walk (report14 V14-M11).
        if let Some(hop) = self.relay_hop(result.walk_id, peer_id, true)
            && let Some(b) = broadcaster
        {
            let frame = encode_pex_frame(PexMsg::Result, &result.encode());
            b.send_to(&hop, TrafficClass::Interactive as u8, frame);
            return PexDispatchOutcome::NoResponse;
        }
        // Forward to the PEX initiator task for peer connection.
        let _ = self.event_tx.try_send(PexEvent::Result {
            result,
            from_peer: peer_id,
        });
        PexDispatchOutcome::NoResponse
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn find_closest_peer(
    active: &[[u8; 32]],
    target: &[u8; 32],
    exclude: &[[u8; 32]],
) -> Option<[u8; 32]> {
    active
        .iter()
        .copied()
        .filter(|id| !exclude.contains(id))
        .min_by_key(|id| xor_distance(id, target))
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

fn compute_origin_difficulty(walk: &PexWalk) -> u8 {
    let hash = blake3::hash(
        &[
            walk.origin_pubkey.as_slice(),
            &walk.origin_nonce.to_le_bytes(),
        ]
        .concat(),
    );
    veil_util::leading_zero_bits(hash.as_bytes()).min(255) as u8
}

/// Authenticate a walk's stamped origin before we trust ANY origin-derived
/// field (the PoW-difficulty reduction in `compute_origin_difficulty`, and the
/// `LearnedPeer` fan-out).
///
/// Check one — node_id ↔ pubkey binding: `BLAKE3(origin_pubkey) ==
/// origin_node_id` (same rule as `pex_binding_ok`), so a forged pubkey can't
/// impersonate another node's identity to grind a low difficulty.
///
/// Check two — `origin_sig` is a valid Ed25519 signature over
/// `signable_bytes()` (`walk_id ‖ target_node_id`), proving the origin
/// actually issued this walk rather than a third party replaying/forging it.
///
/// PEX is Ed25519-only (the initiator disables walks for non-Ed25519 nodes),
/// so a 32-byte pubkey is required; unsigned / forged / mis-bound origins are
/// rejected. Without this, an attacker could forge `origin_pubkey` /
/// `origin_nonce` with many leading-zero bits to lower the anti-amplification
/// PoW the terminating node charges, and inject spoofed `LearnedPeer` contacts.
fn verify_walk_origin(walk: &PexWalk) -> bool {
    use base64::Engine as _;
    // Ed25519 only — origin_sig is a fixed [u8; 64].
    if walk.origin_pubkey.len() != 32 {
        return false;
    }
    if *blake3::hash(&walk.origin_pubkey).as_bytes() != walk.origin_node_id {
        return false;
    }
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&walk.origin_pubkey);
    veil_crypto::signature::verify_message(
        SignatureAlgorithm::Ed25519,
        &pubkey_b64,
        &walk.signable_bytes(),
        &walk.origin_sig,
    )
    .is_ok()
}

fn verify_pex_pow(
    response: &PexResponse,
    server_challenge_nonce: &[u8; 32],
    difficulty: u8,
) -> bool {
    // Verify against the SERVER-issued nonce, not the client-supplied one.
    // Using response.challenge_nonce would allow the client to pre-compute
    // a solution for any nonce they choose, bypassing the PoW challenge.
    let hash_input = [
        server_challenge_nonce.as_slice(),
        response.pow_solution.as_slice(),
    ]
    .concat();
    let hash = blake3::hash(&hash_input);
    veil_util::leading_zero_bits(hash.as_bytes()) >= difficulty as u32
}

fn verify_origin_sig(walk: &PexWalk, response: &PexResponse) -> bool {
    use base64::Engine as _;
    // PEX is Ed25519-only: `origin_sig` is a fixed `[u8; 64]` (Falcon-512 sigs
    // are ~660 B and can't be carried), and the initiator disables walks for
    // non-Ed25519 nodes. Hard-require a 32-byte pubkey rather than silently
    // dispatching to an unreachable Falcon-512 branch that could never verify.
    if walk.origin_pubkey.len() != 32 {
        return false;
    }
    let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&walk.origin_pubkey);
    let msg = [
        response.walk_id.to_be_bytes().as_slice(),
        response.challenge_nonce.as_slice(),
        response.pow_solution.as_slice(),
    ]
    .concat();
    veil_crypto::signature::verify_message(
        SignatureAlgorithm::Ed25519,
        &pubkey_b64,
        &msg,
        &response.origin_sig,
    )
    .is_ok()
}

#[cfg(test)]
mod walk_origin_auth_tests {
    use super::*;
    use base64::Engine as _;
    use veil_crypto::generate_keypair;

    fn signed_walk(walk_id: u64, target: [u8; 32]) -> PexWalk {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let pubkey_raw = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        let origin_node_id = *blake3::hash(&pubkey_raw).as_bytes();
        let mut w = PexWalk {
            walk_id,
            target_node_id: target,
            origin_node_id,
            origin_pubkey: pubkey_raw,
            origin_nonce: 7,
            origin_sig: [0u8; 64],
            ttl: 5,
            origin_transport: "obfs4-tcp://1.2.3.4:5556".to_string(),
            walk_nonce: [0u8; 32],
        };
        let sig = veil_crypto::signature::sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &w.signable_bytes(),
        )
        .unwrap();
        w.origin_sig.copy_from_slice(&sig);
        w
    }

    #[test]
    fn accepts_valid_signed_walk() {
        assert!(verify_walk_origin(&signed_walk(0xABCD, [0x11; 32])));
    }

    #[test]
    fn rejects_unsigned_origin() {
        let mut w = signed_walk(0xABCD, [0x11; 32]);
        w.origin_sig = [0u8; 64];
        assert!(!verify_walk_origin(&w));
    }

    #[test]
    fn rejects_forged_node_id_binding() {
        // pubkey no longer hashes to origin_node_id → grind-a-low-difficulty
        // / impersonation attempt is rejected before any signature work.
        let mut w = signed_walk(0xABCD, [0x11; 32]);
        w.origin_node_id = [0xFF; 32];
        assert!(!verify_walk_origin(&w));
    }

    #[test]
    fn rejects_tampered_target() {
        // signature was over the original (walk_id ‖ target); mutating target
        // after signing must break verification.
        let mut w = signed_walk(0xABCD, [0x11; 32]);
        w.target_node_id = [0x22; 32];
        assert!(!verify_walk_origin(&w));
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let mut w = signed_walk(0xABCD, [0x11; 32]);
        w.origin_pubkey.truncate(16);
        assert!(!verify_walk_origin(&w));
    }

    fn pex_peer(id: u8, transport: &str) -> PexPeer {
        PexPeer {
            node_id: [id; 32],
            transport: transport.to_owned(),
            public_key: vec![id; 32],
            nonce: 0,
        }
    }

    /// We pass on peers, not rumours.
    ///
    /// `discovered_peers` is whatever the last result told us, contacted or
    /// not. A production seed served transports on another network's port from
    /// that pool — its own PSK can never complete them — and the entries
    /// returned within two hours of being deleted, because the neighbours kept
    /// handing them out.
    ///
    /// Break-check: make `from_sessions` ignore `live` and the rumour is
    /// served.
    #[test]
    fn a_peer_we_never_reached_is_not_passed_on() {
        let known = vec![
            (
                pex_peer(0x11, "obfs4-tcp://198.51.100.11:5556"),
                Instant::now(),
            ),
            (
                pex_peer(0x22, "obfs4-tcp://198.51.100.11:5557"),
                Instant::now(),
            ),
        ];
        let live: std::collections::HashSet<[u8; 32]> = [[0x11u8; 32]].into_iter().collect();

        let vouched = VouchedPeers::from_sessions(&known, &live);

        let served: Vec<&str> = vouched
            .as_slice()
            .iter()
            .map(|p| p.transport.as_str())
            .collect();
        assert_eq!(
            served,
            vec!["obfs4-tcp://198.51.100.11:5556"],
            "only the peer we hold a session with may be handed on"
        );
    }

    /// No session, nothing to say — an empty answer beats a wrong one.
    #[test]
    fn a_node_with_no_sessions_vouches_for_nobody() {
        let known = vec![(
            pex_peer(0x33, "obfs4-tcp://198.51.100.7:5556"),
            Instant::now(),
        )];
        let vouched = VouchedPeers::from_sessions(&known, &Default::default());
        assert!(
            vouched.as_slice().is_empty(),
            "a node that has reached nobody cannot vouch for anybody"
        );
    }
}

#[cfg(test)]
mod reverse_path_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    const ORIGIN: [u8; 32] = [0x01; 32];
    const RELAY: [u8; 32] = [0x02; 32];
    const TERMINAL: [u8; 32] = [0x03; 32];

    /// One frame the wire carried: to whom, of what kind, and its payload.
    type SentFrame = ([u8; 32], u16, Vec<u8>);

    #[derive(Default)]
    struct Wire {
        sent: StdMutex<Vec<([u8; 32], u16)>>,
        /// The frames themselves, for a test that needs what was SAID and not
        /// only that something was. Kept beside `sent` rather than replacing
        /// it, so the tests that only ask "which kinds went where" stay as
        /// they read.
        bodies: StdMutex<Vec<SentFrame>>,
        /// Peers this node has a session with. A `send_to` to anybody else
        /// fails, which is the whole shape of the finding: the terminal node
        /// has no session with the origin.
        reachable: Vec<[u8; 32]>,
    }

    impl Wire {
        fn with(reachable: Vec<[u8; 32]>) -> Self {
            Self {
                sent: StdMutex::new(Vec::new()),
                bodies: StdMutex::new(Vec::new()),
                reachable,
            }
        }

        /// The payload of the first frame of `kind` sent to `peer`.
        fn body_of(&self, peer: [u8; 32], kind: u16) -> Option<Vec<u8>> {
            self.bodies
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .find(|(p, k, _)| *p == peer && *k == kind)
                .map(|(_, _, body)| body.clone())
        }
        fn to(&self, peer: [u8; 32]) -> Vec<u16> {
            self.sent
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|(p, _)| *p == peer)
                .map(|(_, m)| *m)
                .collect()
        }
    }

    impl FrameBroadcaster for Wire {
        fn send_to(&self, peer_id: &[u8; 32], _priority: u8, bytes: Vec<u8>) -> bool {
            if !self.reachable.contains(peer_id) {
                return false;
            }
            // The frame's msg_type through the real decoder: reading it out of
            // the header by hand gave 19505 — two bytes of the magic — and a
            // test that compares the wrong number is a test about nothing.
            let msg = veil_proto::codec::decode_header(&bytes)
                .map(|h| h.msg_type)
                .unwrap_or(u16::MAX);
            self.sent
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((*peer_id, msg));
            // The payload is everything after the fixed header.
            let body = bytes
                .get(veil_proto::HEADER_SIZE..)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            self.bodies
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((*peer_id, msg, body));
            true
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.reachable.clone()
        }
    }

    struct Quiet;
    impl PexLogger for Quiet {
        fn info(&self, _event: &str, _message: &str) {}
        fn warn(&self, _event: &str, _message: &str) {}
    }

    fn dispatcher(local: [u8; 32]) -> (PexDispatcher, tokio::sync::mpsc::Receiver<PexEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let cfg = veil_types::PexConfig::default();
        (
            PexDispatcher::new(local, vec![0u8; 32], 0, 0, &cfg, tx, Arc::new(Quiet)),
            rx,
        )
    }

    fn walk_with_nonce(walk_id: u64, ttl: u8, target: [u8; 32], nonce: [u8; 32]) -> PexWalk {
        PexWalk {
            walk_nonce: nonce,
            ..walk(walk_id, ttl, target)
        }
    }

    fn walk(walk_id: u64, ttl: u8, target: [u8; 32]) -> PexWalk {
        PexWalk {
            walk_id,
            target_node_id: target,
            origin_node_id: ORIGIN,
            origin_pubkey: vec![0u8; 32],
            origin_nonce: 0,
            origin_sig: [0u8; 64],
            ttl,
            origin_transport: String::new(),
            walk_nonce: [0u8; 32],
        }
    }

    /// Everything a walk provokes has to come back along the path the walk
    /// took. Nothing recorded that path: the terminal node addressed the
    /// ORIGIN, which a node two hops out has no session with, so the frame was
    /// refused and dropped in silence — and multi-hop discovery never
    /// completed (report14 V14-M11).
    #[test]
    fn a_relayed_walk_carries_its_answers_back_along_the_path() {
        let (relay, _rx) = dispatcher(RELAY);
        // The relay talks to the origin and to the terminal node; the two ends
        // do not talk to each other.
        let wire = Wire::with(vec![ORIGIN, TERMINAL]);
        let known = VouchedPeers::from_sessions(&[], &Default::default());

        // The target is the origin's own key-space neighbourhood, so the relay
        // is NOT closer to it than the sender and the walk is forwarded rather
        // than terminated here. `should_terminate` is that comparison, and a
        // target picked without checking it makes this test about termination
        // instead.
        let w = walk(77, 6, ORIGIN);
        relay.dispatch(
            PexMsg::Walk as u16,
            &w.encode(),
            ORIGIN,
            Some(&wire),
            &[],
            &known,
        );
        assert_eq!(
            wire.to(TERMINAL),
            vec![PexMsg::Walk as u16],
            "the fixture did not forward the walk, so there is no path to test"
        );

        // The terminal node challenges. It reaches the relay, not the origin.
        let challenge = PexChallenge {
            walk_id: 77,
            challenge_nonce: [9u8; 32],
            timestamp: 0,
            difficulty: 1,
        };
        relay.dispatch(
            PexMsg::Challenge as u16,
            &challenge.encode(),
            TERMINAL,
            Some(&wire),
            &[],
            &known,
        );
        assert!(
            wire.to(ORIGIN).contains(&(PexMsg::Challenge as u16)),
            "the challenge stopped at the relay; the origin is still waiting"
        );

        // A frame arriving from the WRONG side is not bounced back.
        let before = wire.to(TERMINAL).len();
        relay.dispatch(
            PexMsg::Challenge as u16,
            &challenge.encode(),
            ORIGIN,
            Some(&wire),
            &[],
            &known,
        );
        assert_eq!(
            wire.to(TERMINAL).len(),
            before,
            "a challenge from the origin's side is not the relay's to pass on"
        );
    }

    /// The terminal node's own half: with no session to the origin, the
    /// challenge goes back to the peer that handed it the walk.
    #[test]
    fn a_terminal_node_challenges_back_along_the_walk() {
        let (terminal, _rx) = dispatcher(TERMINAL);
        // Only the relay is reachable — exactly the case that used to drop the
        // challenge on the floor.
        let wire = Wire::with(vec![RELAY]);
        let known = VouchedPeers::from_sessions(&[], &Default::default());

        // ttl 1 terminates here.
        let w = walk(88, 1, TERMINAL);
        terminal.dispatch(
            PexMsg::Walk as u16,
            &w.encode(),
            RELAY,
            Some(&wire),
            &[],
            &known,
        );

        assert!(
            wire.to(RELAY).contains(&(PexMsg::Challenge as u16)),
            "the challenge was addressed to a node this one cannot reach, so \
             it went nowhere"
        );
    }
    /// The node that TERMINATES a walk echoes its nonce into the Result.
    ///
    /// The origin refuses a Result whose echo is wrong and accepts one with no
    /// echo at all — the rolling-upgrade shape. So a responder that quietly
    /// stopped echoing would look exactly like an old peer, the proof would go
    /// inert, and nothing anywhere would say so: reverting the echo left every
    /// other test in this crate green. This is the one that reddens
    /// (report16 V16-M3).
    ///
    /// Driven the whole way round — walk, challenge, a solved and SIGNED
    /// response, result — because the echo is carried by state the terminal
    /// node keeps between the challenge and the answer, and a test that
    /// short-circuits that carries nothing.
    #[test]
    fn a_terminal_node_echoes_the_walks_nonce_into_its_result() {
        use ed25519_dalek::{Signer, SigningKey};

        const NONCE: [u8; 32] = [0x5C; 32];
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let origin_pubkey = signing.verifying_key().as_bytes().to_vec();

        let (terminal, _rx) = dispatcher(TERMINAL);
        let wire = Wire::with(vec![RELAY]);
        let known = VouchedPeers::from_sessions(&[], &Default::default());

        // ttl 1 terminates here, and the challenge goes back to the relay.
        let mut w = walk_with_nonce(91, 1, TERMINAL, NONCE);
        w.origin_pubkey = origin_pubkey;
        terminal.dispatch(
            PexMsg::Walk as u16,
            &w.encode(),
            RELAY,
            Some(&wire),
            &[],
            &known,
        );

        let challenge_body = wire
            .body_of(RELAY, PexMsg::Challenge as u16)
            .expect("the terminal challenged");
        let challenge =
            veil_proto::pex::PexChallenge::decode(&challenge_body).expect("a challenge");

        // Solved and signed the way the origin does it.
        let solution =
            crate::initiator::solve_pex_pow(&challenge.challenge_nonce, challenge.difficulty)
                .expect("the fixture difficulty is solvable");
        let msg = [
            challenge.walk_id.to_be_bytes().as_slice(),
            challenge.challenge_nonce.as_slice(),
            solution.as_slice(),
        ]
        .concat();
        let response = veil_proto::pex::PexResponse {
            walk_id: challenge.walk_id,
            challenge_nonce: challenge.challenge_nonce,
            pow_solution: solution,
            origin_sig: signing.sign(&msg).to_bytes(),
        };

        let outcome = terminal.dispatch(
            PexMsg::Response as u16,
            &response.encode(),
            RELAY,
            Some(&wire),
            &[],
            &known,
        );

        let body = match outcome {
            PexDispatchOutcome::Response(frame) => frame,
            other => panic!("the terminal did not answer with a Result: {other:?}"),
        };
        let header = veil_proto::codec::decode_header(&body).expect("a pex frame");
        assert_eq!(header.msg_type, PexMsg::Result as u16);
        let result = PexResult::decode(&body[veil_proto::HEADER_SIZE..]).expect("a result");

        assert_eq!(
            result.walk_nonce, NONCE,
            "the far end answered without the proof only it could give"
        );
    }
}
