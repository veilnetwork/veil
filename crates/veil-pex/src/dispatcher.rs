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
    walk_rate: Mutex<HashMap<[u8; 32], Instant>>,
    /// Channel to forward Challenge/Result events to the PEX initiator task.
    event_tx: tokio::sync::mpsc::Sender<PexEvent>,
    logger: Arc<dyn PexLogger>,
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
        known_peers: &[(PexPeer, Instant)],
    ) -> PexDispatchOutcome {
        let msg = match PexMsg::try_from(msg_type) {
            Ok(m) => m,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
        match msg {
            PexMsg::Walk => self.handle_walk(body, peer_id, broadcaster),
            PexMsg::Challenge => self.handle_challenge_incoming(body, peer_id),
            PexMsg::Response => self.handle_response(body, peer_id, advertise_uris, known_peers),
            PexMsg::Result => self.handle_result(body, peer_id),
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

        // Learn the walk's ORIGIN as a dialable contact (if it advertised an
        // address and it isn't us). Every node a walk traverses thus records
        // the origin → an under-connected / keyspace-isolated origin (which
        // peers would otherwise never learn an address for, leaving it stuck on
        // outbound-only sessions) becomes discoverable cluster-wide and the mesh
        // fills. Rate-limited above (1 walk/peer/min). The initiator validates
        // the node_id↔pubkey binding and drops wildcard addresses before dialing
        // (same path as `Result` peers), so a spoofed `origin_transport` at most
        // wastes one dial.
        if !walk.origin_transport.is_empty() && walk.origin_node_id != self.local_node_id {
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
            return self.emit_challenge(&walk, peer_id, broadcaster);
        }

        // Forward the walk to the peer closest to target.
        if let Some(b) = broadcaster {
            let mut forwarded = walk.clone();
            forwarded.ttl = forwarded.ttl.saturating_sub(1);
            let frame = encode_pex_frame(PexMsg::Walk, &forwarded.encode());
            let active = b.active_node_ids();
            let exclude = [peer_id, walk.origin_node_id];
            if let Some(next_hop) = find_closest_peer(&active, &walk.target_node_id, &exclude) {
                b.send_to(&next_hop, TrafficClass::Background as u8, frame);
            }
        }
        PexDispatchOutcome::NoResponse
    }

    fn emit_challenge(
        &self,
        walk: &PexWalk,
        _peer_id: [u8; 32],
        broadcaster: Option<&dyn FrameBroadcaster>,
    ) -> PexDispatchOutcome {
        let origin_difficulty = compute_origin_difficulty(walk);
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

        // Send challenge back to origin via the session to the forwarding peer.
        if let Some(b) = broadcaster {
            let frame = encode_pex_frame(PexMsg::Challenge, &challenge.encode());
            b.send_to(&walk.origin_node_id, TrafficClass::Interactive as u8, frame);
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

    fn handle_challenge_incoming(&self, body: &[u8], peer_id: [u8; 32]) -> PexDispatchOutcome {
        let challenge = match PexChallenge::decode(body) {
            Ok(c) => c,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
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
        _peer_id: [u8; 32],
        advertise_uris: &[String],
        known_peers: &[(PexPeer, Instant)],
    ) -> PexDispatchOutcome {
        let response = match PexResponse::decode(body) {
            Ok(r) => r,
            Err(e) => return PexDispatchOutcome::Violation(format!("bad PexResponse: {e}")),
        };

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
        for (peer, _) in known_peers {
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
        };

        // Send result back to origin.
        PexDispatchOutcome::Response(encode_pex_frame(PexMsg::Result, &result.encode()))
    }

    fn handle_result(&self, body: &[u8], peer_id: [u8; 32]) -> PexDispatchOutcome {
        let result = match PexResult::decode(body) {
            Ok(r) => r,
            Err(_) => return PexDispatchOutcome::NoResponse,
        };
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
    let b64 = base64::engine::general_purpose::STANDARD;
    let pubkey_b64 = b64.encode(&walk.origin_pubkey);
    let algo = if walk.origin_pubkey.len() == 32 {
        SignatureAlgorithm::Ed25519
    } else {
        SignatureAlgorithm::Falcon512
    };
    let msg = [
        response.walk_id.to_be_bytes().as_slice(),
        response.challenge_nonce.as_slice(),
        response.pow_solution.as_slice(),
    ]
    .concat();
    veil_crypto::signature::verify_message(algo, &pubkey_b64, &msg, &response.origin_sig).is_ok()
}
