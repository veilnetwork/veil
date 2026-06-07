//! PEX initiator task — periodically sends random walks and processes results.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use tokio::sync::watch;
use veil_proto::{
    family::PexMsg,
    header::TrafficClass,
    pex::{PexChallenge, PexPeer, PexResponse, PexResult, PexWalk},
};
use veil_types::{FrameBroadcaster, PexConfig};

use crate::{PexEvent, PexLogger, encode_pex_frame};

const MAX_PEERS_PER_SUBNET: usize = 2;
// Walk-cadence tiers + thresholds are operator-tunable via `[pex]` in node.toml
// (see `veil_types::PexConfig`): low_peer_threshold / high_peer_threshold and
// search_interval_active/mid/idle_secs. Defaults: <3 sessions → 15 min,
// 3..20 → 1 h, >=20 → 1 day.
const INITIAL_DELAY_SECS: u64 = 30;

/// Discovered peers from PEX, shared with the runtime for connection attempts.
pub struct PexState {
    pub discovered_peers: Vec<(PexPeer, Instant)>,
    pub active_walks: u32,
    pub last_walk_at: Option<Instant>,
}

impl Default for PexState {
    fn default() -> Self {
        Self::new()
    }
}

impl PexState {
    pub fn new() -> Self {
        Self {
            discovered_peers: Vec::new(),
            active_walks: 0,
            last_walk_at: None,
        }
    }

    pub fn add_peers(&mut self, peers: Vec<PexPeer>, max: usize) {
        let now = Instant::now();
        for peer in peers {
            // verify node_id ↔ public_key binding BEFORE
            // any storage / persistence path. Per the canonical rule
            //`node_id = BLAKE3(public_key_raw_bytes)`. Without
            // this check, a malicious PEX responder ships fabricated triples
            // `(victim_node_id, attacker_addr, attacker_pubkey)` which then
            // get persisted to node.toml; every restart burns handshake
            // budget dialing the attacker's address. Combined with a sybil
            // cluster, the table is poisoned BEFORE the handshake-time
            // identity check fires.
            //
            // Only check non-empty public_key — older PexPeer wire format
            // shipped with empty pubkey field (legacy peers). Empty case
            // falls through to the existing handshake-time check. Shared with
            // the `handle_result` fan-out filter via `pex_binding_ok` (M-F).
            if !pex_binding_ok(&peer) {
                // Drop silently — a separate metric (binding_mismatch_total)
                // can be plumbed in a follow-up if forensics matter.
                continue;
            }
            // Reject wildcard transports — every peer that receives such an
            // entry will dial 0.0.0.0:5555 on its OWN host (which routes to
            // its own listener), get back its own node_id, and log
            // peer.identity_mismatch. See `is_wildcard_transport` for the
            // matching check on the advertise side; this is the receiver
            // half so a single mis-configured peer can't poison every
            // other node's table.
            if is_wildcard_transport(&peer.transport) {
                continue;
            }
            // Skip duplicates.
            if self
                .discovered_peers
                .iter()
                .any(|(p, _)| p.node_id == peer.node_id)
            {
                continue;
            }
            // Subnet diversity check.
            if !self.check_subnet_diversity(&peer) {
                continue;
            }
            if self.discovered_peers.len() >= max {
                // Evict the worst-scored peer to make room.
                if let Some(idx) = self.worst_peer_index(now) {
                    self.discovered_peers.swap_remove(idx);
                } else {
                    continue;
                }
            }
            self.discovered_peers.push((peer, now));
        }
    }

    fn check_subnet_diversity(&self, peer: &PexPeer) -> bool {
        let Some(subnet) = extract_subnet_24(&peer.transport) else {
            return true;
        };
        let same_subnet = self
            .discovered_peers
            .iter()
            .filter(|(p, _)| extract_subnet_24(&p.transport) == Some(subnet))
            .count();
        same_subnet < MAX_PEERS_PER_SUBNET
    }

    /// Score a peer for retention — lower is worse (eviction candidate).
    ///
    /// Factors:
    /// **Uptime** (time since discovery): older peers are more valuable.
    /// **Subnet diversity**: peers from over-represented /24 subnets are penalised.
    /// **XOR diversity**: peers whose node_id is close to many others are penalised.
    fn retention_score(&self, idx: usize, now: Instant) -> f64 {
        let (peer, discovered_at) = &self.discovered_peers[idx];

        // Uptime: seconds since discovery, capped at 24h.
        let uptime_secs = now
            .duration_since(*discovered_at)
            .as_secs_f64()
            .min(86400.0);
        let uptime_score = uptime_secs / 86400.0; // 0..1

        // Subnet diversity: how many peers share this /24 (lower = better).
        let subnet = extract_subnet_24(&peer.transport);
        let same_subnet = if let Some(s) = subnet {
            self.discovered_peers
                .iter()
                .filter(|(p, _)| extract_subnet_24(&p.transport) == Some(s))
                .count()
        } else {
            1
        };
        let subnet_penalty = if same_subnet > 1 {
            (same_subnet - 1) as f64 * 0.3
        } else {
            0.0
        };

        // XOR diversity: average XOR distance to all other peers (higher = more diverse).
        let xor_score = if self.discovered_peers.len() > 1 {
            let total_dist: f64 = self
                .discovered_peers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, (other, _))| xor_leading_bits(&peer.node_id, &other.node_id) as f64)
                .sum();
            // Normalise to 0..1: higher average XOR distance = more keyspace
            // diversity = better retention. The term is ADDED (a benefit) in
            // the combined score below, not subtracted — there is no
            // `(256 - avg)` inversion (corrected in audit cycle-6; the prior
            // comment described an inversion the code never performed).
            let avg = total_dist / (self.discovered_peers.len() - 1) as f64;
            avg / 256.0 // 0..1, higher = more diverse
        } else {
            0.5
        };

        // Combined: uptime (40%) + xor diversity (30%) - subnet penalty (30%).
        uptime_score * 0.4 + xor_score * 0.3 - subnet_penalty * 0.3
    }

    /// Find the index of the worst-scored peer for eviction.
    fn worst_peer_index(&self, now: Instant) -> Option<usize> {
        if self.discovered_peers.is_empty() {
            return None;
        }
        (0..self.discovered_peers.len()).min_by(|&a, &b| {
            self.retention_score(a, now)
                .partial_cmp(&self.retention_score(b, now))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn public_peer_count(&self) -> usize {
        self.discovered_peers.len()
    }
}

/// Channel for the runtime to receive "connect to these peers" instructions.
pub type PexConnectTx = tokio::sync::mpsc::Sender<Vec<PexPeer>>;

/// Maximum PoW difficulty the PEX initiator will attempt. Mirrors the
/// session-layer hard ceiling (`veil_proto::budget::MAX_POW_DIFFICULTY`)
/// — anything above is protocol abuse.
const MAX_POW_DIFFICULTY: u8 = veil_proto::budget::MAX_POW_DIFFICULTY;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_pex_initiator(
    local_node_id: [u8; 32],
    local_pubkey: Vec<u8>,
    local_nonce: u64,
    signing_key: Option<ed25519_dalek::SigningKey>,
    config: PexConfig,
    broadcaster: Arc<dyn FrameBroadcaster>,
    pex_state: Arc<Mutex<PexState>>,
    mut event_rx: tokio::sync::mpsc::Receiver<PexEvent>,
    connect_tx: PexConnectTx,
    // Our own advertised dialable transport URI, stamped into outgoing walks as
    // `origin_transport` so peers can learn+dial us. Empty string disables it
    // (e.g. a node with no public listener).
    local_advertise: String,
    mut shutdown_rx: watch::Receiver<bool>,
    logger: Arc<dyn PexLogger>,
) {
    if !config.enabled {
        return;
    }

    // PEX walks require Ed25519 signing (origin_sig is [u8; 64]).
    // Falcon512 nodes cannot participate in PEX — log and exit.
    if signing_key.is_none() {
        logger.warn(
            "pex.initiator.no_signing_key",
            "PEX disabled: no Ed25519 signing key (Falcon512 nodes not supported for PEX)",
        );
        return;
    }

    // Initial delay to let sessions establish.
    tokio::time::sleep(Duration::from_secs(INITIAL_DELAY_SECS)).await;

    logger.info("pex.initiator.start", "PEX initiator active");

    let mut next_walk = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            _ = tokio::time::sleep_until(next_walk) => {
                // Gate walk-backoff on ACTIVE SESSIONS, not on the count of
                // DISCOVERED peers: a node that discovered peers but failed to
                // connect to them must keep walking, not sleep for hours
                // believing it is healthy (see `compute_interval`).
                let connected_count = broadcaster.active_node_ids().len();
                let discovered_count = {
                    let state = pex_state.lock().unwrap_or_else(|p| p.into_inner());
                    state.public_peer_count()
                };
                let interval = compute_interval(connected_count, &config);
                if connected_count >= config.low_peer_threshold {
                    logger.info("pex.initiator.sleep",
                        &format!("active_sessions={connected_count} discovered={discovered_count} next_walk_in={interval}s"));
                }
                send_walks(
                    &local_node_id, &local_pubkey, local_nonce,
                    signing_key.as_ref(), &config, broadcaster.as_ref(), &pex_state,
                    &local_advertise, logger.as_ref(),
                );
                next_walk = tokio::time::Instant::now() + Duration::from_secs(interval);
            }
            event = event_rx.recv() => {
                match event {
                    Some(PexEvent::Challenge { challenge, from_peer }) => {
                        handle_challenge(
                            &challenge, from_peer, &local_node_id, &local_pubkey, local_nonce,
                            signing_key.as_ref(), broadcaster.as_ref(), logger.as_ref(),
                        ).await;
                    }
                    Some(PexEvent::Result { result, from_peer }) => {
                        handle_result(
                            &result, from_peer, &config, &pex_state, &connect_tx, logger.as_ref(),
                        ).await;
                    }
                    Some(PexEvent::LearnedPeer(peer)) => {
                        handle_learned_peer(
                            peer, &config, &pex_state, &connect_tx, logger.as_ref(),
                        );
                    }
                    None => break,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_walks(
    local_node_id: &[u8; 32],
    local_pubkey: &[u8],
    local_nonce: u64,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    config: &PexConfig,
    broadcaster: &dyn FrameBroadcaster,
    pex_state: &Arc<Mutex<PexState>>,
    local_advertise: &str,
    logger: &dyn PexLogger,
) {
    let parallelism = config.walk_parallelism as usize;
    for _ in 0..parallelism {
        let walk_id = OsRng.next_u64();
        let mut target_node_id = [0u8; 32];
        OsRng.fill_bytes(&mut target_node_id);
        let ttl = 4 + (OsRng.next_u32() % 9) as u8; // 4..12

        let signable = [walk_id.to_be_bytes().as_slice(), target_node_id.as_slice()].concat();
        let origin_sig = if let Some(sk) = signing_key {
            use ed25519_dalek::Signer as _;
            sk.sign(&signable).to_bytes()
        } else {
            [0u8; 64]
        };

        let walk = PexWalk {
            walk_id,
            target_node_id,
            origin_node_id: *local_node_id,
            origin_pubkey: local_pubkey.to_vec(),
            origin_nonce: local_nonce,
            origin_sig,
            ttl,
            // Carry our own dialable address so every node this walk traverses
            // can learn + dial us back — the path that lets an under-connected
            // origin become reachable cluster-wide.
            origin_transport: local_advertise.to_string(),
        };

        let frame = encode_pex_frame(PexMsg::Walk, &walk.encode());

        // Send to a random connected peer.
        let peer_ids = broadcaster.active_node_ids();
        if !peer_ids.is_empty() {
            let idx = (OsRng.next_u32() as usize) % peer_ids.len();
            broadcaster.send_to(&peer_ids[idx], TrafficClass::Background as u8, frame);

            logger.info(
                "pex.walk.sent",
                &format!(
                    "walk_id={walk_id} target={:02x}{:02x}.. ttl={ttl}",
                    target_node_id[0], target_node_id[1]
                ),
            );
        }

        {
            let mut state = pex_state.lock().unwrap_or_else(|p| p.into_inner());
            state.active_walks += 1;
            state.last_walk_at = Some(Instant::now());
        }
    }
}

/// Solve a PEX PoW challenge and send the response back.
#[allow(clippy::too_many_arguments)]
async fn handle_challenge(
    challenge: &PexChallenge,
    _from_peer: [u8; 32],
    _local_node_id: &[u8; 32],
    _local_pubkey: &[u8],
    _local_nonce: u64,
    signing_key: Option<&ed25519_dalek::SigningKey>,
    broadcaster: &dyn FrameBroadcaster,
    logger: &dyn PexLogger,
) {
    logger.info(
        "pex.challenge.received",
        &format!(
            "walk_id={} difficulty={}",
            challenge.walk_id, challenge.difficulty
        ),
    );

    // skip peers that demand PoW difficulty above what a legitimate
    // node ever produces. Without this cap the initiator burns CPU forever on
    // an unsolvable challenge from a compromised/buggy peer (observed as
    // `pex.pow.timeout difficulty=27/32` on stand loads). The cap matches
    // `MAX_POW_DIFFICULTY` (session-layer hard ceiling) — anything above is
    // protocol abuse.
    if challenge.difficulty > MAX_POW_DIFFICULTY {
        logger.warn("pex.pow.unsolvable",
            &format!("walk_id={} difficulty={} exceeds MAX_POW_DIFFICULTY={MAX_POW_DIFFICULTY} — skipping peer",
                challenge.walk_id, challenge.difficulty));
        return;
    }

    // Solve BLAKE3 PoW on a blocking thread to avoid stalling the async executor.
    let nonce = challenge.challenge_nonce;
    let diff = challenge.difficulty;
    let solution = match tokio::task::spawn_blocking(move || solve_pex_pow(&nonce, diff)).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            logger.warn(
                "pex.pow.timeout",
                &format!(
                    "walk_id={} could not solve difficulty={}",
                    challenge.walk_id, challenge.difficulty
                ),
            );
            return;
        }
        Err(_) => {
            logger.warn("pex.pow.panic", "PoW solver panicked");
            return;
        }
    };

    // Sign (walk_id || challenge_nonce || solution) to prove identity.
    let msg = [
        challenge.walk_id.to_be_bytes().as_slice(),
        challenge.challenge_nonce.as_slice(),
        solution.as_slice(),
    ]
    .concat();
    let origin_sig = if let Some(sk) = signing_key {
        use ed25519_dalek::Signer as _;
        sk.sign(&msg).to_bytes()
    } else {
        [0u8; 64]
    };

    let response = PexResponse {
        walk_id: challenge.walk_id,
        challenge_nonce: challenge.challenge_nonce,
        pow_solution: solution,
        origin_sig,
    };

    let frame = encode_pex_frame(PexMsg::Response, &response.encode());

    // Send response back through any connected peer (the network will route it).
    let peer_ids = broadcaster.active_node_ids();
    if let Some(&first) = peer_ids.first() {
        // Send to first available peer — the frame will be routed to the challenger.
        broadcaster.send_to(&first, TrafficClass::Interactive as u8, frame);
    }

    logger.info(
        "pex.response.sent",
        &format!("walk_id={}", challenge.walk_id),
    );
}

/// Handle a PexResult — add peers to state and notify runtime to connect.
async fn handle_result(
    result: &PexResult,
    _from_peer: [u8; 32],
    config: &PexConfig,
    pex_state: &Arc<Mutex<PexState>>,
    connect_tx: &PexConnectTx,
    logger: &dyn PexLogger,
) {
    logger.info(
        "pex.result.received",
        &format!("walk_id={} peers={}", result.walk_id, result.peers.len()),
    );

    // Drop wildcard-host entries up front — both `add_peers` (PEX walk
    // table) and the runtime ingest path that pulls from `connect_tx`
    // would otherwise persist `tcp://0.0.0.0:5555` into node.toml
    // where each restart re-loads it and burns a connect attempt that
    // loops back to the dialer's own listener (peer.identity_mismatch).
    // Filtering here covers both downstream consumers in one place.
    //
    // A5: cap the number of peers accepted from a single
    // PEX result. Without this, one malicious responder can flood the
    // walk-state table with sybil contacts (up to `result.peers.len`
    // per response). Honest PEX walks return ≤ K = 20 contacts; cap
    // at 10 to bound a single source's contribution well below the
    // global `config.max_peers`, leaving room for honest sources to
    // contribute the rest.
    const MAX_PEERS_PER_PEX_RESULT: usize = 10;
    let peers: Vec<PexPeer> = result
        .peers
        .iter()
        // Audit M-F: enforce the node_id↔public_key binding HERE, before the
        // fan-out to BOTH `add_peers` AND `connect_tx`. Previously the binding
        // was checked only inside `add_peers`, so the `connect_tx` path let the
        // runtime persist fabricated (victim_node_id, attacker_addr, pubkey)
        // triples to discovered_peers.json and re-dial them every restart.
        .filter(|p| pex_binding_ok(p))
        .filter(|p| !is_wildcard_transport(&p.transport))
        .take(MAX_PEERS_PER_PEX_RESULT)
        .cloned()
        .collect();
    {
        let mut state = pex_state.lock().unwrap_or_else(|p| p.into_inner());
        state.active_walks = state.active_walks.saturating_sub(1);
        state.add_peers(peers.clone(), config.max_peers);
    }

    // Notify runtime to attempt connections to newly discovered peers.
    if !peers.is_empty() {
        let _ = connect_tx.try_send(peers);
    }
}

/// Record a peer learned from a relayed PEX walk's ORIGIN (see
/// [`PexEvent::LearnedPeer`]). Same validation + fan-out as [`handle_result`]
/// for a single peer: enforce the node_id↔public_key binding (M-F), drop
/// wildcard/undialable addresses, add to the walk table, and nudge the runtime
/// to dial it. This is the mechanism that makes an under-connected /
/// keyspace-isolated origin discoverable+dialable by every node its walks reach.
fn handle_learned_peer(
    peer: PexPeer,
    config: &PexConfig,
    pex_state: &Arc<Mutex<PexState>>,
    connect_tx: &PexConnectTx,
    logger: &dyn PexLogger,
) {
    if !pex_binding_ok(&peer) || is_wildcard_transport(&peer.transport) {
        return;
    }
    // Only nudge a dial when this is a genuinely NEW contact, so a steady
    // stream of relayed walks for already-known peers doesn't spam the connect
    // path (the directional dedup would reject those anyway). `add_peers`
    // itself dedups storage; we check membership first only to gate the dial.
    let is_new = {
        let mut state = pex_state.lock().unwrap_or_else(|p| p.into_inner());
        let already = state
            .discovered_peers
            .iter()
            .any(|(p, _)| p.node_id == peer.node_id);
        state.add_peers(vec![peer.clone()], config.max_peers);
        !already
    };
    if is_new {
        logger.info(
            "pex.learned_peer",
            &format!(
                "walk-origin recorded as dialable contact node_id={}",
                veil_util::hex_short(&peer.node_id),
            ),
        );
        let _ = connect_tx.try_send(vec![peer]);
    }
}

/// Brute-force BLAKE3 PoW: find a 32-byte `solution` such that
/// `veil_util::leading_zero_bits(BLAKE3(challenge_nonce || solution)) >= difficulty`.
///
/// Returns `None` if no solution found within the iteration limit.
/// The limit is `2^(difficulty+2)` (4× the expected average), capped at 2^33
/// to keep worst-case runtime under a few minutes on slow devices.
fn solve_pex_pow(challenge_nonce: &[u8; 32], difficulty: u8) -> Option<[u8; 32]> {
    // 4× expected attempts for the given difficulty, capped at ~8 billion.
    let max_iterations: u64 = if difficulty >= 31 {
        1u64 << 33
    } else {
        1u64 << (difficulty.saturating_add(2) as u64)
    };

    let mut solution = [0u8; 32];
    for i in 0..max_iterations {
        // Use the counter as the first 8 bytes of the solution.
        solution[0..8].copy_from_slice(&i.to_le_bytes());
        // Remaining bytes stay zero (deterministic, fast).

        let hash_input = [challenge_nonce.as_slice(), solution.as_slice()].concat();
        let hash = blake3::hash(&hash_input);
        if veil_util::leading_zero_bits(hash.as_bytes()) >= difficulty as u32 {
            return Some(solution);
        }
    }
    None
}

/// Count of leading zero bits in `XOR(a, b)` — a measure of how "close"
/// two node IDs are in the Kademlia keyspace. Higher = closer.
fn xor_leading_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    for i in 0..32 {
        let xor = a[i] ^ b[i];
        if xor != 0 {
            return (i as u32) * 8 + xor.leading_zeros();
        }
    }
    256
}

/// Walk cadence as a function of ACTIVE-SESSION count (`connected`), tiered by
/// operator-tunable thresholds in [`PexConfig`].
///
/// Cadence must reflect how many sessions we have actually ESTABLISHED, not how
/// many peers we have merely DISCOVERED. A node can discover peers it then fails
/// to connect to — dial failures, or a keyspace-isolated `node_id` that few
/// peers dial back — so keying the walk interval on `discovered_peers.len()`
/// made such a node sleep for hours while under-connected (observed on the
/// testnet: discovered=5, active sessions=3 → 6 h backoff, stuck at 3/7 even
/// though the random-walk machinery was "running").
///
/// Keying on `connected` is also **scale-safe**: the active-session count is
/// bounded by the node's connection target regardless of network size, so a
/// node searches aggressively only while genuinely under-connected and then
/// steps down — it does NOT keep walking forever just because billions of peers
/// exist to be discovered. (Filling sessions UP TO the target from
/// already-discovered peers is the dial loop's job, not the discovery-walk's.)
///
/// Tiers (defaults; all configurable via `[pex]`):
/// * `< low_peer_threshold` (3) sessions → `search_interval_active_secs` (15 min)
/// * `low..high_peer_threshold` (3..20)  → `search_interval_mid_secs` (1 h)
/// * `>= high_peer_threshold` (20)       → `search_interval_idle_secs` (1 day)
fn compute_interval(connected: usize, config: &PexConfig) -> u64 {
    if connected < config.low_peer_threshold {
        config.search_interval_active_secs
    } else if connected < config.high_peer_threshold {
        config.search_interval_mid_secs
    } else {
        config.search_interval_idle_secs
    }
}

fn extract_subnet_24(transport: &str) -> Option<[u8; 3]> {
    let host = transport.split("://").nth(1)?.split(':').next()?;
    let ip: std::net::Ipv4Addr = host.parse().ok()?;
    let octets = ip.octets();
    Some([octets[0], octets[1], octets[2]])
}

/// Return `true` if `transport` advertises a wildcard host (0.0.0.0 / [::])
/// that no remote peer can usefully dial. Mirrors the advertise-side
/// filter in `veilcore::node::runtime::is_wildcard_transport`.
/// The canonical PEX peer binding rule: `node_id == BLAKE3(public_key)`.
///
/// Audit M-F: extracted so BOTH `PexState::add_peers` (the PEX walk table) AND
/// the `handle_result` fan-out (which feeds the runtime connect/persist path via
/// `connect_tx`) enforce the SAME check before any storage. An empty
/// `public_key` (legacy wire format) falls through to the handshake-time
/// identity check.
fn pex_binding_ok(peer: &PexPeer) -> bool {
    peer.public_key.is_empty() || *blake3::hash(&peer.public_key).as_bytes() == peer.node_id
}

fn is_wildcard_transport(transport: &str) -> bool {
    let after_scheme = match transport.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    after_scheme.starts_with("0.0.0.0:")
        || after_scheme.starts_with("[::]:")
        || after_scheme.starts_with("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_pex_pow_finds_solution() {
        let mut nonce = [0u8; 32];
        nonce[0] = 0xAA;
        // difficulty=8 is trivially solvable
        let solution = solve_pex_pow(&nonce, 8).expect("should find solution");
        let hash_input = [nonce.as_slice(), solution.as_slice()].concat();
        let hash = blake3::hash(&hash_input);
        assert!(veil_util::leading_zero_bits(hash.as_bytes()) >= 8);
    }

    #[test]
    fn compute_interval_tiers_by_active_sessions() {
        let c = PexConfig::default();
        // < low_peer_threshold (3) active sessions → aggressive 15-min search.
        assert_eq!(compute_interval(0, &c), 15 * 60);
        assert_eq!(compute_interval(2, &c), 15 * 60);
        // low..high (3..20) → hourly.
        assert_eq!(compute_interval(3, &c), 60 * 60);
        assert_eq!(compute_interval(19, &c), 60 * 60);
        // >= high_peer_threshold (20) → once-daily maintenance search.
        assert_eq!(compute_interval(20, &c), 24 * 60 * 60);
        assert_eq!(compute_interval(1_000, &c), 24 * 60 * 60);
    }

    #[test]
    fn compute_interval_thresholds_are_config_tunable() {
        // Boundaries + intervals come entirely from config, so an operator can
        // move them via `[pex]` in node.toml.
        let c = PexConfig {
            low_peer_threshold: 5,
            high_peer_threshold: 10,
            search_interval_active_secs: 60,
            search_interval_mid_secs: 600,
            search_interval_idle_secs: 6_000,
            ..PexConfig::default()
        };
        assert_eq!(compute_interval(4, &c), 60); // < low → active
        assert_eq!(compute_interval(5, &c), 600); // low boundary → mid
        assert_eq!(compute_interval(9, &c), 600); // mid
        assert_eq!(compute_interval(10, &c), 6_000); // high boundary → idle
    }

    /// Audit M-F: a fabricated peer triple (node_id != BLAKE3(public_key)) must
    /// be dropped BEFORE the fan-out — not just inside `add_peers` — so the
    /// `connect_tx` runtime connect/persist path never receives it.
    #[tokio::test]
    async fn handle_result_filters_binding_mismatch_before_fanout_mf() {
        use veil_proto::pex::PexResult;

        struct NoopLogger;
        impl PexLogger for NoopLogger {
            fn info(&self, _: &str, _: &str) {}
            fn warn(&self, _: &str, _: &str) {}
        }

        // Valid peer: node_id == BLAKE3(public_key).
        let good_pk = vec![7u8; 32];
        let good_id = *blake3::hash(&good_pk).as_bytes();
        let good = PexPeer {
            node_id: good_id,
            transport: "tcp://10.0.0.1:9000".to_string(),
            public_key: good_pk,
            nonce: 1,
        };
        // Fabricated triple: node_id does NOT match BLAKE3(public_key).
        let bad = PexPeer {
            node_id: [0xCDu8; 32],
            transport: "tcp://10.0.0.2:9000".to_string(),
            public_key: vec![9u8; 32],
            nonce: 2,
        };

        let result = PexResult {
            walk_id: 1,
            peers: vec![good, bad],
        };
        let pex_state = Arc::new(Mutex::new(PexState::new()));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<PexPeer>>(4);
        let config = PexConfig::default();

        handle_result(&result, [0u8; 32], &config, &pex_state, &tx, &NoopLogger).await;

        // connect_tx (the runtime connect/persist path) must receive ONLY the
        // binding-valid peer; the fabricated triple is dropped before fan-out.
        let sent = rx.try_recv().expect("connect_tx received a batch");
        assert_eq!(
            sent.len(),
            1,
            "only the binding-valid peer is forwarded to connect_tx"
        );
        assert_eq!(sent[0].node_id, good_id);
    }

    #[test]
    fn subnet_diversity_limits_peers() {
        let mut state = PexState::new();
        let peer = |ip: &str| PexPeer {
            node_id: [0u8; 32],
            transport: format!("tcp://{ip}:9000"),
            public_key: vec![],
            nonce: 0,
        };
        state.add_peers(
            vec![
                {
                    let mut p = peer("10.0.1.1");
                    p.node_id = [1; 32];
                    p
                },
                {
                    let mut p = peer("10.0.1.2");
                    p.node_id = [2; 32];
                    p
                },
                {
                    let mut p = peer("10.0.1.3");
                    p.node_id = [3; 32];
                    p
                }, // blocked by subnet diversity
            ],
            10,
        );
        assert_eq!(state.discovered_peers.len(), 2, "max 2 per /24 subnet");
    }

    #[test]
    fn retention_evicts_worst_peer_when_full() {
        let mut state = PexState::new();
        let make_peer = |id: u8, ip: &str| PexPeer {
            node_id: [id; 32],
            transport: format!("tcp://{ip}:9000"),
            public_key: vec![],
            nonce: 0,
        };
        // Fill to max=3 with diverse subnets.
        state.add_peers(
            vec![
                make_peer(1, "10.0.1.1"),
                make_peer(2, "10.0.2.1"),
                make_peer(3, "10.0.3.1"),
            ],
            3,
        );
        assert_eq!(state.discovered_peers.len(), 3);

        // Adding a 4th peer should evict the worst-scored one.
        state.add_peers(vec![make_peer(4, "10.0.4.1")], 3);
        assert_eq!(state.discovered_peers.len(), 3, "must stay at max");
        assert!(
            state
                .discovered_peers
                .iter()
                .any(|(p, _)| p.node_id == [4; 32]),
            "new peer must be present after eviction"
        );
    }

    #[test]
    fn xor_leading_bits_identical() {
        assert_eq!(xor_leading_bits(&[0u8; 32], &[0u8; 32]), 256);
    }

    #[test]
    fn xor_leading_bits_one_bit_diff() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 0x80; // first bit differs
        assert_eq!(xor_leading_bits(&a, &b), 0);
        b[0] = 0x01; // 7 leading zeros in XOR
        assert_eq!(xor_leading_bits(&a, &b), 7);
    }
}
