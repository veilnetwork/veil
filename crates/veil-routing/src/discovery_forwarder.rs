//! Route discovery forwarder.
//!
//! Processes incoming [`RouteDiscoveryPacket`]s:
//! 1. Validates PoW and timestamp.
//! 2. Enforces per-source and global rate limits.
//! 3. Decrements TTL.
//! 4. When TTL reaches 0 and this node can accept inbound connections →
//!    returns [`ForwardDecision::Respond`] so the caller can look up the
//!    initiator via the discovery directory and send a
//!    [`RouteDiscoverOfferPayload`] back.
//! 5. Otherwise selects the next hop via a biased random walk:
//!    75 % prefer the XOR-far neighbor, 25 % pick at random.
//!    Leaf neighbors and the packet's sender are excluded from candidates.
//!
//! The forwarder is pure logic — it takes no I/O actions itself.

use std::{collections::HashMap, time::Instant};

use veil_abuse::rate_limiter::TokenBucket;
use veil_proto::{
    budget::{
        DISCOVERY_GLOBAL_RATE_BURST, DISCOVERY_RATE_BURST, DISCOVERY_RATE_REFILL_SECS,
        MAX_DISCOVERY_RATE_ENTRIES, ROUTE_DISCOVERY_POW_DIFFICULTY,
    },
    routing::RouteDiscoveryPacket,
};
use veil_types::NodeRole;

use super::pow::verify_discovery_pow;

// ── DiscoveryNeighbor ─────────────────────────────────────────────────────────

/// One entry in the neighbor list passed [`DiscoveryForwarder::handle`].
#[derive(Debug, Clone)]
pub struct DiscoveryNeighbor {
    pub node_id: [u8; 32],
    pub role: NodeRole,
}

// ── ForwardDecision ───────────────────────────────────────────────────────────

/// The decision returned by [`DiscoveryForwarder::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// Drop the packet for the given reason.
    Drop(DropReason),
    /// Forward the packet (with TTL already decremented) to this neighbor.
    Forward([u8; 32]),
    /// TTL reached 0 and this node can respond. The caller should:
    /// 1. Look up `src_node_id` in the discovery directory.
    /// 2. Connect to the initiator via their gateway.
    /// 3. Send a [`veil_proto::RouteDiscoverOfferPayload`].
    Respond,
}

/// Reason a discovery packet was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// PoW invalid or timestamp outside the validity window.
    InvalidPoW,
    /// Per-source or global rate limit exceeded.
    RateLimited,
    /// No eligible non-Leaf neighbor to forward (or TTL=0 but this node
    /// cannot accept inbound connections).
    NoEligibleNeighbor,
}

// ── DiscoveryForwarder ────────────────────────────────────────────────────────

/// Stateful forwarder for route discovery packets.
///
/// Clone is intentionally not derived — state (rate-limit buckets, RNG) must
/// not be accidentally duplicated. Wrap in `Arc<Mutex<_>>` if shared.
pub struct DiscoveryForwarder {
    local_id: [u8; 32],
    local_role: NodeRole,
    difficulty: u8,
    per_src: HashMap<[u8; 32], TokenBucket>,
    global: TokenBucket,
    /// Simple xorshift64 PRNG — no external dependency needed for this use.
    rng: u64,
}

impl DiscoveryForwarder {
    /// Create a new forwarder.
    ///
    /// `difficulty` is the PoW difficulty this node enforces on incoming packets
    /// (should match the network constant, default [`ROUTE_DISCOVERY_POW_DIFFICULTY`]).
    pub fn new(local_id: [u8; 32], local_role: NodeRole, difficulty: u8) -> Self {
        // seed RNG from the local node ID to avoid
        // determinism across nodes. Direct array indexing — `local_id` is
        // always 32 B at compile time, so the first 8 bytes are guaranteed
        // present. The legacy `try_into.unwrap_or([1u8; 8])` hid a logic
        // bug behind a benign-looking fallback.
        let rng_seed = u64::from_le_bytes([
            local_id[0],
            local_id[1],
            local_id[2],
            local_id[3],
            local_id[4],
            local_id[5],
            local_id[6],
            local_id[7],
        ]);
        Self {
            local_id,
            local_role,
            difficulty,
            per_src: HashMap::new(),
            // capacity=BURST, refill_rate=1 token/sec for global; 1/REFILL_SECS for per-src.
            global: TokenBucket::new(DISCOVERY_GLOBAL_RATE_BURST as f64, 1.0),
            rng: if rng_seed == 0 { 1 } else { rng_seed },
        }
    }

    /// Convenience constructor using the default network difficulty.
    pub fn with_default_difficulty(local_id: [u8; 32], local_role: NodeRole) -> Self {
        Self::new(local_id, local_role, ROUTE_DISCOVERY_POW_DIFFICULTY)
    }

    /// Process an incoming discovery packet.
    ///
    /// * `pkt` — the received packet.
    /// * `from` — `node_id` of the neighbor that sent it.
    /// * `neighbors` — current neighbor list (used for next-hop selection).
    /// * `now_secs` — current unix timestamp (seconds); injected for testability.
    ///
    /// Returns a [`ForwardDecision`] describing what to do next.
    /// The caller is responsible for any I/O (actually sending the packet
    /// connecting back, etc.).
    pub fn handle(
        &mut self,
        pkt: &RouteDiscoveryPacket,
        from: &[u8; 32],
        neighbors: &[DiscoveryNeighbor],
        now_secs: u64,
    ) -> ForwardDecision {
        let now = Instant::now();

        // 1. Validate PoW + timestamp.
        if !verify_discovery_pow(
            &pkt.src_node_id,
            pkt.timestamp,
            &pkt.pow_nonce,
            self.difficulty,
            now_secs,
        ) {
            return ForwardDecision::Drop(DropReason::InvalidPoW);
        }

        // 2. Global rate limit (all sources combined).
        if !self.global.allow_at(now) {
            return ForwardDecision::Drop(DropReason::RateLimited);
        }

        // 3. Per-source rate limit (burst=DISCOVERY_RATE_BURST, refill=1/REFILL_SECS tokens/sec).
        // Evict the least-recently-used entry if the map is at capacity.
        // We use `TokenBucket::last_refill` as the LRU timestamp — it is
        // updated on every `allow_at` call so it accurately tracks recency.
        // This prevents a flood-source from evicting a legitimate quiet peer.
        if self.per_src.len() >= MAX_DISCOVERY_RATE_ENTRIES
            && !self.per_src.contains_key(&pkt.src_node_id)
            && let Some(lru_key) = self
                .per_src
                .iter()
                .min_by_key(|(_, b)| b.last_refill())
                .map(|(k, _)| *k)
        {
            self.per_src.remove(&lru_key);
        }
        let refill_rate = 1.0 / DISCOVERY_RATE_REFILL_SECS as f64;
        let bucket = self
            .per_src
            .entry(pkt.src_node_id)
            .or_insert_with(|| TokenBucket::new(DISCOVERY_RATE_BURST as f64, refill_rate));
        if !bucket.allow_at(now) {
            return ForwardDecision::Drop(DropReason::RateLimited);
        }

        // 4. Decrement TTL.
        let new_ttl = pkt.ttl.saturating_sub(1);
        if new_ttl == 0 {
            return if self.can_respond() {
                ForwardDecision::Respond
            } else {
                ForwardDecision::Drop(DropReason::NoEligibleNeighbor)
            };
        }

        // 5. Choose next hop: exclude sender + self + originator + Leaf nodes.
        let candidates: Vec<&DiscoveryNeighbor> = neighbors
            .iter()
            .filter(|n| {
                n.node_id != *from && n.node_id != self.local_id && n.node_id != pkt.src_node_id
            })
            .filter(|n| !matches!(n.role, NodeRole::Leaf))
            .collect();

        if candidates.is_empty() {
            return ForwardDecision::Drop(DropReason::NoEligibleNeighbor);
        }

        // 6. Biased random walk: 75 % XOR-far, 25 % random.
        let chosen = if self.rand_bool_75() {
            candidates
                .iter()
                .max_by_key(|n| xor_distance_key(&n.node_id, &pkt.src_node_id))
                .expect("candidates non-empty — checked by is_empty() above")
        } else {
            let idx = (self.rand_u64() % candidates.len() as u64) as usize;
            &candidates[idx]
        };

        ForwardDecision::Forward(chosen.node_id)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn can_respond(&self) -> bool {
        matches!(self.local_role, NodeRole::Core)
    }

    fn rand_u64(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// Returns `true` with probability ≈ 75 % (3 out of 4).
    fn rand_bool_75(&mut self) -> bool {
        !self.rand_u64().is_multiple_of(4)
    }
}

/// XOR distance metric: first 16 bytes of `a XOR b` interpreted as u128.
/// Used only for `max_by_key` comparison — the absolute value is not meaningful.
fn xor_distance_key(a: &[u8; 32], b: &[u8; 32]) -> u128 {
    let la = u128::from_be_bytes(a[..16].try_into().unwrap());
    let lb = u128::from_be_bytes(b[..16].try_into().unwrap());
    la ^ lb
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::solve_discovery_pow;

    const DIFFICULTY: u8 = 0; // trivial — tests run fast

    fn make_fwd(role: NodeRole) -> DiscoveryForwarder {
        DiscoveryForwarder::new([1u8; 32], role, DIFFICULTY)
    }

    fn make_pkt(src: u8, ts: u64, ttl: u8) -> RouteDiscoveryPacket {
        RouteDiscoveryPacket {
            src_node_id: [src; 32],
            timestamp: ts,
            pow_nonce: [0u8; 32], // trivially valid at difficulty=0
            ttl,
        }
    }

    fn relay_neighbor(id: u8) -> DiscoveryNeighbor {
        DiscoveryNeighbor {
            node_id: [id; 32],
            role: NodeRole::Core,
        }
    }

    fn leaf_neighbor(id: u8) -> DiscoveryNeighbor {
        DiscoveryNeighbor {
            node_id: [id; 32],
            role: NodeRole::Leaf,
        }
    }

    #[test]
    fn invalid_pow_drops() {
        // Use difficulty=8 so the zero nonce fails.
        let mut fwd = DiscoveryForwarder::new([1u8; 32], NodeRole::Core, 8);
        let pkt = make_pkt(2, 1_700_000_000, 4);
        let neighbors = vec![relay_neighbor(3)];
        let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_700_000_000);
        assert_eq!(res, ForwardDecision::Drop(DropReason::InvalidPoW));
    }

    #[test]
    fn ttl_1_relay_responds() {
        let mut fwd = make_fwd(NodeRole::Core);
        let pkt = make_pkt(2, 1_000, 1);
        let res = fwd.handle(&pkt, &[9u8; 32], &[], 1_000);
        assert_eq!(res, ForwardDecision::Respond);
    }

    #[test]
    fn ttl_1_leaf_drops() {
        let mut fwd = make_fwd(NodeRole::Leaf);
        let pkt = make_pkt(2, 1_000, 1);
        let res = fwd.handle(&pkt, &[9u8; 32], &[], 1_000);
        assert_eq!(res, ForwardDecision::Drop(DropReason::NoEligibleNeighbor));
    }

    #[test]
    fn leaf_neighbors_excluded() {
        let mut fwd = make_fwd(NodeRole::Core);
        let pkt = make_pkt(2, 1_000, 4);
        // Only leaf neighbors → no eligible next-hop.
        let neighbors = vec![leaf_neighbor(3), leaf_neighbor(4)];
        let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_000);
        assert_eq!(res, ForwardDecision::Drop(DropReason::NoEligibleNeighbor));
    }

    #[test]
    fn sender_excluded_from_candidates() {
        let mut fwd = make_fwd(NodeRole::Core);
        let pkt = make_pkt(2, 1_000, 4);
        let from = [3u8; 32];
        // Only neighbor is the sender.
        let neighbors = vec![DiscoveryNeighbor {
            node_id: from,
            role: NodeRole::Core,
        }];
        let res = fwd.handle(&pkt, &from, &neighbors, 1_000);
        assert_eq!(res, ForwardDecision::Drop(DropReason::NoEligibleNeighbor));
    }

    #[test]
    fn forwards_to_eligible_neighbor() {
        let mut fwd = make_fwd(NodeRole::Core);
        let pkt = make_pkt(2, 1_000, 4);
        let neighbors = vec![relay_neighbor(5)];
        let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_000);
        assert_eq!(res, ForwardDecision::Forward([5u8; 32]));
    }

    #[test]
    fn rate_limit_blocks_after_burst() {
        let mut fwd = make_fwd(NodeRole::Core);
        let neighbors = vec![relay_neighbor(5)];
        let src = 0xAAu8;

        // Exhaust the burst (DISCOVERY_RATE_BURST = 3).
        for i in 0..DISCOVERY_RATE_BURST {
            let pkt = make_pkt(src, 1_000 + i as u64, 4);
            let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_000 + i as u64);
            assert!(
                matches!(res, ForwardDecision::Forward(_)),
                "burst packet {i} should forward"
            );
        }
        // Next packet from same src should be rate-limited.
        let pkt = make_pkt(src, 1_100, 4);
        let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_100);
        assert_eq!(res, ForwardDecision::Drop(DropReason::RateLimited));
    }

    #[test]
    fn xor_biased_walk_prefers_far_neighbor() {
        let far_id = [0xFFu8; 32]; // XOR distance [0x00;32] = u128::MAX
        let near_id = [0x01u8; 32]; // XOR distance [0x00;32] = small
        let neighbors = vec![
            DiscoveryNeighbor {
                node_id: near_id,
                role: NodeRole::Core,
            },
            DiscoveryNeighbor {
                node_id: far_id,
                role: NodeRole::Core,
            },
        ];

        let mut fwd = DiscoveryForwarder::new([1u8; 32], NodeRole::Core, 0);
        let mut far_count = 0usize;
        let mut forward_count = 0usize;
        let trials = 200usize;

        // Use a unique src_node_id per trial to avoid the per-source rate limit.
        // Keep the first byte 0x00 so far_id=[0xFF;32] always has a larger XOR
        // distance from src than near_id=[0x01;32].
        for i in 0..trials {
            let mut src = [0x00u8; 32];
            // Vary bytes 1+ only so src[0] stays 0x00.
            src[1] = (i & 0xFF) as u8;
            src[2] = ((i >> 8) & 0xFF) as u8;
            let pkt = RouteDiscoveryPacket {
                src_node_id: src,
                timestamp: 1_000 + i as u64,
                pow_nonce: [0u8; 32],
                ttl: 4,
            };
            let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, 1_000 + i as u64);
            if let ForwardDecision::Forward(id) = &res {
                forward_count += 1;
                if *id == far_id {
                    far_count += 1;
                }
            }
        }
        // Must have collected enough actual forwards for a meaningful ratio check.
        assert!(
            forward_count > 10,
            "too few forwards ({forward_count}) — rate limits too tight"
        );
        // Among actual forwards, far node should be chosen ≥ 60 % of the time.
        assert!(
            far_count * 100 / forward_count >= 60,
            "far node picked {far_count}/{forward_count} forwards ({:.0}%), want ≥ 60 %",
            far_count as f64 / forward_count as f64 * 100.0,
        );
    }

    #[test]
    fn difficulty_8_solve_and_forward() {
        let src_id = [0xBBu8; 32];
        let ts = 1_700_000_000u64;
        let nonce = solve_discovery_pow(&src_id, ts, 8);
        let mut fwd = DiscoveryForwarder::new([1u8; 32], NodeRole::Core, 8);
        let pkt = RouteDiscoveryPacket {
            src_node_id: src_id,
            timestamp: ts,
            pow_nonce: nonce,
            ttl: 4,
        };
        let neighbors = vec![relay_neighbor(7)];
        let res = fwd.handle(&pkt, &[9u8; 32], &neighbors, ts);
        assert_eq!(res, ForwardDecision::Forward([7u8; 32]));
    }
}
