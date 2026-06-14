//! Route discovery initiator.
//!
//! Manages the adaptive send interval and constructs outgoing
//! [`RouteDiscoveryPacket`]s.
//!
//! # Send interval
//!
//! | Routes in cache | Interval |
//! |-----------------|-------------------|
//! | 0 | 1 hour (minimum) |
//! | 1 – 7 | linear interpolation → up to 24 hours |
//! | 8+ | 48 hours (maximum) |
//!
//! Nodes with `manual_only = true` (Leaf nodes or explicit config flag) never
//! send automatically; the operator triggers discovery via the CLI.

use crate::pow::solve_discovery_pow;
use veil_proto::{
    budget::{
        DISCOVERY_MAX_INTERVAL_SECS, DISCOVERY_MAX_ROUTES_TARGET, DISCOVERY_MIN_INTERVAL_SECS,
        ROUTE_DISCOVERY_INITIAL_TTL, ROUTE_DISCOVERY_POW_DIFFICULTY,
    },
    routing::RouteDiscoveryPacket,
};

// ── DiscoveryInitiator ────────────────────────────────────────────────────────

/// Builds and schedules outgoing route discovery packets.
pub struct DiscoveryInitiator {
    local_id: [u8; 32],
    difficulty: u8,
    /// When `true` the initiator never fires automatically.
    manual_only: bool,
}

impl DiscoveryInitiator {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            local_id,
            difficulty: ROUTE_DISCOVERY_POW_DIFFICULTY,
            manual_only: false,
        }
    }

    pub fn with_difficulty(mut self, difficulty: u8) -> Self {
        self.difficulty = difficulty;
        self
    }

    /// Disable automatic sending (Leaf nodes or manual-only config).
    pub fn manual_only(mut self) -> Self {
        self.manual_only = true;
        self
    }

    /// Whether automatic sending is enabled for this initiator.
    pub fn is_automatic(&self) -> bool {
        !self.manual_only
    }

    /// Compute the next send interval (seconds) given the current route count.
    ///
    /// Linearly interpolates between `DISCOVERY_MIN_INTERVAL_SECS` (0 routes)
    /// and half of `DISCOVERY_MAX_INTERVAL_SECS` (target − 1 routes), then
    /// returns `DISCOVERY_MAX_INTERVAL_SECS` once the target is reached.
    pub fn next_interval_secs(route_count: usize) -> u64 {
        if route_count >= DISCOVERY_MAX_ROUTES_TARGET {
            return DISCOVERY_MAX_INTERVAL_SECS;
        }
        let frac = route_count as f64 / DISCOVERY_MAX_ROUTES_TARGET as f64;
        let range = (DISCOVERY_MAX_INTERVAL_SECS - DISCOVERY_MIN_INTERVAL_SECS) as f64;
        DISCOVERY_MIN_INTERVAL_SECS + (range * frac) as u64
    }

    /// Return the current unix timestamp in seconds.
    pub fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Solve PoW for the given timestamp.
    ///
    /// **Blocking** — must be called inside `tokio::task::spawn_blocking`.
    pub fn solve(&self, timestamp: u64) -> [u8; 32] {
        solve_discovery_pow(&self.local_id, timestamp, self.difficulty)
    }

    /// Assemble a [`RouteDiscoveryPacket`] after PoW has been solved.
    pub fn build_packet(&self, timestamp: u64, pow_nonce: [u8; 32]) -> RouteDiscoveryPacket {
        RouteDiscoveryPacket {
            src_node_id: self.local_id,
            timestamp,
            pow_nonce,
            ttl: ROUTE_DISCOVERY_INITIAL_TTL,
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_zero_routes_is_min() {
        assert_eq!(
            DiscoveryInitiator::next_interval_secs(0),
            DISCOVERY_MIN_INTERVAL_SECS
        );
    }

    #[test]
    fn interval_at_target_is_max() {
        assert_eq!(
            DiscoveryInitiator::next_interval_secs(DISCOVERY_MAX_ROUTES_TARGET),
            DISCOVERY_MAX_INTERVAL_SECS,
        );
    }

    #[test]
    fn interval_grows_monotonically() {
        let mut prev = 0u64;
        for i in 0..=DISCOVERY_MAX_ROUTES_TARGET {
            let cur = DiscoveryInitiator::next_interval_secs(i);
            assert!(cur >= prev, "interval must be non-decreasing at {i} routes");
            prev = cur;
        }
    }

    #[test]
    fn interval_above_target_clamped() {
        assert_eq!(
            DiscoveryInitiator::next_interval_secs(DISCOVERY_MAX_ROUTES_TARGET + 100),
            DISCOVERY_MAX_INTERVAL_SECS,
        );
    }

    #[test]
    fn build_packet_has_correct_fields() {
        let local_id = [0x42u8; 32];
        let initiator = DiscoveryInitiator::new(local_id);
        let ts = 1_700_000_000u64;
        let nonce = [0xABu8; 32];
        let pkt = initiator.build_packet(ts, nonce);
        assert_eq!(pkt.src_node_id, local_id);
        assert_eq!(pkt.timestamp, ts);
        assert_eq!(pkt.pow_nonce, nonce);
        assert_eq!(pkt.ttl, ROUTE_DISCOVERY_INITIAL_TTL);
    }

    #[test]
    fn manual_only_flag() {
        let a = DiscoveryInitiator::new([1u8; 32]);
        assert!(a.is_automatic());
        let b = DiscoveryInitiator::new([1u8; 32]).manual_only();
        assert!(!b.is_automatic());
    }

    #[test]
    fn solve_and_verify_difficulty_0() {
        let initiator = DiscoveryInitiator::new([0x11u8; 32]).with_difficulty(0);
        let ts = 1_000u64;
        let nonce = initiator.solve(ts);
        // difficulty=0 → any nonce passes
        use crate::pow::verify_discovery_pow;
        assert!(verify_discovery_pow(&initiator.local_id, ts, &nonce, 0, ts));
    }
}
