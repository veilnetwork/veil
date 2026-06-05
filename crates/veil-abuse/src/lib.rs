//! Abuse-resistance subsystem.
//!
//! Provides rate limiting, per-sender quotas, attachment quotas, replay
//! protection, peer banning, and violation-based auto-banning.
//!
//! extraction: this crate is logger-agnostic — the auto-ban path
//! (in `violation_tracker`) emits one `abuse.auto_ban` event through the
//! [`AbuseLogger`] trait, which `veilcore::node::observability::NodeLogger`
//! implements via a small bridge in `node::transport_hints`.

/// Logger surface used by the auto-ban path to surface "peer banned"
/// notifications to operators. Implemented by veilcore's `NodeLogger`.
pub trait AbuseLogger: Send + Sync {
    fn warn(&self, event: &str, message: &str);
}

pub mod backpressure;
pub mod ban_list;
pub mod bandwidth_gate;
pub mod dht_quota;
pub mod identity_quota;
pub mod per_peer_limiter;
pub mod pow_verifier;
pub mod rate_limiter;
pub mod replay_window;
pub mod scanner_shield;
pub mod violation_tracker;

pub use backpressure::BackpressureAimd;
pub use ban_list::{BanEntry, BanList};
pub use bandwidth_gate::BandwidthGate;
pub use dht_quota::DhtQuota;
pub use per_peer_limiter::PerPeerLimiter;
pub use pow_verifier::PowVerifier;
pub use rate_limiter::{RateLimiter, TokenBucket};
pub use replay_window::ReplayWindow;
pub use violation_tracker::ViolationTracker;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::time::Duration;

    // ── Scenario B: rate limit burst ─────────────────────────────────────────

    /// After burst, ~99% of frames must be dropped.
    #[test]
    fn rate_limit_drops_burst() {
        let mut lim = PerPeerLimiter::new(1.0, 5.0, Duration::from_secs(60));
        let peer = [0xBBu8; 32];
        let mut allowed = 0usize;
        let total = 1_000usize;
        for _ in 0..total {
            if lim.allow(peer) {
                allowed += 1;
            }
        }
        // Burst capacity is 5 — only 5 should pass (no time elapses between calls)
        assert!(
            allowed <= 5,
            "allowed={allowed}, expected ≤ 5 (burst capacity)"
        );
        assert!(
            (total - allowed) >= total * 95 / 100,
            "at least 95% should be dropped; dropped={}",
            total - allowed
        );
    }

    // ── Scenario C: replay attack ─────────────────────────────────────────────

    /// Same request_id submitted twice — second must be rejected.
    #[test]
    fn replay_second_submission_rejected() {
        let mut window = ReplayWindow::new(1000);
        let nonce = 0xDEAD_BEEF_u64;
        assert!(
            window.check_and_insert(nonce),
            "first submission must be accepted"
        );
        assert!(
            !window.check_and_insert(nonce),
            "second submission must be rejected"
        );
    }

    // ── Scenario D: auto-ban escalation ──────────────────────────────────────

    /// Repeated violations auto-ban the peer via `ViolationTracker`.
    #[test]
    fn violation_tracker_auto_bans_after_threshold() {
        let threshold = 3u32;
        let mut tracker = ViolationTracker::with_fixed_duration(
            threshold,
            Duration::from_secs(60),
            Duration::from_secs(600),
        )
        .unwrap();
        let mut ban_list = BanList::new();
        let offender = [0xCCu8; 32];

        for i in 0..threshold {
            tracker.record(offender, &mut ban_list);
            if i + 1 < threshold {
                assert!(
                    !ban_list.is_banned(&offender),
                    "should not be banned yet at violation {}",
                    i + 1
                );
            }
        }
        assert!(
            ban_list.is_banned(&offender),
            "peer must be banned after {} violations",
            threshold
        );
    }

    // ── integration tests ────────────────────────────────────────────

    // 252.1: Per-peer byte-rate enforcement
    #[test]
    fn per_peer_byte_rate_throttles_large_frames() {
        // 1 byte/sec burst=10 bytes → allow first 10 bytes, deny next
        let mut lim =
            PerPeerLimiter::new(100.0, 100.0, Duration::from_secs(60)).with_byte_rate(1.0, 10.0);
        let peer = [0x01u8; 32];

        // Should be able to send 10 bytes (burst capacity)
        assert!(
            lim.allow_bytes(peer, 10),
            "burst of 10 bytes must be allowed"
        );
        // Next byte exceeds budget
        assert!(
            !lim.allow_bytes(peer, 1),
            "byte budget exhausted — must be denied"
        );
    }

    #[test]
    fn per_peer_byte_rate_disabled_always_allows() {
        let mut lim = PerPeerLimiter::new(100.0, 100.0, Duration::from_secs(60));
        // No byte-rate configured
        assert!(lim.allow_bytes([0x01u8; 32], usize::MAX));
    }

    #[test]
    fn different_peers_have_independent_byte_budgets() {
        let mut lim =
            PerPeerLimiter::new(100.0, 100.0, Duration::from_secs(60)).with_byte_rate(1.0, 5.0);
        let peer_a = [0xAAu8; 32];
        let peer_b = [0xBBu8; 32];
        // Drain peer_a's budget
        assert!(lim.allow_bytes(peer_a, 5));
        assert!(!lim.allow_bytes(peer_a, 1), "peer_a exhausted");
        // peer_b still has its own budget
        assert!(
            lim.allow_bytes(peer_b, 5),
            "peer_b must have independent budget"
        );
    }

    // 252.2: Node aggregate bandwidth
    #[test]
    fn bandwidth_gate_limits_node_egress() {
        // 1 kbps = 1024 bytes/sec, burst = 2048 bytes
        let mut gate = BandwidthGate::new(1);
        assert!(gate.allow_bytes(1024));
        assert!(gate.allow_bytes(1024));
        assert!(!gate.allow_bytes(1), "node bandwidth exhausted");
    }

    #[test]
    fn bandwidth_gate_unlimited_never_blocks() {
        let mut gate = BandwidthGate::new(0);
        for _ in 0..100 {
            assert!(gate.allow_bytes(1_000_000));
        }
    }

    // 252.4: DHT quota enforcement
    #[test]
    fn dht_quota_rejects_after_window_exhausted() {
        let mut q = DhtQuota::new(2, Duration::from_secs(60));
        let peer = [0x55u8; 32];
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(!q.allow(peer), "DHT quota exhausted — must reject");
    }

    // 252.5: Backpressure AIMD convergence
    #[test]
    fn backpressure_aimd_responds_to_signals() {
        let mut ctrl = BackpressureAimd::new(100.0, 1.0, 200.0, 10.0, 0.5);

        // Congestion: halve
        ctrl.on_congestion();
        assert!(
            (ctrl.rate() - 50.0).abs() < f64::EPSILON,
            "rate should halve to 50"
        );

        // Recovery: additive increase
        ctrl.on_success();
        assert!(
            (ctrl.rate() - 60.0).abs() < f64::EPSILON,
            "rate should increase by 10 to 60"
        );
    }

    #[test]
    fn backpressure_aimd_does_not_exceed_max() {
        let mut ctrl = BackpressureAimd::new(190.0, 1.0, 200.0, 10.0, 0.5);
        ctrl.on_success();
        ctrl.on_success();
        assert!(ctrl.rate() <= 200.0, "rate must not exceed max");
        assert!(ctrl.is_at_maximum());
    }
}
