//! Node-aggregate outbound bandwidth enforcement.
//!
//! `BandwidthGate` wraps a `TokenBucket` operating in byte-mode:
//! `capacity = max_burst_bytes`, `refill_rate = bytes_per_second`.
//!
//! All outbound paths call `allow_bytes(n)` before sending `n` bytes.
//! Frames that exceed the budget are dropped (or queued by the caller).

use std::time::Instant;

use super::rate_limiter::TokenBucket;

/// Node-wide bandwidth throttle (inbound or outbound).
///
/// Configured by [`crate::cfg::NodeCapacityConfig`] bandwidth fields.
/// A value of `0` means unlimited — `allow_bytes` always returns `true`.
/// Use `NodeCapacityConfig::bandwidth_kbps_to_gate` to convert the config's
/// `i64` value (`-1` = unlimited) to the `u32` expected here.
///
/// # Units note
///
/// The `kbps` суффикс в `NodeCapacityConfig::max_inbound_bandwidth_kbps`
/// и [`Self::new`]'s `max_kbps` parameter is **misleading**: by industry
/// convention "kbps" = **kilobits per second** (decimal, ÷8), but this
/// gate's math (`bytes_per_sec = kbps * 1024.0`) treats it as **kibibytes
/// per second** (binary, ×1024). Default config value `100_000` therefore
/// yields:
/// * Steady rate: `100_000 × 1024 = 102_400_000 bytes/sec` ≈ **97.7 MiB/s**
///   ≈ **820 Mbit/s** (NOT 100 Mbit/s as the name implies).
/// * Burst capacity: `2 × steady = ~195 MiB`.
///
/// Operators tuning the gate должны интерпретировать the config value
/// as **KiB/s** (binary kibibytes/sec), not kilobits/sec. A future cleanup
/// (tracked in audit follow-up) will rename the field к
/// `max_inbound_kib_per_sec` to remove the ambiguity.
#[derive(Debug)]
pub struct BandwidthGate {
    /// `None` when unlimited.
    bucket: Option<TokenBucket>,
    /// Configured limit in kbps (0 = unlimited).
    limit_kbps: u32,
    /// Total bytes passed through (accepted).
    pub total_bytes: u64,
    /// Total bytes dropped (rejected).
    pub dropped_bytes: u64,
}

impl BandwidthGate {
    /// Create a gate enforcing `max_kbps` **kibibytes per second** (NOT
    /// kilobits — see struct-level "Units note" docstring). `0` means
    /// unlimited; burst capacity is fixed at `2× steady rate` (a
    /// 2-second burst window).
    pub fn new(max_kbps: u32) -> Self {
        if max_kbps == 0 {
            return Self {
                bucket: None,
                limit_kbps: 0,
                total_bytes: 0,
                dropped_bytes: 0,
            };
        }
        let bytes_per_sec = max_kbps as f64 * 1024.0;
        let burst_bytes = bytes_per_sec * 2.0;
        Self {
            bucket: Some(TokenBucket::new(burst_bytes, bytes_per_sec)),
            limit_kbps: max_kbps,
            total_bytes: 0,
            dropped_bytes: 0,
        }
    }

    /// Attempt to send `byte_count` bytes through the gate.
    ///
    /// Returns `true` if the budget permits; `false` if the frame should be
    /// dropped or queued. Unlimited gates always return `true`.
    /// Create with explicit burst capacity.
    pub fn with_burst(max_kbps: u32, burst_bytes: f64) -> Self {
        if max_kbps == 0 {
            return Self {
                bucket: None,
                limit_kbps: 0,
                total_bytes: 0,
                dropped_bytes: 0,
            };
        }
        let bytes_per_sec = max_kbps as f64 * 1024.0;
        Self {
            bucket: Some(TokenBucket::new(burst_bytes, bytes_per_sec)),
            limit_kbps: max_kbps,
            total_bytes: 0,
            dropped_bytes: 0,
        }
    }

    pub fn allow_bytes(&mut self, byte_count: usize) -> bool {
        match &mut self.bucket {
            None => {
                self.total_bytes += byte_count as u64;
                true
            }
            Some(bucket) => {
                if bucket.allow_n_at(byte_count as f64, Instant::now()) {
                    self.total_bytes += byte_count as u64;
                    true
                } else {
                    self.dropped_bytes += byte_count as u64;
                    false
                }
            }
        }
    }

    /// `true` if this gate is configured with no limit.
    pub fn is_unlimited(&self) -> bool {
        self.bucket.is_none()
    }

    /// Configured limit in kbps (0 = unlimited).
    pub fn limit_kbps(&self) -> u32 {
        self.limit_kbps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_gate_always_allows() {
        let mut g = BandwidthGate::new(0);
        assert!(g.is_unlimited());
        assert!(g.allow_bytes(usize::MAX));
    }

    #[test]
    fn burst_capacity_exhausted() {
        // 1 kbps = 1024 bytes/sec, burst = 2048 bytes
        let mut g = BandwidthGate::new(1);
        // Burst allows 2048 bytes in one shot.
        assert!(
            g.allow_bytes(2048),
            "burst capacity should allow initial bytes"
        );
        // Next byte exceeds remaining budget.
        assert!(!g.allow_bytes(1), "exhausted burst must deny further bytes");
    }

    #[test]
    fn small_chunks_within_burst_are_allowed() {
        // 10 kbps = 10240 bytes/sec, burst = 20480 bytes
        let mut g = BandwidthGate::new(10);
        let mut total = 0usize;
        for _ in 0..10 {
            if g.allow_bytes(1024) {
                total += 1024;
            } else {
                break;
            }
        }
        // Burst is 20480 bytes — all 10 chunks of 1024 must pass.
        assert_eq!(total, 10 * 1024, "all chunks within burst must be allowed");
    }

    #[test]
    fn with_burst_constructor_applies_custom_burst() {
        // 1 kbps, burst only 512 bytes
        let mut g = BandwidthGate::with_burst(1, 512.0);
        assert!(g.allow_bytes(512), "512-byte burst must be allowed");
        assert!(!g.allow_bytes(1), "exceeding burst must be denied");
    }
}
