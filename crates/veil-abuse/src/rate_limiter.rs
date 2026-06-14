//! Rate limiter trait and token-bucket implementation.
//!
//! `TokenBucket` implements a standard leaky-bucket / token-bucket algorithm.
//! Tokens refill continuously at `refill_rate` tokens per second up to `capacity`.
//! Each call to `allow` consumes one token; returns `false` when the bucket is empty.

use std::time::Instant;

// ── RateLimiter trait ─────────────────────────────────────────────────────────

/// Generic rate-limiter interface.
pub trait RateLimiter {
    /// Attempt to consume one token. Returns `true` if allowed, `false` if throttled.
    fn allow(&mut self) -> bool;
}

// ── TokenBucket ───────────────────────────────────────────────────────────────

/// Single-peer token-bucket rate limiter.
///
/// * `capacity` — maximum burst size (tokens).
/// * `refill_rate` — tokens added per second.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new bucket filled to `capacity`.
    ///
    /// Non-positive values are clamped to a small epsilon to prevent division
    /// by zero or silent stalls — this avoids a panic from misconfigured values.
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        let capacity = if capacity > 0.0 { capacity } else { 1.0 };
        let refill_rate = if refill_rate > 0.0 { refill_rate } else { 1.0 };
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time since last call.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// The instant of the last token refill — used externally as an LRU timestamp.
    pub fn last_refill(&self) -> Instant {
        self.last_refill
    }

    /// Attempt to consume one token at the given instant (injectable for tests).
    pub fn allow_at(&mut self, now: Instant) -> bool {
        self.allow_n_at(1.0, now)
    }

    /// Attempt to consume `n` tokens at the given instant.
    ///
    /// Used for byte-rate enforcement where `n = byte_count`.
    /// Returns `false` without consuming any tokens if `n > capacity`.
    pub fn allow_n_at(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Current token level (for diagnostics).
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

impl RateLimiter for TokenBucket {
    fn allow(&mut self) -> bool {
        self.allow_at(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn full_bucket_allows_burst() {
        let mut tb = TokenBucket::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(tb.allow_at(Instant::now()));
        }
    }

    #[test]
    fn empty_bucket_denies() {
        let mut tb = TokenBucket::new(2.0, 0.1);
        let t0 = Instant::now();
        assert!(tb.allow_at(t0));
        assert!(tb.allow_at(t0));
        // bucket empty — no time has passed
        assert!(!tb.allow_at(t0));
    }

    #[test]
    fn refill_restores_tokens() {
        let mut tb = TokenBucket::new(1.0, 10.0); // 10 tokens/sec
        let t0 = Instant::now();
        assert!(tb.allow_at(t0)); // drain
        assert!(!tb.allow_at(t0)); // empty
        // After 200ms → 10 * 0.2 = 2 new tokens (capped at 1 by capacity)
        let t1 = t0 + Duration::from_millis(200);
        assert!(tb.allow_at(t1));
    }

    #[test]
    fn capacity_caps_tokens() {
        let mut tb = TokenBucket::new(3.0, 10.0);
        let t0 = Instant::now();
        // Advance 100s — would generate 1000 tokens, but cap is 3
        let t1 = t0 + Duration::from_secs(100);
        tb.allow_at(t1); // triggers refill, eats 1
        assert!((tb.tokens - 2.0).abs() < 0.01, "tokens={}", tb.tokens);
    }

    #[test]
    fn rate_limiter_trait_dispatch() {
        let mut limiter: Box<dyn RateLimiter> = Box::new(TokenBucket::new(1.0, 1.0));
        assert!(limiter.allow());
    }
}
