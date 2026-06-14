//! Per-receiver token-bucket rate limiter. In-memory only — does not
//! survive restart. Resets gradually (one token per `60 / capacity`
//! seconds). Intentionally simple: bursty senders get a few puts, then
//! throttle to the steady-state rate.
//!
//! ## Why per-receiver and not per-sender
//!
//! Sybil-resistant. An attacker who creates N fake sender identities
//! can still only push at the receiver's rate-limit; per-sender limits
//! get bypassed by minting more identities. See lib.rs `MailboxConfig`
//! for the broader rationale.

use std::collections::{BTreeSet, HashMap};

/// Token bucket per receiver. At construction, the bucket is full
/// (`capacity` tokens). Each `check_and_consume` decrements by 1 if
/// possible; otherwise returns false. Tokens regenerate at
/// `capacity / 60` per second (= 1 token every `60 / capacity`
/// seconds).
///
/// ** the per-receiver `HashMap` is
/// hard-capped at [`MAX_BUCKETS`] entries. Pre-fix, an attacker who
/// could spam `MailboxPut` with one different receiver_id per request
/// would force unbounded HashMap growth (32 + ~24 bytes per entry).
/// Once the cap is hit, the LRU bucket (oldest `last_refill`) is
/// evicted to make room for the newcomer — a fresh receiver always
/// starts with a full bucket, so eviction does not unfairly reset a
/// throttled receiver's allowance.
///
/// Eviction picks the victim via the `lru` `BTreeSet` minimum in
/// O(log n), not an O(n) `min_by_key` scan under the lock — otherwise an
/// attacker keeping the map saturated and rotating `receiver_id` per PUT
/// would force a full-map scan on every request (cheap PUT → O(n) work),
/// turning the cap defense into an amplifier. Mirrors `IdentityWriteQuota`.
#[derive(Debug)]
pub(crate) struct ReceiverRateLimiter {
    /// Maximum tokens a receiver may have at once (also the steady-
    /// state per-minute rate).
    capacity: u32,
    /// Per-receiver state.
    buckets: HashMap<[u8; 32], BucketState>,
    /// Secondary LRU index ordered by `(last_refill, receiver)` so the
    /// at-capacity victim is the minimum (O(log n)). Kept in sync with
    /// `buckets` on every insert / refill-update / eviction; invariant:
    /// `lru.len() == buckets.len()`.
    lru: BTreeSet<(u64, [u8; 32])>,
}

/// Maximum number of receiver buckets held in memory. At ~56 bytes
/// per entry (32 B key + ~24 B value), 65 536 entries cap the bucket
/// HashMap to ≈ 3.5 MiB. Plenty for a realistic mailbox-relay (one
/// entry per recipient currently using the relay) and a hard ceiling
/// against attacker-supplied receiver_id flood.
pub(crate) const MAX_BUCKETS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct BucketState {
    /// Current token count, scaled by `SCALE` for fractional refill.
    tokens_scaled: u64,
    /// Last update time (Unix seconds).
    last_refill: u64,
}

/// Fixed-point scale for fractional token refill. At capacity=60 with
/// SCALE=1000 a token = 1000 ticks; refill rate = capacity*SCALE/60 =
/// 1000 ticks per second = 1 whole token per second.
const SCALE: u64 = 1000;

impl ReceiverRateLimiter {
    pub(crate) fn new(capacity_per_minute: u32) -> Self {
        Self {
            capacity: capacity_per_minute,
            buckets: HashMap::new(),
            lru: BTreeSet::new(),
        }
    }

    /// Returns `true` if a token was available and consumed. `false`
    /// means the receiver is rate-limited; caller should reject the
    /// put.
    pub(crate) fn check_and_consume(&mut self, receiver: [u8; 32], now_secs: u64) -> bool {
        if self.capacity == 0 {
            // Disabled: always allow.
            return true;
        }
        let cap_scaled = self.capacity as u64 * SCALE;
        let refill_per_sec = cap_scaled / 60;
        // Disjoint field borrows so the eviction/insert paths can touch both
        // `buckets` and the `lru` index without going through `&mut self`.
        let Self { buckets, lru, .. } = self;

        // Enforce MAX_BUCKETS before inserting a NEW entry: evict the
        // least-recently-refilled bucket via the LRU index minimum (O(log n)).
        if !buckets.contains_key(&receiver)
            && buckets.len() >= MAX_BUCKETS
            && let Some(&victim) = lru.iter().next()
        {
            lru.remove(&victim);
            buckets.remove(&victim.1);
        }

        match buckets.get_mut(&receiver) {
            Some(bucket) => {
                // Refill since last update; reposition in the LRU index when
                // `last_refill` advances (remove old key, insert new).
                let elapsed = now_secs.saturating_sub(bucket.last_refill);
                if elapsed > 0 {
                    let added = elapsed.saturating_mul(refill_per_sec);
                    bucket.tokens_scaled =
                        bucket.tokens_scaled.saturating_add(added).min(cap_scaled);
                    lru.remove(&(bucket.last_refill, receiver));
                    bucket.last_refill = now_secs;
                    lru.insert((now_secs, receiver));
                }
                if bucket.tokens_scaled >= SCALE {
                    bucket.tokens_scaled -= SCALE;
                    true
                } else {
                    false
                }
            }
            None => {
                // Fresh receiver: full bucket, consume one. (capacity >= 1 here,
                // so cap_scaled >= SCALE — no underflow.)
                buckets.insert(
                    receiver,
                    BucketState {
                        tokens_scaled: cap_scaled - SCALE,
                        last_refill: now_secs,
                    },
                );
                lru.insert((now_secs, receiver));
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_4_p1_zero_capacity_means_disabled() {
        let mut r = ReceiverRateLimiter::new(0);
        for _ in 0..1000 {
            assert!(r.check_and_consume([0u8; 32], 0));
        }
    }

    #[test]
    fn t1_4_p1_burst_up_to_capacity_then_blocks() {
        let mut r = ReceiverRateLimiter::new(60);
        // First 60 succeed (full bucket on first contact).
        for i in 0..60 {
            assert!(r.check_and_consume([0u8; 32], 0), "iteration {i}");
        }
        // 61st without time advance must fail.
        assert!(!r.check_and_consume([0u8; 32], 0));
    }

    #[test]
    fn t1_4_p1_refill_after_one_second() {
        let mut r = ReceiverRateLimiter::new(60);
        for _ in 0..60 {
            r.check_and_consume([7u8; 32], 0);
        }
        assert!(!r.check_and_consume([7u8; 32], 0));
        // 1 second later: 60/60 = 1 token refilled.
        assert!(r.check_and_consume([7u8; 32], 1));
        // Next call same second fails.
        assert!(!r.check_and_consume([7u8; 32], 1));
    }

    #[test]
    fn lru_index_stays_in_sync_with_buckets() {
        // Invariant: exactly one lru entry per bucket, across inserts and
        // refill-driven last_refill repositions.
        let mut r = ReceiverRateLimiter::new(60);
        for i in 0..10u8 {
            r.check_and_consume([i; 32], 0);
        }
        assert_eq!(r.lru.len(), r.buckets.len());
        // Advance time so existing buckets reposition on next touch.
        for i in 0..10u8 {
            r.check_and_consume([i; 32], 5);
        }
        assert_eq!(r.lru.len(), r.buckets.len());
        assert_eq!(r.lru.len(), 10);
    }

    #[test]
    fn t1_4_p1_independent_per_receiver() {
        let mut r = ReceiverRateLimiter::new(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        // A burns its 2 tokens.
        assert!(r.check_and_consume(a, 0));
        assert!(r.check_and_consume(a, 0));
        assert!(!r.check_and_consume(a, 0));
        // B still has its full bucket.
        assert!(r.check_and_consume(b, 0));
        assert!(r.check_and_consume(b, 0));
        assert!(!r.check_and_consume(b, 0));
    }
}
