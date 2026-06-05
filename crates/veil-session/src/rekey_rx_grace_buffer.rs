//! decomposition : bounded ring buffer of previous
//! `rx_cipher` instances stashed at rekey-switch time so in-flight
//! initiator frames sealed с the OLD tx_cipher (sent BEFORE the
//! initiator received our RekeyAck) can still be decrypted instead of
//! triggering а session.violation.
//!
//! Background:
//! * **** introduced the time-based grace window (was
//!   frame-count-based, exhausted faster than RTT under chat-node
//!   load).
//! * **-** widened the buffer от а single
//!   `Option<SessionCipher>` к а 3-deep `VecDeque` so two back-to-back
//!   rekeys (gen-N-1 still в grace when gen-N rekey starts) don't
//!   orphan gen-N-2 frames.
//!
//! Was inline VecDeque + ~30 LoC inline в `SessionRunner::run` —
//! extracted к а dedicated struct with three primitives и an `Outcome`
//! that surfaces cap-evict events back к the caller для logging /
//! metrics (`session.rekey.grace.cap_evict` warn + `inc_rekey_grace_cap
//! _eviction` counter).
//!
//! FIFO ordering: newest entries at the back, oldest at the front.
//! `prune_expired` walks the front because expired entries cluster
//! there; `try_open` walks the back-to-front (newest-first) because
//! the most-recent prev cipher is the most likely match для an
//! immediately-post-rekey arrival.

use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

use veil_crypto::session_cipher::SessionCipher;

/// Successful fallback decrypt result. `slot_from_newest == 0` means
/// "the just-rekeyed prev cipher saved this frame"; higher numbers
/// mean the entry was older. `age_ms` is the time elapsed since the
/// entry was pushed (not the time-until-expiry — the caller's logging
/// already had this convention so we preserve it verbatim).
pub struct FallbackHit {
    pub slot_from_newest: usize,
    pub age_ms: u128,
    pub plaintext: Vec<u8>,
}

/// Result of `push` indicating whether а cap-eviction was needed к
/// make room. Cap-evictions are rare (only under back-to-back rekey
/// scenarios that outpaced the 30 s grace window) but visibility-
/// worthy because they correlate с traffic-burst patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushOutcome {
    pub evicted_due_to_capacity: bool,
}

pub struct RekeyRxGraceBuffer {
    /// (cipher, deadline-Instant). FIFO: oldest at front, newest at back.
    entries: VecDeque<(SessionCipher, Instant)>,
    capacity: usize,
    grace_duration: Duration,
}

impl RekeyRxGraceBuffer {
    pub fn new(capacity: usize, grace_duration: Duration) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            grace_duration,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` если grace buffer is empty.  Companion к [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// decomposition : exposed for log-formatting
    /// inside the extracted `handle_rekey_init_arm` helper.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Pop expired entries от the front. Cheap: single Instant
    /// comparison per popped entry. Should be called BEFORE each
    /// decrypt attempt к keep buffer length proportional к
    /// in-flight rekey overlap rather than session-uptime.
    pub fn prune_expired(&mut self, now: Instant) {
        while let Some(&(_, deadline)) = self.entries.front()
            && now >= deadline
        {
            self.entries.pop_front();
        }
    }

    /// Try к decrypt `body` using each cached prev cipher в
    /// newest-first order. On first success: returns `Some(FallbackHit)`
    /// и that prev cipher's frame counter has advanced (mutating
    /// `iter_mut` is intentional — а subsequent success at the same
    /// slot would use the next nonce). On no-match: returns `None`
    /// no counter advanced.
    pub fn try_open(&mut self, body: &[u8], aad: &[u8], now: Instant) -> Option<FallbackHit> {
        let grace = self.grace_duration;
        self.entries.iter_mut().rev().enumerate().find_map(
            |(slot_from_newest, (prev, deadline))| {
                let deadline = *deadline;
                prev.open(body, aad).ok().map(|plaintext| {
                    let age_ms = if deadline > now {
                        grace
                            .saturating_sub(deadline.duration_since(now))
                            .as_millis()
                    } else {
                        grace.as_millis()
                    };
                    FallbackHit {
                        slot_from_newest,
                        age_ms,
                        plaintext,
                    }
                })
            },
        )
    }

    /// Push а freshly-displaced rx cipher с deadline = `now + grace_duration`.
    /// Если at capacity, the oldest entry is dropped to make room и
    /// `evicted_due_to_capacity = true` is returned (caller logs +
    /// inc-metric).
    pub fn push(&mut self, cipher: SessionCipher, now: Instant) -> PushOutcome {
        let mut evicted = false;
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
            evicted = true;
        }
        self.entries.push_back((cipher, now + self.grace_duration));
        PushOutcome {
            evicted_due_to_capacity: evicted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_cipher(seed: u8) -> SessionCipher {
        let key = [seed; 32];
        SessionCipher::new(&key, true)
    }

    #[tokio::test]
    async fn prune_expired_drops_only_old_entries() {
        let mut buf = RekeyRxGraceBuffer::new(3, Duration::from_millis(100));
        let t0 = Instant::now();
        buf.push(fresh_cipher(0xAA), t0);
        buf.push(fresh_cipher(0xBB), t0 + Duration::from_millis(50));
        buf.push(fresh_cipher(0xCC), t0 + Duration::from_millis(90));
        // At t = t0 + 110 ms: first entry's deadline (t0+100) expired
        // second (t0+150) и third (t0+190) still alive.
        buf.prune_expired(t0 + Duration::from_millis(110));
        assert_eq!(buf.len(), 2);
    }

    #[tokio::test]
    async fn push_at_capacity_evicts_oldest_and_signals() {
        let mut buf = RekeyRxGraceBuffer::new(2, Duration::from_secs(30));
        let t = Instant::now();
        let o0 = buf.push(fresh_cipher(0xA), t);
        let o1 = buf.push(fresh_cipher(0xB), t + Duration::from_millis(1));
        assert!(!o0.evicted_due_to_capacity);
        assert!(!o1.evicted_due_to_capacity);
        let o2 = buf.push(fresh_cipher(0xC), t + Duration::from_millis(2));
        assert!(o2.evicted_due_to_capacity, "third push at cap=2 must evict");
        assert_eq!(buf.len(), 2);
    }

    #[tokio::test]
    async fn try_open_returns_none_when_no_prev_match() {
        let mut buf = RekeyRxGraceBuffer::new(3, Duration::from_secs(30));
        let now = Instant::now();
        buf.push(fresh_cipher(0xAA), now);
        // Random ciphertext won't match the prev cipher.
        let bogus_body = vec![0u8; 32];
        let bogus_aad = vec![0u8; 8];
        assert!(buf.try_open(&bogus_body, &bogus_aad, now).is_none());
    }

    #[tokio::test]
    async fn try_open_finds_newest_match_first() {
        // Build а matching pair: encrypt c sealing cipher, decrypt с
        // matching opening cipher. Place opening cipher in slot 0
        // (newest); add unrelated ciphers behind it.
        use veil_crypto::session_cipher::frame_aad;
        use veil_proto::family::{ControlMsg, FrameFamily};

        let key = [0x42u8; 32];
        let mut sealer = SessionCipher::new(&key, true);
        let opener = SessionCipher::new(&key, true);

        let aad = frame_aad(FrameFamily::Control as u8, ControlMsg::Ping as u16);
        let plaintext = b"hello".to_vec();
        let ciphertext = sealer.seal(&plaintext, &aad).unwrap();

        let mut buf = RekeyRxGraceBuffer::new(3, Duration::from_secs(30));
        let now = Instant::now();
        // Push two unrelated ciphers FIRST (older entries), then the
        // matching one LAST (so it ends up at slot_from_newest = 0).
        buf.push(fresh_cipher(0xAA), now);
        buf.push(fresh_cipher(0xBB), now + Duration::from_millis(1));
        buf.push(opener, now + Duration::from_millis(2));

        let hit = buf
            .try_open(&ciphertext, &aad, now + Duration::from_millis(3))
            .expect("matching cipher in slot 0 must succeed");
        assert_eq!(hit.slot_from_newest, 0);
        assert_eq!(hit.plaintext, plaintext);
    }

    #[tokio::test]
    async fn empty_buffer_methods_are_safe() {
        let mut buf = RekeyRxGraceBuffer::new(3, Duration::from_secs(30));
        let now = Instant::now();
        buf.prune_expired(now); // no-op
        assert!(buf.try_open(&[], &[], now).is_none());
        assert_eq!(buf.len(), 0);
    }
}
