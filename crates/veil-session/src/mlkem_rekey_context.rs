//! decomposition : encapsulates
//! intra-session ML-KEM E2E key-rotation FSM + byte/time threshold
//! gating.
//!
//! Was four scattered inline references in `SessionRunner::run`:
//! * init triplet (state, bytes_since_rekey, last_rekey_at) at top of run
//! * threshold check before drain (idle && over-threshold ⇒ enter AwaitingAck)
//! * bytes accumulation on every tx/rx (3 call sites)
//! * `MlKemRekeyAck` arrival handler (extract dk_seed, reset bytes/last_rekey_at)
//!
//! Pure refactor of the state machine; the actual ML-KEM keypair
//! generation, frame encoding, and dispatcher dk-cache mutation stay
//! at the call site (those are intertwined with `&mut self` access to
//! `per_session_mlkem_dk` / `peer_mlkem_keys`, and moving them would
//! turn this slice into a much bigger one).
//!
//! API mirrors the structurally-similar rekey state idiom
//! (covered the rx_cipher_prev grace buffer; this slice
//! covers the parallel ML-KEM threshold ledger).

use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;

use veil_e2e::DK_SEED_BYTES;

/// Tracks the intra-session ML-KEM E2E key-rotation protocol state
///
pub enum MlKemRekeyState {
    /// No ML-KEM rekey in progress.
    Idle,
    /// We sent `MlKemRekeyEk` with a new encapsulation key and are waiting
    /// for `MlKemRekeyAck` from the peer. `dk_seed` is the 64-byte seed
    /// from which the decapsulation key for the new `ek` was derived.
    /// Once the peer acks, we commit `dk_seed` to
    /// `per_session_mlkem_dk[peer_id]` so the dispatcher can decrypt
    /// future E2E messages from the peer that were encrypted with the new
    /// key.
    /// `dk_seed` is wrapped in `Zeroizing` so that if the session tears
    /// down mid-rekey (context dropped while still `AwaitingAck`) the
    /// 64-byte decapsulation seed is wiped rather than left in freed heap.
    /// Mirrors the X25519 rekey sibling's zeroize-on-drop discipline.
    AwaitingAck {
        dk_seed: Zeroizing<[u8; DK_SEED_BYTES]>,
    },
}

pub struct MlKemRekeyContext {
    state: MlKemRekeyState,
    bytes_since_rekey: u64,
    last_rekey_at: Instant,
    bytes_threshold: u64,
    time_threshold: Duration,
}

impl MlKemRekeyContext {
    pub fn new(bytes_threshold: u64, time_threshold_secs: u64) -> Self {
        Self {
            state: MlKemRekeyState::Idle,
            bytes_since_rekey: 0,
            last_rekey_at: Instant::now(),
            bytes_threshold,
            time_threshold: Duration::from_secs(time_threshold_secs),
        }
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state, MlKemRekeyState::Idle)
    }

    pub fn is_awaiting_ack(&self) -> bool {
        matches!(self.state, MlKemRekeyState::AwaitingAck { .. })
    }

    /// Saturating add to the bytes-since-last-rekey counter. Called
    /// for every tx / rx body byte to track session traffic against
    /// the rekey threshold.
    pub fn record_bytes(&mut self, n: u64) {
        self.bytes_since_rekey = self.bytes_since_rekey.saturating_add(n);
    }

    /// Test whether either threshold is crossed. Caller should also
    /// check `is_idle` AND that ML-KEM infrastructure (per_session
    /// _mlkem_dk + peer_mlkem_keys) is wired up before initiating —
    /// extracting those checks would couple this struct to
    /// `SessionRunner` internals.
    pub fn should_initiate_rekey(&self, now: Instant) -> bool {
        self.bytes_since_rekey >= self.bytes_threshold
            || now.duration_since(self.last_rekey_at) >= self.time_threshold
    }

    /// Transition to `AwaitingAck` with the freshly-generated dk_seed.
    /// Caller must have just pushed the matching `MlKemRekeyEk` frame
    /// onto the priority queue.
    pub fn enter_awaiting_ack(&mut self, dk_seed: [u8; DK_SEED_BYTES]) {
        self.state = MlKemRekeyState::AwaitingAck {
            dk_seed: Zeroizing::new(dk_seed),
        };
    }

    /// Atomically transitions from `AwaitingAck` back to `Idle`
    /// returning the stashed `dk_seed`. Resets bytes-since-rekey
    /// and last_rekey_at on success.
    ///
    /// Returns `None` if we were not actually in `AwaitingAck` — a
    /// rare FSM-invariant violation that could happen if the same
    /// session received two `MlKemRekeyAck` frames back-to-back.
    /// Callers should log a warning in that case.
    pub fn take_dk_seed_on_ack(&mut self, now: Instant) -> Option<[u8; DK_SEED_BYTES]> {
        match std::mem::replace(&mut self.state, MlKemRekeyState::Idle) {
            MlKemRekeyState::AwaitingAck { dk_seed } => {
                self.bytes_since_rekey = 0;
                self.last_rekey_at = now;
                // Deref-copy the seed out; the `Zeroizing` wrapper wipes its
                // own storage as it drops at the end of this arm. The caller
                // immediately re-wraps the returned copy in mlocked storage.
                Some(*dk_seed)
            }
            MlKemRekeyState::Idle => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_context_starts_idle_with_zero_bytes() {
        let ctx = MlKemRekeyContext::new(1000, 60);
        assert!(ctx.is_idle());
        assert!(!ctx.is_awaiting_ack());
    }

    #[tokio::test]
    async fn record_bytes_accumulates_saturating() {
        let mut ctx = MlKemRekeyContext::new(1000, 60);
        ctx.record_bytes(500);
        ctx.record_bytes(300);
        assert!(
            !ctx.should_initiate_rekey(Instant::now()),
            "800 < 1000 ⇒ no rekey yet"
        );
        ctx.record_bytes(300);
        assert!(
            ctx.should_initiate_rekey(Instant::now()),
            "1100 >= 1000 ⇒ rekey due"
        );
    }

    #[tokio::test]
    async fn record_bytes_saturates_on_u64_max() {
        let mut ctx = MlKemRekeyContext::new(100, 60);
        ctx.record_bytes(u64::MAX);
        ctx.record_bytes(1); // would overflow without saturating_add
        assert!(ctx.should_initiate_rekey(Instant::now()));
    }

    #[tokio::test]
    async fn time_threshold_alone_can_trigger_rekey() {
        let mut ctx = MlKemRekeyContext::new(u64::MAX, 1);
        let later = ctx.last_rekey_at + Duration::from_secs(2);
        assert!(
            ctx.should_initiate_rekey(later),
            "2 s elapsed ≥ 1 s threshold ⇒ rekey due"
        );
        // Reset via take_dk_seed_on_ack flow.
        ctx.enter_awaiting_ack([0u8; DK_SEED_BYTES]);
        let _ = ctx.take_dk_seed_on_ack(later);
        // After reset, time threshold no longer crossed at `later`.
        assert!(!ctx.should_initiate_rekey(later));
    }

    #[tokio::test]
    async fn enter_awaiting_ack_changes_state() {
        let mut ctx = MlKemRekeyContext::new(1000, 60);
        ctx.enter_awaiting_ack([0xAAu8; DK_SEED_BYTES]);
        assert!(!ctx.is_idle());
        assert!(ctx.is_awaiting_ack());
    }

    #[tokio::test]
    async fn take_dk_seed_returns_seed_and_resets_counters() {
        let mut ctx = MlKemRekeyContext::new(1000, 60);
        ctx.record_bytes(2000);
        ctx.enter_awaiting_ack([0xBBu8; DK_SEED_BYTES]);
        let now_after = Instant::now() + Duration::from_secs(5);
        let seed = ctx.take_dk_seed_on_ack(now_after);
        assert_eq!(seed, Some([0xBBu8; DK_SEED_BYTES]));
        assert!(ctx.is_idle(), "state must transition back to Idle");
        assert!(
            !ctx.should_initiate_rekey(now_after),
            "bytes-since-rekey must reset to 0 after ack"
        );
    }

    #[tokio::test]
    async fn take_dk_seed_returns_none_when_not_awaiting_ack() {
        let mut ctx = MlKemRekeyContext::new(1000, 60);
        // Never entered AwaitingAck — the ack is a protocol violation.
        let result = ctx.take_dk_seed_on_ack(Instant::now());
        assert_eq!(result, None);
        assert!(ctx.is_idle());
    }

    #[tokio::test]
    async fn take_dk_seed_twice_returns_none_second_time() {
        let mut ctx = MlKemRekeyContext::new(1000, 60);
        ctx.enter_awaiting_ack([0xCCu8; DK_SEED_BYTES]);
        let _ = ctx.take_dk_seed_on_ack(Instant::now());
        let second = ctx.take_dk_seed_on_ack(Instant::now());
        assert_eq!(
            second, None,
            "second take must return None — state already Idle"
        );
    }
}
