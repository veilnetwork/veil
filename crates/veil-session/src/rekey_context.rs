//! decomposition : encapsulates the X25519
//! rekey FSM + threshold ledger + per-session generation counter.
//!
//! Was scattered ~12 inline references in `SessionRunner::run` —
//! the most invasive slice yet because rekey-state mutations live in:
//! * init triplet (state, bytes_since_rekey, last_rekey_at) + generation
//! * threshold check (-6.33 visibility tags rekey_generation
//!   on every init.tx / init.rx / ack.tx / ack.rx / complete event)
//! * bytes accumulation on 4 tx/rx call sites
//! * RekeyInit arrival with d916e3b mutual-collision tie-breaker
//! * Responder rekey-complete (after RekeyAck out → switch ciphers)
//! * Initiator rekey-complete (after peer's RekeyAck arrives)
//!
//! Pure refactor; keypair generation, frame encoding, and cipher swap
//! stay at call sites because they are coupled with `&mut self` access to
//! `tx_cipher`/`rx_cipher`/`session_id`. This struct manages just
//! the FSM + threshold/generation arithmetic.

use std::time::Duration;
use tokio::time::Instant;

use veil_crypto::kex;

/// Tracks the X25519 rekey-protocol state.
pub enum RekeyState {
    /// No rekey in progress.
    Idle,
    /// We sent `RekeyInit` and are waiting for `RekeyAck` from the peer.
    /// `since` records when we entered this state so a never-answered init
    /// (peer crash / lost frame — there is no rekey retransmit) can be timed
    /// out back to `Idle` instead of pinning the FSM forever (audit cycle-8 H7).
    AwaitingAck {
        keypair: kex::EphemeralKeypair,
        since: Instant,
    },
}

/// Reason a rekey was triggered — used in the visibility log
/// `session.rekey.init.tx trigger=…` so operator can judge mix
/// between byte / time / nonce-pressure events across the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyTrigger {
    BytesThreshold,
    TimeThreshold,
    NonceWatermark,
}

impl RekeyTrigger {
    pub fn as_log_str(self) -> &'static str {
        match self {
            Self::BytesThreshold => "bytes_threshold",
            Self::TimeThreshold => "time_threshold",
            Self::NonceWatermark => "nonce_watermark",
        }
    }
}

pub struct RekeyContext {
    state: RekeyState,
    bytes_since_rekey: u64,
    last_rekey_at: Instant,
    bytes_threshold: u64,
    time_threshold: Duration,
    generation: u64,
}

impl RekeyContext {
    pub fn new(bytes_threshold: u64, time_threshold_secs: u64) -> Self {
        Self {
            state: RekeyState::Idle,
            bytes_since_rekey: 0,
            last_rekey_at: Instant::now(),
            bytes_threshold,
            time_threshold: Duration::from_secs(time_threshold_secs),
            generation: 0,
        }
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state, RekeyState::Idle)
    }

    pub fn is_awaiting_ack(&self) -> bool {
        matches!(self.state, RekeyState::AwaitingAck { .. })
    }

    pub fn record_bytes(&mut self, n: u64) {
        self.bytes_since_rekey = self.bytes_since_rekey.saturating_add(n);
    }

    pub fn bytes_since_rekey(&self) -> u64 {
        self.bytes_since_rekey
    }

    pub fn last_rekey_at(&self) -> Instant {
        self.last_rekey_at
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Decide whether a rekey should fire NOW, returning the trigger
    /// reason (or `None` if no threshold crossed). Caller must
    /// also have verified `is_idle` to avoid double-initiating.
    /// `nonce_pressure` is computed by the caller from the AEAD
    /// counter watermark.
    pub fn should_initiate_rekey(
        &self,
        now: Instant,
        nonce_pressure: bool,
    ) -> Option<RekeyTrigger> {
        if nonce_pressure {
            return Some(RekeyTrigger::NonceWatermark);
        }
        if self.bytes_since_rekey >= self.bytes_threshold {
            return Some(RekeyTrigger::BytesThreshold);
        }
        if now.duration_since(self.last_rekey_at) >= self.time_threshold {
            return Some(RekeyTrigger::TimeThreshold);
        }
        None
    }

    /// Transition to `AwaitingAck { keypair, since: now }`. Caller has just
    /// pushed the matching `RekeyInit` frame onto the priority queue.
    pub fn enter_awaiting_ack(&mut self, keypair: kex::EphemeralKeypair, now: Instant) {
        self.state = RekeyState::AwaitingAck {
            keypair,
            since: now,
        };
    }

    /// audit cycle-8 H7: returns true if we have been in `AwaitingAck` longer
    /// than `timeout` — the peer never answered the `RekeyInit` (it crashed, or
    /// the `RekeyAck` was lost and there is no rekey retransmit). The caller
    /// resets to `Idle` so a fresh rekey (and the nonce-exhaustion failsafe,
    /// which is gated on `is_idle`) can fire again instead of the session being
    /// stuck unable to ever rekey.
    pub fn awaiting_ack_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        match &self.state {
            RekeyState::AwaitingAck { since, .. } => now.duration_since(*since) >= timeout,
            RekeyState::Idle => false,
        }
    }

    /// Atomically take the keypair from `AwaitingAck` and transition to
    /// `Idle`. Returns `None` if state was already Idle (FSM
    /// invariant violation; caller treats as no-op).
    pub fn take_initiator_keypair(&mut self) -> Option<kex::EphemeralKeypair> {
        match std::mem::replace(&mut self.state, RekeyState::Idle) {
            RekeyState::AwaitingAck { keypair, .. } => Some(keypair),
            RekeyState::Idle => None,
        }
    }

    /// Reset to `Idle` without extracting a keypair. Used in the d916e3b
    /// collision-aborted_init path: own init is dropped, then we
    /// fall through to the responder path with peer's RekeyInit.
    pub fn reset_to_idle(&mut self) {
        self.state = RekeyState::Idle;
    }

    /// Push `last_rekey_at` to a new instant without incrementing generation
    /// or touching byte counter. Used by the kept_init back-off path: when
    /// peer signals it kept its init and dropped ours, we want to suppress
    /// our own time-threshold rekey trigger for the next grace window so
    /// both sides don't immediately re-collide. Byte counter stays so
    /// byte-threshold can still fire if traffic keeps coming.
    pub fn touch_last_rekey_at(&mut self, now: Instant) {
        self.last_rekey_at = now;
    }

    /// Mark a rekey-complete event: increment generation, reset
    /// bytes counter, update last_rekey_at. Called from both
    /// responder-side (after RekeyAck-tx) and initiator-side (after
    /// peer's RekeyAck-rx) completion paths.
    pub fn record_rekey_complete(&mut self, now: Instant) {
        self.bytes_since_rekey = 0;
        self.last_rekey_at = now;
        self.generation = self.generation.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_keypair() -> kex::EphemeralKeypair {
        kex::generate_ephemeral()
    }

    #[tokio::test]
    async fn new_starts_idle_zero_bytes_gen_zero() {
        let ctx = RekeyContext::new(1000, 60);
        assert!(ctx.is_idle());
        assert_eq!(ctx.bytes_since_rekey(), 0);
        assert_eq!(ctx.generation(), 0);
    }

    #[tokio::test]
    async fn record_bytes_advances_threshold_check() {
        let mut ctx = RekeyContext::new(1000, 3600);
        let now = ctx.last_rekey_at();
        ctx.record_bytes(500);
        assert_eq!(ctx.should_initiate_rekey(now, false), None);
        ctx.record_bytes(600);
        assert_eq!(
            ctx.should_initiate_rekey(now, false),
            Some(RekeyTrigger::BytesThreshold)
        );
    }

    #[tokio::test]
    async fn time_threshold_only_triggers_when_bytes_low() {
        let mut ctx = RekeyContext::new(u64::MAX, 1);
        let later = ctx.last_rekey_at() + Duration::from_secs(2);
        assert_eq!(
            ctx.should_initiate_rekey(later, false),
            Some(RekeyTrigger::TimeThreshold)
        );
        // Reset by completing
        ctx.record_rekey_complete(later);
        assert_eq!(ctx.should_initiate_rekey(later, false), None);
    }

    #[tokio::test]
    async fn nonce_pressure_takes_priority_over_other_triggers() {
        let mut ctx = RekeyContext::new(1000, 60);
        ctx.record_bytes(2000); // would be BytesThreshold
        assert_eq!(
            ctx.should_initiate_rekey(Instant::now(), true),
            Some(RekeyTrigger::NonceWatermark)
        );
    }

    #[tokio::test]
    async fn enter_and_take_keypair_round_trips() {
        let mut ctx = RekeyContext::new(1000, 60);
        let kp = fresh_keypair();
        let pubkey = kp.public_key;
        ctx.enter_awaiting_ack(kp, Instant::now());
        assert!(ctx.is_awaiting_ack());
        let taken = ctx.take_initiator_keypair().expect("must return keypair");
        assert_eq!(taken.public_key, pubkey);
        assert!(ctx.is_idle(), "transitions back to Idle");
    }

    #[tokio::test]
    async fn take_keypair_returns_none_when_idle() {
        let mut ctx = RekeyContext::new(1000, 60);
        assert!(ctx.take_initiator_keypair().is_none());
    }

    #[tokio::test]
    async fn reset_to_idle_drops_keypair() {
        let mut ctx = RekeyContext::new(1000, 60);
        ctx.enter_awaiting_ack(fresh_keypair(), Instant::now());
        ctx.reset_to_idle();
        assert!(ctx.is_idle());
        // Subsequent take returns None — keypair was dropped.
        assert!(ctx.take_initiator_keypair().is_none());
    }

    /// audit cycle-8 H7: a never-answered RekeyInit must time out so the FSM
    /// doesn't pin in AwaitingAck forever (which would also block the
    /// nonce-exhaustion failsafe).
    #[tokio::test]
    async fn awaiting_ack_times_out_and_idle_never_does_h7() {
        let mut ctx = RekeyContext::new(1000, 60);
        let t0 = Instant::now();
        ctx.enter_awaiting_ack(fresh_keypair(), t0);
        assert!(ctx.is_awaiting_ack());
        // Within the window: not timed out.
        assert!(!ctx.awaiting_ack_timed_out(t0 + Duration::from_secs(30), Duration::from_secs(60)));
        // Past the window: timed out.
        assert!(ctx.awaiting_ack_timed_out(t0 + Duration::from_secs(61), Duration::from_secs(60)));
        // After reset, Idle never reports a timeout.
        ctx.reset_to_idle();
        assert!(ctx.is_idle());
        assert!(
            !ctx.awaiting_ack_timed_out(t0 + Duration::from_secs(600), Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn record_rekey_complete_resets_bytes_and_increments_generation() {
        let mut ctx = RekeyContext::new(1000, 60);
        ctx.record_bytes(500);
        let later = ctx.last_rekey_at() + Duration::from_secs(5);
        ctx.record_rekey_complete(later);
        assert_eq!(ctx.bytes_since_rekey(), 0);
        assert_eq!(ctx.generation(), 1);
        assert_eq!(ctx.last_rekey_at(), later);
    }

    #[tokio::test]
    async fn generation_saturates_at_u64_max() {
        let mut ctx = RekeyContext::new(1000, 60);
        for _ in 0..3 {
            ctx.record_rekey_complete(Instant::now());
        }
        assert_eq!(ctx.generation(), 3);
    }

    #[tokio::test]
    async fn trigger_log_strings_match_inline_format() {
        assert_eq!(RekeyTrigger::BytesThreshold.as_log_str(), "bytes_threshold");
        assert_eq!(RekeyTrigger::TimeThreshold.as_log_str(), "time_threshold");
        assert_eq!(RekeyTrigger::NonceWatermark.as_log_str(), "nonce_watermark");
    }
}
