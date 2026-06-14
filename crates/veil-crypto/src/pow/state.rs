use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use veil_error::{ConfigError, Result};

use super::score::{PowScore, u32_to_nonce};
use super::search::{PowProgress, PowResult, PowStopReason};
use crate::Base64Nonce;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BestCandidate {
    nonce: u32,
    zero_bits: u32,
}

#[derive(Debug)]
pub(super) struct PowSharedState {
    best: Mutex<BestCandidate>,
    /// Atomic mirror of `best.zero_bits` — allows a lock-free pre-check in
    /// `update_best` so the mutex is only acquired when the score actually
    /// beats the current best (avoids contention on every candidate).
    best_zero_bits: AtomicU32,
    last_checked: AtomicU32,
    stop: AtomicBool,
    interrupted: Arc<AtomicBool>,
    started_at: Instant,
    timeout: Duration,
    target_zero_bits: u32,
}

impl PowSharedState {
    pub(super) fn new(
        start_nonce: u32,
        initial_score: PowScore,
        interrupted: Arc<AtomicBool>,
        timeout: Duration,
        target_zero_bits: u32,
    ) -> Self {
        // If the very first nonce already meets the target, set stop immediately
        // so workers exit after one iteration rather than running until timeout.
        let already_found = initial_score.zero_bits >= target_zero_bits;
        Self {
            best: Mutex::new(BestCandidate {
                nonce: start_nonce,
                zero_bits: initial_score.zero_bits,
            }),
            best_zero_bits: AtomicU32::new(initial_score.zero_bits),
            last_checked: AtomicU32::new(start_nonce),
            stop: AtomicBool::new(already_found),
            interrupted,
            started_at: Instant::now(),
            timeout,
            target_zero_bits,
        }
    }

    pub(super) fn should_stop(&self) -> bool {
        if self.interrupted.load(Ordering::Relaxed) {
            self.stop.store(true, Ordering::Relaxed);
            return true;
        }
        if self.started_at.elapsed() >= self.timeout {
            self.stop.store(true, Ordering::Relaxed);
            return true;
        }
        self.stop.load(Ordering::Relaxed)
    }

    pub(super) fn record_candidate(&self, candidate: u32) {
        self.last_checked.fetch_max(candidate, Ordering::Relaxed);
    }

    pub(super) fn update_best(
        &self,
        candidate: u32,
        score: PowScore,
    ) -> Result<Option<PowProgress>> {
        // Fast path: skip the mutex if this score can't possibly beat the current
        // best. The atomic load is a relaxed read — no ordering guarantee needed
        // here because the mutex below provides the authoritative sequencing.
        if score.zero_bits <= self.best_zero_bits.load(Ordering::Relaxed) {
            // Even if we miss the target here due to a race, the thread that set
            // the winning score will have stored `stop = true` itself.
            return Ok(None);
        }

        // Potential improvement — take the lock for the authoritative check.
        let mut current_best = self
            .best
            .lock()
            .map_err(|_| ConfigError::PoisonedState("best nonce"))?;

        if score.zero_bits > current_best.zero_bits {
            *current_best = BestCandidate {
                nonce: candidate,
                zero_bits: score.zero_bits,
            };
            // Keep the atomic mirror in sync so other threads skip the mutex.
            self.best_zero_bits
                .store(score.zero_bits, Ordering::Relaxed);
            if score.zero_bits >= self.target_zero_bits {
                self.stop.store(true, Ordering::Relaxed);
            }
            return Ok(Some(PowProgress {
                nonce: Base64Nonce::new(STANDARD.encode(u32_to_nonce(candidate)))?,
                zero_bits: score.zero_bits,
            }));
        }

        Ok(None)
    }

    pub(super) fn finalize(&self) -> Result<PowResult> {
        let best = *self
            .best
            .lock()
            .map_err(|_| ConfigError::PoisonedState("best nonce"))?;
        let stop_reason = if best.zero_bits >= self.target_zero_bits {
            PowStopReason::Found
        } else if self.interrupted.load(Ordering::Relaxed) {
            PowStopReason::Interrupted
        } else {
            PowStopReason::Timeout
        };

        Ok(PowResult {
            best_nonce: Base64Nonce::new(STANDARD.encode(u32_to_nonce(best.nonce)))?,
            best_zero_bits: best.zero_bits,
            stopped_at: Base64Nonce::new(
                STANDARD.encode(u32_to_nonce(self.last_checked.load(Ordering::Relaxed))),
            )?,
            stop_reason,
        })
    }
}
