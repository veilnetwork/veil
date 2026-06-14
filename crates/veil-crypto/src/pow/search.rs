use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use veil_error::{ConfigError, Result};
use veil_types::SignatureAlgorithm;

use super::super::{Base64Nonce, Base64PrivateKey, Base64PublicKey};
use super::interrupt::interrupt_flag;
use super::pow_score;
use super::score::{
    CachedSigningKey, PowScratch, decode_nonce, decode_pk_bytes, decode_sk_bytes, nonce_to_u32,
    pow_score_raw_into, u32_to_nonce,
};
use super::state::PowSharedState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowResult {
    pub best_nonce: Base64Nonce,
    pub best_zero_bits: u32,
    pub stopped_at: Base64Nonce,
    pub stop_reason: PowStopReason,
}

#[derive(Clone)]
pub struct PowParams {
    pub algo: SignatureAlgorithm,
    pub public_key: Base64PublicKey,
    pub private_key: Base64PrivateKey,
    pub target_zero_bits: u32,
    pub timeout: Duration,
    pub start_from: Base64Nonce,
    pub threads: usize,
    pub progress: Option<mpsc::Sender<PowProgress>>,
}

// manual Debug impl — redact private_key to prevent accidental key leakage in logs.
impl std::fmt::Debug for PowParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PowParams")
            .field("algo", &self.algo)
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("target_zero_bits", &self.target_zero_bits)
            .field("timeout", &self.timeout)
            .field("threads", &self.threads)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowProgress {
    pub nonce: Base64Nonce,
    pub zero_bits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowStopReason {
    Found,
    Timeout,
    Interrupted,
}

pub fn search_nonce(params: PowParams) -> Result<PowResult> {
    if params.threads == 0 {
        return Err(ConfigError::PowThreadsZero);
    }
    if params.threads > u32::MAX as usize {
        // distinct error variant for the nonce-stride overflow
        // path — prior impl returned `PowThreadsZero`, whose message
        // ("must be greater than zero") was confusingly wrong.
        return Err(ConfigError::PowThreadsOverflowU32);
    }

    let start_nonce = nonce_to_u32(&decode_nonce(params.start_from.as_str())?);

    // Decode keys once — avoids base64 decode on every PoW iteration.
    let pk_bytes = Arc::new(decode_pk_bytes(params.algo, &params.public_key)?);
    let sk_bytes_raw = decode_sk_bytes(params.algo, &params.private_key)?;

    let initial_score = pow_score(
        params.algo,
        &params.public_key,
        &params.private_key,
        &params.start_from,
    )?;
    let interrupted = interrupt_flag()?;
    // NOTE: do NOT reset the flag here. Resetting inside search_nonce would
    // race with concurrent searches and silently swallow Ctrl-C for them.
    // Callers that start a fresh interactive search should call
    // `reset_interrupt_flag` explicitly beforehand.
    let state = Arc::new(PowSharedState::new(
        start_nonce,
        initial_score,
        Arc::clone(interrupted),
        params.timeout,
        params.target_zero_bits,
    ));
    let mut handles = Vec::with_capacity(params.threads);

    for thread_index in 0..params.threads {
        let state = Arc::clone(&state);
        let progress = params.progress.clone();
        let pk_bytes = Arc::clone(&pk_bytes);
        // Build a per-thread CachedSigningKey from the already-decoded bytes.
        let signing_key = CachedSigningKey::from_private_key(params.algo, &sk_bytes_raw)?;
        let threads = params.threads;
        let handle = thread::spawn(move || -> Result<()> {
            let mut candidate = start_nonce.wrapping_add(thread_index as u32);
            // Reuse scratch across the whole search — zero per-nonce allocation.
            let mut scratch = PowScratch::default();

            while !state.should_stop() {
                state.record_candidate(candidate);
                // Hot path: raw score with pre-decoded keys — no base64 overhead.
                let nonce_bytes = u32_to_nonce(candidate);
                let score =
                    pow_score_raw_into(&pk_bytes, &signing_key, &nonce_bytes, &mut scratch)?;

                if let Some(progress_event) = state.update_best(candidate, score)?
                    && let Some(progress) = &progress
                {
                    let _ = progress.send(progress_event);
                }

                candidate = candidate.wrapping_add(threads as u32);
            }

            Ok(())
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .map_err(|_| ConfigError::PowWorkerPanicked)??;
    }

    state.finalize()
}
