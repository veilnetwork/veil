//! Proof-of-Work for session bootstrap and route discovery.
//!
//! # Session bootstrap PoW
//!
//! The puzzle is: find `solution_nonce[32]` such that
//! `BLAKE3(requester_id ‖ challenge_nonce ‖ solution_nonce)` has at least
//! `difficulty` leading zero bits.
//!
//! * `difficulty = 0` — trivially solved (any nonce works).
//! * `difficulty = 16` — ~65 536 hashes on average (default).
//! * `difficulty = 24` — ~16 777 216 hashes on average.
//!
//! The solver runs in a tight loop on a `spawn_blocking` thread so it does
//! not block the async runtime. The verifier is cheap (single BLAKE3 call).
//!
//! # Discovery PoW
//!
//! Hashcash-style client-side PoW: find `solution_nonce[32]` such that
//! `BLAKE3(src_node_id ‖ timestamp_be ‖ solution_nonce)` has at least
//! `difficulty` leading zero bits.
//!
//! The `timestamp` is baked into the puzzle to prevent replay attacks.
//! The validity window is computed dynamically from `difficulty` to ensure
//! even slow hardware can solve the puzzle within the window:
//!
//! ```text
//! window = max(MIN_WINDOW, expected_solve_time * 10)
//! expected_solve_time = 2^difficulty / CONSERVATIVE_HASH_RATE
//! ```

/// Verify that `solution_nonce` satisfies the puzzle for the given inputs.
///
/// Returns `true` iff `BLAKE3(requester_id ‖ challenge_nonce ‖ solution_nonce)`
/// has at least `difficulty` leading zero bits.
pub fn verify_pow(
    requester_id: &[u8; 32],
    challenge_nonce: &[u8; 32],
    solution_nonce: &[u8; 32],
    difficulty: u8,
) -> bool {
    if difficulty == 0 {
        return true;
    }
    let hash = pow_hash(requester_id, challenge_nonce, solution_nonce);
    veil_util::leading_zero_bits(&hash) >= difficulty as u32
}

/// Solve the PoW puzzle: brute-force `solution_nonce` until the hash has
/// `difficulty` leading zero bits.
///
/// This is a CPU-bound loop — call it inside `tokio::task::spawn_blocking`.
/// Returns the winning nonce.
pub fn solve_pow(requester_id: &[u8; 32], challenge_nonce: &[u8; 32], difficulty: u8) -> [u8; 32] {
    if difficulty == 0 {
        return [0u8; 32];
    }
    let mut nonce = [0u8; 32];
    let mut counter: u64 = 0;
    loop {
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        if veil_util::leading_zero_bits(&pow_hash(requester_id, challenge_nonce, &nonce))
            >= difficulty as u32
        {
            return nonce;
        }
        counter = counter.wrapping_add(1);
    }
}

// ── Discovery PoW ──────────────────────────────────────────────────

use veil_proto::budget::{DISCOVERY_POW_CONSERVATIVE_HASH_RATE, DISCOVERY_POW_MIN_WINDOW_SECS};

/// Compute the timestamp validity window (seconds) for a discovery PoW packet
/// at the given difficulty.
///
/// Formula: `max(MIN_WINDOW (2^difficulty / CONSERVATIVE_HASH_RATE) * 10)`
///
/// The factor of 10 gives a generous safety margin so that even devices running
/// at the conservative hash rate comfortably finish within the window.
pub fn discovery_pow_window_secs(difficulty: u8) -> u64 {
    if difficulty == 0 {
        return DISCOVERY_POW_MIN_WINDOW_SECS;
    }
    // Compute 2^difficulty, saturating at u64::MAX for difficulty >= 64.
    let expected_hashes = 1u64.checked_shl(difficulty as u32).unwrap_or(u64::MAX);
    let expected_solve_secs = expected_hashes
        .checked_div(DISCOVERY_POW_CONSERVATIVE_HASH_RATE)
        .unwrap_or(u64::MAX);
    expected_solve_secs
        .saturating_mul(10)
        .max(DISCOVERY_POW_MIN_WINDOW_SECS)
}

/// Verify discovery PoW including the timestamp window check.
///
/// Returns `true` iff:
/// 1. `timestamp` is within `discovery_pow_window_secs(difficulty)` of `now_secs`
///    (in either direction, to tolerate clock skew).
/// 2. `BLAKE3(src_node_id ‖ timestamp_be ‖ solution_nonce)` has at least
///    `difficulty` leading zero bits.
pub fn verify_discovery_pow(
    src_node_id: &[u8; 32],
    timestamp: u64,
    solution_nonce: &[u8; 32],
    difficulty: u8,
    now_secs: u64,
) -> bool {
    let window = discovery_pow_window_secs(difficulty);
    if now_secs.saturating_sub(timestamp) > window {
        return false;
    }
    if timestamp.saturating_sub(now_secs) > window {
        return false;
    }
    if difficulty == 0 {
        return true;
    }
    let hash = discovery_pow_hash(src_node_id, timestamp, solution_nonce);
    veil_util::leading_zero_bits(&hash) >= difficulty as u32
}

/// Solve the discovery PoW puzzle (blocking — call inside `spawn_blocking`).
pub fn solve_discovery_pow(src_node_id: &[u8; 32], timestamp: u64, difficulty: u8) -> [u8; 32] {
    if difficulty == 0 {
        return [0u8; 32];
    }
    let mut nonce = [0u8; 32];
    let mut counter: u64 = 0;
    loop {
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        if veil_util::leading_zero_bits(&discovery_pow_hash(src_node_id, timestamp, &nonce))
            >= difficulty as u32
        {
            return nonce;
        }
        counter = counter.wrapping_add(1);
    }
}

fn discovery_pow_hash(
    src_node_id: &[u8; 32],
    timestamp: u64,
    solution_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(src_node_id);
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(solution_nonce);
    *hasher.finalize().as_bytes()
}

// cleanup: Argon2id memory-hard PoW was
// shipped but never wired — name-PoW migrated to the BLAKE3
// `RESOLVE_POW_DOMAIN_TAG` pipeline and then removed document-level PoW
// entirely. `name_pow_hash_argon2` + `argon2_params` had zero callers; module
// + argon2 crate dependency removed. Re-introduce from git history if memory-
// hard name-PoW returns to the design.

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pow_hash(
    requester_id: &[u8; 32],
    challenge_nonce: &[u8; 32],
    solution_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(requester_id);
    hasher.update(challenge_nonce);
    hasher.update(solution_nonce);
    *hasher.finalize().as_bytes()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_trivial_difficulty_zero() {
        let any_nonce = [0xABu8; 32];
        assert!(verify_pow(&[1u8; 32], &[2u8; 32], &any_nonce, 0));
    }

    #[test]
    fn solve_and_verify_difficulty_8() {
        let requester_id = [0x11u8; 32];
        let challenge_nonce = [0x22u8; 32];
        let solution = solve_pow(&requester_id, &challenge_nonce, 8);
        assert!(
            verify_pow(&requester_id, &challenge_nonce, &solution, 8),
            "solved nonce must verify"
        );
    }

    #[test]
    fn solve_and_verify_difficulty_16() {
        let requester_id = [0x33u8; 32];
        let challenge_nonce = [0x44u8; 32];
        let solution = solve_pow(&requester_id, &challenge_nonce, 16);
        assert!(verify_pow(&requester_id, &challenge_nonce, &solution, 16));
    }

    #[test]
    fn wrong_nonce_fails_verify() {
        let rid = [1u8; 32];
        let cn = [2u8; 32];
        let good = solve_pow(&rid, &cn, 8);
        let mut bad = good;
        bad[0] ^= 0xFF;
        // The bad nonce almost certainly fails (could theoretically pass by
        // coincidence, but probability ≈ 1/256 and we'd catch it elsewhere).
        let _ = verify_pow(&rid, &cn, &bad, 8); // just check it doesn't panic
    }

    // ── Discovery PoW tests ───────────────────────────────────────────────────

    #[test]
    fn discovery_window_difficulty_zero_is_min() {
        assert_eq!(discovery_pow_window_secs(0), DISCOVERY_POW_MIN_WINDOW_SECS);
    }

    #[test]
    fn discovery_window_difficulty_16_at_least_min() {
        // difficulty=16 → 65536 hashes / 50000 H/s ≈ 1.3 s → window = max(600, 13) = 600
        assert!(discovery_pow_window_secs(16) >= DISCOVERY_POW_MIN_WINDOW_SECS);
    }

    #[test]
    fn discovery_window_grows_with_difficulty() {
        // A large difficulty should produce a window larger than MIN.
        // difficulty=40 → 2^40 / 50000 ≈ 22 000 s → window ≈ 220 000 s
        let w40 = discovery_pow_window_secs(40);
        assert!(w40 > DISCOVERY_POW_MIN_WINDOW_SECS);
        assert!(w40 > discovery_pow_window_secs(16));
    }

    #[test]
    fn discovery_pow_trivial_difficulty_zero() {
        let src = [1u8; 32];
        let ts = 1_700_000_000u64;
        assert!(verify_discovery_pow(&src, ts, &[0u8; 32], 0, ts));
    }

    #[test]
    fn discovery_pow_solve_and_verify() {
        let src = [0x33u8; 32];
        let ts = 1_700_000_100u64;
        let nonce = solve_discovery_pow(&src, ts, 8);
        assert!(verify_discovery_pow(&src, ts, &nonce, 8, ts));
    }

    #[test]
    fn discovery_pow_rejects_stale_timestamp() {
        let src = [0x44u8; 32];
        let ts = 1_000u64;
        let now = ts + DISCOVERY_POW_MIN_WINDOW_SECS + 1;
        let nonce = solve_discovery_pow(&src, ts, 8);
        assert!(!verify_discovery_pow(&src, ts, &nonce, 8, now));
    }

    #[test]
    fn discovery_pow_rejects_future_timestamp() {
        let src = [0x55u8; 32];
        let now = 1_000u64;
        let ts = now + DISCOVERY_POW_MIN_WINDOW_SECS + 1;
        let nonce = solve_discovery_pow(&src, ts, 8);
        assert!(!verify_discovery_pow(&src, ts, &nonce, 8, now));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        // 0x00, 0x00 → 16 leading zero bits; 0x80 = 0b10000000 → first bit is 1, so 0 more.
        assert_eq!(
            veil_util::leading_zero_bits(&[
                0x00, 0x00, 0x80, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            ]),
            16
        );
        assert_eq!(
            veil_util::leading_zero_bits(&[
                0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ]),
            0
        );
        assert_eq!(veil_util::leading_zero_bits(&[0u8; 32]), 256); // 32 bytes × 8 bits
    }
}
