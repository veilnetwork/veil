//! Opt-in sampling shared by endpoint and opaque IPC cell diagnostics.
//! Callers must check their trace gate before using this helper. Nothing here
//! changes a wire field, traffic role, admission decision or packet lifetime.

use std::sync::OnceLock;

const DEFAULT_INTERVAL: u64 = 50;

fn interval(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| (1..=DEFAULT_INTERVAL).contains(value))
        .unwrap_or(DEFAULT_INTERVAL)
}

/// Keep the first candidate and every Nth cell. An explicitly configured
/// `VEIL_RT_TRACE_SEALED_EVERY=1` records every cell in an owned diagnostic
/// capture. Invalid configuration retains the existing sparse default.
pub fn sample(sequence: u64) -> bool {
    static INTERVAL: OnceLock<u64> = OnceLock::new();
    let every = *INTERVAL
        .get_or_init(|| interval(std::env::var("VEIL_RT_TRACE_SEALED_EVERY").ok().as_deref()));
    sampled(sequence, every)
}

fn sampled(sequence: u64, every: u64) -> bool {
    sequence != 0 && (sequence == 1 || sequence.is_multiple_of(every))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_intervals_keep_sparse_default() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some("51"),
            Some("nan"),
        ] {
            assert_eq!(interval(value), 50);
        }
        assert_eq!(interval(Some("18446744073709551616")), 50);
        assert_eq!(interval(Some(" 1 ")), 1);
        assert_eq!(interval(Some("10")), 10);
    }

    #[test]
    fn first_candidate_and_full_capture_preserve_sequence_identity() {
        for every in 1..=50 {
            assert!(!sampled(0, every));
            assert!(sampled(1, every));
            for sequence in 2..=200 {
                assert_eq!(sampled(sequence, every), sequence % every == 0);
            }
        }
    }
}
