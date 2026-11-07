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

// Embedded Android processes do not inherit the adb shell's environment.
// Keep the operator's existing full-cell diagnostic mode available there
// without changing process environment after native threads have started.
// This property selects sampling only; callers still require their trace gate.
#[cfg(target_os = "android")]
fn platform_interval() -> Option<String> {
    let mut value = [0u8; 92]; // Android PROP_VALUE_MAX includes the trailing NUL.
    let length = unsafe {
        libc::__system_property_get(
            c"debug.xveil.sealed_every".as_ptr(),
            value.as_mut_ptr().cast(),
        )
    };
    let length = usize::try_from(length).ok()?;
    if length == 0 || length >= value.len() {
        return None;
    }
    std::str::from_utf8(&value[..length])
        .ok()
        .map(str::to_owned)
}

#[cfg(not(target_os = "android"))]
fn platform_interval() -> Option<String> {
    None
}

fn configured_interval(environment: Option<&str>, platform: Option<&str>) -> u64 {
    interval(environment.or(platform))
}

/// Keep the first candidate and every Nth cell. An explicitly configured
/// `VEIL_RT_TRACE_SEALED_EVERY=1` records every cell in an owned diagnostic
/// capture. Invalid configuration retains the existing sparse default.
/// Android also accepts `debug.xveil.sealed_every` when the environment option
/// is absent. The value is fixed at the first sample until process restart.
pub fn sample(sequence: u64) -> bool {
    static INTERVAL: OnceLock<u64> = OnceLock::new();
    let every = *INTERVAL.get_or_init(|| {
        let environment = std::env::var("VEIL_RT_TRACE_SEALED_EVERY").ok();
        let platform = environment.is_none().then(platform_interval).flatten();
        configured_interval(environment.as_deref(), platform.as_deref())
    });
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

    #[test]
    fn platform_sampling_is_bounded_and_never_overrides_explicit_environment() {
        assert_eq!(configured_interval(None, Some("1")), 1);
        assert_eq!(configured_interval(None, Some("0")), 50);
        assert_eq!(configured_interval(None, Some("51")), 50);
        assert_eq!(configured_interval(None, None), 50);
        assert_eq!(configured_interval(Some("10"), Some("1")), 10);
        // An explicit invalid environment option still retains sparse mode.
        assert_eq!(configured_interval(Some("0"), Some("1")), 50);
    }
}
