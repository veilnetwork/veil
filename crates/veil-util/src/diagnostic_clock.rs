//! Absolute local monotonic timestamps for same-host diagnostic correlation.
//! Never use these as remote clocks, protocol timestamps or expiry authority.

/// Matches Python's `time.monotonic()` on the Unix stand hosts. Darwin's
/// CLOCK_MONOTONIC includes prior sleep and has a different absolute origin
/// from mach_absolute_time; CLOCK_UPTIME_RAW is the required domain there.
#[cfg(unix)]
pub fn monotonic_us() -> Option<u64> {
    #[cfg(target_vendor = "apple")]
    let clock = libc::CLOCK_UPTIME_RAW;
    #[cfg(not(target_vendor = "apple"))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: stamp is an initialized, writable timespec. The fixed clock ID
    // comes from this platform's libc; failure leaves the timestamp unknown.
    if unsafe { libc::clock_gettime(clock, &mut stamp) } != 0 {
        return None;
    }
    let seconds = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000)?.checked_add(nanos / 1000)
}

#[cfg(not(unix))]
pub fn monotonic_us() -> Option<u64> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn local_diagnostic_clock_is_available_and_nondecreasing() {
        let before = monotonic_us().expect("monotonic platform clock");
        let after = monotonic_us().unwrap();
        assert!(after >= before);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    #[allow(deprecated)] // Test the system clock domain without adding a Mach dependency.
    fn darwin_diagnostics_use_the_mach_absolute_time_domain() {
        let mut info = libc::mach_timebase_info_data_t { numer: 0, denom: 0 };
        // SAFETY: an initialized writable platform timebase structure.
        assert_eq!(unsafe { libc::mach_timebase_info(&mut info) }, 0);
        assert_ne!(info.denom, 0);
        let to_us = |ticks: u64| {
            (u128::from(ticks) * u128::from(info.numer) / u128::from(info.denom) / 1000) as u64
        };
        // SAFETY: both reads have no pointer arguments or side effects.
        let before = to_us(unsafe { libc::mach_absolute_time() });
        let observed = monotonic_us().unwrap();
        let after = to_us(unsafe { libc::mach_absolute_time() });
        assert!(
            before <= observed && observed <= after,
            "wrong absolute clock domain"
        );
    }
}
