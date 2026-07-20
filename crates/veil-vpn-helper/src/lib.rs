//! Privileged Windows system-VPN helper loaded by xVeil's elevated helper mode.
//!
//! The helper is a DLL, not a separately installed service or executable. The
//! normal Windows runner re-executes the same `xveil.exe` through UAC and that
//! process calls [`veil_run_windows_vpn_helper`].

#[cfg(any(windows, test))]
mod policy;

#[cfg(windows)]
mod windows;

/// Run one lifecycle-bound Windows VPN helper request.
///
/// `config_path` is a NUL-terminated UTF-16 path. The call blocks until the
/// host asks the helper to stop, the host process exits, or the tunnel fails.
///
/// # Safety
/// `config_path` must point to a live NUL-terminated UTF-16 string for this
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_run_windows_vpn_helper(config_path: *const u16) -> i32 {
    if config_path.is_null() {
        return -1;
    }
    #[cfg(windows)]
    {
        // SAFETY: forwarded under this function's pointer contract.
        windows::run(unsafe { wide_path(config_path) }).unwrap_or(-1)
    }
    #[cfg(not(windows))]
    {
        let _ = config_path;
        -1
    }
}

#[cfg(windows)]
unsafe fn wide_path(value: *const u16) -> std::path::PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let mut length = 0usize;
    // The C ABI contract requires a NUL terminator. Keep a defensive upper
    // bound so a malformed caller cannot scan arbitrary process memory.
    while length < 32_768 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        return std::path::PathBuf::new();
    }
    // SAFETY: the caller promised `length + 1` live UTF-16 code units and the
    // bounded scan found the terminator.
    let units = unsafe { std::slice::from_raw_parts(value, length) };
    std::path::PathBuf::from(OsString::from_wide(units))
}
