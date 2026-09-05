//! Privileged Windows system-VPN helper loaded by xVeil's elevated helper mode.
//!
//! The helper is a DLL, not a separately installed service or executable. The
//! normal Windows runner re-executes the same `xveil.exe` through UAC and that
//! process calls [`veil_run_windows_vpn_helper_v2`].

#[cfg(any(windows, test))]
mod integrity;
#[cfg(any(windows, test))]
mod policy;

#[cfg(windows)]
mod windows;

/// Run one lifecycle-bound Windows VPN helper request.
///
/// `config_path` is a NUL-terminated UTF-16 path; `expected_sha256` is the
/// lowercase hex SHA-256 of the bytes the HOST wrote there, as UTF-16. The
/// call blocks until the host asks the helper to stop, the host process exits,
/// or the tunnel fails.
///
/// The digest is what ties this elevated run to the request the person
/// approved: the file lives in a directory their own unprivileged processes
/// can write, and the command line does not. See `integrity`.
///
/// `_v2` because the single-argument entry point it replaces read the request
/// on trust. Renaming rather than adding means a runner from a different build
/// finds no symbol and fails, instead of silently taking the unchecked route —
/// the shim and this DLL ship in one bundle, so that can only be a mixed
/// installation.
///
/// # Safety
/// Both pointers must reference live NUL-terminated UTF-16 strings for this
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_run_windows_vpn_helper_v2(
    config_path: *const u16,
    expected_sha256: *const u16,
) -> i32 {
    if config_path.is_null() || expected_sha256.is_null() {
        return -1;
    }
    #[cfg(windows)]
    {
        // SAFETY: forwarded under this function's pointer contract.
        let expected = unsafe { wide_string(expected_sha256) };
        // SAFETY: same contract.
        windows::run(unsafe { wide_path(config_path) }, &expected).unwrap_or(-1)
    }
    #[cfg(not(windows))]
    {
        let _ = (config_path, expected_sha256);
        -1
    }
}

#[cfg(windows)]
unsafe fn wide_string(value: *const u16) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // SAFETY: forwarded under the caller's pointer contract.
    let units = unsafe { wide_units(value) };
    OsString::from_wide(units).to_string_lossy().into_owned()
}

#[cfg(windows)]
unsafe fn wide_path(value: *const u16) -> std::path::PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // SAFETY: forwarded under the caller's pointer contract.
    let units = unsafe { wide_units(value) };
    if units.is_empty() {
        return std::path::PathBuf::new();
    }
    std::path::PathBuf::from(OsString::from_wide(units))
}

#[cfg(windows)]
unsafe fn wide_units<'a>(value: *const u16) -> &'a [u16] {
    let mut length = 0usize;
    // The C ABI contract requires a NUL terminator. Keep a defensive upper
    // bound so a malformed caller cannot scan arbitrary process memory.
    while length < 32_768 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        return &[];
    }
    // SAFETY: the caller promised `length + 1` live UTF-16 code units and the
    // bounded scan found the terminator.
    unsafe { std::slice::from_raw_parts(value, length) }
}
