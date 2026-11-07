//! Exact, default-off operator gates. Android apps do not inherit adb shell
//! environment. Properties only choose diagnostics, never protocol policy.

use std::ffi::{CStr, OsStr};

fn choose(environment: Option<&OsStr>, platform: Option<&[u8]>) -> bool {
    match environment {
        Some(value) => value == OsStr::new("1"),
        None => platform == Some(b"1"),
    }
}

#[cfg(target_os = "android")]
fn property(name: &CStr) -> Option<Vec<u8>> {
    let mut value = [0u8; 92]; // Android PROP_VALUE_MAX, including NUL.
    // SAFETY: name is NUL-terminated and value is a full property buffer.
    let length = unsafe { libc::__system_property_get(name.as_ptr(), value.as_mut_ptr().cast()) };
    let length = usize::try_from(length).ok()?;
    (length > 0 && length < value.len()).then(|| value[..length].to_vec())
}

#[cfg(not(target_os = "android"))]
fn property(_: &CStr) -> Option<Vec<u8>> {
    None
}

/// An explicit environment value, including invalid/non-UTF8, always wins.
/// Callers may cache this choice for their process lifetime with OnceLock.
pub fn enabled(environment: &str, android_property: &CStr) -> bool {
    let value = std::env::var_os(environment);
    let platform = value
        .is_none()
        .then(|| property(android_property))
        .flatten();
    choose(value.as_deref(), platform.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_gates_are_exact_default_off_and_environment_wins() {
        assert!(!choose(None, None));
        assert!(choose(None, Some(b"1")));
        for invalid in [&b""[..], b"0", b"true", b" 1 ", b"1\0", &[0xff]] {
            assert!(!choose(None, Some(invalid)));
        }
        for invalid in ["", "0", "true", " 1 "] {
            assert!(!choose(Some(OsStr::new(invalid)), Some(b"1")));
        }
        assert!(choose(Some(OsStr::new("1")), None));
        assert!(choose(Some(OsStr::new("1")), Some(b"0")));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_explicit_environment_cannot_enable_platform_fallback() {
        use std::os::unix::ffi::OsStrExt;
        assert!(!choose(Some(OsStr::from_bytes(&[0xff])), Some(b"1")));
    }
}
