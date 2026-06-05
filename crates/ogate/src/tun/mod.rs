//! Platform-abstracted TUN device.
//!
//! The bridge consumes `Device` purely; the per-platform module decides
//! how to create the kernel resource, set addresses, and split into
//! reader / writer halves.
//!
//! Supported targets:
//! * Linux / macOS / Windows — wraps the `tun` crate's `AsyncDevice`
//!   and shells out to `ip` / `ifconfig` / `netsh` for IPv6 / route
//!   setup that the crate cannot do cross-platform.
//! * FreeBSD — opens `/dev/tun` directly, sets `TUNSIFHEAD = 0` (raw
//!   IP mode), then drives `ifconfig` for address / MTU configuration.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod standard;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use standard::{Device, Reader, Writer};

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::{Device, Reader, Writer};

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
)))]
compile_error!(
    "ogate supports only Linux / macOS / Windows / FreeBSD; \
     other targets need a platform module"
);

/// Shared error type for platform-specific TUN setup failures.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("setup: {0}")]
    Setup(String),
}

/// Common interface for adding routes / addresses post-creation.
/// Re-exported by each platform module so the bridge does not import
/// `std::process::Command` directly.
pub(crate) fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TunError> {
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| TunError::Setup(format!("spawn {prog}: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(TunError::Setup(format!(
            "{prog} {args:?} failed: {}",
            err.trim()
        )));
    }
    Ok(())
}
