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

/// Resolve a network-config helper (`ip` / `ifconfig` / `route` / `netsh`) to
/// an absolute path from a FIXED set of trusted, root-owned system directories
/// rather than consulting `$PATH`. ogate may run as root / with
/// `CAP_NET_ADMIN`; a hostile `$PATH` (set by a local unprivileged user before
/// launch) must not be able to substitute the binary we exec. The trusted dirs
/// are root-owned, so an attacker who could plant a binary there already has
/// the privileges this guards. (audit M-3: local PATH hijack.)
fn resolve_trusted_prog(prog: &str) -> Result<std::path::PathBuf, TunError> {
    #[cfg(windows)]
    let dirs: &[&str] = &[r"C:\Windows\System32", r"C:\Windows\Sysnative"];
    #[cfg(not(windows))]
    let dirs: &[&str] = &["/sbin", "/usr/sbin", "/bin", "/usr/bin"];
    for dir in dirs {
        let candidate = std::path::Path::new(dir).join(prog);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(TunError::Setup(format!(
        "network helper {prog:?} not found in trusted system directories \
         {dirs:?} — refusing to resolve via $PATH"
    )))
}

/// Common interface for adding routes / addresses post-creation.
/// Re-exported by each platform module so the bridge does not import
/// `std::process::Command` directly.
pub(crate) fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TunError> {
    let abs = resolve_trusted_prog(prog)?;
    // Override PATH with the same trusted dirs (don't env_clear — `netsh` needs
    // SystemRoot etc.) so any internal lookups by the helper are hijack-safe too.
    #[cfg(windows)]
    let safe_path = r"C:\Windows\System32";
    #[cfg(not(windows))]
    let safe_path = "/sbin:/usr/sbin:/bin:/usr/bin";
    let out = std::process::Command::new(&abs)
        .args(args)
        .env("PATH", safe_path)
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
