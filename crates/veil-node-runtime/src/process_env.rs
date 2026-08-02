//! Process-wide settings that used to be carried in environment variables.
//!
//! Mutating the environment is not thread-safe. Rust marks `set_var` and
//! `remove_var` unsafe for exactly that reason: another thread calling
//! `getenv` — anywhere, including inside libc or a linked C library — while
//! the table is being rewritten is undefined behaviour, and the runtime is
//! embedded in hosts (a Flutter app, an Android service) that already have
//! threads running long before it is asked to start (audit V-06).
//!
//! The two things that needed it are here instead, as ordinary process state:
//! written once, read by anyone, no unsafe.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Where the deferred boot should place its working directory.
///
/// The embedded FFI entry point used to point `TMPDIR` at an app-writable
/// directory, because on Android `std::env::temp_dir()` is `/data/local/tmp`
/// — which an ordinary app cannot write, so the deferred boot's working dir
/// failed with EACCES and the node thread died before binding its admin
/// socket. Redirecting the whole process's idea of "temp" was a large hammer
/// for one directory, and an unsafe one in a threaded host.
///
/// `None` means "use the platform default", which is what every non-Android
/// build does.
static DEFERRED_WORK_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Set the deferred boot's working directory. First call wins.
///
/// Safe to call from anywhere at any time, which is the whole point: a
/// `OnceLock` write is synchronised, an environment write is not.
pub fn set_deferred_work_dir(dir: impl Into<PathBuf>) {
    let _ = DEFERRED_WORK_DIR.set(dir.into());
}

/// The configured deferred-boot working directory, if a host set one.
pub fn deferred_work_dir() -> Option<&'static Path> {
    DEFERRED_WORK_DIR.get().map(PathBuf::as_path)
}

/// Whether this process may rewrite its own environment.
///
/// Only an entry point that knows it is still SINGLE-THREADED may say yes —
/// in practice the `veil-cli` daemon, which reads its configuration before
/// starting the tokio runtime. An embedded host cannot: by the time it calls
/// in, its own threads are already running.
///
/// Consulted before the one remaining environment write: erasing the
/// passphrase variable so a later fork/exec cannot inherit it. Where the
/// answer is no, the variable is left in place and the erase is skipped —
/// losing a defence, but not at the price of undefined behaviour in a host we
/// do not control.
static ENV_WRITES_ALLOWED: OnceLock<bool> = OnceLock::new();

/// Declare that this process is still single-threaded and may rewrite its
/// environment. Call from the entry point, before spawning anything.
pub fn allow_env_writes() {
    let _ = ENV_WRITES_ALLOWED.set(true);
}

/// True only if an entry point explicitly declared it safe.
pub fn env_writes_allowed() -> bool {
    *ENV_WRITES_ALLOWED.get().unwrap_or(&false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: these are readable and writable from any thread,
    /// which the environment is not.
    ///
    /// `set_var`/`remove_var` are unsafe because another thread calling
    /// `getenv` — anywhere, including inside libc — during the write is
    /// undefined behaviour. The runtime is embedded in hosts that have had
    /// threads running since before it was loaded, so "we do it early" was
    /// never true there (audit V-06).
    #[test]
    fn the_settings_are_writable_from_any_thread_and_first_write_wins() {
        // Default before anyone sets anything.
        assert!(!env_writes_allowed(), "no entry point has declared it safe");

        let dir = std::env::temp_dir().join("v06-first");
        let other = std::env::temp_dir().join("v06-second");
        let (d1, d2) = (dir.clone(), other.clone());

        // Two threads racing to set it. Whichever wins, the value is one of
        // theirs and it never changes again — no torn state, no UB.
        let a = std::thread::spawn(move || set_deferred_work_dir(d1));
        let b = std::thread::spawn(move || set_deferred_work_dir(d2));
        a.join().unwrap();
        b.join().unwrap();

        let settled = deferred_work_dir().expect("one of them won");
        assert!(settled == dir || settled == other);

        // First write wins: a later call cannot move it.
        set_deferred_work_dir(std::env::temp_dir().join("v06-third"));
        assert_eq!(deferred_work_dir().unwrap(), settled);
    }
}
