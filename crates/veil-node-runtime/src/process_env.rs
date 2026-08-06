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

use std::sync::OnceLock;

// The deferred boot's working directory used to live here, as a `OnceLock`
// whose first write won. It is gone: that directory is a property of ONE boot,
// not of the process.
//
// Holding it here was wrong in both directions. The value is a node's ephemeral
// runtime directory, which teardown deletes — so the second boot in a process
// (an anonymity toggle) kept the first one's deleted path and died with ENOENT
// before binding its admin socket. And a process can host several nodes at
// once, which do not share a runtime directory at all.
//
// It is now a parameter of `run_foreground_deferred_with_shutdown`, derived by
// the FFI from the admin socket that boot was handed. The V-06 lesson that put
// it here — do not rewrite a threaded process's environment — is unchanged;
// only the shape was wrong.

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

    /// This is process state, readable from any thread, which the environment
    /// is not.
    ///
    /// `set_var`/`remove_var` are unsafe because another thread calling
    /// `getenv` — anywhere, including inside libc — during the write is
    /// undefined behaviour. The runtime is embedded in hosts that have had
    /// threads running since before it was loaded, so "we do it early" was
    /// never true there (audit V-06).
    ///
    /// What is NOT here any more is the deferred working directory. It was a
    /// `OnceLock` beside this one, and the first-write-wins that suits a
    /// permission flag is exactly wrong for a path that changes every boot.
    #[test]
    fn env_writes_are_refused_until_an_entry_point_declares_it_safe() {
        assert!(!env_writes_allowed(), "no entry point has declared it safe");
    }
}
