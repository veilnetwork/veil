use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use veil_error::{ConfigError, Result};

pub(super) fn interrupt_flag() -> Result<&'static Arc<AtomicBool>> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    // Separate OnceLock tracks whether the ctrlc handler is already installed
    // avoiding the fragile string-matching on the error message.
    static HANDLER_INSTALLED: OnceLock<()> = OnceLock::new();

    if let Some(flag) = FLAG.get() {
        return Ok(flag);
    }

    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&flag);

    // Install the Ctrl-C handler exactly once. Any subsequent call that
    // arrives here (before FLAG is set) is safe to ignore because the handler
    // is already pointing at the same static AtomicBool.
    HANDLER_INSTALLED.get_or_init(|| {
        let _ = ctrlc::set_handler(move || {
            handler_flag.store(true, Ordering::Relaxed);
        });
    });

    let _ = FLAG.set(flag);
    FLAG.get()
        .ok_or(ConfigError::PoisonedState("interrupt flag"))
}

/// Reset the interrupt flag to `false`.
///
/// Call this **before** starting a new interactive PoW search from the CLI so
/// that a previous Ctrl-C does not immediately abort the new search.
///
/// **Do not** call this from inside `search_nonce` itself — resetting the
/// global flag mid-search would silently cancel a concurrent search's
/// interrupt signal.
pub fn reset_interrupt_flag() -> Result<()> {
    interrupt_flag()?.store(false, Ordering::Relaxed);
    Ok(())
}
