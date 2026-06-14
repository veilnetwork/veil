use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use veil_error::Result;

pub(super) fn interrupt_flag() -> Result<&'static Arc<AtomicBool>> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    // Create the flag AND install the handler inside a single `get_or_init`.
    // `get_or_init`'s closure runs exactly once even under concurrent first
    // calls (other threads block until it returns), so the Arc the handler
    // captures is *guaranteed* to be the same Arc published to `FLAG`. The
    // previous split (a separate `HANDLER_INSTALLED` OnceLock + `FLAG.set`)
    // raced: thread A could install the handler against A's flag while thread
    // B's flag won `FLAG.set`, decoupling the two — Ctrl-C then set a cell the
    // search never read. Returning `Result` is kept for caller compatibility;
    // the init is now infallible.
    Ok(FLAG.get_or_init(|| {
        let flag = Arc::new(AtomicBool::new(false));
        let handler_flag = Arc::clone(&flag);
        // `set_handler` errors only if some OTHER subsystem already owns the
        // process Ctrl-C handler; the interactive PoW interrupt is best-effort,
        // so ignore that and keep the (then-inert) flag.
        let _ = ctrlc::set_handler(move || {
            handler_flag.store(true, Ordering::Relaxed);
        });
        flag
    }))
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
