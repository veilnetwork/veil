//! Opt-in observations at the decrypting endpoint, never on a relay path.
//! No addresses, payloads or key material; no input to authorization/routing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static ENABLED: AtomicBool = AtomicBool::new(false);
static BUDGET: LazyLock<Mutex<(u64, u16)>> = LazyLock::new(Default::default);

/// Driven by the existing embedded-node stand trace switch. Off by default.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
    if !on {
        *BUDGET.lock().unwrap_or_else(|p| p.into_inner()) = (0, 0);
    }
}

pub(crate) fn terminal(marker: Option<u8>, provenance: veil_app::registry::SenderProvenance) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let form = match marker {
        Some(veil_proto::RATCHET_E2E_MARKER) => "ratchet",
        Some(veil_proto::E2E_MARKER) => "mlkem",
        Some(veil_proto::META_E2E_MARKER) => "meta_mlkem",
        _ => return,
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return;
    };
    // Diagnostic logging must remain bounded even for forged sender claims.
    {
        let mut budget = BUDGET.lock().unwrap_or_else(|p| p.into_inner());
        if budget.0 != now.as_secs() {
            *budget = (now.as_secs(), 0);
        }
        if budget.1 >= 128 {
            return;
        }
        budget.1 += 1;
    }
    log::info!(
        "app.auth_trace.terminal at_ms={} form={form} provenance={provenance:?}",
        now.as_millis(),
    );
}
