//! Operator-only observations of opaque ordered records. Off by default.
//! Hashes and local child IDs are private correlation data, not anonymous
//! reports, wire fields, delivery acknowledgments or traffic classifications.

use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

const LIMIT: u64 = 100_000;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ROWS: AtomicU64 = AtomicU64::new(0);
static NEXT_CHILD: AtomicU64 = AtomicU64::new(1);

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        veil_util::operator_trace::enabled(
            "VEIL_DIAG_ORDERED_RECORDS",
            c"debug.xveil.ordered_records",
        )
    })
}

pub(crate) fn new_child() -> u64 {
    if enabled() {
        NEXT_CHILD.fetch_add(1, Ordering::Relaxed)
    } else {
        0
    }
}

/// Whole encrypted session record, excluding its two-byte transport prefix.
/// A caller must not use this digest as authentication or replay authority.
pub fn fingerprint(payload: &[u8]) -> Option<String> {
    if !enabled() || payload.is_empty() || payload.len() > crate::ordered_records::MAX_RECORD_BYTES
    {
        return None;
    }
    Some(veil_util::hex_str(&Sha256::digest(payload)))
}

#[derive(Clone, Copy)]
pub enum Stage {
    SendAdmitted,
    WriteStart,
    FirstWrite,
    Flushed,
    ExpiredBeforeWrite,
    ExpiredDuringWrite,
    WriteError,
    WriteTimeout,
    ReadComplete,
    DecodeInput,
    FragmentPending,
    DecodeRejected,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::SendAdmitted => "send_admitted",
            Self::WriteStart => "write_start",
            Self::FirstWrite => "first_write",
            Self::Flushed => "flushed",
            Self::ExpiredBeforeWrite => "expired_before_write",
            Self::ExpiredDuringWrite => "expired_during_write",
            Self::WriteError => "write_error",
            Self::WriteTimeout => "write_timeout",
            Self::ReadComplete => "read_complete",
            Self::DecodeInput => "decode_input",
            Self::FragmentPending => "fragment_pending",
            Self::DecodeRejected => "decode_rejected",
        }
    }
}

/// `Flushed` means local AsyncWrite/flush completion, never a remote ACK.
/// ReadComplete precedes incoming queue admission and session authentication.
pub fn note(stage: Stage, child: u64, payload: &[u8]) {
    if !enabled() || ROWS.load(Ordering::Relaxed) > LIMIT {
        return;
    }
    let Some(digest) = fingerprint(payload) else {
        return;
    };
    let row = ROWS.fetch_add(1, Ordering::Relaxed);
    if row == LIMIT {
        log::info!("transport.ordered_record_trace_limit rows={LIMIT}");
    }
    if row >= LIMIT {
        return;
    }
    let monotonic_us = veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from);
    log::info!(
        "transport.ordered_record stage={} monotonic_us={monotonic_us} child_local={child} record_bytes={} record_sha256={digest}",
        stage.label(),
        payload.len(),
    );
}
