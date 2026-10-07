//! Endpoint-local, opt-in correlation of encrypted UDP datagrams.
//! No addresses, connection IDs, contents, media roles or wire fields are emitted.
//! This measures socket handoff to peer socket read, including kernel/scheduling
//! time; it does not on its own attribute that delay to the carrier.
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(wasm_browser))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(wasm_browser)]
use web_time::{SystemTime, UNIX_EPOCH};

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
fn enabled_cell() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Toggle local encrypted-datagram correlation. Disabled by default.
pub fn set_udp_wire_trace(on: bool) {
    enabled_cell().store(on, Ordering::Relaxed);
}

// This is a correlation tag, not an authentication primitive. Fixed keys of
// DefaultHasher::new make identical encrypted bytes match across endpoints
// built with the same Rust toolchain. Nothing uses this tag for authorization.
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hash = DefaultHasher::new();
    hash.write(bytes);
    hash.finish()
}

pub(crate) fn record(stage: &'static str, bytes: &[u8], segment_size: Option<usize>) {
    if !enabled_cell().load(Ordering::Relaxed) || bytes.is_empty() {
        return;
    }
    for datagram in bytes.chunks(segment_size.filter(|n| *n > 0).unwrap_or(bytes.len())) {
        let digest = fingerprint(datagram);
        // Deterministic sampling: a received copy is selected exactly when
        // its transmitted copy was, including GSO/GRO segmentation.
        if digest & 15 != 0 {
            continue;
        }
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        tracing::info!(
            "quic.udp_wire.sample stage={stage} at_ms={at_ms} digest={digest:016x} bytes={}",
            datagram.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn correlation_matches_gso_segments_and_distinguishes_ciphertext() {
        let a = [0x51; 1200];
        let b = [0x72; 500];
        let batched = [a.as_slice(), b.as_slice()].concat();
        let transmitted: Vec<_> = batched.chunks(1200).map(fingerprint).collect();
        assert_eq!(transmitted, vec![fingerprint(&a), fingerprint(&b)]);
        assert_ne!(transmitted[0], transmitted[1]);
        // Sampling depends only on the exact datagram, not on send/receive stage.
        assert_eq!(fingerprint(&batched[..1200]) & 15, fingerprint(&a) & 15);
    }
}
