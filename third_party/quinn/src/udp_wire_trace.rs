//! Endpoint-local, opt-in correlation of encrypted UDP datagrams.
//! No addresses, wire connection IDs, contents, media roles or wire fields are emitted.
//! A process-local connection ordinal joins send samples to transport counters;
//! it is neither a pointer nor a protocol identifier and never leaves the log.
//! This measures socket handoff to peer socket read, including kernel/scheduling
//! time; it does not on its own attribute that delay to the carrier.
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
#[cfg(not(wasm_browser))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(wasm_browser)]
use web_time::{SystemTime, UNIX_EPOCH};

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
static NEXT_CONNECTION_TRACE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_connection_trace_id() -> u64 {
    NEXT_CONNECTION_TRACE_ID.fetch_add(1, Ordering::Relaxed)
}
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

pub(crate) fn enabled() -> bool {
    enabled_cell().load(Ordering::Relaxed)
}

#[cfg(test)]
fn record(stage: &'static str, bytes: &[u8], segment_size: Option<usize>) {
    record_inner(stage, bytes, segment_size, None, false, 0);
}

pub(crate) fn record_send(bytes: &[u8], segment_size: Option<usize>, connection_trace_id: u64) {
    record_inner(
        "send",
        bytes,
        segment_size,
        None,
        false,
        connection_trace_id,
    );
}

pub(crate) fn record_receive(bytes: &[u8], kernel_recv_unix_ns: Option<u64>, grouped: bool) {
    record_inner("receive", bytes, None, kernel_recv_unix_ns, grouped, 0);
}

fn record_inner(
    stage: &'static str,
    bytes: &[u8],
    segment_size: Option<usize>,
    kernel_recv_unix_ns: Option<u64>,
    grouped: bool,
    connection_trace_id: u64,
) {
    if !enabled() || bytes.is_empty() {
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
        log::info!(
            "quic.udp_wire.sample stage={stage} at_ms={at_ms} digest={digest:016x} bytes={} kernel_recv_ns={} kernel_grouped={grouped} connection_trace_id={connection_trace_id}",
            datagram.len(),
            kernel_recv_unix_ns.unwrap_or(0)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestLogger(std::sync::Mutex<Vec<String>>);
    static LOGGER: TestLogger = TestLogger(std::sync::Mutex::new(Vec::new()));
    impl log::Log for TestLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            self.0.lock().unwrap().push(format!("{}", record.args()));
        }
        fn flush(&self) {}
    }

    #[test]
    fn enabled_trace_reaches_embedded_log_bridge_and_disabled_trace_is_silent() {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        let selected = |len| {
            (0u32..8192)
                .map(|n| {
                    let mut bytes = vec![0x51; len];
                    bytes[..4].copy_from_slice(&n.to_be_bytes());
                    bytes
                })
                .find(|b| fingerprint(b) & 15 == 0)
                .unwrap()
        };
        let a = selected(1200);
        let b = selected(500);
        let batch = [a.as_slice(), b.as_slice()].concat();
        set_udp_wire_trace(true);
        record("send", &batch, Some(1200));
        record("receive", &a, None);
        record_receive(&a, Some(123456789), true);
        record_send(&batch, Some(1200), 41);
        record_send(&a, None, 42);
        set_udp_wire_trace(false);
        record("send", &batch, Some(1200));
        record_send(&a, None, 41);
        let rows = LOGGER.0.lock().unwrap();
        assert_eq!(
            rows.len(),
            7,
            "SDK log bridge must receive sampled datagrams"
        );
        assert!(rows[0].contains("stage=send"));
        assert!(rows[2].contains("stage=receive"));
        let digest = |s: &str| {
            s.split_whitespace()
                .find(|v| v.starts_with("digest="))
                .unwrap()
                .to_owned()
        };
        assert_eq!(digest(&rows[0]), digest(&rows[2]));
        assert!(rows[0].contains("bytes=1200"));
        assert!(rows[1].contains("bytes=500"));
        assert!(rows[0].contains("kernel_recv_ns=0"));
        assert!(rows[3].contains("kernel_recv_ns=123456789"));
        assert!(rows[3].contains("kernel_grouped=true"));
        assert!(rows[2].contains("connection_trace_id=0"));
        assert!(rows[4].contains("connection_trace_id=41"));
        assert!(rows[5].contains("connection_trace_id=41"));
        assert!(rows[6].contains("connection_trace_id=42"));
        assert_eq!(digest(&rows[0]), digest(&rows[4]));
        assert_eq!(digest(&rows[4]), digest(&rows[6]));
    }

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
