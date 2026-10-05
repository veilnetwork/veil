//! Sparse origin observations for local IPC relay admission. No relay policy,
//! payload parsing or wire fields; queue admission is not end-to-end delivery.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
type Key = ([u8; 32], [u8; 32], u8, [u8; 32]);
struct Sample {
    logged_at: Instant,
    accepted: u64,
    refused: u64,
}
static SAMPLES: LazyLock<Mutex<HashMap<Key, Sample>>> = LazyLock::new(Default::default);

fn enabled() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Embedded-node twin of the existing VEIL_RT_TRACE stand switch.
pub fn set_enabled(on: bool) {
    enabled().store(on, Ordering::Relaxed);
    if !on {
        SAMPLES.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

pub(crate) fn observe(
    local: [u8; 32],
    destination: [u8; 32],
    local_lane: u8,
    hop: [u8; 32],
    accepted: bool,
    datagram_transport: bool,
) {
    if !enabled().load(Ordering::Relaxed) {
        return;
    }
    let now = Instant::now();
    let key = (local, destination, local_lane, hop);
    let snapshot = {
        let mut samples = SAMPLES.lock().unwrap_or_else(|p| p.into_inner());
        let fresh = !samples.contains_key(&key);
        if fresh && samples.len() >= 256 {
            samples.retain(|_, s| now.duration_since(s.logged_at) < Duration::from_secs(10));
            if samples.len() >= 256 {
                return;
            }
        }
        let s = samples.entry(key).or_insert(Sample {
            logged_at: now,
            accepted: 0,
            refused: 0,
        });
        if accepted {
            s.accepted = s.accepted.saturating_add(1);
        } else {
            s.refused = s.refused.saturating_add(1);
        }
        if !fresh && now.duration_since(s.logged_at) < Duration::from_secs(1) {
            return;
        }
        let result = (s.accepted, s.refused);
        s.accepted = 0;
        s.refused = 0;
        s.logged_at = now;
        result
    };
    log::info!(
        "ipc.rt_trace.relay_admission source={} dst={} local_slot={} hop={} accepted={} refused={} datagram_transport={}",
        veil_util::hex_short(&local),
        veil_util::hex_short(&destination),
        local_lane,
        veil_util::hex_short(&hop),
        snapshot.0,
        snapshot.1,
        datagram_transport,
    );
}
