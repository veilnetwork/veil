//! Local transport-success registry.
//!
//! Tracks observed `connect` outcomes per transport scheme (`tcp`, `tls`
//! `quic`, `ws`, `wss`, `socks`, `sockstls`, `unix`). Applications query the
//! registry via IPC to get a ranked list of transports that have actually
//! worked from this node, rather than guessing or hard-coding.
//!
//! # Use case
//!
//! Mobile client behind operator X opens veil; the node has tried TCP
//! TLS, QUIC and WebSocket against various peers. The local hints reflect
//! "from this network, TLS succeeded 90% of the time, QUIC was filtered (5%
//! success), WebSocket worked 80% of the time". The app uses this to bias
//! its reconnect strategy without operator config.
//!
//! # Scope
//!
//! This is the **local** registry only. Cross-node aggregation (so a
//! freshly-joined node benefits from older nodes' observations) is a
//! follow-on task — would publish the per-(asn, scheme) bundle into the DHT
//! similarly to config bundles.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::registry::TransportHintSink;

/// Per-scheme connect-attempt counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemeCounters {
    /// Number of successful `connect` calls observed for this scheme.
    pub success: u32,
    /// Number of failed `connect` calls observed for this scheme.
    pub failure: u32,
}

impl SchemeCounters {
    /// Success rate as a percentage (0..=100). Returns 0 when no probes
    /// have been recorded yet — callers should consult `total` to
    /// distinguish "no data" from "0% success".
    pub fn success_pct(&self) -> u8 {
        let total = self.total();
        if total == 0 {
            return 0;
        }
        ((self.success as u64 * 100) / total as u64) as u8
    }

    /// Total probe count.
    pub fn total(&self) -> u32 {
        self.success.saturating_add(self.failure)
    }
}

/// Bounded per-scheme counter map. Connect attempts are logged via
/// [`record`]; queries return a snapshot ordered by success-rate descending
/// ties broken by sample count (higher first) for stability.
pub struct TransportHintRegistry {
    inner: Mutex<HashMap<String, SchemeCounters>>,
    /// Ceiling on samples per scheme — once reached, both counters decay
    /// proportionally to keep recent data weighted higher. Without decay a
    /// long-running node would have stale historical data dominate fresh
    /// observations.
    sample_cap: u32,
}

impl Default for TransportHintRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportHintRegistry {
    /// Default cap of 1024 samples per scheme — enough for a low-noise rate
    /// estimate without keeping decades of history.
    pub const DEFAULT_SAMPLE_CAP: u32 = 1024;

    /// Create an empty registry with the default sample cap.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            sample_cap: Self::DEFAULT_SAMPLE_CAP,
        }
    }

    /// Record a probe outcome for `scheme` (e.g. "tcp", "quic", "tls").
    /// When the per-scheme sample count would exceed `sample_cap`, both
    /// success and failure counters are halved before incrementing — a
    /// cheap exponential-decay approximation.
    pub fn record(&self, scheme: &str, success: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let counters = inner.entry(scheme.to_owned()).or_default();
        if counters.total() >= self.sample_cap {
            counters.success /= 2;
            counters.failure /= 2;
        }
        if success {
            counters.success += 1;
        } else {
            counters.failure += 1;
        }
    }

    /// Snapshot all schemes ranked by success-rate descending. Schemes
    /// with no recorded probes are omitted. Tie-break: higher sample count
    /// wins (more confident estimate).
    pub fn ranked_snapshot(&self) -> Vec<(String, SchemeCounters)> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut entries: Vec<(String, SchemeCounters)> = inner
            .iter()
            .filter(|(_, c)| c.total() > 0)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| {
            b.1.success_pct()
                .cmp(&a.1.success_pct())
                .then(b.1.total().cmp(&a.1.total()))
                .then(a.0.cmp(&b.0))
        });
        entries
    }
}

// Same-crate impl: no orphan rule issues since `TransportHintSink` is also
// defined in this crate (`registry.rs`).
impl TransportHintSink for TransportHintRegistry {
    fn record(&self, scheme: &str, success: bool) {
        TransportHintRegistry::record(self, scheme, success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_returns_empty_snapshot() {
        let reg = TransportHintRegistry::new();
        assert!(reg.ranked_snapshot().is_empty());
    }

    #[test]
    fn success_rate_computed_correctly() {
        let reg = TransportHintRegistry::new();
        for _ in 0..9 {
            reg.record("tcp", true);
        }
        reg.record("tcp", false);
        let snap = reg.ranked_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "tcp");
        assert_eq!(snap[0].1.success_pct(), 90);
        assert_eq!(snap[0].1.total(), 10);
    }

    #[test]
    fn snapshot_orders_by_success_rate_then_sample_count() {
        let reg = TransportHintRegistry::new();
        // tcp: 80% (8/10)
        for _ in 0..8 {
            reg.record("tcp", true);
        }
        for _ in 0..2 {
            reg.record("tcp", false);
        }
        // quic: 100% (1/1) — highest rate, low confidence
        reg.record("quic", true);
        // tls: 80% (16/20) — same rate as tcp, more samples → ranks higher
        for _ in 0..16 {
            reg.record("tls", true);
        }
        for _ in 0..4 {
            reg.record("tls", false);
        }

        let snap = reg.ranked_snapshot();
        assert_eq!(snap[0].0, "quic"); // 100%
        assert_eq!(snap[1].0, "tls"); // 80%, 20 samples
        assert_eq!(snap[2].0, "tcp"); // 80%, 10 samples
    }

    #[test]
    fn schemes_with_no_data_are_omitted() {
        let reg = TransportHintRegistry::new();
        reg.record("tcp", true);
        // No `quic` records — must not appear in snapshot.
        let snap = reg.ranked_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "tcp");
    }

    #[test]
    fn sample_cap_decays_old_observations() {
        let mut reg = TransportHintRegistry::new();
        reg.sample_cap = 8;
        // Fill with 8 successes — at cap.
        for _ in 0..8 {
            reg.record("tcp", true);
        }
        let snap = reg.ranked_snapshot();
        assert_eq!(snap[0].1.success, 8);
        assert_eq!(snap[0].1.failure, 0);

        // 9th probe (failure) triggers decay: success 8 → 4, then failure
        // 0 → 1. So new ratio = 4/(4+1) = 80% — recent failure has more
        // weight than it would in a pure-counter model where it'd be 8/9 ≈ 89%.
        reg.record("tcp", false);
        let snap = reg.ranked_snapshot();
        assert_eq!(snap[0].1.success, 4);
        assert_eq!(snap[0].1.failure, 1);
        assert_eq!(snap[0].1.success_pct(), 80);
    }
}
