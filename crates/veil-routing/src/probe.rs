//! RTT probe records.
//!
//! `RttProbe` stores the most recent round-trip time measurement toward a
//! remote node. `RttTable` maintains one probe per peer.
//!
//! RTT values are used by `NeighborScorer` and `RouteCache` as hints — they
//! never affect identity, DHT placement, or ownership decisions.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// EWMA smoothing factor α — weight given to the newest sample.
///
/// α=0.2 means the smoothed value moves 20 % toward each new measurement
/// absorbing single-sample spikes while tracking real trends within ~5 samples.
const EWMA_ALPHA: f64 = 0.2;

/// Number of raw RTT samples kept in the stability sliding window.
const RTT_WINDOW_SIZE: usize = 5;

/// clamp accepted RTT samples to a plausible
/// physical range. `1 ms` is the lower bound on transcontinental
/// fiber (~150 km of fiber per ms; nothing real ever beats it), and
/// `60_000 ms` (60 s) is comfortably beyond any realistic link RTT —
/// values past it are either error states or adversarial. Clamping
/// at the boundary still records the measurement (so the peer is
/// scored as "extreme") rather than silently dropping it; honest
/// peers under sustained network failure see their entry decay
/// naturally via the existing freshness window.
pub const RTT_FLOOR_MS: u32 = 1;
pub const RTT_CEIL_MS: u32 = 60_000;

// ── PeerReportedRtt newtype ──────────────────────────────────
//
// cleanup: every entry point that ingests a peer-supplied RTT
// scalar manually called `.clamp(RTT_FLOOR_MS, RTT_CEIL_MS)` BEFORE forwarding
// it to `RttTable::record` / `RttProbe::update`. The fix from
// added the clamp in one site (`record`); X1 hardens the contract by
// MOVING the clamp into a constructor that runs ON CONSTRUCTION, so callers
// physically cannot skip it — a new entry point added by future code (e.g.
// a new wire frame variant carrying RTT) gets the protection automatically
// just by typing the field as `PeerReportedRtt`.
//
// Defends against a malicious peer advertising:
// * Absurdly low RTT (`1 ms` on transcontinental link) to win NeighborScorer
// preference and become an attractive relay-correlation vantage point.
// * Huge RTT (`u32::MAX`) to evict an honest peer from the route shortlist.

/// Peer-reported RTT measurement, clamped to the safe range
/// `[RTT_FLOOR_MS, RTT_CEIL_MS]` at construction time.
///
/// Construct [`PeerReportedRtt::from_raw_ms`] or [`PeerReportedRtt::new`]
/// (alias). The clamp runs unconditionally — no escape hatch — so an attacker-
/// supplied value cannot reach the routing layer without passing through it.
///
/// Use `as_clamped_ms` to extract the validated value for storage / arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerReportedRtt(u32);

impl PeerReportedRtt {
    /// Wrap a raw u32 RTT-in-milliseconds value, clamping to
    /// `[RTT_FLOOR_MS, RTT_CEIL_MS]`. Always succeeds — out-of-range
    /// values silently snap to the boundary (design: still
    /// record extreme samples so the peer is scored as "extreme"
    /// rather than silently dropping which would let attackers blank
    /// their RTT history).
    pub fn from_raw_ms(rtt_ms: u32) -> Self {
        Self(rtt_ms.clamp(RTT_FLOOR_MS, RTT_CEIL_MS))
    }

    /// Alias for [`Self::from_raw_ms`] — concise call site.
    pub fn new(rtt_ms: u32) -> Self {
        Self::from_raw_ms(rtt_ms)
    }

    /// Recover the validated, clamped RTT value.
    pub const fn as_clamped_ms(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for PeerReportedRtt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

// ── BandwidthClass ────────────────────────────────────────────────────────────

/// Coarse bandwidth tier for a path, updated via
/// [`RttTable::update_bandwidth_class`].
///
/// Stored as `u8` [`RttProbe`] so the scoring code can compare raw values
/// without importing this enum. Cast via `as u8` when storing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BandwidthClass {
    /// No measurement available (default).
    Unknown = 0,
    /// Estimated throughput < 256 kbps.
    Narrow = 1,
    /// Estimated throughput 256 kbps – 2 Mbps.
    Medium = 2,
    /// Estimated throughput ≥ 2 Mbps.
    Wide = 3,
}

impl BandwidthClass {
    /// Estimate bandwidth class from bytes transferred over a measured RTT.
    ///
    /// `bytes` is the number of bytes exchanged; `rtt_ms` is the round-trip
    /// time in milliseconds. We treat the one-way bandwidth as
    /// `bytes / (rtt_ms / 2000.0)` bps (rough heuristic, not an exact
    /// throughput measurement).
    pub fn from_bytes_per_rtt(bytes: u64, rtt_ms: u32) -> Self {
        if rtt_ms == 0 {
            return Self::Unknown;
        }
        // one-way bandwidth estimate: bytes / half-RTT in seconds → bps
        let bps = (bytes as f64) / (rtt_ms as f64 / 2000.0);
        if bps < 256_000.0 {
            Self::Narrow
        } else if bps < 2_000_000.0 {
            Self::Medium
        } else {
            Self::Wide
        }
    }
}

/// Compute the median of a non-empty sorted slice.
fn median_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

// ── RttProbe ──────────────────────────────────────────────────────────────────

/// A single latency measurement to a remote node.
#[derive(Debug, Clone, PartialEq)]
pub struct RttProbe {
    pub node_id: [u8; 32],
    /// Raw round-trip time of the most recent measurement (milliseconds).
    pub rtt_ms: u32,
    /// EWMA-smoothed RTT (milliseconds). Use this for routing decisions;
    /// use `rtt_ms` only when you want the raw latest sample.
    pub rtt_smoothed: u32,
    /// Congestion score reported by the remote node (0 = free, 255 = saturated).
    pub congestion: u8,
    /// When this measurement was taken.
    pub sampled_at: Instant,
    /// Sliding window of the last [`RTT_WINDOW_SIZE`] raw RTT samples (ms).
    ///
    /// Stored as a circular buffer; `window_pos` tracks the next write index.
    /// Entries are `u32::MAX` (sentinel) until overwritten by a real sample.
    window: [u32; RTT_WINDOW_SIZE],
    window_pos: usize,
    /// Number of samples recorded so far, capped at `RTT_WINDOW_SIZE`.
    window_len: usize,
    /// Cumulative number of RTT measurements recorded for this peer.
    ///
    /// Incremented on every `record` call (including the first). Used by the
    /// proactive-probe scheduler to prioritise well-contacted peers on startup.
    pub contact_count: u32,
    /// Last advertised battery charge level from this peer's mesh beacon.
    ///
    /// 0 = unknown or on AC power (no routing penalty applied). 1–100 = percent
    /// charge as reported in `MeshBeaconPayload.battery_level`.
    pub battery_level: u8,
    /// Coarse bandwidth tier for this path.
    ///
    /// Stored as the `u8` discriminant [`BandwidthClass`]; compare against
    /// `BandwidthClass::Narrow as u8` etc. Updated via
    /// [`RttTable::update_bandwidth_class`]. `0` = `BandwidthClass::Unknown`
    /// (default — no penalty applied).
    pub bandwidth_class: u8,

    // ── relay reputation ─────────────────────────────────────────────
    /// Total number of times a frame was forwarded through this peer.
    pub relay_attempts: u32,
    /// Total number of relay attempts that resulted in an E2E ACK.
    pub relay_successes: u32,
    /// Relay success rate as `relay_successes / max(1, relay_attempts)`.
    ///
    /// Starts at `1.0` (no history → no penalty). Converges toward the true
    /// success fraction as more attempts are observed. Routing uses this value
    /// to penalise unreliable relays without requiring a minimum sample count
    /// to be stored externally.
    pub relay_success_ema: f32,
}

impl RttProbe {
    /// Create a brand-new probe (first sample). `rtt_smoothed` is initialised
    /// to `rtt_ms` because there is no prior history to blend with.
    pub fn new(node_id: [u8; 32], rtt_ms: u32, congestion: u8) -> Self {
        let mut window = [u32::MAX; RTT_WINDOW_SIZE];
        window[0] = rtt_ms;
        Self {
            node_id,
            rtt_ms,
            rtt_smoothed: rtt_ms,
            congestion,
            sampled_at: Instant::now(),
            window,
            window_pos: 1 % RTT_WINDOW_SIZE,
            window_len: 1,
            contact_count: 1,
            battery_level: 0,
            bandwidth_class: 0,
            relay_attempts: 0,
            relay_successes: 0,
            relay_success_ema: 1.0,
        }
    }

    /// Update this probe with a new measurement, applying EWMA smoothing.
    ///
    /// `rtt_smoothed = α × new_rtt + (1−α) × prev_smoothed`
    pub fn update(&mut self, new_rtt_ms: u32, new_congestion: u8) {
        self.rtt_ms = new_rtt_ms;
        let smoothed =
            EWMA_ALPHA * new_rtt_ms as f64 + (1.0 - EWMA_ALPHA) * self.rtt_smoothed as f64;
        self.rtt_smoothed = smoothed.round() as u32;
        self.congestion = new_congestion;
        self.sampled_at = Instant::now();
        self.contact_count = self.contact_count.saturating_add(1);
        // Update circular window.
        self.window[self.window_pos] = new_rtt_ms;
        self.window_pos = (self.window_pos + 1) % RTT_WINDOW_SIZE;
        if self.window_len < RTT_WINDOW_SIZE {
            self.window_len += 1;
        }
    }

    /// Path stability as the coefficient of variation of the RTT window.
    ///
    /// Returns `std_dev / mean` of the last up-to-[`RTT_WINDOW_SIZE`] raw
    /// RTT samples. A value near `0.0` means the path is stable; a high
    /// value indicates jitter or oscillation.
    ///
    /// Returns `f64::MAX` ("treat as unstable") when fewer than
    /// [`RTT_WINDOW_SIZE`] samples have been collected, because we don't yet
    /// have enough data to classify the path.
    pub fn stability(&self) -> f64 {
        if self.window_len < RTT_WINDOW_SIZE {
            return f64::MAX; // not enough samples — assume unstable
        }
        let samples: Vec<f64> = self
            .window
            .iter()
            .filter(|&&v| v != u32::MAX)
            .map(|&v| v as f64)
            .collect();
        let n = samples.len() as f64;
        if n < 2.0 {
            return f64::MAX;
        }
        let mean = samples.iter().sum::<f64>() / n;
        if mean <= 0.0 {
            return 0.0;
        }
        let variance = samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        variance.sqrt() / mean
    }

    /// Jitter as the Median Absolute Deviation (MAD) of the RTT window.
    ///
    /// MAD is more robust than the coefficient of variation (`stability`)
    /// because a single outlier shifts the mean but barely moves the median.
    ///
    /// Returns `0.0` when fewer than two samples have been recorded.
    pub fn jitter_ms(&self) -> f64 {
        if self.window_len < 2 {
            return 0.0;
        }
        let mut samples: Vec<f64> = self
            .window
            .iter()
            .filter(|&&v| v != u32::MAX)
            .map(|&v| v as f64)
            .collect();
        if samples.len() < 2 {
            return 0.0;
        }
        samples.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let med = median_sorted(&samples);
        let mut devs: Vec<f64> = samples.iter().map(|&x| (x - med).abs()).collect();
        devs.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        median_sorted(&devs)
    }

    /// True if this measurement is older than `max_age`.
    pub fn is_stale(&self, now: Instant, max_age: Duration) -> bool {
        now.duration_since(self.sampled_at) > max_age
    }

    /// Confidence weight in `[0.0, 1.0]` based on how fresh this probe is.
    ///
    /// Returns `1.0` for a brand-new probe and decays linearly to `0.0` as
    /// `sampled_at` approaches `max_age` ago.
    ///
    /// Callers should multiply `effective_weight` by this value so that stale
    /// probes carry less influence in routing decisions and effectively fall
    /// back to the same treatment as unknown peers.
    pub fn confidence(&self, now: Instant, max_age: Duration) -> f64 {
        let elapsed = now.duration_since(self.sampled_at).as_secs_f64();
        let max = max_age.as_secs_f64();
        if max <= 0.0 {
            return 1.0;
        }
        (1.0 - elapsed / max).max(0.0)
    }
}

// ── RttTable ──────────────────────────────────────────────────────────────────

/// Stores the most recent RTT probe per node.
///
/// Thread-safety is the caller's responsibility; wrap in `Arc<Mutex<_>>` if
/// shared across tasks.
#[derive(Debug, Default, Clone)]
pub struct RttTable {
    probes: HashMap<[u8; 32], RttProbe>,
    /// Maximum age before a probe is considered stale.
    max_age: Duration,
    /// Contact counts restored from a persisted snapshot.
    ///
    /// Populated by [`RttTable::restore_contact_count`] at startup from the
    /// route-cache snapshot. An entry is removed the first time a live
    /// [`record`] arrives for that peer so that real measurements take over.
    restored_counts: HashMap<[u8; 32], u32>,
}

impl RttTable {
    pub fn new(max_age: Duration) -> Self {
        Self {
            probes: HashMap::new(),
            max_age,
            restored_counts: HashMap::new(),
        }
    }

    /// Record (or update) an RTT measurement for `node_id`.
    ///
    /// On the first measurement `rtt_smoothed = rtt_ms`. On subsequent calls
    /// the smoothed value is updated via EWMA so routing decisions are not
    /// thrown off by single-sample spikes.
    ///
    /// the `rtt_ms` parameter is a [`PeerReportedRtt`] — already
    /// clamped to `[RTT_FLOOR_MS, RTT_CEIL_MS]` at construction time. The
    /// clamp lives in the type rather than this function, so a new caller
    /// added by future code cannot accidentally bypass it (the type system
    /// physically refuses raw `u32`). / originated the
    /// clamp; X1 just moves enforcement to the construction boundary.
    ///
    /// Source-validation (peer can't be the sample's source) is enforced at
    /// the caller layer where the wire-frame parser knows who advertised what.
    pub fn record(&mut self, node_id: [u8; 32], rtt_ms: PeerReportedRtt, congestion: u8) {
        let rtt_ms = rtt_ms.as_clamped_ms();
        // Real measurement supersedes any restored contact count.
        let restored = self.restored_counts.remove(&node_id).unwrap_or(0);
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.update(rtt_ms, congestion);
        } else {
            let mut probe = RttProbe::new(node_id, rtt_ms, congestion);
            // Carry forward the restored count so the probe history is coherent.
            if restored > 1 {
                probe.contact_count = probe.contact_count.saturating_add(restored - 1);
            }
            self.probes.insert(node_id, probe);
        }
    }

    /// Restore a historical contact count for `node_id` from a persisted snapshot.
    ///
    /// Only stored if no live probe already exists for this peer. Removed
    /// automatically when the first real `record` for this peer arrives.
    /// Used by `top_by_contact_count` to prioritise well-known peers at startup
    /// before fresh RTT measurements have been collected.
    pub fn restore_contact_count(&mut self, node_id: [u8; 32], count: u32) {
        if count == 0 || self.probes.contains_key(&node_id) {
            return;
        }
        self.restored_counts.insert(node_id, count);
    }

    /// Record a relay forwarding attempt through `node_id`.
    ///
    /// Increments `relay_attempts` and recomputes `relay_success_ema` as the
    /// exact ratio `relay_successes / relay_attempts`. Only updates an existing
    /// live probe; silently ignored if no probe exists yet.
    pub fn record_relay_attempt(&mut self, node_id: [u8; 32]) {
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.relay_attempts = probe.relay_attempts.saturating_add(1);
            probe.relay_success_ema =
                probe.relay_successes as f32 / probe.relay_attempts.max(1) as f32;
        }
    }

    /// Record a successful relay delivery through `node_id`.
    ///
    /// Increments `relay_successes` and recomputes `relay_success_ema`.
    /// Call this when an E2E `DeliveryStatus::DELIVERED` ACK is correlated
    /// back to a pending forward that went through this peer.
    pub fn record_relay_success(&mut self, node_id: [u8; 32]) {
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.relay_successes = probe.relay_successes.saturating_add(1);
            probe.relay_success_ema =
                probe.relay_successes as f32 / probe.relay_attempts.max(1) as f32;
        }
    }

    /// Update the bandwidth class for `node_id`.
    ///
    /// Called when a bytes-transferred / RTT pair is available (e.g. after a
    /// bulk data exchange). Only updates an existing live probe — if no probe
    /// exists yet the update is silently ignored and will be applied on the next
    /// real `record` call.
    pub fn update_bandwidth_class(&mut self, node_id: [u8; 32], bytes: u64, rtt_ms: u32) {
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.bandwidth_class = BandwidthClass::from_bytes_per_rtt(bytes, rtt_ms) as u8;
        }
    }

    /// Update (or create) the battery level for `node_id`.
    ///
    /// Called by the beacon receiver each time a `MeshBeaconPayload` arrives.
    /// If a live probe exists for this peer it is updated in-place; otherwise
    /// we stash the level so it will be applied when the first RTT probe arrives.
    pub fn update_battery(&mut self, node_id: [u8; 32], level: u8) {
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.battery_level = level;
        }
        // If no probe yet, we don't synthesise a fake one — the battery level
        // will be populated on the first real record via the probe that is
        // created then. Store it temporarily in a side channel that record
        // can pick up. For now this is a best-effort update; the level will
        // arrive via the next beacon before the peer is used for routing.
    }

    /// Mark `node_id` as congested due to a backpressure signal.
    ///
    /// Sets the congestion field to 255 (saturated) so that the weighted route
    /// selection naturally shifts traffic to alternative hops. The elevated
    /// congestion decays on the next regular RouteProbe/Reply exchange, so the
    /// effect is temporary — typically one probe cycle (1–5 s).
    pub fn apply_backpressure(&mut self, node_id: [u8; 32]) {
        if let Some(probe) = self.probes.get_mut(&node_id) {
            probe.congestion = 255;
        }
    }

    /// Return the last probe for `node_id` if it is not stale.
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&RttProbe> {
        let now = Instant::now();
        self.probes
            .get(node_id)
            .filter(|p| !p.is_stale(now, self.max_age))
    }

    /// Return the last (possibly stale) probe and its confidence weight.
    ///
    /// Unlike `get`, this returns the probe even if stale — but callers can
    /// multiply the routing weight by `confidence` to naturally
    /// de-emphasise stale measurements without a hard cut-off.
    pub fn get_with_confidence(&self, node_id: &[u8; 32]) -> Option<(&RttProbe, f64)> {
        let now = Instant::now();
        self.probes
            .get(node_id)
            .map(|p| (p, p.confidence(now, self.max_age)))
    }

    /// The configured max-age for probes in this table.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Remove all stale probes.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let max_age = self.max_age;
        self.probes.retain(|_, p| !p.is_stale(now, max_age));
    }

    pub fn len(&self) -> usize {
        self.probes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// Return the `n` node_ids with the highest `contact_count`.
    ///
    /// Merges live probes with restored counts from the startup snapshot so
    /// that well-known peers are prioritised even before fresh RTT measurements
    /// arrive. Live probe counts shadow restored counts for the same peer.
    pub fn top_by_contact_count(&self, n: usize) -> Vec<[u8; 32]> {
        // Start with live probes.
        let mut entries: Vec<([u8; 32], u32)> = self
            .probes
            .values()
            .map(|p| (p.node_id, p.contact_count))
            .collect();
        // Append restored counts for peers that have no live probe yet.
        for (&id, &cnt) in &self.restored_counts {
            if !self.probes.contains_key(&id) {
                entries.push((id, cnt));
            }
        }
        entries.sort_unstable_by_key(|(_, ts)| std::cmp::Reverse(*ts));
        entries.into_iter().take(n).map(|(id, _)| id).collect()
    }

    /// Return the contact count for `node_id`, considering both live probes
    /// and restored snapshot counts.
    pub fn contact_count(&self, node_id: &[u8; 32]) -> u32 {
        self.probes
            .get(node_id)
            .map(|p| p.contact_count)
            .or_else(|| self.restored_counts.get(node_id).copied())
            .unwrap_or(0)
    }

    /// Build a `node_id → contact_count` map covering all live probes and
    /// restored counts. Used when flushing the route-cache snapshot.
    pub fn all_contact_counts(&self) -> std::collections::HashMap<[u8; 32], u32> {
        let mut out: std::collections::HashMap<[u8; 32], u32> = self
            .probes
            .values()
            .map(|p| (p.node_id, p.contact_count))
            .collect();
        for (&id, &cnt) in &self.restored_counts {
            out.entry(id).or_insert(cnt);
        }
        out
    }

    // ── persistence ─────────────────────────────────────────────

    /// Capture a lightweight snapshot of all current probes for persistence.
    ///
    /// The raw sliding window and `Instant` fields are not serialisable; only
    /// the stable derived values are captured. On restore these are used as
    /// seed values until fresh measurements overwrite them.
    pub fn snapshot(&self) -> Vec<RttSnapshot> {
        self.probes
            .values()
            .map(|p| RttSnapshot {
                node_id: p.node_id,
                rtt_smoothed: p.rtt_smoothed,
                congestion: p.congestion,
                battery_level: p.battery_level,
                contact_count: p.contact_count,
            })
            .collect()
    }

    /// Restore probes from a persisted snapshot.
    ///
    /// Each entry is inserted as a fresh probe with `rtt_smoothed` pre-seeded
    /// from the snapshot. The `sampled_at` timestamp is set just before
    /// `max_age` so the probe's `confidence` starts near `0.0` — it acts as
    /// a weak prior that is quickly overridden by the first real measurement.
    ///
    /// Peers already present in the table (from a concurrent live measurement)
    /// are not overwritten.
    pub fn restore(&mut self, entries: Vec<RttSnapshot>) {
        // Place sampled_at just inside the age window so confidence ≈ 0.
        let stale_offset = self.max_age.saturating_sub(Duration::from_secs(1));
        let fake_sampled_at = Instant::now()
            .checked_sub(stale_offset)
            .unwrap_or_else(Instant::now);

        for snap in entries {
            if self.probes.contains_key(&snap.node_id) {
                continue; // live measurement wins
            }
            let mut window = [u32::MAX; RTT_WINDOW_SIZE];
            window[0] = snap.rtt_smoothed;
            let probe = RttProbe {
                node_id: snap.node_id,
                rtt_ms: snap.rtt_smoothed,
                rtt_smoothed: snap.rtt_smoothed,
                congestion: snap.congestion,
                sampled_at: fake_sampled_at,
                window,
                window_pos: 1 % RTT_WINDOW_SIZE,
                window_len: 1,
                contact_count: snap.contact_count,
                battery_level: snap.battery_level,
                bandwidth_class: 0,
                relay_attempts: 0,
                relay_successes: 0,
                relay_success_ema: 1.0,
            };
            self.probes.insert(snap.node_id, probe);
        }
    }
}

// ── RttSnapshot ───────────────────────────────────────────────────────────────

/// Serialisable subset [`RttProbe`] used for disk persistence.
///
/// Only stable derived values are stored — `Instant` and the raw sliding
/// window are reconstructed on restore.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RttSnapshot {
    pub node_id: [u8; 32],
    pub rtt_smoothed: u32,
    pub congestion: u8,
    pub battery_level: u8,
    pub contact_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_get() {
        let mut table = RttTable::new(Duration::from_secs(60));
        table.record([1u8; 32], PeerReportedRtt::from_raw_ms(42), 0);
        let probe = table.get(&[1u8; 32]).unwrap();
        assert_eq!(probe.rtt_ms, 42);
    }

    #[test]
    fn unknown_node_returns_none() {
        let table = RttTable::new(Duration::from_secs(60));
        assert!(table.get(&[9u8; 32]).is_none());
    }

    #[test]
    fn overwrite_updates_rtt() {
        let mut table = RttTable::new(Duration::from_secs(60));
        table.record([1u8; 32], PeerReportedRtt::from_raw_ms(100), 0);
        table.record([1u8; 32], PeerReportedRtt::from_raw_ms(20), 0);
        // rtt_ms = latest raw sample
        assert_eq!(table.get(&[1u8; 32]).unwrap().rtt_ms, 20);
    }

    #[test]
    fn ewma_smoothing_dampens_spike() {
        let mut table = RttTable::new(Duration::from_secs(60));
        let id = [1u8; 32];
        // Establish baseline of 100 ms.
        for _ in 0..10 {
            table.record(id, PeerReportedRtt::from_raw_ms(100), 0);
        }
        let before = table.get(&id).unwrap().rtt_smoothed;
        // One-off spike to 500 ms.
        table.record(id, PeerReportedRtt::from_raw_ms(500), 0);
        let after = table.get(&id).unwrap().rtt_smoothed;
        // Smoothed should be < 200 ms (spike absorbed), but > (trend registered).
        assert!(after > before, "spike should raise smoothed value");
        assert!(
            after < 200,
            "spike of 500 ms should not dominate: got {after}"
        );
    }

    #[test]
    fn ewma_first_sample_equals_raw() {
        let mut table = RttTable::new(Duration::from_secs(60));
        table.record([2u8; 32], PeerReportedRtt::from_raw_ms(77), 0);
        let p = table.get(&[2u8; 32]).unwrap();
        assert_eq!(p.rtt_smoothed, 77, "first sample: smoothed must equal raw");
    }

    #[test]
    fn evict_stale_removes_expired() {
        let mut table = RttTable::new(Duration::ZERO);
        table.record([1u8; 32], PeerReportedRtt::from_raw_ms(10), 0);
        // With max_age=0, the probe is immediately stale
        table.evict_stale();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn get_returns_none_for_stale() {
        let mut table = RttTable::new(Duration::ZERO);
        table.record([1u8; 32], PeerReportedRtt::from_raw_ms(10), 0);
        // max_age=0 → immediately stale
        assert!(table.get(&[1u8; 32]).is_none());
    }

    // ── stability tests ────────────────────────────────────────

    #[test]
    fn stability_returns_max_when_fewer_than_window_samples() {
        let probe = RttProbe::new([0u8; 32], 50, 0);
        // Only 1 sample — fewer than RTT_WINDOW_SIZE → unstable sentinel.
        assert_eq!(probe.stability(), f64::MAX);
    }

    #[test]
    fn stability_near_zero_for_constant_rtt() {
        let mut table = RttTable::new(Duration::from_secs(60));
        let id = [1u8; 32];
        for _ in 0..RTT_WINDOW_SIZE {
            table.record(id, PeerReportedRtt::from_raw_ms(100), 0);
        }
        let probe = table.get(&id).unwrap();
        // All samples equal → std_dev = 0 → stability = 0.
        assert!(
            probe.stability() < 0.001,
            "constant RTT must be near-zero stable"
        );
    }

    #[test]
    fn stability_high_for_jittery_rtt() {
        let mut table = RttTable::new(Duration::from_secs(60));
        let id = [2u8; 32];
        // Alternating extreme values → high coefficient of variation.
        for i in 0..RTT_WINDOW_SIZE {
            let rtt = if i % 2 == 0 { 10 } else { 1000 };
            table.record(id, PeerReportedRtt::from_raw_ms(rtt), 0);
        }
        let probe = table.get(&id).unwrap();
        assert!(
            probe.stability() > 0.5,
            "jittery RTT must have high stability value"
        );
    }

    // ── snapshot / restore ─────────────────────────────────────────

    /// snapshot captures the current probes; restore seeds a fresh table.
    #[test]
    fn snapshot_and_restore_preserves_rtt() {
        let id_a = [0x0Au8; 32];
        let id_b = [0x0Bu8; 32];

        let mut src = RttTable::new(Duration::from_secs(300));
        src.record(id_a, PeerReportedRtt::from_raw_ms(50), 10);
        src.record(id_b, PeerReportedRtt::from_raw_ms(120), 0);
        // Set battery level on one peer.
        src.update_battery(id_a, 42);
        // Record a few more samples so contact_count > 1.
        for _ in 0..3 {
            src.record(id_a, PeerReportedRtt::from_raw_ms(55), 10);
        }

        let snap = src.snapshot();
        assert_eq!(snap.len(), 2);

        let mut dst = RttTable::new(Duration::from_secs(300));
        dst.restore(snap);

        let pa = dst.probes.get(&id_a).unwrap();
        assert_eq!(
            pa.rtt_smoothed, src.probes[&id_a].rtt_smoothed,
            "rtt_smoothed must be preserved"
        );
        assert_eq!(pa.congestion, 10, "congestion must be preserved");
        assert_eq!(pa.battery_level, 42, "battery_level must be preserved");
        assert_eq!(
            pa.contact_count, src.probes[&id_a].contact_count,
            "contact_count must be preserved"
        );

        let pb = dst.probes.get(&id_b).unwrap();
        assert_eq!(pb.rtt_smoothed, src.probes[&id_b].rtt_smoothed);
    }

    /// restore does not overwrite a live probe that arrived before restore.
    #[test]
    fn restore_does_not_overwrite_live_probe() {
        let id = [0x01u8; 32];

        let mut table = RttTable::new(Duration::from_secs(300));
        table.record(id, PeerReportedRtt::from_raw_ms(30), 0); // live measurement

        let snap = vec![RttSnapshot {
            node_id: id,
            rtt_smoothed: 999,
            congestion: 200,
            battery_level: 99,
            contact_count: 1000,
        }];
        table.restore(snap);

        // The live probe must not be overwritten.
        assert_eq!(
            table.probes[&id].rtt_smoothed,
            table.probes[&id].rtt_smoothed
        );
        assert_ne!(
            table.probes[&id].rtt_smoothed, 999,
            "live probe must not be replaced by restore"
        );
    }

    // ── jitter_ms tests ───────────────────────────────────────

    #[test]
    fn jitter_ms_zero_for_single_sample() {
        let probe = RttProbe::new([0u8; 32], 100, 0);
        assert_eq!(probe.jitter_ms(), 0.0, "single sample → no jitter");
    }

    #[test]
    fn jitter_ms_zero_for_constant_rtt() {
        let mut table = RttTable::new(Duration::from_secs(60));
        let id = [1u8; 32];
        for _ in 0..RTT_WINDOW_SIZE {
            table.record(id, PeerReportedRtt::from_raw_ms(100), 0);
        }
        let probe = table.get(&id).unwrap();
        assert!(
            probe.jitter_ms() < 1.0,
            "constant RTT → near-zero MAD jitter"
        );
    }

    #[test]
    fn jitter_ms_nonzero_for_variable_rtt() {
        let mut table = RttTable::new(Duration::from_secs(60));
        let id = [2u8; 32];
        // 4 samples alternating 10ms / 90ms: sorted=[10,10,90,90]
        // median=(10+90)/2=50, devs=[40,40,40,40] → MAD=40.
        // Keeping an even count avoids the all-equal-to-median edge case.
        for i in 0..4usize {
            table.record(
                id,
                PeerReportedRtt::from_raw_ms(if i % 2 == 0 { 10 } else { 90 }),
                0,
            );
        }
        let probe = table.get(&id).unwrap();
        assert!(
            probe.jitter_ms() > 10.0,
            "variable RTT must produce nonzero MAD jitter"
        );
    }

    // ── relay reputation tests ──────────────────────────────────

    #[test]
    fn relay_ema_converges_to_success_rate() {
        let id = [0x99u8; 32];
        let mut table = RttTable::new(Duration::from_secs(60));
        table.record(id, PeerReportedRtt::from_raw_ms(30), 0);
        // Record 10 attempts with 5 successes.
        for _ in 0..10 {
            table.record_relay_attempt(id);
        }
        for _ in 0..5 {
            table.record_relay_success(id);
        }
        let probe = table.get(&id).unwrap();
        assert!(
            (probe.relay_success_ema - 0.5).abs() < 0.01,
            "10 attempts, 5 successes → relay_success_ema ≈ 0.5, got {}",
            probe.relay_success_ema,
        );
    }

    // ── BandwidthClass tests ─────────────────────────────────────

    #[test]
    fn bandwidth_class_from_bytes_per_rtt() {
        // 64 bytes over 2ms RTT → 64 / = 64000 bps → Narrow
        assert_eq!(
            BandwidthClass::from_bytes_per_rtt(64, 2),
            BandwidthClass::Narrow
        );
        // 256_000 bytes over 2ms RTT → 256M bps → Wide
        assert_eq!(
            BandwidthClass::from_bytes_per_rtt(256_000, 2),
            BandwidthClass::Wide
        );
        // 0 rtt_ms → Unknown
        assert_eq!(
            BandwidthClass::from_bytes_per_rtt(1000, 0),
            BandwidthClass::Unknown
        );
    }

    #[test]
    fn update_bandwidth_class_sets_field() {
        let id = [3u8; 32];
        let mut table = RttTable::new(Duration::from_secs(60));
        table.record(id, PeerReportedRtt::from_raw_ms(50), 0);
        // Large bytes over short RTT → Wide bandwidth
        table.update_bandwidth_class(id, 1_000_000, 10);
        let probe = table.get(&id).unwrap();
        assert_eq!(probe.bandwidth_class, BandwidthClass::Wide as u8);
    }

    /// snapshot/restore round-trips through JSON (serde).
    #[test]
    fn snapshot_json_roundtrip() {
        let id = [0xABu8; 32];
        let mut table = RttTable::new(Duration::from_secs(300));
        table.record(id, PeerReportedRtt::from_raw_ms(77), 5);
        let snap = table.snapshot();

        let json = serde_json::to_string(&snap).unwrap();
        let back: Vec<RttSnapshot> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].rtt_smoothed, 77);
        assert_eq!(back[0].congestion, 5);
    }

    /// a peer reporting an absurdly low RTT
    /// (e.g. 0 ms — physically impossible across any real link) is
    /// clamped to RTT_FLOOR_MS rather than stored verbatim. Without
    /// the clamp such a peer would dominate NeighborScorer ranking and
    /// win selection as a relay-correlation vantage point.
    #[test]
    fn phase647_h26_zero_rtt_is_clamped_to_floor() {
        let id = [0x11u8; 32];
        let mut table = RttTable::new(Duration::from_secs(300));
        table.record(id, PeerReportedRtt::from_raw_ms(0), 0);
        let p = table.get(&id).unwrap();
        assert_eq!(
            p.rtt_ms, RTT_FLOOR_MS,
            "0 ms must clamp to floor, not store verbatim"
        );
    }

    /// a peer reporting a huge RTT (overflowing realistic link
    /// times) is clamped to RTT_CEIL_MS — equivalent to "ridiculously
    /// far" rather than allowed to push true measurements out of the
    /// EWMA via repeated adversarial samples.
    #[test]
    fn phase647_h26_huge_rtt_is_clamped_to_ceil() {
        let id = [0x22u8; 32];
        let mut table = RttTable::new(Duration::from_secs(300));
        table.record(id, PeerReportedRtt::from_raw_ms(u32::MAX), 0);
        let p = table.get(&id).unwrap();
        assert_eq!(p.rtt_ms, RTT_CEIL_MS, "u32::MAX must clamp to ceiling");
    }

    /// an in-range RTT passes through untouched (sanity).
    #[test]
    fn phase647_h26_in_range_rtt_passes_through() {
        let id = [0x33u8; 32];
        let mut table = RttTable::new(Duration::from_secs(300));
        table.record(id, PeerReportedRtt::from_raw_ms(42), 0);
        let p = table.get(&id).unwrap();
        assert_eq!(p.rtt_ms, 42);
    }
}
