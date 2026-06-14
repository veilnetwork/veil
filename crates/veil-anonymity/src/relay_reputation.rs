//! Per-sender-local anonymity-relay reputation slice (Epic 482.3 / 482.4).
//!
//! **Wiring status (Epic 482.3/482.4 Phase A — wired):** the production sender
//! now selects hops via
//! [`crate::sender::build_outbound_anonymous_cell_with_diversity_reported_and_reputation`]
//! → [`crate::circuit_builder::pick_circuit_hops_latency_aware_with_diversity_and_reputation`],
//! feeding this ledger's [`RelayReputation::rtt_penalty_ms`] into the latency
//! score so failed relays sort behind alternatives. The runtime owns one
//! `Arc<RelayReputation>` (in `AnonymityState`) and records failures from TWO
//! signals:
//!
//! - **first-hop send failure** — an anonymity send whose chosen first hop has
//!   no live session (`session_tx_registry.send_to` returns `false`); recorded
//!   in `NodeServices::send_anonymous` / `send_via_rendezvous`.
//! - **relayed delivery timeout** — an acked delivery that exhausts all
//!   retransmits, attributed to its `next_hop` ONLY when `next_hop !=
//!   dst_node_id` (so a direct send to an offline destination is not blamed on
//!   a relay); recorded in the pending-ack tick (`spawn_pending_ack_tick`).
//!
//! Not covered (deferred): a relay that ADMITS a circuit build then silently
//! drops/stalls cells MID-STREAM. The anonymity send is intentionally
//! fire-and-forget with no return-ack (a return path would deanonymise the
//! sender), so there is no leak-free inline signal for it — catching it needs a
//! dedicated anonymity ack-protocol with its own deanonymisation trade-offs.
//!
//! Anonymity relays advertise `advertised_bps` in [`crate::directory::
//! RelayDirectoryEntry`] which is operator-self-reported and unverifiable
//! at directory-publish time. Relays can:
//!
//! - Lie about bandwidth (claim 1 Gbps, deliver 1 Mbps under load).
//! - Drop circuit cells silently after admitting the build.
//! - Stall mid-stream / time out on relayed cells.
//!
//! [`crate::circuit_builder::pick_circuit_hops_latency_aware`] selects
//! relays purely by RTT — a relay that admits builds quickly but then
//! drops or stalls cells keeps winning circuit slots until the operator
//! intervenes. This module gives the sender a short-term memory of
//! "which relays did NOT work as advertised" and downweights them in the
//! latency-aware sort.
//!
//! ## Threat model addressed
//!
//! Sybil-relay flooding and lying-about-advertised-bps are documented in
//! [`crate::directory`] as "out of scope here". Phase A of the mitigation
//! is exactly this module: per-sender-local failure counter that adds a
//! latency penalty to the relay's RTT score. After a handful of observed
//! drops, the relay sorts behind alternatives regardless of how low its
//! true RTT is.
//!
//! ## Symmetry with anycast reputation
//!
//! This is the same shape as [`veil_anycast::AnycastReputation`]:
//! - LRU-bounded HashMap by node_id (no service_tag dimension — a relay
//!   misbehaviour applies to all circuit usage of that relay).
//! - Failures only; successes are peer-game-able and not tracked.
//! - Wall-clock decay: one failure is forgiven per [`FAILURE_DECAY_INTERVAL`],
//!   so a false positive from the delivery-timeout signal self-heals instead of
//!   burying an honest relay forever (LRU still bounds memory). (Anycast Phase A
//!   has no decay; relays here are fed by a noisier timeout signal, so they need
//!   it more — see `FAILURE_DECAY_INTERVAL`.)
//! - No cross-sender sharing; per-sender-local Phase A only.
//!
//! Phase B (cross-sender gossip / signed reputation attestations) is
//! deferred for the same reasons as anycast Phase B: wire-protocol
//! work multiplier and new attack vectors (sybil-poisoning reputation
//! gossip itself).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use veil_util::lock;

/// Max number of (node_id) entries kept in memory before LRU eviction.
/// Each entry is ~44 bytes (32 + 12); 4096 ≈ 175 KiB. Same bound as
/// [`veil_anycast::reputation::REPUTATION_LRU_CAP`].
pub const RELAY_REPUTATION_LRU_CAP: usize = 4096;

/// Latency penalty (milliseconds) added per recorded failure. Applied
/// linearly to the relay's RTT score during sort in the latency-aware
/// circuit selector.
///
/// Tuning rationale: typical relay RTTs are 30–300 ms; common bad-relay
/// alternatives differ by 50–200 ms. 500 ms per failure pushes a
/// misbehaving relay behind viable alternatives after a single observed
/// drop, and past most candidates after 2–3 drops. Linear (not quadratic)
/// to keep the math obvious and avoid runaway penalties from a single
/// blip.
pub const FAILURE_PENALTY_MS: u32 = 500;

/// Wall-clock interval over which ONE recorded failure is forgiven.
///
/// The ledger is fed partly by a delivery-timeout signal that can false-positive
/// (a relayed timeout is sometimes the DESTINATION being offline, not the relay
/// misbehaving). Without decay those false positives accumulate forever (bounded
/// only by LRU eviction) and could bury an honest relay. Linear forgiveness —
/// `failures` drops by 1 for every whole interval of elapsed time since the most
/// recent failure — so one false positive (a single 500 ms penalty) clears in
/// one interval, while a genuinely misbehaving relay that keeps failing stays
/// penalised. 10 min balances quick recovery from a blip against not
/// whitewashing a persistently bad relay between a sender's circuit rebuilds.
pub const FAILURE_DECAY_INTERVAL: Duration = Duration::from_secs(600);

/// In-memory counter for one relay.
#[derive(Debug, Clone, Copy)]
struct Counter {
    failures: u32,
    /// Last access (record OR query) — drives LRU eviction recency.
    last_seen: Instant,
    /// Decay anchor: advanced by whole [`FAILURE_DECAY_INTERVAL`]s as failures
    /// are forgiven, and reset to "now" on each fresh failure.
    last_failure_at: Instant,
}

impl Counter {
    /// Apply elapsed-time forgiveness up to `now`, in place. Advances
    /// `last_failure_at` ONLY by the whole intervals consumed, so the
    /// sub-interval remainder is preserved (decay does not restart on every
    /// query). Does not touch `last_seen` (LRU recency is the caller's job).
    fn decay_to(&mut self, now: Instant) {
        let elapsed_secs = now
            .saturating_duration_since(self.last_failure_at)
            .as_secs();
        let intervals = (elapsed_secs / FAILURE_DECAY_INTERVAL.as_secs()) as u32;
        if intervals > 0 {
            self.failures = self.failures.saturating_sub(intervals);
            self.last_failure_at += FAILURE_DECAY_INTERVAL * intervals;
        }
    }
}

#[derive(Default)]
struct Inner {
    by_node: HashMap<[u8; 32], Counter>,
}

/// Bounded, in-memory relay-failure ledger.
///
/// Construct once per sender (or share across senders within a node).
/// Clone-cheap if wrapped in [`std::sync::Arc`].
pub struct RelayReputation {
    inner: Mutex<Inner>,
    cap: usize,
}

impl Default for RelayReputation {
    fn default() -> Self {
        Self::with_capacity(RELAY_REPUTATION_LRU_CAP)
    }
}

impl RelayReputation {
    /// Reputation slice with default LRU capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reputation slice with custom LRU capacity. Use in tests or memory-
    /// constrained environments. Capacity of 0 disables tracking
    /// entirely (every insert no-ops; penalty always returns 0).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap,
        }
    }

    /// Record one observed failure for the relay.
    ///
    /// Caller responsibility: only invoke after a concrete failure signal
    /// — circuit-build timeout, mid-stream stall, malformed forward, or
    /// gross bandwidth-claim violation. False positives directly hurt
    /// honest relays (mitigated by time-decay — see [`FAILURE_DECAY_INTERVAL`]).
    pub fn record_failure(&self, node_id: [u8; 32]) {
        self.record_failure_at(node_id, Instant::now());
    }

    /// [`Self::record_failure`] at an explicit `now` (test seam for decay).
    fn record_failure_at(&self, node_id: [u8; 32], now: Instant) {
        if self.cap == 0 {
            return;
        }
        let mut inner = lock!(self.inner);
        let entry = inner.by_node.entry(node_id).or_insert(Counter {
            failures: 0,
            last_seen: now,
            last_failure_at: now,
        });
        // Forgive elapsed time BEFORE adding the new failure, then re-anchor the
        // decay clock to this failure.
        entry.decay_to(now);
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_at = now;
        entry.last_seen = now;

        if inner.by_node.len() > self.cap
            && let Some(victim) = inner
                .by_node
                .iter()
                .min_by_key(|(_, c)| c.last_seen)
                .map(|(k, _)| *k)
        {
            inner.by_node.remove(&victim);
        }
    }

    /// RTT penalty (in ms) for the relay's latency-aware score. Returns
    /// 0 if no (un-decayed) failures remain. Querying applies pending decay,
    /// reclaims a fully-forgiven entry, and touches it for LRU purposes.
    pub fn rtt_penalty_ms(&self, node_id: [u8; 32]) -> u32 {
        self.rtt_penalty_ms_at(node_id, Instant::now())
    }

    /// [`Self::rtt_penalty_ms`] at an explicit `now` (test seam for decay).
    fn rtt_penalty_ms_at(&self, node_id: [u8; 32], now: Instant) -> u32 {
        if self.cap == 0 {
            return 0;
        }
        let mut inner = lock!(self.inner);
        let failures = {
            let Some(c) = inner.by_node.get_mut(&node_id) else {
                return 0;
            };
            c.decay_to(now);
            c.last_seen = now;
            c.failures
        };
        if failures == 0 {
            // Fully forgiven — reclaim the slot so it stops occupying LRU space.
            inner.by_node.remove(&node_id);
            return 0;
        }
        failures.saturating_mul(FAILURE_PENALTY_MS)
    }

    /// Test/diag: current entry count.
    pub fn entry_count(&self) -> usize {
        lock!(self.inner).by_node.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_penalty_is_zero() {
        let rep = RelayReputation::new();
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), 0);
    }

    #[test]
    fn decay_forgives_one_failure_per_interval() {
        // 3 failures at t0. Each whole FAILURE_DECAY_INTERVAL of elapsed time
        // forgives exactly one, and a fully-forgiven entry is reclaimed.
        let rep = RelayReputation::new();
        let t0 = Instant::now();
        for _ in 0..3 {
            rep.record_failure_at([0xAA; 32], t0);
        }
        assert_eq!(
            rep.rtt_penalty_ms_at([0xAA; 32], t0),
            3 * FAILURE_PENALTY_MS
        );

        // 2 intervals later → 2 forgiven → 1 remains.
        let t2 = t0 + FAILURE_DECAY_INTERVAL * 2;
        assert_eq!(rep.rtt_penalty_ms_at([0xAA; 32], t2), FAILURE_PENALTY_MS);

        // 1 more interval → fully forgiven; the slot is reclaimed.
        let t3 = t2 + FAILURE_DECAY_INTERVAL;
        assert_eq!(rep.rtt_penalty_ms_at([0xAA; 32], t3), 0);
        assert_eq!(
            rep.entry_count(),
            0,
            "fully-forgiven entry must be reclaimed"
        );
    }

    #[test]
    fn decay_preserves_subinterval_remainder() {
        // The decay clock advances only by WHOLE consumed intervals, so the
        // sub-interval remainder is not discarded on each query (which would
        // make decay slower the more often a relay is consulted).
        let rep = RelayReputation::new();
        let t0 = Instant::now();
        rep.record_failure_at([0xBB; 32], t0);
        rep.record_failure_at([0xBB; 32], t0); // 2 failures

        // 1.5 intervals → floor → 1 forgiven; the 0.5 remainder is carried.
        let t1 = t0 + FAILURE_DECAY_INTERVAL + FAILURE_DECAY_INTERVAL / 2;
        assert_eq!(rep.rtt_penalty_ms_at([0xBB; 32], t1), FAILURE_PENALTY_MS);

        // Another 0.5 interval → the carried 0.5 + 0.5 = one full interval →
        // the last failure is forgiven (would still be 1 if the remainder had
        // been discarded at t1).
        let t2 = t1 + FAILURE_DECAY_INTERVAL / 2;
        assert_eq!(rep.rtt_penalty_ms_at([0xBB; 32], t2), 0);
    }

    #[test]
    fn fresh_failure_reanchors_decay_clock() {
        // A failure long after a prior one starts the relay clean (the old one
        // fully decayed) and the new penalty is a single unit, not stale-plus-one.
        let rep = RelayReputation::new();
        let t0 = Instant::now();
        rep.record_failure_at([0xCC; 32], t0);
        // 5 intervals later the first failure is long gone; record a fresh one.
        let t_late = t0 + FAILURE_DECAY_INTERVAL * 5;
        rep.record_failure_at([0xCC; 32], t_late);
        assert_eq!(
            rep.rtt_penalty_ms_at([0xCC; 32], t_late),
            FAILURE_PENALTY_MS,
            "fresh failure after full decay = exactly one penalty unit",
        );
    }

    #[test]
    fn single_failure_adds_one_penalty() {
        let rep = RelayReputation::new();
        rep.record_failure([0xAA; 32]);
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), FAILURE_PENALTY_MS);
    }

    #[test]
    fn multiple_failures_compound_linearly() {
        let rep = RelayReputation::new();
        for _ in 0..4 {
            rep.record_failure([0xAA; 32]);
        }
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), 4 * FAILURE_PENALTY_MS);
    }

    #[test]
    fn separate_nodes_are_independent() {
        let rep = RelayReputation::new();
        rep.record_failure([0xAA; 32]);
        rep.record_failure([0xBB; 32]);
        rep.record_failure([0xBB; 32]);
        rep.record_failure([0xBB; 32]);
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), FAILURE_PENALTY_MS);
        assert_eq!(rep.rtt_penalty_ms([0xBB; 32]), 3 * FAILURE_PENALTY_MS);
        assert_eq!(rep.rtt_penalty_ms([0xCC; 32]), 0);
    }

    #[test]
    fn lru_evicts_oldest_when_over_cap() {
        let rep = RelayReputation::with_capacity(3);
        rep.record_failure([0x01; 32]);
        rep.record_failure([0x02; 32]);
        rep.record_failure([0x03; 32]);
        assert_eq!(rep.entry_count(), 3);

        let _ = rep.rtt_penalty_ms([0x01; 32]); // touch 0x01

        rep.record_failure([0x04; 32]); // over-cap insert
        assert_eq!(rep.entry_count(), 3);
        assert!(rep.rtt_penalty_ms([0x01; 32]) > 0);
        assert_eq!(rep.rtt_penalty_ms([0x02; 32]), 0, "0x02 was LRU victim");
        assert!(rep.rtt_penalty_ms([0x03; 32]) > 0);
        assert!(rep.rtt_penalty_ms([0x04; 32]) > 0);
    }

    #[test]
    fn zero_capacity_disables_tracking() {
        let rep = RelayReputation::with_capacity(0);
        rep.record_failure([0xAA; 32]);
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), 0);
        assert_eq!(rep.entry_count(), 0);
    }

    #[test]
    fn saturation_does_not_panic() {
        let rep = RelayReputation::new();
        // Force counter near saturation.
        rep.record_failure([0xAA; 32]);
        {
            let mut inner = lock!(rep.inner);
            inner.by_node.get_mut(&[0xAA; 32]).unwrap().failures = u32::MAX - 1;
        }
        rep.record_failure([0xAA; 32]);
        rep.record_failure([0xAA; 32]);
        rep.record_failure([0xAA; 32]);
        assert_eq!(rep.rtt_penalty_ms([0xAA; 32]), u32::MAX);
    }
}
