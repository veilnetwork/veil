//! What this node will spend serving OTHER people.
//!
//! # Why this exists
//!
//! Measured on an idle production client (18.08.2026, `role = "leaf"`, three
//! bytes per second of actual application traffic): **14.8 KB/s, 1.3 GB a day**
//! — and on a phone, 5 GB a day. Split by message type, the bill read:
//!
//! | what | B/s | MB/day |
//! |---|---:|---:|
//! | `discovery/store` — strangers writing records into our store | 4323 | 373 |
//! | `routing/recursive_response` — we are a hop of somebody's walk | 955 | 83 |
//! | `discovery/find_node_v2` — somebody else's search | 576 | 50 |
//! | `discovery/resolve_transport` — somebody else's resolve | 359 | 31 |
//! | `relay_chain` — somebody else's onion circuits | 345 | 30 |
//! | **answers to OUR OWN questions** | **13** | **1** |
//!
//! A client's own needs were one thousandth of the bill. Everything else was
//! work done for other people, unmetered and unbounded, on a battery.
//!
//! # Why a budget rather than a switch
//!
//! Turning it off is the obvious move and the wrong one here: every xVeil
//! client runs as `leaf` and only the seeds are `core`, so a leaf that stops
//! storing takes the DHT's whole replica set down to the seeds. A budget keeps
//! clients contributing, and makes the contribution a number the owner sets
//! rather than a surprise the network decides.
//!
//! # What is and is not charged
//!
//! Charged: work whose beneficiary is someone else — storing their records,
//! answering their lookups, forwarding their walks, carrying their circuits.
//!
//! Never charged: our own requests and the answers to them, the route gossip
//! we need to stay reachable ourselves, keepalive, session and control. A
//! budget that could starve those would take a node off the network to save
//! its bandwidth, which is not a trade anyone asked for.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use veil_abuse::rate_limiter::TokenBucket;
use veil_types::NodeRole;

/// The kind of favour being asked, for the refusal log and the counters.
///
/// Kept as an enum rather than a string so a new charged path cannot be added
/// without deciding what it is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// A stranger wants their record kept in our store.
    StoreRecord,
    /// A stranger wants an answer from our routing table or store.
    Lookup,
    /// We are asked to be one hop of somebody's recursive walk.
    ForwardWalk,
    /// We are asked to carry somebody's onion circuit.
    RelayCircuit,
}

impl ServiceKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ServiceKind::StoreRecord => "store_record",
            ServiceKind::Lookup => "lookup",
            ServiceKind::ForwardWalk => "forward_walk",
            ServiceKind::RelayCircuit => "relay_circuit",
        }
    }
}

/// Bytes per hour this node will spend on other people's work by default.
///
/// Sized from the measurement above: serving cost was ~5.8 KB/s inbound plus
/// roughly as much again in the replies, i.e. ~40 MB an hour. 8 MB an hour is
/// a fifth of that — enough that a node stays a useful replica and a useful
/// hop, small enough that the bill stops being the dominant line.
pub const DEFAULT_SERVICE_BYTES_PER_HOUR: u64 = 8 * 1024 * 1024;

/// What a phone should spend by default: an eighth of the desktop figure,
/// about 24 MB a day. A mobile node is the one paying for this in metered data
/// and battery, and it is also the one the network can least rely on as a
/// replica — it is asleep half the time.
pub const MOBILE_SERVICE_BYTES_PER_HOUR: u64 = 1024 * 1024;

/// How much of an hour's budget may be spent at once.
///
/// A quarter: a burst of somebody else's traffic must not be able to eat the
/// whole hour in a minute and leave the node refusing everything for the next
/// fifty-nine. The DHT's own retry behaviour then spreads the load rather than
/// concentrating it.
const BURST_FRACTION: f64 = 0.25;

/// Metered participation in other people's work.
pub struct ServiceBudget {
    bucket: Mutex<TokenBucket>,
    bytes_per_hour: u64,
    served_bytes: AtomicU64,
    refused_bytes: AtomicU64,
    refusals: AtomicU64,
}

impl ServiceBudget {
    /// A budget of `bytes_per_hour`. Zero means "serve nothing" — the honest
    /// strict-leaf posture, available to an operator who wants it, and never
    /// the default.
    #[must_use]
    pub fn new(bytes_per_hour: u64) -> Self {
        let per_sec = bytes_per_hour as f64 / 3600.0;
        let burst = (bytes_per_hour as f64 * BURST_FRACTION).max(1.0);
        Self {
            bucket: Mutex::new(TokenBucket::new(burst, per_sec.max(f64::MIN_POSITIVE))),
            bytes_per_hour,
            served_bytes: AtomicU64::new(0),
            refused_bytes: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        }
    }

    /// The budget a node of this role should run with, honouring an explicit
    /// operator setting when there is one.
    ///
    /// A `Core` node is UNMETERED by default and that is deliberate: the seeds
    /// are Core, serving other people IS their job, and a budget on a seed
    /// would meter the network's own backbone. Only `Leaf` — every xVeil
    /// client, phone and desktop alike — gets a bill.
    #[must_use]
    pub fn for_role(role: NodeRole, configured: Option<u64>) -> Self {
        match (configured, role) {
            (Some(explicit), _) => Self::new(explicit),
            (None, NodeRole::Core) => Self::unmetered(),
            (None, NodeRole::Leaf) => Self::new(DEFAULT_SERVICE_BYTES_PER_HOUR),
        }
    }

    /// No bill at all. What a Core node runs with unless an operator says
    /// otherwise.
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(1.0, 1.0)),
            bytes_per_hour: u64::MAX,
            served_bytes: AtomicU64::new(0),
            refused_bytes: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        }
    }

    /// Whether this budget declines nothing.
    #[must_use]
    pub fn is_unmetered(&self) -> bool {
        self.bytes_per_hour == u64::MAX
    }

    /// The configured rate, for diagnostics and for the "unmetered" check.
    #[must_use]
    pub fn bytes_per_hour(&self) -> u64 {
        self.bytes_per_hour
    }

    /// Whether this budget declines everything.
    #[must_use]
    pub fn serves_nothing(&self) -> bool {
        self.bytes_per_hour == 0
    }

    /// Ask to spend `cost` bytes on `kind`. Returns whether it is allowed.
    ///
    /// The cost is charged BEFORE the work, from what the request itself
    /// weighs: the reply cannot be measured until it has been built, and
    /// building it is most of what we are trying not to pay for.
    pub fn try_serve(&self, kind: ServiceKind, cost: u64) -> bool {
        self.try_serve_at(kind, cost, Instant::now())
    }

    /// [`try_serve`](Self::try_serve) with an injectable clock, so the refill
    /// arithmetic is testable without sleeping through an hour.
    pub fn try_serve_at(&self, kind: ServiceKind, cost: u64, now: Instant) -> bool {
        if self.is_unmetered() {
            self.served_bytes.fetch_add(cost, Ordering::Relaxed);
            return true;
        }
        if self.bytes_per_hour == 0 {
            self.refused_bytes.fetch_add(cost, Ordering::Relaxed);
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Charge at least one byte: a stream of zero-length requests is still
        // work, and a free operation is one an attacker can repeat forever.
        let cost = cost.max(1);
        let allowed = {
            let mut b = self.bucket.lock().unwrap_or_else(|p| p.into_inner());
            b.allow_n_at(cost as f64, now)
        };
        if allowed {
            self.served_bytes.fetch_add(cost, Ordering::Relaxed);
        } else {
            self.refused_bytes.fetch_add(cost, Ordering::Relaxed);
            self.refusals.fetch_add(1, Ordering::Relaxed);
            log::debug!(
                target: "service_budget.refused",
                "declined {} of {cost} B — hourly budget {} B is spent",
                kind.label(),
                self.bytes_per_hour,
            );
        }
        allowed
    }

    /// `(served, refused, refusals)` since start, for the metrics endpoint.
    #[must_use]
    pub fn totals(&self) -> (u64, u64, u64) {
        (
            self.served_bytes.load(Ordering::Relaxed),
            self.refused_bytes.load(Ordering::Relaxed),
            self.refusals.load(Ordering::Relaxed),
        )
    }
}

impl Default for ServiceBudget {
    fn default() -> Self {
        Self::new(DEFAULT_SERVICE_BYTES_PER_HOUR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_budget_spends_its_burst_then_refuses_until_it_refills() {
        let b = ServiceBudget::new(3600 * 1000); // 1000 B/s, burst 900_000 B
        let t0 = Instant::now();
        assert!(b.try_serve_at(ServiceKind::StoreRecord, 900_000, t0));
        assert!(
            !b.try_serve_at(ServiceKind::StoreRecord, 1000, t0),
            "the burst is spent, so the next favour waits",
        );
        // Ten seconds buys ten thousand bytes back and no more.
        let t1 = t0 + Duration::from_secs(10);
        assert!(b.try_serve_at(ServiceKind::Lookup, 10_000, t1));
        assert!(!b.try_serve_at(ServiceKind::Lookup, 1, t1));
    }

    /// A burst must not be able to eat the hour in a minute.
    #[test]
    fn one_burst_cannot_spend_the_whole_hour() {
        let hourly = 8 * 1024 * 1024;
        let b = ServiceBudget::new(hourly);
        let t0 = Instant::now();
        assert!(
            !b.try_serve_at(ServiceKind::RelayCircuit, hourly, t0),
            "a single request must not be able to claim an hour of budget",
        );
        let (_, refused, n) = b.totals();
        assert_eq!(n, 1);
        assert_eq!(refused, hourly);
    }

    /// Zero is the strict-leaf posture: available, and never silently free.
    #[test]
    fn a_zero_budget_refuses_everything_and_says_how_much() {
        let b = ServiceBudget::new(0);
        assert!(b.serves_nothing());
        assert!(!b.try_serve_at(ServiceKind::ForwardWalk, 500, Instant::now()));
        assert_eq!(b.totals(), (0, 500, 1));
    }

    /// A free operation is one an attacker can repeat forever.
    #[test]
    fn an_empty_request_is_still_charged() {
        let b = ServiceBudget::new(3600); // 1 B/s, burst 900
        let t0 = Instant::now();
        for _ in 0..900 {
            assert!(b.try_serve_at(ServiceKind::Lookup, 0, t0));
        }
        assert!(
            !b.try_serve_at(ServiceKind::Lookup, 0, t0),
            "zero-length requests must exhaust the budget like any other",
        );
    }

    /// A seed must never be metered by a default nobody chose. The seeds are
    /// Core, serving other people is their whole job, and a budget on them
    /// would meter the network's own backbone.
    #[test]
    fn a_core_node_is_unmetered_unless_the_operator_says_otherwise() {
        let core = ServiceBudget::for_role(NodeRole::Core, None);
        assert!(core.is_unmetered());
        let huge = 64 * 1024 * 1024;
        assert!(core.try_serve_at(ServiceKind::StoreRecord, huge, Instant::now()));

        let leaf = ServiceBudget::for_role(NodeRole::Leaf, None);
        assert!(!leaf.is_unmetered());
        assert_eq!(leaf.bytes_per_hour(), DEFAULT_SERVICE_BYTES_PER_HOUR);
        assert!(!leaf.try_serve_at(ServiceKind::StoreRecord, huge, Instant::now()));
    }

    /// An explicit setting wins for BOTH roles — including a Core operator who
    /// wants a bill, and a Leaf operator who wants none.
    #[test]
    fn an_explicit_setting_beats_the_role_default() {
        assert_eq!(
            ServiceBudget::for_role(NodeRole::Core, Some(1000)).bytes_per_hour(),
            1000,
        );
        let generous = ServiceBudget::for_role(NodeRole::Leaf, Some(u64::MAX));
        assert!(generous.is_unmetered());
    }

    /// The mobile default has to be materially smaller than the desktop one,
    /// or the "gradation" is a word rather than a behaviour.
    #[test]
    fn the_mobile_default_is_meaningfully_smaller() {
        assert!(MOBILE_SERVICE_BYTES_PER_HOUR * 4 <= DEFAULT_SERVICE_BYTES_PER_HOUR);
    }
}
