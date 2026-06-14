//! Global memory budget manager.
//!
//! Distributes a configurable RAM budget across veil components and
//! triggers proportional eviction when the budget is exceeded.
//!
//! # Components
//!
//! Each component reports its current memory usage and eviction capability:
//! Route cache — shrink via LRU eviction
//! DHT store — shrink via oldest-entry eviction
//! Peer pubkey cache — shrink via LRU
//! Session TX registry — reduce per-session queue depth
//! Vivaldi coordinates — shrink peer vivaldi map
//!
//! # Priority
//!
//! When over budget, components are shrunk in priority order (lowest first):
//! `vivaldi < pubkey_cache < dht_store < route_cache < sessions`

use std::sync::atomic::{AtomicUsize, Ordering};

/// Component ID for memory accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryComponent {
    RouteCache,
    DhtStore,
    PubkeyCache,
    Sessions,
    Vivaldi,
}

impl MemoryComponent {
    /// Eviction priority (lower = evicted first under pressure).
    pub fn priority(self) -> u8 {
        match self {
            Self::Vivaldi => 0,
            Self::PubkeyCache => 1,
            Self::DhtStore => 2,
            Self::RouteCache => 3,
            Self::Sessions => 4,
        }
    }
}

/// Global memory budget.
///
/// Components update their usage via `report`. The runtime calls
/// `over_budget` periodically and triggers eviction on the lowest-priority
/// component.
pub struct MemoryBudget {
    /// Total allowed memory in bytes.
    total_budget: usize,
    /// Per-component reported usage.
    route_cache: AtomicUsize,
    dht_store: AtomicUsize,
    pubkey_cache: AtomicUsize,
    sessions: AtomicUsize,
    vivaldi: AtomicUsize,
}

impl MemoryBudget {
    /// Create a budget with the given total in bytes (default 256 MiB).
    pub fn new(total_budget: usize) -> Self {
        Self {
            total_budget,
            route_cache: AtomicUsize::new(0),
            dht_store: AtomicUsize::new(0),
            pubkey_cache: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            vivaldi: AtomicUsize::new(0),
        }
    }

    /// Default budget: 256 MiB.
    pub fn default_budget() -> Self {
        Self::new(256 * 1024 * 1024)
    }

    /// Report current memory usage for a component.
    pub fn report(&self, component: MemoryComponent, bytes: usize) {
        let counter = match component {
            MemoryComponent::RouteCache => &self.route_cache,
            MemoryComponent::DhtStore => &self.dht_store,
            MemoryComponent::PubkeyCache => &self.pubkey_cache,
            MemoryComponent::Sessions => &self.sessions,
            MemoryComponent::Vivaldi => &self.vivaldi,
        };
        counter.store(bytes, Ordering::Relaxed);
    }

    /// Total reported usage across all components.
    pub fn total_used(&self) -> usize {
        self.route_cache.load(Ordering::Relaxed)
            + self.dht_store.load(Ordering::Relaxed)
            + self.pubkey_cache.load(Ordering::Relaxed)
            + self.sessions.load(Ordering::Relaxed)
            + self.vivaldi.load(Ordering::Relaxed)
    }

    /// Whether total usage exceeds the budget.
    pub fn over_budget(&self) -> bool {
        self.total_used() > self.total_budget
    }

    /// Return the component with the lowest priority that has nonzero usage.
    /// This is the first candidate for eviction when over budget.
    pub fn eviction_candidate(&self) -> Option<(MemoryComponent, usize)> {
        let mut candidates = [
            (
                MemoryComponent::Vivaldi,
                self.vivaldi.load(Ordering::Relaxed),
            ),
            (
                MemoryComponent::PubkeyCache,
                self.pubkey_cache.load(Ordering::Relaxed),
            ),
            (
                MemoryComponent::DhtStore,
                self.dht_store.load(Ordering::Relaxed),
            ),
            (
                MemoryComponent::RouteCache,
                self.route_cache.load(Ordering::Relaxed),
            ),
            (
                MemoryComponent::Sessions,
                self.sessions.load(Ordering::Relaxed),
            ),
        ];
        candidates.sort_by_key(|(c, _)| c.priority());
        candidates.into_iter().find(|(_, usage)| *usage > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_budget() {
        let mb = MemoryBudget::new(1000);
        mb.report(MemoryComponent::RouteCache, 400);
        mb.report(MemoryComponent::DhtStore, 300);
        assert_eq!(mb.total_used(), 700);
        assert!(!mb.over_budget());
    }

    #[test]
    fn over_budget_detection() {
        let mb = MemoryBudget::new(500);
        mb.report(MemoryComponent::RouteCache, 300);
        mb.report(MemoryComponent::DhtStore, 300);
        assert!(mb.over_budget());
        assert_eq!(mb.total_used().saturating_sub(500), 100);
    }

    #[test]
    fn eviction_candidate_lowest_priority() {
        let mb = MemoryBudget::new(100);
        mb.report(MemoryComponent::Sessions, 200);
        mb.report(MemoryComponent::Vivaldi, 50);
        let (comp, usage) = mb.eviction_candidate().unwrap();
        assert_eq!(comp, MemoryComponent::Vivaldi);
        assert_eq!(usage, 50);
    }

    /// simulate memory pressure — repeated eviction reduces usage.
    #[test]
    fn memory_pressure_eviction_loop() {
        let mb = MemoryBudget::new(500);
        // Simulate high memory usage across all components.
        mb.report(MemoryComponent::Sessions, 200);
        mb.report(MemoryComponent::RouteCache, 150);
        mb.report(MemoryComponent::DhtStore, 100);
        mb.report(MemoryComponent::PubkeyCache, 80);
        mb.report(MemoryComponent::Vivaldi, 50);
        assert!(mb.over_budget()); // 580 > 500
        assert_eq!(mb.total_used().saturating_sub(500), 80);

        // Simulate eviction loop: shrink lowest-priority until within budget.
        let mut iterations = 0;
        while mb.over_budget() && iterations < 10 {
            if let Some((comp, usage)) = mb.eviction_candidate() {
                // Simulate shrinking the component by 50%.
                mb.report(comp, usage / 2);
            }
            iterations += 1;
        }
        assert!(
            !mb.over_budget(),
            "budget should be restored after eviction loop (used={})",
            mb.total_used()
        );
        assert!(
            iterations <= 10,
            "should converge in ≤10 iterations, took {iterations}"
        );
    }
}
