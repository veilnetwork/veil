//! Learn a newly linked sender's verified key without requiring an outbound
//! message to that exact device. Claims spend bounded lookup work, never grant
//! authorization. The existing resolver verifies the latest document and cert.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const COOLDOWN: Duration = Duration::from_secs(30);
const WINDOW: Duration = Duration::from_secs(1);
const MAX_PER_WINDOW: usize = 4;
const MAX_RECENT: usize = 128;
type Key = ([u8; 32], [u8; 16]);

#[derive(Default)]
struct Budget {
    recent: HashMap<Key, Instant>,
    window: VecDeque<Instant>,
}

impl Budget {
    fn admit(&mut self, key: Key, now: Instant) -> bool {
        self.recent
            .retain(|_, at| now.saturating_duration_since(*at) < COOLDOWN);
        while self
            .window
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= WINDOW)
        {
            self.window.pop_front();
        }
        if self.recent.contains_key(&key)
            || self.recent.len() >= MAX_RECENT
            || self.window.len() >= MAX_PER_WINDOW
        {
            return false;
        }
        self.recent.insert(key, now);
        self.window.push_back(now);
        true
    }
}

pub(super) fn warmer(
    resolver: Arc<dyn veil_types::MlKemEkResolver>,
    runtime: tokio::runtime::Handle,
) -> veil_dispatcher::PeerCertWarmFn {
    let budget = Arc::new(Mutex::new(Budget::default()));
    let slots = Arc::new(tokio::sync::Semaphore::new(4));
    Arc::new(move |peer, instance| {
        // The cached lookup also revalidates learned document changes and
        // removes retired sender keys. It is synchronous and never walks DHT.
        if resolver
            .resolve_cert_for_instance_cached(peer, instance)
            .is_some()
        {
            return;
        }
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            return;
        };
        if !budget
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit((peer, instance), Instant::now())
        {
            return;
        }
        let resolver = Arc::clone(&resolver);
        runtime.spawn(async move {
            let _slot = slot;
            // A timeout leaves no task waiting for the semaphore, and no
            // claimed sender can hold one of the four slots indefinitely.
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                resolver.resolve_cert_for_instance(peer, instance),
            )
            .await;
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_sender_is_cooled_down_and_global_work_is_bounded() {
        let now = Instant::now();
        let mut budget = Budget::default();
        let key = ([1; 32], [2; 16]);
        assert!(budget.admit(key, now));
        assert!(!budget.admit(key, now));
        for n in 3..6 {
            assert!(budget.admit(([n; 32], [n; 16]), now));
        }
        assert!(!budget.admit(([9; 32], [9; 16]), now));
        assert!(budget.admit(([9; 32], [9; 16]), now + WINDOW));
        assert!(!budget.admit(key, now + WINDOW));
        assert!(budget.admit(key, now + COOLDOWN));
    }

    #[test]
    fn arbitrary_claims_cannot_grow_recent_memory_past_the_bound() {
        let now = Instant::now();
        let mut budget = Budget::default();
        for n in 0..1000_u32 {
            let mut peer = [0; 32];
            peer[..4].copy_from_slice(&n.to_le_bytes());
            budget.admit((peer, [1; 16]), now);
        }
        assert_eq!(budget.recent.len(), MAX_PER_WINDOW);
        assert_eq!(budget.window.len(), MAX_PER_WINDOW);
        assert!(!budget.admit(([0; 32], [1; 16]), now - Duration::from_secs(1)));
    }
}
