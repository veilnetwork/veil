//! Endpoint-only path groups. Nothing in this module is encoded on the wire.
//!
//! Independent producers prefer different live first-hop sessions. A scarce
//! network still permits sharing; this is not a relay scheduling class or a
//! bandwidth guarantee. Reservations live as long as their circuit handles.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

type Node = [u8; 32];
type Usage = HashMap<Node, usize>;
type Groups = Vec<Weak<Mutex<Usage>>>;

/// A local producer's circuit ownership within one set of independent producers.
#[derive(Clone)]
pub struct LocalCircuitPathGroup {
    groups: Arc<Mutex<Groups>>,
    usage: Arc<Mutex<Usage>>,
    reuse_first_hop: bool,
}

impl Default for LocalCircuitPathGroup {
    fn default() -> Self {
        let usage = Arc::new(Mutex::new(HashMap::new()));
        Self {
            groups: Arc::new(Mutex::new(vec![Arc::downgrade(&usage)])),
            usage,
            reuse_first_hop: false,
        }
    }
}

impl LocalCircuitPathGroup {
    /// Allocate an independent producer in the same local isolation set.
    /// Its circuits prefer reusing its own first hop to leave others available.
    pub fn isolated(&self) -> Self {
        let usage = Arc::new(Mutex::new(HashMap::new()));
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        groups.retain(|g| g.strong_count() != 0);
        groups.push(Arc::downgrade(&usage));
        Self {
            groups: Arc::clone(&self.groups),
            usage,
            reuse_first_hop: true,
        }
    }

    /// Serialize only synchronous path selection/admission, never directory
    /// warming or circuit confirmation. Parallel builders cannot both choose
    /// the same apparently unused session before recording their reservation.
    pub(super) fn select<T, E>(
        &self,
        open: impl FnOnce(&[Node], &[Node]) -> Result<(T, Node), E>,
    ) -> Result<(T, Reservation), E> {
        let mut groups = self.groups.lock().unwrap_or_else(|p| p.into_inner());
        let mut excluded = Vec::new();
        groups.retain(|weak| {
            let Some(usage) = weak.upgrade() else {
                return false;
            };
            if !Arc::ptr_eq(&usage, &self.usage) {
                excluded.extend(
                    usage
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .keys()
                        .copied(),
                );
            }
            true
        });
        let preferred: Vec<_> = if self.reuse_first_hop {
            self.usage
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .copied()
                .collect()
        } else {
            Vec::new()
        };
        let (value, node) = open(&excluded, &preferred)?;
        *self
            .usage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(node)
            .or_default() += 1;
        Ok((
            value,
            Reservation {
                usage: Arc::clone(&self.usage),
                node,
            },
        ))
    }
}

pub(super) struct Reservation {
    usage: Arc<Mutex<Usage>>,
    node: Node,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self.usage.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = usage.get_mut(&self.node) {
            *count -= 1;
            if *count == 0 {
                usage.remove(&self.node);
            }
        }
    }
}

/// Preserve the random candidate order, prefer a live unshared first hop, and
/// fall back to a shared live session when the network has no alternative.
pub(super) fn prefer_first_hop(
    candidates: &mut [Node],
    live: &std::collections::HashSet<Node>,
    excluded: &[Node],
    preferred: &[Node],
) {
    let best = candidates
        .iter()
        .position(|n| live.contains(n) && !excluded.contains(n) && preferred.contains(n))
        .or_else(|| {
            candidates
                .iter()
                .position(|n| live.contains(n) && !excluded.contains(n))
        })
        .or_else(|| {
            candidates
                .iter()
                .position(|n| live.contains(n) && preferred.contains(n))
        })
        .or_else(|| candidates.iter().position(|n| live.contains(n)));
    if let Some(pos) = best {
        candidates.swap(0, pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_is_counted_until_the_last_circuit_closes() {
        let a = LocalCircuitPathGroup::default();
        let b = a.isolated();
        let reserve = || a.select::<_, ()>(|_, _| Ok(((), [1; 32]))).unwrap().1;
        let first = reserve();
        let second = reserve();
        drop(first);
        b.select::<(), ()>(|excluded, _| {
            assert_eq!(excluded, &[[1; 32]]);
            Err(())
        })
        .ok();
        drop(second);
        b.select::<(), ()>(|excluded, _| {
            assert!(excluded.is_empty());
            Err(())
        })
        .ok();
    }

    #[test]
    fn live_alternatives_and_scarce_network_fallback_keep_all_hops() {
        let mut path = [[1; 32], [2; 32], [3; 32]];
        let live = std::collections::HashSet::from([[1; 32], [3; 32]]);
        prefer_first_hop(&mut path, &live, &[[1; 32]], &[]);
        assert_eq!(path[0], [3; 32]);
        prefer_first_hop(&mut path, &live, &[[1; 32], [3; 32]], &[]);
        assert_eq!(path[0], [3; 32]);
        path.sort_unstable();
        assert_eq!(path, [[1; 32], [2; 32], [3; 32]]);
    }

    #[test]
    fn parallel_producers_reserve_distinct_sessions_atomically() {
        let a = LocalCircuitPathGroup::default();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let tasks: Vec<_> = [a.clone(), a.isolated()]
            .into_iter()
            .map(|group| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let (node, reservation) = group
                        .select::<_, ()>(|excluded, _| {
                            let node = [[1; 32], [2; 32]]
                                .into_iter()
                                .find(|n| !excluded.contains(n))
                                .unwrap();
                            Ok((node, node))
                        })
                        .unwrap();
                    barrier.wait();
                    (node, reservation)
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert_ne!(results[0].0, results[1].0);
    }
    #[test]
    fn producer_affinity_does_not_consume_every_free_session() {
        let root = LocalCircuitPathGroup::default();
        let media = root.isolated();
        let (_, reservation) = media.select::<_, ()>(|_, _| Ok(((), [2; 32]))).unwrap();
        media
            .select::<(), ()>(|excluded, preferred| {
                let mut path = [[1; 32], [2; 32], [3; 32]];
                let live = std::collections::HashSet::from(path);
                prefer_first_hop(&mut path, &live, excluded, preferred);
                assert_eq!(path[0], [2; 32]);
                Err(())
            })
            .ok();
        drop(reservation);
    }

    #[test]
    fn failed_open_and_dropped_groups_do_not_reserve_sessions() {
        let root = LocalCircuitPathGroup::default();
        {
            let media = root.isolated();
            assert!(media.select::<(), ()>(|_, _| Err(())).is_err());
        }
        root.select::<(), ()>(|excluded, _| {
            assert!(excluded.is_empty());
            Err(())
        })
        .ok();
        assert_eq!(root.groups.lock().unwrap().len(), 1);
    }
}
