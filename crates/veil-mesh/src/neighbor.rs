//! `MeshNeighborProvider` — registry of locally reachable neighbours.
//!
//! Each mesh node maintains a set of `LocalLink`s to its direct neighbours.
//! The `MeshNeighborProvider` is the read interface: given a destination
//! `node_id`, it returns the link to use (or `None` for unknown destinations).
//!
//! The `NeighborTable` is the mutable implementation used by `InMemoryRealm`
//! and the future real transports.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use veil_util::lock;

use super::link::LocalLink;
use veil_proto::budget::MAX_NEIGHBOR_TABLE_SIZE;

// ── MeshNeighborProvider ──────────────────────────────────────────────────────

/// Read interface: map destination node_id → outgoing link.
pub trait MeshNeighborProvider: Send + Sync {
    /// Return the link toward `node_id`, or `None` if not a direct neighbour.
    fn link_to(&self, node_id: &[u8; 32]) -> Option<Arc<dyn LocalLink>>;

    /// All currently known neighbour IDs.
    fn all_neighbors(&self) -> Vec<[u8; 32]>;

    /// Remove dead links (links where `is_alive` returns false).
    /// Called periodically from the maintenance loop.
    fn prune_dead(&self);
}

// ── NeighborTable ─────────────────────────────────────────────────────────────

/// Mutable neighbour registry backed by a `HashMap`.
///
/// Clone-cheap: inner state is behind `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct NeighborTable {
    #[allow(clippy::type_complexity)]
    inner: Arc<Mutex<HashMap<[u8; 32], Arc<dyn LocalLink>>>>,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register (or replace) the link toward `node_id`.
    ///
    /// Returns `false` if the table is already at `MAX_NEIGHBOR_TABLE_SIZE`
    /// and `node_id` is not an existing entry (replacement always succeeds).
    pub fn add(&self, node_id: [u8; 32], link: Arc<dyn LocalLink>) -> bool {
        let mut guard = lock!(self.inner);
        if !guard.contains_key(&node_id) && guard.len() >= MAX_NEIGHBOR_TABLE_SIZE {
            return false;
        }
        guard.insert(node_id, link);
        true
    }

    /// Remove a neighbour (e.g. link went down).
    pub fn remove(&self, node_id: &[u8; 32]) {
        lock!(self.inner).remove(node_id);
    }

    /// Remove all dead links (is_alive == false).
    pub fn prune_dead(&self) {
        lock!(self.inner).retain(|_, link| link.is_alive());
    }

    pub fn len(&self) -> usize {
        lock!(self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        lock!(self.inner).is_empty()
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshNeighborProvider for NeighborTable {
    fn link_to(&self, node_id: &[u8; 32]) -> Option<Arc<dyn LocalLink>> {
        lock!(self.inner).get(node_id).cloned()
    }

    fn all_neighbors(&self) -> Vec<[u8; 32]> {
        lock!(self.inner).keys().copied().collect()
    }

    fn prune_dead(&self) {
        lock!(self.inner).retain(|_, link| link.is_alive());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::InMemoryLink;

    fn add_link(table: &NeighborTable, remote_id: [u8; 32]) -> Arc<InMemoryLink> {
        let (link, _inbox) = InMemoryLink::pair(remote_id);
        let link = Arc::new(link);
        table.add(remote_id, Arc::clone(&link) as Arc<dyn LocalLink>);
        link
    }

    #[test]
    fn add_and_find() {
        let table = NeighborTable::new();
        add_link(&table, [1u8; 32]);
        assert!(table.link_to(&[1u8; 32]).is_some());
        assert!(table.link_to(&[2u8; 32]).is_none());
    }

    #[test]
    fn remove() {
        let table = NeighborTable::new();
        add_link(&table, [1u8; 32]);
        table.remove(&[1u8; 32]);
        assert!(table.link_to(&[1u8; 32]).is_none());
    }

    #[test]
    fn prune_dead_removes_disconnected() {
        let table = NeighborTable::new();
        let link = add_link(&table, [3u8; 32]);
        link.disconnect();
        table.prune_dead();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn all_neighbors() {
        let table = NeighborTable::new();
        add_link(&table, [1u8; 32]);
        add_link(&table, [2u8; 32]);
        let mut ids = table.all_neighbors();
        ids.sort();
        assert_eq!(ids, vec![[1u8; 32], [2u8; 32]]);
    }

    #[test]
    fn add_respects_max_neighbor_table_size() {
        use veil_proto::budget::MAX_NEIGHBOR_TABLE_SIZE;
        let table = NeighborTable::new();
        // Fill to the limit
        for i in 0..MAX_NEIGHBOR_TABLE_SIZE {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let ok = add_link_bool(&table, id);
            assert!(ok, "entry {i} should fit");
        }
        assert_eq!(table.len(), MAX_NEIGHBOR_TABLE_SIZE);
        // One more new entry must be rejected
        let overflow_id = [0xFFu8; 32];
        let (link, _) = InMemoryLink::pair(overflow_id);
        let rejected = !table.add(overflow_id, Arc::new(link) as Arc<dyn LocalLink>);
        assert!(
            rejected,
            "table should reject entries beyond MAX_NEIGHBOR_TABLE_SIZE"
        );
        assert_eq!(table.len(), MAX_NEIGHBOR_TABLE_SIZE);
        // Replacing an existing entry must still succeed
        let existing_id = {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&0u64.to_be_bytes());
            id
        };
        let ok = add_link_bool(&table, existing_id);
        assert!(ok, "replacement of existing entry should always succeed");
    }

    fn add_link_bool(table: &NeighborTable, remote_id: [u8; 32]) -> bool {
        let (link, _inbox) = InMemoryLink::pair(remote_id);
        table.add(remote_id, Arc::new(link) as Arc<dyn LocalLink>)
    }
}
