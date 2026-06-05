//! `LocalTransport` — backend abstraction for local mesh transports.
//!
//! A `LocalTransport` manages one physical or virtual link medium (UDP LAN
//! broadcast, BLE, Wi-Fi Direct, etc.) and exposes the links it discovers as
//! `LocalLink` instances. The `MeshForwarder` combines links from one or more
//! transports to route mesh frames.
//!
//! # Adding a new backend
//!
//! 1. Implement `LocalTransport` for your backend struct.
//! 2. Start it with `start` and give it to a `MultiTransportNeighborTable`.
//! 3. The forwarder automatically picks up new links through the shared
//!    `NeighborTable`.
//!
//! Existing backends:
//! * `UdpRealm` — LAN UDP broadcast (development & testing)
//! * (planned) BLE backend — GATT-based frame exchange over Bluetooth Low Energy
//! * (planned) Wi-Fi Direct backend — Android/Linux P2P connection manager

use std::sync::Arc;

use veil_proto::mesh::RealmId;

use super::{link::LocalLink, neighbor::NeighborTable};

// ── LocalTransport ────────────────────────────────────────────────────────────

/// Abstraction over a local mesh transport backend.
///
/// Implementations must be `Send + Sync` so they can be shared across async tasks.
pub trait LocalTransport: Send + Sync {
    /// Human-readable name of this transport backend (e.g. `"udp"`, `"ble"`).
    fn name(&self) -> &str;

    /// The realm this transport is serving.
    fn realm_id(&self) -> RealmId;

    /// Return all currently reachable (node_id, link) pairs from this backend.
    ///
    /// Called periodically by the topology manager to refresh the shared
    /// `NeighborTable`. Implementations should return only live links.
    fn current_links(&self) -> Vec<([u8; 32], Arc<dyn LocalLink>)>;

    /// True if this transport is considered "local" (sub-millisecond latency
    /// no metered bandwidth). Local transports are preferred over relay paths.
    ///
    /// Returns `true` by default. Set to `false` for high-latency backends.
    fn is_local(&self) -> bool {
        true
    }
}

// ── MultiTransportNeighborTable ───────────────────────────────────────────────

/// Aggregates links from multiple `LocalTransport` backends into a single
/// `NeighborTable`.
///
/// Call `refresh` periodically (e.g. every beacon interval) to synchronise
/// the table with the current view from all backends.
pub struct MultiTransportNeighborTable {
    transports: Vec<Arc<dyn LocalTransport>>,
    table: NeighborTable,
}

impl MultiTransportNeighborTable {
    pub fn new(table: NeighborTable) -> Self {
        Self {
            transports: Vec::new(),
            table,
        }
    }

    /// Register a transport backend.
    pub fn add_transport(&mut self, transport: Arc<dyn LocalTransport>) {
        self.transports.push(transport);
    }

    /// Refresh the neighbor table from all registered backends.
    ///
    /// Inserts newly-discovered links; does NOT remove stale entries (call
    /// `table.prune_dead` separately to evict dead links).
    pub fn refresh(&self) {
        for t in &self.transports {
            for (node_id, link) in t.current_links() {
                self.table.add(node_id, link);
            }
        }
    }

    /// Access the underlying shared `NeighborTable`.
    pub fn table(&self) -> &NeighborTable {
        &self.table
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        link::{InMemoryLink, LocalLink, SendResult},
        neighbor::{MeshNeighborProvider, NeighborTable},
    };
    use veil_proto::mesh::RealmId;

    struct MockTransport {
        realm: RealmId,
        links: Vec<([u8; 32], Arc<dyn LocalLink>)>,
    }

    impl LocalTransport for MockTransport {
        fn name(&self) -> &str {
            "mock"
        }
        fn realm_id(&self) -> RealmId {
            self.realm
        }
        fn current_links(&self) -> Vec<([u8; 32], Arc<dyn LocalLink>)> {
            self.links.clone()
        }
    }

    fn make_link(remote_id: [u8; 32]) -> Arc<dyn LocalLink> {
        let (link, _inbox) = InMemoryLink::pair(remote_id);
        Arc::new(link) as Arc<dyn LocalLink>
    }

    #[test]
    fn refresh_populates_neighbor_table() {
        let realm = RealmId([1u8; 16]);
        let id_a = [0xAAu8; 32];
        let id_b = [0xBBu8; 32];

        let transport = Arc::new(MockTransport {
            realm,
            links: vec![(id_a, make_link(id_a)), (id_b, make_link(id_b))],
        });

        let table = NeighborTable::new();
        let mut mtt = MultiTransportNeighborTable::new(table);
        mtt.add_transport(transport);
        mtt.refresh();

        assert!(mtt.table().link_to(&id_a).is_some());
        assert!(mtt.table().link_to(&id_b).is_some());
        assert_eq!(mtt.table().len(), 2);
    }

    #[test]
    fn multiple_transports_combined() {
        let realm = RealmId([2u8; 16]);
        let id1 = [1u8; 32];
        let id2 = [2u8; 32];

        let t1 = Arc::new(MockTransport {
            realm,
            links: vec![(id1, make_link(id1))],
        });
        let t2 = Arc::new(MockTransport {
            realm,
            links: vec![(id2, make_link(id2))],
        });

        let table = NeighborTable::new();
        let mut mtt = MultiTransportNeighborTable::new(table);
        mtt.add_transport(t1);
        mtt.add_transport(t2);
        mtt.refresh();

        assert_eq!(mtt.table().len(), 2);
    }

    #[test]
    fn is_local_defaults_to_true() {
        let t = MockTransport {
            realm: RealmId([0u8; 16]),
            links: vec![],
        };
        assert!(t.is_local());
    }

    #[test]
    fn send_result_variants() {
        assert_eq!(SendResult::Ok, SendResult::Ok);
        assert_eq!(SendResult::Disconnected, SendResult::Disconnected);
    }
}
