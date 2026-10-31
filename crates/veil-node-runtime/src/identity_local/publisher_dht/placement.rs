//! Bounded, short-lived memory of this publisher's OWN public records.
//! Admission is not delivery; normal complete publications remain the backstop.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::Instant;
use veil_dht::KademliaService;
use veil_session::tx_registry::SessionTxRegistry;

const MAX_RECORDS: usize = 64;
const MAX_BYTES: usize = 512 * 1024;
const LEASE: Duration = Duration::from_secs(60);

struct Record {
    value: Vec<u8>,
    until: Instant,
    offered: HashMap<[u8; 32], u64>,
}

#[derive(Default)]
pub(super) struct PlacementTracker {
    records: BTreeMap<[u8; 32], Record>,
    bytes: usize,
}

#[derive(Default)]
pub(crate) struct PlacementReport {
    pub(crate) enqueued: usize,
    pub(crate) retry: bool,
}

impl PlacementTracker {
    pub(super) fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.records.retain(|_, record| {
            if now >= record.until {
                self.bytes -= record.value.len();
                false
            } else {
                true
            }
        });
    }

    /// False means no tracking capacity: caller retains the ordinary publish.
    pub(super) fn publish(
        &mut self,
        key: [u8; 32],
        value: &[u8],
        dht: &Arc<KademliaService>,
        registry: &Arc<RwLock<SessionTxRegistry>>,
        local: [u8; 32],
    ) -> bool {
        self.expire();
        if let Some(old) = self.records.remove(&key) {
            self.bytes -= old.value.len();
        }
        if self.records.len() >= MAX_RECORDS || value.len() > MAX_BYTES.saturating_sub(self.bytes) {
            return false;
        }
        self.bytes += value.len();
        let record = self.records.entry(key).or_insert_with(|| Record {
            value: value.to_vec(),
            until: Instant::now() + LEASE,
            offered: HashMap::new(),
        });
        let _ = Self::reconcile_record(key, record, dht, registry, local);
        true
    }

    pub(super) fn reconcile(
        &mut self,
        dht: &Arc<KademliaService>,
        registry: &Arc<RwLock<SessionTxRegistry>>,
        local: [u8; 32],
    ) -> PlacementReport {
        self.expire();
        // This adapter is not the sole writer of the owner's public records.
        // Never replay a snapshot after observing a replacement in the local
        // DHT. Absence (e.g. eviction) does not contradict our own publication;
        // a different value does. A subsequent put starts a fresh lease.
        self.records.retain(|key, record| {
            if dht
                .get_local(key)
                .is_some_and(|current| current != record.value)
            {
                self.bytes -= record.value.len();
                false
            } else {
                true
            }
        });
        let mut report = PlacementReport::default();
        for (key, record) in &mut self.records {
            let update = Self::reconcile_record(*key, record, dht, registry, local);
            report.enqueued += update.enqueued;
            report.retry |= update.retry;
        }
        report
    }

    fn reconcile_record(
        key: [u8; 32],
        record: &mut Record,
        dht: &Arc<KademliaService>,
        registry: &Arc<RwLock<SessionTxRegistry>>,
        local: [u8; 32],
    ) -> PlacementReport {
        let targets = super::replication_targets(dht, registry, local, key);
        record.offered.retain(|peer, _| targets.contains(peer));
        let mut report = PlacementReport::default();
        let mut frame = None;
        for peer in targets {
            let registration = registry
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .live_registration(&peer);
            let Some(registration) = registration else {
                continue;
            };
            if record.offered.get(&peer) == Some(&registration) {
                continue;
            }
            // A fresh query ID is essential when placement changes: an old
            // recursive STORE may have visited this peer before it was eligible.
            let bytes = frame
                .get_or_insert_with(|| super::encode_replication(local, key, record.value.clone()));
            let admitted = SessionTxRegistry::send_local_replication(registry, peer, bytes.clone());
            let unchanged = registry
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .live_registration(&peer)
                == Some(registration);
            if admitted && unchanged {
                record.offered.insert(peer, registration);
                report.enqueued += 1;
            } else {
                // Never credit a replacement registration or failed admission.
                report.retry = true;
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::super::DhtBackedPublisher;
    use super::*;
    use veil_identity::publish::IdentityPublisher;
    use veil_proto::routing::RecursiveQueryPayload;
    use veil_session::frame_outbox::FrameOutbox;

    fn setup() -> (
        Arc<KademliaService>,
        Arc<RwLock<SessionTxRegistry>>,
        FrameOutbox,
        DhtBackedPublisher,
    ) {
        let dht = Arc::new(KademliaService::new([0; 32]));
        let mut registry = SessionTxRegistry::new();
        let first = registry.register([1; 32]);
        let registry = Arc::new(RwLock::new(registry));
        let publisher =
            DhtBackedPublisher::with_topology_replication(dht.clone(), registry.clone(), [0; 32]);
        (dht, registry, first, publisher)
    }

    async fn receive(rx: &mut FrameOutbox) -> RecursiveQueryPayload {
        let (priority, bytes) = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(priority, veil_proto::priority::BACKGROUND);
        let header = veil_proto::codec::decode_header(&bytes).unwrap();
        assert_eq!(
            header.family,
            veil_proto::family::FrameFamily::Routing as u8
        );
        let query = RecursiveQueryPayload::decode(&bytes[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(
            query.query_type,
            veil_proto::routing::recursive_query_type::STORE
        );
        query
    }

    #[tokio::test(start_paused = true)]
    async fn topology_deltas_reach_only_new_registrations_with_fresh_query_ids() {
        let (_, registry, mut first, publisher) = setup();
        let key = [42; 32];
        publisher.put(key, vec![7; 100]).await.unwrap();
        let initial = receive(&mut first).await;
        assert_eq!(publisher.reconcile_topology().enqueued, 0);
        let mut second = registry.write().unwrap().register([2; 32]);
        let delta = publisher.reconcile_topology();
        assert_eq!(delta.enqueued, 1);
        assert!(!delta.retry);
        let copy = receive(&mut second).await;
        assert_eq!(
            (copy.target_key, copy.payload),
            (key, initial.payload.clone())
        );
        assert_ne!(copy.query_id, initial.query_id);
        assert!(
            first.try_recv().is_err(),
            "unchanged peer got a full-bundle replay"
        );
        assert_eq!(publisher.reconcile_topology().enqueued, 0);
        let mut replacement = registry.write().unwrap().register([2; 32]);
        assert_eq!(publisher.reconcile_topology().enqueued, 1);
        let again = receive(&mut replacement).await;
        assert_ne!(again.query_id, copy.query_id);
        assert_eq!(again.payload, initial.payload);
        assert!(first.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_queue_admission_is_not_a_placement_witness() {
        let (_, registry, mut receiver, publisher) = setup();
        // Fill the real paced queue without yielding to its worker. No copy of
        // that queue's capacity constant is built into the test.
        let mut blockers = 0;
        while SessionTxRegistry::send_local_replication(&registry, [1; 32], vec![0]) {
            blockers += 1;
            assert!(blockers < 1024, "publication queue must be bounded");
        }
        assert!(blockers > 0);
        publisher.put([42; 32], vec![7; 100]).await.unwrap();
        let refused = publisher.reconcile_topology();
        assert_eq!(refused.enqueued, 0);
        assert!(refused.retry);
        for _ in 0..blockers {
            assert_eq!(&receiver.recv().await.unwrap().1[..], &[0]);
        }
        let repaired = publisher.reconcile_topology();
        assert_eq!(repaired.enqueued, 1);
        assert!(!repaired.retry);
        assert_eq!(receive(&mut receiver).await.payload, vec![7; 100]);
    }

    #[tokio::test(start_paused = true)]
    async fn updated_values_replace_the_replay_and_bundle_reset_forgets_old_keys() {
        let (_, registry, mut first, publisher) = setup();
        publisher.put([42; 32], vec![1]).await.unwrap();
        receive(&mut first).await;
        publisher.put([42; 32], vec![2]).await.unwrap();
        assert_eq!(receive(&mut first).await.payload, vec![2]);
        let mut second = registry.write().unwrap().register([2; 32]);
        assert_eq!(publisher.reconcile_topology().enqueued, 1);
        assert_eq!(receive(&mut second).await.payload, vec![2]);
        publisher.begin_bundle();
        let _third = registry.write().unwrap().register([3; 32]);
        assert_eq!(publisher.reconcile_topology().enqueued, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cache_bounds_and_expiry_do_not_block_ordinary_publication() {
        let dht = Arc::new(KademliaService::new([0; 32]));
        let registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let publisher =
            DhtBackedPublisher::with_topology_replication(dht.clone(), registry.clone(), [0; 32]);
        for n in 0..MAX_RECORDS as u8 {
            publisher.put([n; 32], vec![1]).await.unwrap();
        }
        let mut live = registry.write().unwrap().register([1; 32]);
        // The 65th key takes the old publisher path, even though it cannot be
        // retained for rapid topology repair.
        publisher.put([250; 32], vec![9]).await.unwrap();
        assert_eq!(receive(&mut live).await.target_key, [250; 32]);
        assert_eq!(dht.get_local(&[250; 32]), Some(vec![9]));
        assert_eq!(
            publisher
                .placement
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .records
                .len(),
            MAX_RECORDS
        );
        tokio::time::advance(LEASE).await;
        assert_eq!(publisher.reconcile_topology().enqueued, 0);
        let tracker = publisher.placement.as_ref().unwrap().lock().unwrap();
        assert!(tracker.records.is_empty());
        assert_eq!(tracker.bytes, 0);
        drop(tracker);
        assert_eq!(
            dht.get_local(&[250; 32]),
            Some(vec![9]),
            "lease expiry must not delete DHT state"
        );

        let empty = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut tracker = PlacementTracker::default();
        assert!(tracker.publish([1; 32], &vec![0; MAX_BYTES], &dht, &empty, [0; 32]));
        assert!(!tracker.publish([2; 32], &[1], &dht, &empty, [0; 32]));
        assert_eq!(tracker.bytes, MAX_BYTES);
        assert_eq!(tracker.records.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_locally_replaced_record_is_not_replayed_from_an_old_lease() {
        let (dht, registry, mut first, publisher) = setup();
        let key = [42; 32];
        publisher.put(key, vec![1]).await.unwrap();
        receive(&mut first).await;
        // Another legitimate local publication can replace the value without
        // going through this task's adapter. The old lease is not authority to
        // put an earlier version back on the network.
        dht.store_local(key, vec![2]);
        let mut second = registry.write().unwrap().register([2; 32]);
        let update = publisher.reconcile_topology();
        assert_eq!(update.enqueued, 0);
        assert!(second.try_recv().is_err());
        assert_eq!(dht.get_local(&key), Some(vec![2]));
        assert!(
            publisher
                .placement
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .records
                .is_empty()
        );
        publisher.put(key, vec![2]).await.unwrap();
        assert_eq!(receive(&mut second).await.payload, vec![2]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_known_decliner_is_not_a_topology_repair_target() {
        let (dht, registry, mut first, publisher) = setup();
        publisher.put([42; 32], vec![7]).await.unwrap();
        receive(&mut first).await;
        dht.add_contact_trusted(veil_dht::routing::Contact::with_caps(
            [2; 32],
            "tcp://quiet:9000",
            veil_types::DiscoveryMode::Public,
            false,
        ));
        let mut quiet = registry.write().unwrap().register([2; 32]);
        assert_eq!(publisher.reconcile_topology().enqueued, 0);
        assert!(quiet.try_recv().is_err());
        dht.add_contact_trusted(veil_dht::routing::Contact::with_caps(
            [2; 32],
            "tcp://quiet:9000",
            veil_types::DiscoveryMode::Public,
            true,
        ));
        assert_eq!(publisher.reconcile_topology().enqueued, 1);
        assert_eq!(receive(&mut quiet).await.payload, vec![7]);
    }
}
