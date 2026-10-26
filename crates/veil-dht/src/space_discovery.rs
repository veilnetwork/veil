//! Atomic arbitration for bounded public Space holder samples.
use crate::KademliaService;
use veil_crypto::space_discovery::{SpaceDiscoveryRecord, merge_space_discovery_sample};

impl KademliaService {
    /// All admission paths share this commit: verification/merge runs outside
    /// the store mutex, then exact-byte CAS prevents a delayed STORE or mirror
    /// from erasing an intervening holder or a newer refresh.
    pub fn store_space_discovery_sample(
        &self,
        key: [u8; 32],
        value: &[u8],
        origin: [u8; 32],
    ) -> bool {
        let Some(record) = SpaceDiscoveryRecord::from_bytes(value) else {
            return false;
        };
        if record.route.dht_key() != key {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        for _ in 0..3 {
            let current = self.get_local(&key);
            let Some(merged) =
                merge_space_discovery_sample(current.as_deref(), value, now, &self.local_node_id())
            else {
                return false;
            };
            if self.store_with_origin_if(key, merged, origin, |stored| stored == current.as_deref())
            {
                return true;
            }
            if self.get_local(&key) == current {
                return false;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::{Arc, Barrier};
    use veil_crypto::space_discovery::{SpaceDiscoveryRoute, decode_space_discovery_samples};

    fn record(seed: u8, now: u64) -> SpaceDiscoveryRecord {
        SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Search([42; 32]),
            [17; 32],
            &SigningKey::from_bytes(&[seed; 32]),
            now,
            now + 3_600_000,
            vec![seed; 20],
        )
    }

    #[test]
    fn space_samples_concurrent_holders_and_stale_refresh_converge() {
        let service = Arc::new(KademliaService::with_config([9; 32], Default::default()));
        let now = veil_util::unix_secs_now_u64() * 1000;
        let first = record(1, now);
        let second = record(2, now);
        let key = first.route.dht_key();
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            for value in [&first, &second] {
                let service = Arc::clone(&service);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    assert!(service.store_space_discovery_sample(
                        key,
                        &value.to_bytes(),
                        value.holder_node_id
                    ));
                });
            }
        });
        assert_eq!(
            decode_space_discovery_samples(&service.get_local(&key).unwrap())
                .unwrap()
                .len(),
            2
        );
        let refreshed = record(1, now + 1);
        assert!(service.store_space_discovery_sample(
            key,
            &refreshed.to_bytes(),
            first.holder_node_id
        ));
        assert!(!service.store_space_discovery_sample(
            key,
            &first.to_bytes(),
            first.holder_node_id
        ));
        let records = decode_space_discovery_samples(&service.get_local(&key).unwrap()).unwrap();
        assert_eq!(
            records
                .iter()
                .find(|r| r.holder_node_id == first.holder_node_id)
                .unwrap(),
            &refreshed
        );
        assert!(records.contains(&second));
    }

    #[test]
    fn space_samples_charge_merged_bytes_to_origin_and_keep_old_value_on_cap_refusal() {
        let now = veil_util::unix_secs_now_u64() * 1000;
        let first = record(1, now);
        let second = record(2, now);
        let key = first.route.dht_key();
        let service = KademliaService::with_config(
            [9; 32],
            crate::DhtRuntimeConfig {
                per_origin_max_bytes: Some(first.to_bytes().len() as u64 + 1),
                ..Default::default()
            },
        );
        assert!(service.store_space_discovery_sample(key, &first.to_bytes(), first.holder_node_id));
        assert!(!service.store_space_discovery_sample(
            key,
            &second.to_bytes(),
            second.holder_node_id
        ));
        assert_eq!(service.get_local(&key), Some(first.to_bytes()));
        assert!(!service.store_space_discovery_sample(
            [0; 32],
            &second.to_bytes(),
            second.holder_node_id
        ));
    }

    #[test]
    fn space_samples_legacy_find_value_never_returns_a_local_bucket() {
        let now = veil_util::unix_secs_now_u64() * 1000;
        let first = record(1, now);
        let second = record(2, now);
        let key = first.route.dht_key();
        let service = KademliaService::with_config([9; 32], Default::default());
        for record in [&first, &second] {
            assert!(service.store_space_discovery_sample(
                key,
                &record.to_bytes(),
                record.holder_node_id
            ));
        }
        let veil_proto::discovery::FindValueResponse::Value(value) =
            service.handle_find_value(veil_proto::discovery::FindValuePayload { key })
        else {
            panic!("missing holder");
        };
        assert!(value == first.to_bytes() || value == second.to_bytes());
        assert!(value.len() <= veil_proto::budget::MAX_DHT_VALUE_BYTES);
    }

    #[tokio::test]
    async fn space_samples_republish_sends_individual_carriers_and_keeps_newer_local_state() {
        struct Router(std::sync::Mutex<Vec<Vec<u8>>>);
        impl crate::FrameRouter for Router {
            fn send_request(
                &self,
                _: [u8; 32],
                _: u32,
                frame: Vec<u8>,
            ) -> Option<tokio::sync::oneshot::Receiver<Option<Vec<u8>>>> {
                let header = veil_proto::codec::decode_header(&frame).unwrap();
                if header.family == veil_proto::family::FrameFamily::Discovery as u8
                    && header.msg_type == veil_proto::family::DiscoveryMsg::Store as u16
                {
                    let value = veil_proto::discovery::StorePayload::decode(
                        &frame[veil_proto::header::HEADER_SIZE..],
                    )
                    .unwrap();
                    self.0.lock().unwrap().push(value.value);
                }
                let (_, rx) = tokio::sync::oneshot::channel();
                Some(rx)
            }
            fn peer_ids(&self) -> Vec<[u8; 32]> {
                vec![[3; 32]]
            }
        }
        let now = veil_util::unix_secs_now_u64() * 1000;
        let first = record(1, now);
        let second = record(2, now);
        let key = first.route.dht_key();
        let service = KademliaService::with_config([9; 32], Default::default());
        for record in [&first, &second] {
            assert!(service.store_space_discovery_sample(
                key,
                &record.to_bytes(),
                record.holder_node_id
            ));
        }
        let snapshot = service.get_local(&key).unwrap();
        let refreshed = record(1, now + 1);
        assert!(service.store_space_discovery_sample(
            key,
            &refreshed.to_bytes(),
            first.holder_node_id
        ));
        let router = Arc::new(Router(Default::default()));
        let fanout = service
            .store_replicated(key, snapshot, router.clone())
            .await
            .unwrap();
        assert_eq!(fanout, 1, "replica count counts peers, not sample frames");
        let wire = router.0.lock().unwrap();
        assert_eq!(wire.len(), 2);
        assert!(
            wire.iter()
                .all(|value| SpaceDiscoveryRecord::from_bytes(value).is_some())
        );
        let stored = decode_space_discovery_samples(&service.get_local(&key).unwrap()).unwrap();
        assert!(stored.contains(&refreshed) && stored.contains(&second));
    }
}
