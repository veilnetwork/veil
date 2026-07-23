//! Public Space discovery over the existing contested DHT read plane.
//!
//! xVeil owns and verifies the strict descriptor payload. The node runtime
//! only accepts the self-authenticating outer carrier, samples multi-writer
//! search keys per replica, and returns all valid contested replicas to the
//! application for holder-quorum merge.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use veil_crypto::space_discovery::{
    SpaceDiscoveryRecord, SpaceDiscoveryRoute, SpaceDiscoveryStoreDecision,
    space_discovery_store_decision,
};

use super::NodeServices;

const SPACE_DISCOVERY_REPLICAS: usize = 5;

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

impl NodeServices {
    /// Publish one already-signed discovery carrier.
    ///
    /// The record must be signed by this embedded node. Relays may keep and
    /// periodically republish cached records, but an application cannot use
    /// this method to originate a sample under somebody else's holder id.
    pub async fn space_discovery_publish(&self, bytes: Vec<u8>) -> Result<(), String> {
        let record = SpaceDiscoveryRecord::from_bytes(&bytes)
            .ok_or_else(|| "malformed SpaceDiscoveryRecord".to_owned())?;
        let now = unix_now_ms();
        record
            .verify_at(now)
            .map_err(|error| format!("invalid SpaceDiscoveryRecord: {error:?}"))?;
        if record.holder_node_id != self.local_node_id {
            return Err("SpaceDiscoveryRecord holder is not this embedded node".to_owned());
        }
        let key = record.route.dht_key();
        if matches!(
            space_discovery_store_decision(
                self.dht.get_local(&key).as_deref(),
                &bytes,
                now,
                &self.local_node_id,
            ),
            SpaceDiscoveryStoreDecision::Accept
        ) {
            self.dht.store_local(key, bytes.clone());
        }
        crate::identity_local::publisher_dht::replicate_dht_value(
            &self.dht,
            &self.session_tx_registry,
            self.local_node_id,
            key,
            bytes,
        );
        Ok(())
    }

    /// Read a bounded contested replica set for an exact Space or search token.
    ///
    /// No candidate is collapsed to a last-writer winner here: independent
    /// replicas intentionally retain different rendezvous samples, and the
    /// application verifies descriptor/holder signatures and quorum.
    pub async fn space_discovery_resolve(
        &self,
        route: SpaceDiscoveryRoute,
        timeout: Duration,
    ) -> Vec<Vec<u8>> {
        let now = unix_now_ms();
        let values = self
            .dht_get_replicated_contested(
                route.dht_key(),
                SPACE_DISCOVERY_REPLICAS,
                timeout,
                |bytes| {
                    SpaceDiscoveryRecord::from_bytes(bytes).is_some_and(|record| {
                        record.route == route && record.verify_at(now).is_ok()
                    })
                },
            )
            .await;
        let mut seen = HashSet::new();
        values
            .into_iter()
            .filter(|bytes| {
                let Some(record) = SpaceDiscoveryRecord::from_bytes(bytes) else {
                    return false;
                };
                record.route == route
                    && record.verify_at(unix_now_ms()).is_ok()
                    && seen.insert(blake3::hash(bytes))
            })
            .collect()
    }
}
