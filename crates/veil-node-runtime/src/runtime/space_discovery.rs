//! Public Space discovery over the existing contested DHT read plane.
//!
//! xVeil owns and verifies the strict descriptor payload. The node runtime
//! only accepts the self-authenticating outer carrier, retains bounded sets
//! of independent holder samples, and returns valid contested samples to the
//! application for holder-quorum merge.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use veil_crypto::space_discovery::{
    MAX_SPACE_DISCOVERY_SAMPLES, SpaceDiscoveryRecord, SpaceDiscoveryRoute,
    space_discovery_sample_query,
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
        self.dht
            .store_space_discovery_sample(key, &bytes, veil_dht::store::ORIGIN_INTERNAL);
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
    /// Query bounded sample slots concurrently. Each response is still one
    /// original carrier within the existing DHT wire-size budget. Legacy peers
    /// repeat their singleton; duplicate bytes never count as extra holders.
    pub async fn space_discovery_resolve(
        &self,
        route: SpaceDiscoveryRoute,
        timeout: Duration,
    ) -> Vec<Vec<u8>> {
        let now = unix_now_ms();
        let batches = futures::future::join_all((0..MAX_SPACE_DISCOVERY_SAMPLES).map(|index| {
            let selector = space_discovery_sample_query(index).expect("bounded sample index");
            self.dht_get_replicated_contested_with_payload(
                route.dht_key(),
                SPACE_DISCOVERY_REPLICAS,
                timeout,
                move |bytes| {
                    SpaceDiscoveryRecord::from_bytes(bytes).is_some_and(|record| {
                        record.route == route && record.verify_at(now).is_ok()
                    })
                },
                selector.to_vec(),
            )
        }))
        .await;
        let values = batches.into_iter().flatten();
        let mut seen = HashSet::new();
        values
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
