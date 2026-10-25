//! Keep verified revocations when an offline device republishes an old record.
//! This is replica arbitration; recipients still verify their own durable floor.
use super::FrameDispatcher;
use veil_proto::identity_document::{IDENTITY_DOCUMENT_MAGIC, IdentityDocument};

impl FrameDispatcher {
    pub(crate) fn mirror_discovery_value(&self, key: [u8; 32], value: Vec<u8>) {
        if value.get(..2) == Some(&IDENTITY_DOCUMENT_MAGIC[..]) {
            self.store_discovery_value(key, value, veil_dht::store::ORIGIN_INTERNAL);
        } else {
            self.dht.store_local(key, value);
        }
    }

    pub(crate) fn store_discovery_value(
        &self,
        key: [u8; 32],
        value: Vec<u8>,
        origin: [u8; 32],
    ) -> bool {
        if value.get(..2) != Some(&IDENTITY_DOCUMENT_MAGIC[..]) {
            return self.dht.store_with_origin(key, value, origin);
        }
        let now = veil_util::unix_secs_now_u64();
        let Ok(incoming) = IdentityDocument::decode(&value) else {
            return false;
        };
        if IdentityDocument::dht_key(&incoming.node_id) != key
            || veil_identity::verify::verify_identity_document(&incoming, now).is_err()
        {
            return false;
        }
        // Verify outside the DHT mutex. Commit against the exact bytes read,
        // so two concurrent stores cannot both beat an older snapshot and then
        // let the last writer erase the first writer's revocations.
        for _ in 0..3 {
            let current = self.dht.get_local(&key);
            if let Some(previous) = current
                .as_deref()
                .and_then(|bytes| IdentityDocument::decode(bytes).ok())
                .filter(|doc| doc.node_id == incoming.node_id)
                .filter(|doc| {
                    veil_identity::verify::verify_identity_document(
                        doc,
                        now.min(doc.valid_until_unix),
                    )
                    .is_ok()
                })
                && (incoming.issued_at_unix < previous.issued_at_unix
                    || previous.revoked_devices.iter().any(|revoked| {
                        !incoming
                            .revoked_devices
                            .iter()
                            .any(|r| r.device_id == revoked.device_id)
                    }))
            {
                return false;
            }
            if self
                .dht
                .store_with_origin_if(key, value.clone(), origin, |live| {
                    live == current.as_deref()
                })
            {
                return true;
            }
            if self.dht.get_local(&key) == current {
                return false; // quota/cap refusal, rather than a racing writer
            }
        }
        false
    }
}
