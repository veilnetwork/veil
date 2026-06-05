//! Discovery service — handles ANNOUNCE_ATTACHMENT, GET_ATTACHMENT
//! and GET_APP_ENDPOINT requests.
//!
//! # Role enforcement
//!
//! All roles may look up records. Only `NodeRole::Core` may announce
//! (store) records.

use std::{
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use veil_util::lock;

use veil_dht::KademliaService;
use veil_proto::discovery::{
    AnnounceAttachmentPayload, AppEndpointResponse, AttachmentResponse, FindValuePayload,
    FindValueResponse, GetAppEndpointPayload, GetAttachmentPayload, app_endpoint_key,
};
use veil_types::NodeRole;

use super::directory::{AppEndpointEntry, StaticDirectory, entry_to_response};

// ── DiscoveryError ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Node role does not permit storing records.
    NotAllowed,
    /// The announcement's `expires_at` is already in the past.
    Expired,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => write!(f, "node role does not allow storing discovery records"),
            Self::Expired => write!(f, "announcement expires_at is already in the past"),
        }
    }
}

// ── DiscoveryService ──────────────────────────────────────────────────────────

/// Static discovery service.
///
/// Clone-cheap: the inner directory is behind `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct DiscoveryService {
    pub dir: Arc<Mutex<StaticDirectory>>,
    role: NodeRole,
    /// Optional DHT backend for distributed app-endpoint storage.
    dht: Option<Arc<KademliaService>>,
    /// Ed25519 signing key for signed DHT records. When `Some`
    /// `announce_app_endpoint` publishes in the signed self-authenticating
    /// format so intermediate Core nodes can replicate the record cross-DHT
    /// without requiring transport-layer STORE signatures.
    signing_key: Option<Arc<ed25519_dalek::SigningKey>>,
    /// Falcon-512 signing material (base64 pubkey + privkey).
    /// When `Some`, `announce_app_endpoint` / `handle_announce_attachment`
    /// publish Falcon-signed V2 records so Falcon-only nodes also participate
    /// in cross-DHT replication. Exactly one of `signing_key` or
    /// `falcon_signer` should be set per node; `None` on both disables signed
    /// announcements entirely.
    falcon_signer: Option<Arc<FalconSigner>>,
}

/// per-node Falcon-512 key material used to sign DHT records.
///
/// Stored as base64 strings so the signer plugs directly into
/// [`veil_crypto::sign_message`] without extra decoding.
#[derive(Clone, Debug)]
pub struct FalconSigner {
    /// Raw (non-base64) public-key bytes — 897 bytes for Falcon-512.
    pub public_key: Vec<u8>,
    /// Base64-encoded private key, as emitted by `crypto::generate_keypair`.
    pub private_key_b64: String,
}

impl DiscoveryService {
    pub fn new(role: NodeRole) -> Self {
        let mut dir = StaticDirectory::new();
        dir.max_entries = veil_proto::budget::MAX_DISCOVERY_ENTRIES;
        Self {
            dir: Arc::new(Mutex::new(dir)),
            role,
            dht: None,
            signing_key: None,
            falcon_signer: None,
        }
    }

    /// Wire in a Kademlia DHT for distributed app-endpoint storage (248.2/248.3).
    pub fn with_dht(mut self, dht: Arc<KademliaService>) -> Self {
        self.dht = Some(dht);
        self
    }

    /// Attach an ed25519 signing key so announced records carry self-
    /// authenticating signatures. Pair with [`Self::with_falcon_signer`]
    /// is not expected — exactly one algo per node.
    pub fn with_signing_key(mut self, sk: Arc<ed25519_dalek::SigningKey>) -> Self {
        self.signing_key = Some(sk);
        self
    }

    /// attach a Falcon-512 signer so Falcon-only nodes also emit
    /// signed V2 DHT records (cross-DHT replicable via the same accept-path
    /// as Ed25519 V2 records).
    pub fn with_falcon_signer(mut self, s: Arc<FalconSigner>) -> Self {
        self.falcon_signer = Some(s);
        self
    }

    fn can_store(&self) -> bool {
        matches!(self.role, NodeRole::Core)
    }

    // ── handlers ─────────────────────────────────────────────────────────

    pub fn handle_announce_attachment(
        &self,
        payload: AnnounceAttachmentPayload,
    ) -> Result<(), DiscoveryError> {
        if !self.can_store() {
            return Err(DiscoveryError::NotAllowed);
        }
        // Reject stale announcements — prevents DHT poisoning via replayed records.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if payload.expires_at <= now_secs {
            return Err(DiscoveryError::Expired);
        }
        lock!(self.dir).announce_attachment(payload);
        Ok(())
    }

    pub fn handle_get_attachment(&self, payload: GetAttachmentPayload) -> AttachmentResponse {
        // 1. Local directory fast path.
        {
            let dir = lock!(self.dir);
            if let Some(rec) = dir.get_attachment(&payload.node_id) {
                return AttachmentResponse::found(rec.clone());
            }
        }
        // 2. DHT fallback: look up a signed "AT"-wrapper from
        // the local DHT store (populated by `DHT-republish` task on
        // intermediate Core nodes). The wrapper is self-authenticating —
        // `decode_and_verify_signed_attachment` performs pubkey/sig
        // verification before the record is trusted.
        if let Some(dht) = &self.dht {
            let key = veil_proto::discovery::attachment_key(&payload.node_id);
            if let FindValueResponse::Value(bytes) = dht.handle_find_value(FindValuePayload { key })
                && let Some(rec) = super::directory::decode_and_verify_signed_attachment(&bytes)
            {
                // Warm local cache for subsequent lookups.
                lock!(self.dir).announce_attachment(rec.clone());
                return AttachmentResponse::found(rec);
            }
        }
        AttachmentResponse::not_found()
    }

    pub fn handle_get_app_endpoint(&self, payload: GetAppEndpointPayload) -> AppEndpointResponse {
        // 1. Local directory fast path.
        {
            let dir = lock!(self.dir);
            if let Some(entry) =
                dir.get_app_endpoint(&payload.node_id, &payload.app_id, payload.endpoint_id)
            {
                return entry_to_response(entry);
            }
        }
        // 2. DHT fallback lookup.
        if let Some(dht) = &self.dht {
            let key = app_endpoint_key(&payload.node_id, &payload.app_id, payload.endpoint_id);
            if let FindValueResponse::Value(bytes) = dht.handle_find_value(FindValuePayload { key })
                && let Some(entry) = AppEndpointEntry::decode_from_dht_any(&bytes)
            {
                // Warm the local cache so subsequent lookups are fast.
                lock!(self.dir).announce_app_endpoint(entry.clone());
                return entry_to_response(&entry);
            }
        }
        AppEndpointResponse::not_found()
    }

    /// Announce an app endpoint (store side).
    ///
    /// Stores in both the local `StaticDirectory` and, if a DHT is wired in
    /// publishes to the distributed Kademlia store.
    pub fn announce_app_endpoint(&self, entry: AppEndpointEntry) -> Result<(), DiscoveryError> {
        if !self.can_store() {
            return Err(DiscoveryError::NotAllowed);
        }
        // DHT store — fire-and-forget; a STORE failure does not block local announce.
        //
        // when we hold an ed25519 signing key, store the
        // self-authenticating signed format so the DHT-republish task can
        // replicate this record to other Core nodes without tripping their
        // "unsigned STORE for non-self key" rejection.
        if let Some(dht) = &self.dht {
            let key = app_endpoint_key(&entry.node_id, &entry.app_id, entry.endpoint_id);
            // every DHT-published AppEndpointEntry must be signed.
            // The legacy unsigned fallback has been removed to block forged
            // records — a node with no signing identity skips DHT publish
            // (local directory still gets the entry).
            let value: Option<Vec<u8>> = if let Some(sk) = &self.signing_key {
                // Ed25519 V1 remains the default so legacy readers keep working;
                // V2 readers accept both versions.
                Some(entry.encode_for_dht_signed(sk))
            } else if let Some(fs) = &self.falcon_signer {
                // Falcon nodes must use V2 — V1 has no room for variable-length
                // keys/signatures. Any encode failure aborts DHT publish.
                entry
                    .encode_for_dht_signed_v2(
                        veil_types::SignatureAlgorithm::Falcon512,
                        &fs.public_key,
                        &fs.private_key_b64,
                    )
                    .ok()
            } else {
                None
            };
            if let Some(v) = value {
                // audit cycle-6 (P1): publish the node's OWN signed AP record via
                // the per-origin-capped `store_with_origin` (origin = entry.node_id,
                // the owner), NOT `handle_store(StorePayload::unsigned(..))`. With
                // the flipped `allow_unsigned_store=false` default, `handle_store`
                // would reject this StorePayload::unsigned at its `(None, None)`
                // arm — it inspects only STORE-level authenticator fields, not the
                // inner AP signature — silently breaking every node's own
                // app-endpoint DHT publish (this call is fire-and-forget). Mirrors
                // the dispatcher Store arm, which attributes AP records to
                // entry.node_id.
                let _ = dht.store_with_origin(key, v, entry.node_id);
            }
        }
        lock!(self.dir).announce_app_endpoint(entry);
        Ok(())
    }

    // ── maintenance ───────────────────────────────────────────────────────

    pub fn cleanup_expired(&self, now: Instant) {
        lock!(self.dir).cleanup_expired(now);
    }

    pub fn attachment_count(&self) -> usize {
        lock!(self.dir).attachment_count()
    }

    /// Total number of records stored (attachments + app endpoints).
    pub fn entry_count(&self) -> usize {
        let dir = lock!(self.dir);
        dir.attachment_count() + dir.app_endpoint_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_dht::{DhtRuntimeConfig, KademliaService};
    use veil_proto::discovery::{AnnounceAttachmentPayload, GetAttachmentPayload};
    use veil_types::NodeRole;

    fn sample_announcement() -> AnnounceAttachmentPayload {
        // Far-future expires_at so the announcement is always considered fresh.
        AnnounceAttachmentPayload {
            node_id: [1u8; 32],
            role: 1,
            realm_id: 10,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        }
    }

    #[test]
    fn expired_announcement_is_rejected() {
        let svc = DiscoveryService::new(NodeRole::Core);
        let mut ann = sample_announcement();
        ann.expires_at = 1; // clearly in the past
        let err = svc.handle_announce_attachment(ann).unwrap_err();
        assert_eq!(err, DiscoveryError::Expired);
    }

    #[test]
    fn leaf_cannot_announce() {
        let svc = DiscoveryService::new(NodeRole::Leaf);
        let err = svc
            .handle_announce_attachment(sample_announcement())
            .unwrap_err();
        assert_eq!(err, DiscoveryError::NotAllowed);
    }

    #[test]
    fn gateway_can_announce_and_lookup() {
        let svc = DiscoveryService::new(NodeRole::Core);
        svc.handle_announce_attachment(sample_announcement())
            .unwrap();
        let resp = svc.handle_get_attachment(GetAttachmentPayload { node_id: [1u8; 32] });
        assert!(resp.found);
        assert_eq!(resp.record.unwrap().node_id, [1u8; 32]);
    }

    #[test]
    fn leaf_can_lookup() {
        // Even a leaf can query — it just cannot store
        let core = DiscoveryService::new(NodeRole::Core);
        core.handle_announce_attachment(sample_announcement())
            .unwrap();

        let leaf = DiscoveryService {
            dir: Arc::clone(&core.dir),
            role: NodeRole::Leaf,
            dht: None,
            signing_key: None,
            falcon_signer: None,
        };
        let resp = leaf.handle_get_attachment(GetAttachmentPayload { node_id: [1u8; 32] });
        assert!(resp.found);
    }

    #[test]
    fn lookup_unknown_not_found() {
        let svc = DiscoveryService::new(NodeRole::Core);
        let resp = svc.handle_get_attachment(GetAttachmentPayload {
            node_id: [99u8; 32],
        });
        assert!(!resp.found);
    }

    #[test]
    fn app_endpoint_announce_and_lookup() {
        let svc = DiscoveryService::new(NodeRole::Core);
        let entry = AppEndpointEntry {
            node_id: [2u8; 32],
            app_id: [3u8; 32],
            endpoint_id: 80,
            gateway_node_id: Some([4u8; 32]),
            epoch: 1,
            expires_at: 1_800_000_000,
            max_concurrent_streams: 8,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        };
        svc.announce_app_endpoint(entry).unwrap();
        let resp = svc.handle_get_app_endpoint(GetAppEndpointPayload {
            node_id: [2u8; 32],
            app_id: [3u8; 32],
            endpoint_id: 80,
        });
        assert!(resp.found);
        assert_eq!(resp.gateway_node_id, Some([4u8; 32]));
        assert_eq!(resp.max_concurrent_streams, 8);
        assert_eq!(resp.protocol_version, 1);
        assert_eq!(resp.bandwidth_hint_kbps, 512);
    }

    // ── DHT store / fallback / hot cache / auto-publish ───────────

    fn make_entry(node: u8, app: u8, ep: u32) -> AppEndpointEntry {
        AppEndpointEntry {
            node_id: [node; 32],
            app_id: [app; 32],
            endpoint_id: ep,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 9_999_999_999,
            max_concurrent_streams: 4,
            protocol_version: 2,
            bandwidth_hint_kbps: 256,
        }
    }

    /// 248.2 — announce stores in DHT; 248.3 — direct lookup finds it via DHT fallback.
    #[test]
    fn dht_store_and_fallback_lookup() {
        use ed25519_dalek::SigningKey;
        // DHT publish requires a signing identity after legacy
        // unsigned format was removed; derive `node_id` from the signing key
        // so the signed record's BLAKE3(pubkey) check passes on decode.
        let sk = Arc::new(SigningKey::from_bytes(&[0x11u8; 32]));
        let node_id: [u8; 32] = *blake3::hash(sk.verifying_key().as_bytes()).as_bytes();
        let dht = Arc::new(KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));
        let svc = DiscoveryService::new(NodeRole::Core)
            .with_dht(Arc::clone(&dht))
            .with_signing_key(Arc::clone(&sk));

        let mut entry = make_entry(0x10, 0x20, 99);
        entry.node_id = node_id;
        svc.announce_app_endpoint(entry.clone()).unwrap();

        // Verify the DHT holds the value.
        use veil_proto::discovery::{FindValuePayload, FindValueResponse, app_endpoint_key};
        let key = app_endpoint_key(&node_id, &[0x20u8; 32], 99);
        assert!(
            matches!(
                dht.handle_find_value(FindValuePayload { key }),
                FindValueResponse::Value(_)
            ),
            "DHT must hold the stored entry"
        );

        // Simulate a cold start: create a second service with an empty local directory
        // but the same DHT — lookup must fall back to DHT.
        let svc2 = DiscoveryService::new(NodeRole::Core).with_dht(Arc::clone(&dht));
        let resp = svc2.handle_get_app_endpoint(GetAppEndpointPayload {
            node_id,
            app_id: [0x20u8; 32],
            endpoint_id: 99,
        });
        assert!(resp.found, "DHT fallback must return the entry");
        assert_eq!(resp.max_concurrent_streams, 4);
        assert_eq!(resp.protocol_version, 2);
    }

    /// 248.3 — after DHT fallback the entry is warmed into the local cache.
    /// record must be signed; node_id derived from pubkey.
    #[test]
    fn dht_fallback_warms_local_cache() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let node_id: [u8; 32] = *blake3::hash(sk.verifying_key().as_bytes()).as_bytes();
        let dht = Arc::new(KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));
        let mut entry = make_entry(0x30, 0x40, 7);
        entry.node_id = node_id;
        let key = veil_proto::discovery::app_endpoint_key(&node_id, &[0x40u8; 32], 7);
        dht.handle_store(veil_proto::discovery::StorePayload::unsigned(
            key,
            entry.encode_for_dht_signed(&sk),
        ))
        .unwrap();

        let svc = DiscoveryService::new(NodeRole::Core).with_dht(Arc::clone(&dht));
        // First lookup — goes to DHT.
        let resp1 = svc.handle_get_app_endpoint(GetAppEndpointPayload {
            node_id,
            app_id: [0x40u8; 32],
            endpoint_id: 7,
        });
        assert!(resp1.found);

        // Second lookup — served from local cache (no DHT needed even if DHT were gone).
        let resp2 = svc.handle_get_app_endpoint(GetAppEndpointPayload {
            node_id,
            app_id: [0x40u8; 32],
            endpoint_id: 7,
        });
        assert!(resp2.found);
        assert_eq!(resp1.bandwidth_hint_kbps, resp2.bandwidth_hint_kbps);
    }

    /// 248.4 — capability fields survive encode/decode roundtrip through DHT bytes.
    #[test]
    fn capability_fields_dht_roundtrip() {
        let entry = AppEndpointEntry {
            node_id: [0xAAu8; 32],
            app_id: [0xBBu8; 32],
            endpoint_id: 1234,
            gateway_node_id: Some([0xCCu8; 32]),
            epoch: 7,
            expires_at: 1_700_000_000,
            max_concurrent_streams: 100,
            protocol_version: 42,
            bandwidth_hint_kbps: 9999,
        };
        let bytes = entry.encode_for_dht();
        let decoded = AppEndpointEntry::decode_from_dht(&bytes).expect("must decode");
        assert_eq!(decoded.max_concurrent_streams, 100);
        assert_eq!(decoded.protocol_version, 42);
        assert_eq!(decoded.bandwidth_hint_kbps, 9999);
        assert_eq!(decoded.gateway_node_id, Some([0xCCu8; 32]));
    }

    // ── cross-node DHT discovery via signed format ────────────────

    /// 453: end-to-end cross-node AppEndpoint discovery. Publisher uses its
    /// ed25519 signing key to write a signed record; consumer on a different
    /// node (empty local directory) looks up via a shared DHT and finds it.
    ///
    /// This simulates the post flow: publisher's `announce_app_endpoint`
    /// emits bytes with magic "AP" → bytes get stored in DHT → consumer's
    /// `handle_get_app_endpoint` reads raw bytes from DHT → `decode_from_dht_any`
    /// verifies the internal signature and returns the entry.
    #[test]
    fn cross_node_app_endpoint_discovery_via_signed_wrapper() {
        use ed25519_dalek::SigningKey;
        let dht = Arc::new(KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));

        // Publisher identity: its node_id must match what's in the AppEndpointEntry.
        let owner_sk = Arc::new(SigningKey::from_bytes(&[0x99u8; 32]));
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();

        let publisher = DiscoveryService::new(NodeRole::Core)
            .with_dht(Arc::clone(&dht))
            .with_signing_key(Arc::clone(&owner_sk));

        let entry = AppEndpointEntry {
            node_id: owner_node_id,
            app_id: [0x33u8; 32],
            endpoint_id: 42,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 9_999_999_999,
            max_concurrent_streams: 8,
            protocol_version: 3,
            bandwidth_hint_kbps: 1024,
        };
        publisher.announce_app_endpoint(entry).unwrap();

        // Verify what's stored in DHT is the signed format (magic "AP").
        let key = app_endpoint_key(&owner_node_id, &[0x33u8; 32], 42);
        match dht.handle_find_value(FindValuePayload { key }) {
            FindValueResponse::Value(bytes) => {
                assert_eq!(
                    &bytes[..2],
                    &crate::directory::APP_ENDPOINT_DHT_MAGIC,
                    "publisher must write signed format to DHT",
                );
            }
            _ => panic!("DHT must hold the stored entry"),
        }

        // Cross-node consumer: fresh service with EMPTY local directory but
        // sharing the same DHT. Lookup must find + verify + warm-cache.
        let consumer = DiscoveryService::new(NodeRole::Core).with_dht(Arc::clone(&dht));
        let resp = consumer.handle_get_app_endpoint(GetAppEndpointPayload {
            node_id: owner_node_id,
            app_id: [0x33u8; 32],
            endpoint_id: 42,
        });
        assert!(resp.found, "cross-node lookup via DHT must succeed");
        assert_eq!(resp.max_concurrent_streams, 8);
        assert_eq!(resp.protocol_version, 3);
        assert_eq!(resp.bandwidth_hint_kbps, 1024);
    }

    /// 453.7: end-to-end cross-node Attachment discovery. The owner signs an
    /// AnnounceAttachmentPayload; publisher (a Core node acting as forwarder)
    /// wraps it with owner's pubkey and stores in shared DHT; consumer on a
    /// third node looks up and finds it after signature verification.
    #[test]
    fn cross_node_attachment_discovery_via_signed_wrapper() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::discovery::{AnnounceAttachmentPayload, attachment_key};

        let dht = Arc::new(KademliaService::with_config(
            [0u8; 32],
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));

        // Owner signs the attachment.
        let owner_sk = SigningKey::from_bytes(&[0xABu8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();

        let mut payload = AnnounceAttachmentPayload {
            node_id: owner_node_id,
            role: 8, // CORE
            realm_id: 0,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![],
            seq_no: 1,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        payload.signature = owner_sk.sign(&payload.signable_body()).to_bytes().to_vec();

        // Intermediate node (e.g., who received the announcement via wire)
        // publishes the signed wrapper in the shared DHT.
        let wrapper = crate::directory::encode_signed_attachment(
            &payload,
            veil_types::SignatureAlgorithm::Ed25519,
            &owner_pk,
        );
        let key = attachment_key(&owner_node_id);
        dht.handle_store(veil_proto::discovery::StorePayload::unsigned(key, wrapper))
            .unwrap();

        // Consumer on a third node: empty directory, shared DHT. The
        // `handle_get_attachment` must consult the DHT and verify the wrapper.
        let consumer = DiscoveryService::new(NodeRole::Core).with_dht(Arc::clone(&dht));
        let resp = consumer.handle_get_attachment(GetAttachmentPayload {
            node_id: owner_node_id,
        });
        assert!(
            resp.found,
            "cross-node attachment lookup via DHT must succeed"
        );
        let rec = resp.record.expect("attachment record must be present");
        assert_eq!(rec.node_id, owner_node_id);
        assert_eq!(rec.role, 8);
        // Local cache warmed — second lookup hits directory fast path.
        {
            let dir = lock!(consumer.dir);
            assert!(
                dir.get_attachment(&owner_node_id).is_some(),
                "consumer warms local cache"
            );
        }
    }

    // `auto_publish_on_register` test moved to
    // `veilcore/tests/discovery_auto_publish.rs` because it wires the
    // concrete `node::app::registry::AppEndpointRegistry` from veilcore.
}
