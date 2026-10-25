//! Which addresses a rendezvous ad may legitimately be published under.
//!
//! One question, asked by two places that must agree: the publisher's own
//! freshness probe, which re-signs when the ad it finds is not a good one, and
//! the sender's resolver, which drops an ad it cannot tie to the receiver it
//! asked for. Two copies of this rule drifting apart would have a node
//! re-publishing an ad every tick that no sender accepts, or the reverse.

use std::sync::Arc;

use veil_anonymity::rendezvous::RendezvousAd;
use veil_dht::KademliaService;

/// Is this ad tied to the address it names?
///
/// Two ways, and the ad does not say which — it carries no index, only the
/// issuer key, so the answer is looked up rather than claimed:
///
/// * `BLAKE3(issuer_pk) == receiver_node_id` — the signer IS the address. That
///   is every legacy node and every identity whose device key is its master,
///   and it needs nothing off the network.
/// * otherwise the identity document at `receiver_node_id` must name the
///   issuer among its device keys. A hybrid identity's address is the hash of
///   a 929-byte master that no device key can reproduce, so this is the ONLY
///   way such a receiver is reachable at the address its contacts know.
///
/// The document is read from the LOCAL shard, on purpose: the callers are
/// synchronous filters and a resolve must not block on a DHT walk. A node that
/// does not hold the document answers no and drops the ad — the same
/// conservative outcome as before delegation existed.
pub(crate) fn ad_binding_ok(dht: &Arc<KademliaService>, ad: &RendezvousAd) -> bool {
    if veil_anonymity::rendezvous::verify_rendezvous_ad(ad).is_ok() {
        return true;
    }
    let Some(keys) = identity_device_keys(dht, &ad.receiver_node_id) else {
        return false;
    };
    veil_anonymity::rendezvous::verify_rendezvous_ad_delegated(ad, &ad.receiver_node_id, &keys)
        .is_ok()
}

/// Network consumers must consult the same monotone authorization floor as
/// certificate resolution, including host checkpoint state. A signed old ad or
/// an old DHT document cannot restore a device already known to be revoked.
pub(crate) fn peer_ad_binding_ok(
    dht: &Arc<KademliaService>,
    authorization: &crate::identity_document_floor::IdentityDocumentFloor,
    ad: &RendezvousAd,
) -> bool {
    if veil_anonymity::rendezvous::verify_rendezvous_ad(ad).is_ok() {
        return true;
    }
    use veil_proto::identity_document::IdentityDocument;
    let now = veil_util::unix_secs_now_u64();
    if let Some(doc) = dht
        .get_local(&IdentityDocument::dht_key(&ad.receiver_node_id))
        .and_then(|bytes| IdentityDocument::decode(&bytes).ok())
        .filter(|doc| doc.node_id == ad.receiver_node_id)
    {
        authorization.observe(&doc, now);
    }
    let Some(doc) = authorization.current(&ad.receiver_node_id) else {
        return false;
    };
    if veil_identity::verify::verify_identity_document(&doc, now).is_err() {
        return false;
    }
    let keys: Vec<_> = doc
        .identity_keys
        .iter()
        .filter(|key| authorization.allows_device_proof(&doc.node_id, &key.device_id, now))
        .map(|key| key.pubkey.clone())
        .collect();
    veil_anonymity::rendezvous::verify_rendezvous_ad_delegated(ad, &doc.node_id, &keys).is_ok()
}

/// The device pubkeys a VERIFIED identity document names for `node_id`.
///
/// The full verifier ladder, clock included: this document came off the
/// network, so an expired delegation must not keep a receiver advertising.
fn identity_device_keys(dht: &Arc<KademliaService>, node_id: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let key = veil_proto::identity_document::IdentityDocument::dht_key(node_id);
    let bytes = dht.get_local(&key)?;
    let doc = veil_proto::identity_document::IdentityDocument::decode(&bytes).ok()?;
    if &doc.node_id != node_id {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    veil_identity::verify::verify_identity_document(&doc, now).ok()?;
    // EACH key's own window, not just the active one's. The document verifier
    // tolerates an aged-out sibling on purpose; handing the whole list back as
    // "the devices this identity has" turned that tolerance into authority for
    // an expired device secret (report27 V02).
    Some(
        (0..doc.identity_keys.len())
            .filter_map(|idx| {
                veil_identity::verify::authorize_device_key_at(&doc, idx, now)
                    .ok()
                    .map(|k| k.pubkey.clone())
            })
            .collect(),
    )
}

/// Every address this node must be findable at as a RECEIVER.
///
/// The device transport id is always one of them: it is what every sender
/// running today's code looks up, and what an ad bound the strict way proves.
/// When a sovereign identity is loaded and its address differs — a hybrid
/// master, or a device provisioned from a recovery certificate — that address
/// is the second, because it is the one the invite hands out and therefore the
/// only one a contact ever asks for.
///
/// Publishing at BOTH is what makes the change cost nobody reachability: an
/// un-updated sender keeps resolving the device-bound ad it can verify, and an
/// updated one finds the identity-bound ad where it actually looks. The first
/// address can be retired once no sender resolves by it.
pub(crate) fn receiver_addresses(
    device: [u8; 32],
    sovereign: &super::identity_state::SovereignIdentityCell,
) -> Vec<[u8; 32]> {
    match sovereign.get() {
        Some(sov) if *sov.node_id() != device => vec![device, *sov.node_id()],
        _ => vec![device],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use veil_anonymity::rendezvous::{
        RendezvousPublisherEntry, decode_rendezvous_ad, rendezvous_ad_dht_key, verify_rendezvous_ad,
    };
    use veil_observability::NodeLogger;

    fn delegated_document(
        seed: u8,
        issued: u64,
        revoke_second: bool,
    ) -> (
        veil_proto::identity_document::IdentityDocument,
        [ed25519_dalek::SigningKey; 2],
    ) {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_crypto::identity::{certify_message, compute_node_id};
        use veil_proto::identity_document::{
            ALGO_ED25519, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey, RevokedDevice,
        };
        let master = SigningKey::from_bytes(&[seed; 32]);
        let devices = [
            SigningKey::from_bytes(&[seed + 1; 32]),
            SigningKey::from_bytes(&[seed + 2; 32]),
        ];
        let identity = compute_node_id(master.verifying_key().as_bytes());
        let until = issued + 7200;
        let mut keys = devices
            .iter()
            .map(|device| {
                let pk = device.verifying_key().to_bytes();
                let device_id = compute_node_id(&pk);
                IdentityKey {
                    algo: ALGO_ED25519,
                    pubkey: pk.to_vec(),
                    device_id,
                    valid_from_unix: issued,
                    valid_until_unix: until,
                    master_sig: master
                        .sign(&certify_message(
                            &identity,
                            ALGO_ED25519,
                            &pk,
                            &device_id,
                            issued,
                            until,
                        ))
                        .to_bytes()
                        .to_vec(),
                }
            })
            .collect::<Vec<_>>();
        let revoked = if revoke_second {
            let device_id = keys.pop().unwrap().device_id;
            vec![RevokedDevice {
                device_id,
                master_sig: master
                    .sign(&RevokedDevice::signing_message(&identity, &device_id))
                    .to_bytes()
                    .to_vec(),
            }]
        } else {
            vec![]
        };
        let mut document = IdentityDocument {
            node_id: identity,
            master_algo: ALGO_ED25519,
            master_pubkey: master.verifying_key().to_bytes().to_vec(),
            issued_at_unix: issued,
            valid_until_unix: until,
            sig_key_idx: 0,
            revoked_devices: revoked,
            identity_keys: keys,
            document_sig: vec![],
        };
        let mut message = DOC_SIG_CONTEXT.to_vec();
        message.extend_from_slice(&document.canonical_signing_bytes());
        document.document_sig = devices[0].sign(&message).to_bytes().to_vec();
        let document = IdentityDocument::decode(&document.encode()).unwrap();
        (document, devices)
    }

    fn delegated_ad_bytes(
        receiver: [u8; 32],
        signer: &ed25519_dalek::SigningKey,
        now: u64,
    ) -> Vec<u8> {
        veil_anonymity::rendezvous::sign_rendezvous_ad(
            receiver,
            [0x41; 32],
            [0x42; 16],
            [0x43; 32],
            now,
            now + 3600,
            &[],
            &[],
            &[],
            &base64::engine::general_purpose::STANDARD.encode(signer.verifying_key().to_bytes()),
            &base64::engine::general_purpose::STANDARD.encode(signer.to_bytes()),
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap()
    }

    fn delegated_ad(
        receiver: [u8; 32],
        signer: &ed25519_dalek::SigningKey,
        now: u64,
    ) -> RendezvousAd {
        decode_rendezvous_ad(&delegated_ad_bytes(receiver, signer, now)).unwrap()
    }

    #[test]
    fn an_identity_ad_refuses_a_revoked_device_even_with_a_valid_signature() {
        use veil_proto::identity_document::IdentityDocument;
        let now = veil_util::unix_secs_now_u64();
        let (before, devices) = delegated_document(11, now - 60, false);
        let (revoked, _) = delegated_document(11, now - 59, true);
        veil_identity::verify::verify_identity_document(&revoked, now).unwrap();
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        let key = IdentityDocument::dht_key(&before.node_id);
        let active_ad = delegated_ad(before.node_id, &devices[0], now);
        let old_ad = delegated_ad(before.node_id, &devices[1], now);
        assert!(
            verify_rendezvous_ad(&old_ad).is_err(),
            "must use delegated verification"
        );
        dht.store_local(key, before.encode());
        assert!(ad_binding_ok(&dht, &active_ad));
        assert!(ad_binding_ok(&dht, &old_ad));
        dht.store_local(key, revoked.encode());
        assert!(ad_binding_ok(&dht, &active_ad));
        assert!(
            !ad_binding_ok(&dht, &old_ad),
            "a revoked device must not redirect the identity's new traffic"
        );
    }

    #[test]
    fn an_identity_ad_refuses_a_valid_document_for_a_different_identity() {
        use veil_proto::identity_document::IdentityDocument;
        let now = veil_util::unix_secs_now_u64();
        let (victim, _) = delegated_document(21, now - 60, false);
        let (other, devices) = delegated_document(31, now - 60, false);
        veil_identity::verify::verify_identity_document(&other, now).unwrap();
        let ad = delegated_ad(victim.node_id, &devices[1], now);
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        // STORE's canonical-key gate normally blocks this remotely. The read
        // boundary still must bind the actual document, not the lookup key.
        dht.store_local(IdentityDocument::dht_key(&victim.node_id), other.encode());
        assert!(!ad_binding_ok(&dht, &ad));
    }

    async fn peer_lookup(
        dht: &Arc<KademliaService>,
        authorization: &crate::identity_document_floor::IdentityDocumentFloor,
        cache: &Arc<super::super::anonymity_state::RendezvousResolveCache>,
        receiver: [u8; 32],
    ) -> Vec<RendezvousAd> {
        super::super::rendezvous_resolver::resolve_fresh_rendezvous_ads(
            dht,
            &Arc::new(std::sync::RwLock::new(
                veil_session::SessionTxRegistry::new(),
            )),
            &Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            [0x10; 32],
            cache,
            &Arc::new(NodeLogger::new_noop()),
            receiver,
            std::time::Duration::from_millis(50),
            super::super::rendezvous_resolver::ResolveMode::Any,
            authorization,
        )
        .await
    }

    #[tokio::test]
    async fn a_cached_identity_route_is_rejected_after_an_observed_device_revocation() {
        use super::super::anonymity_state::RendezvousResolveCache;
        use crate::identity_document_floor::IdentityDocumentFloor;
        use veil_proto::identity_document::IdentityDocument;
        let now = veil_util::unix_secs_now_u64();
        let (before, devices) = delegated_document(11, now - 60, false);
        let (revoked, _) = delegated_document(11, now - 59, true);
        let authorization = IdentityDocumentFloor::ephemeral();
        assert!(authorization.observe(&before, now));
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        dht.store_local(IdentityDocument::dht_key(&before.node_id), before.encode());
        let cache = Arc::new(RendezvousResolveCache::new());
        let old_ad = delegated_ad(before.node_id, &devices[1], now);
        cache.put(before.node_id, vec![old_ad]);
        assert_eq!(
            peer_lookup(&dht, &authorization, &cache, before.node_id)
                .await
                .len(),
            1
        );
        assert!(authorization.observe(&revoked, now));
        assert!(
            peer_lookup(&dht, &authorization, &cache, before.node_id)
                .await
                .is_empty(),
            "a still-signed cached route must not undo an observed revocation"
        );
    }

    #[tokio::test]
    async fn a_restored_device_revocation_rejects_stale_dht_routes() {
        use super::super::anonymity_state::RendezvousResolveCache;
        use crate::identity_document_floor::IdentityDocumentFloor;
        use veil_proto::identity_document::IdentityDocument;
        let now = veil_util::unix_secs_now_u64();
        let (before, devices) = delegated_document(11, now - 60, false);
        let (revoked, _) = delegated_document(11, now - 59, true);
        let previous = IdentityDocumentFloor::ephemeral();
        assert!(previous.observe(&revoked, now));
        let (_, bytes) = previous.export_host().unwrap();
        let authorization = IdentityDocumentFloor::ephemeral();
        authorization.import_host(&bytes, now).unwrap();
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        dht.store_local(IdentityDocument::dht_key(&before.node_id), before.encode());
        dht.store_local(
            rendezvous_ad_dht_key(&before.node_id),
            delegated_ad_bytes(before.node_id, &devices[1], now),
        );
        let cache = Arc::new(RendezvousResolveCache::new());
        assert!(
            peer_lookup(&dht, &authorization, &cache, before.node_id)
                .await
                .is_empty(),
            "a stale DHT document must not restore rights forgotten by the route cache"
        );
        cache.put(
            before.node_id,
            vec![delegated_ad(before.node_id, &devices[0], now)],
        );
        assert_eq!(
            peer_lookup(&dht, &authorization, &cache, before.node_id)
                .await
                .len(),
            1,
            "the remaining active device must remain reachable"
        );
    }

    #[tokio::test]
    async fn delegated_routes_wait_for_the_hosts_authorization_checkpoint() {
        use super::super::anonymity_state::RendezvousResolveCache;
        use crate::identity_document_floor::IdentityDocumentFloor;
        use veil_proto::identity_document::IdentityDocument;
        let now = veil_util::unix_secs_now_u64();
        let (doc, devices) = delegated_document(11, now - 60, false);
        let authorization = IdentityDocumentFloor::ephemeral();
        authorization
            .import_host(br#"{"version":1,"entries":[]}"#, now)
            .unwrap();
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        dht.store_local(IdentityDocument::dht_key(&doc.node_id), doc.encode());
        let ad = delegated_ad(doc.node_id, &devices[1], now);
        dht.store_local(
            rendezvous_ad_dht_key(&doc.node_id),
            delegated_ad_bytes(doc.node_id, &devices[1], now),
        );
        let cache = Arc::new(RendezvousResolveCache::new());
        cache.put(doc.node_id, vec![ad.clone()]);
        assert!(
            peer_lookup(&dht, &authorization, &cache, doc.node_id)
                .await
                .is_empty()
        );
        assert!(!authorization.is_durable(&doc.node_id));
        authorization
            .acknowledge_host(authorization.revision())
            .unwrap();
        cache.put(doc.node_id, vec![ad]);
        assert_eq!(
            peer_lookup(&dht, &authorization, &cache, doc.node_id)
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn an_unreadable_authorization_store_cannot_admit_a_cached_delegated_ad() {
        use super::super::anonymity_state::RendezvousResolveCache;
        use crate::identity_document_floor::IdentityDocumentFloor;
        use veil_proto::identity_document::IdentityDocument;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("peer_identity_floors.json"), b"not-json").unwrap();
        let authorization = IdentityDocumentFloor::load(&dir.path().join("node.toml"));
        let now = veil_util::unix_secs_now_u64();
        let (doc, devices) = delegated_document(11, now - 60, false);
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        dht.store_local(IdentityDocument::dht_key(&doc.node_id), doc.encode());
        let cache = Arc::new(RendezvousResolveCache::new());
        cache.put(
            doc.node_id,
            vec![delegated_ad(doc.node_id, &devices[1], now)],
        );
        assert!(
            peer_lookup(&dht, &authorization, &cache, doc.node_id)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refreshing_a_delegated_ad_fetches_a_newer_revocation_even_when_the_old_document_matches()
     {
        use super::super::{
            anonymity_state::RendezvousResolveCache,
            rendezvous_resolver::{ResolveMode, resolve_fresh_rendezvous_ads},
        };
        use crate::identity_document_floor::IdentityDocumentFloor;
        use std::sync::{
            Mutex, RwLock,
            atomic::{AtomicUsize, Ordering},
        };
        use veil_proto::{identity_document::IdentityDocument, routing::RecursiveQueryPayload};
        let now = veil_util::unix_secs_now_u64();
        let (before, devices) = delegated_document(11, now - 60, false);
        let (revoked, _) = delegated_document(11, now - 59, true);
        let authorization = IdentityDocumentFloor::ephemeral();
        assert!(authorization.observe(&before, now));
        let dht = Arc::new(KademliaService::new([0x10; 32]));
        let doc_key = IdentityDocument::dht_key(&before.node_id);
        let ad_key = rendezvous_ad_dht_key(&before.node_id);
        let ad_bytes = delegated_ad_bytes(before.node_id, &devices[1], now);
        dht.store_local(doc_key, before.encode());
        dht.store_local(ad_key, ad_bytes.clone());
        let mut registry = veil_session::SessionTxRegistry::new();
        let mut rx = registry.register([0x51; 32]);
        let registry = Arc::new(RwLock::new(registry));
        let pending = Arc::new(Mutex::new(std::collections::HashMap::<
            [u8; 16],
            veil_dispatcher::PendingRecursive,
        >::new()));
        let fetched = Arc::new(AtomicUsize::new(0));
        let replies = tokio::spawn({
            let pending = pending.clone();
            let fetched = fetched.clone();
            let revoked_bytes = revoked.encode();
            async move {
                while let Some((_, frame)) = rx.recv().await {
                    let query =
                        RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
                    let bytes = if query.target_key == doc_key {
                        fetched.fetch_add(1, Ordering::Relaxed);
                        revoked_bytes.clone()
                    } else if query.target_key == ad_key {
                        ad_bytes.clone()
                    } else {
                        vec![]
                    };
                    let waiter = pending.lock().unwrap().remove(&query.query_id).unwrap();
                    let _ = waiter.tx.send(bytes);
                }
            }
        });
        let cache = Arc::new(RendezvousResolveCache::new());
        cache.put(
            before.node_id,
            vec![delegated_ad(before.node_id, &devices[1], now)],
        );
        let ads = resolve_fresh_rendezvous_ads(
            &dht,
            &registry,
            &pending,
            [0x10; 32],
            &cache,
            &Arc::new(NodeLogger::new_noop()),
            before.node_id,
            std::time::Duration::from_secs(1),
            ResolveMode::RefreshAhead,
            &authorization,
        )
        .await;
        replies.abort();
        assert!(replies.await.unwrap_err().is_cancelled());
        assert!(pending.lock().unwrap().is_empty());
        assert!(
            fetched.load(Ordering::Relaxed) > 0,
            "a valid cached document must not suppress the revocation lookup"
        );
        assert!(ads.is_empty());
        assert_eq!(
            authorization
                .current(&before.node_id)
                .unwrap()
                .issued_at_unix,
            revoked.issued_at_unix
        );
    }

    /// Both addresses, and only when they are two.
    ///
    /// The device id must stay in the list: it is what every sender running
    /// today's code resolves by, and dropping it would take reachability away
    /// from all of them on the day this ships. The identity address joins it
    /// only when the two differ — for a legacy or standalone node they are one
    /// value, and publishing the same ad twice under one key is work for
    /// nothing.
    #[test]
    fn a_sovereign_receiver_advertises_at_both_addresses() {
        use crate::runtime::identity_state::SovereignIdentityCell;

        let dir = std::env::temp_dir().join(format!(
            "rzv-addrs-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let out = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rzv".to_string(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .expect("create_identity");
        std::fs::write(
            dir.join("device_identity_sk.bin"),
            out.identity_sk_seed.as_array(),
        )
        .unwrap();
        let sov = std::sync::Arc::new(
            veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir)
                .expect("the identity just written must load"),
        );

        let device = [0x11u8; 32];
        assert_ne!(device, *sov.node_id());

        // No sovereign identity: unchanged, one address.
        let empty = SovereignIdentityCell::new(None);
        assert_eq!(receiver_addresses(device, &empty), vec![device]);

        // With one whose address differs: both, device FIRST.
        let cell = SovereignIdentityCell::new(Some(std::sync::Arc::clone(&sov)));
        assert_eq!(
            receiver_addresses(device, &cell),
            vec![device, *sov.node_id()],
            "a sender on today's code resolves by the device id and must keep \
             finding an ad there",
        );

        // And when the two coincide — the standalone shape — one address, not
        // the same ad written twice.
        assert_eq!(
            receiver_addresses(*sov.node_id(), &cell),
            vec![*sov.node_id()]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A device of an identity may advertise at the IDENTITY's address.
    ///
    /// The strict binding is `BLAKE3(issuer_pk) == receiver_node_id`, which no
    /// device key of a real identity satisfies: the address is the hash of the
    /// MASTER, and `create_identity` mints a separate device subkey. So a
    /// receiver could publish only at its device address, while every contact
    /// looks it up by the identity address the invite carries — an ad at an
    /// address nobody asks for, and inbound delivery with nowhere to land.
    ///
    /// The control is the whole point of the test: WITHOUT the document, the
    /// same ad is refused. Nothing is waved through; the document is what
    /// proves the binding, and a node that cannot read one admits nothing.
    #[test]
    fn a_device_may_advertise_at_its_identitys_address() {
        use std::sync::{Arc, Mutex};

        let dir = std::env::temp_dir().join(format!(
            "rzv-binding-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let out = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rzv".to_string(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .expect("create_identity");

        // The device key the identity actually runs on — a SUBKEY, filed in
        // the document, whose hash is not the address.
        let seed: [u8; 32] = *out.identity_sk_seed.as_array();
        let device_sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let device_pk = device_sk.verifying_key().to_bytes();
        let device_identity = crate::local_identity::HandshakeIdentity {
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD.encode(device_pk),
            private_key: base64::engine::general_purpose::STANDARD.encode(seed),
            nonce: "AAAA".to_owned(),
            node_id: veil_cfg::NodeId::from_public_key(
                veil_cfg::SignatureAlgorithm::Ed25519,
                &base64::engine::general_purpose::STANDARD.encode(device_pk),
            )
            .unwrap(),
        };
        assert_ne!(
            *device_identity.node_id.as_bytes(),
            out.node_id,
            "fixture is vacuous unless the device and the identity are two addresses",
        );

        let dht = Arc::new(veil_dht::KademliaService::new(
            *device_identity.node_id.as_bytes(),
        ));
        let x25519_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let logger = Arc::new(NodeLogger::new_noop());
        let entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
            rendezvous_node_id: [0xCC; 32],
            auth_cookie: [0xDD; 16],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            ephemeral_ad_identity: None,
            rendezvous_kem_valid_until_unix: 0,
        }]));

        // Through the PUBLIC entry point with the identity cell a node holds,
        // so the wiring is covered too: the caller no longer chooses an
        // address, and nothing it passes can leave one of the two unpublished.
        std::fs::write(
            dir.join("device_identity_sk.bin"),
            out.identity_sk_seed.as_array(),
        )
        .unwrap();
        let sov = std::sync::Arc::new(
            veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir)
                .expect("the identity just written must load"),
        );
        let cell = crate::runtime::identity_state::SovereignIdentityCell::new(Some(sov));

        let published = crate::runtime::NodeRuntime::tick_publish_rendezvous_ads(
            &entries,
            &x25519_sk,
            &device_identity,
            &cell,
            &dht,
            &logger,
            None,
        );
        assert_eq!(
            published, 2,
            "one ad per address the receiver is findable at"
        );
        assert!(
            dht.get_local(&rendezvous_ad_dht_key(device_identity.node_id.as_bytes()))
                .is_some(),
            "the device address keeps its ad — that is what every sender on \
             today's code resolves by",
        );

        let bytes = dht
            .get_local(&rendezvous_ad_dht_key(&out.node_id))
            .expect("an ad at the IDENTITY address");
        let ad = decode_rendezvous_ad(&bytes).expect("decode");
        assert_eq!(ad.receiver_node_id, out.node_id);
        assert!(
            verify_rendezvous_ad(&ad).is_err(),
            "the strict binding cannot hold here — if it does, the fixture is \
             not the case this is about",
        );

        // Control FIRST: with no document to read, the ad is refused.
        assert!(
            !ad_binding_ok(&dht, &ad),
            "without the identity document there is no binding to check",
        );

        // And with the document the identity itself published, it is admitted.
        dht.store_local(
            veil_proto::identity_document::IdentityDocument::dht_key(&out.node_id),
            out.document.encode(),
        );
        assert!(
            ad_binding_ok(&dht, &ad),
            "the document names this device key, which is what ties it to the \
             address",
        );

        // A LOCATION-ANONYMOUS entry does not gain an address. Its ad is keyed
        // and signed under a per-service PSEUDO identity, so publishing for two
        // addresses still produces ONE ad, at that pseudo key and nowhere else.
        //
        // This documents the shape rather than guarding it: the skip in
        // `publish_rendezvous_ads_at` saves the second pass some work, and
        // removing it changes nothing here, because the second pass would find
        // its own ad fresh. What keeps the pseudo identity unlinked is the key,
        // not the skip.
        {
            use veil_anonymity::rendezvous::EphemeralAdIdentity;
            let eph_sk = ed25519_dalek::SigningKey::from_bytes(&[0x5E; 32]);
            let eph_pk = eph_sk.verifying_key().to_bytes();
            let pseudo = *blake3::hash(&eph_pk).as_bytes();
            let eph_entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
                rendezvous_node_id: [0xCC; 32],
                auth_cookie: [0xDD; 16],
                validity_window_secs: 3600,
                push_envelope: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: Vec::new(),
                ephemeral_ad_identity: Some(EphemeralAdIdentity {
                    pseudo_node_id: pseudo,
                    public_key: base64::engine::general_purpose::STANDARD.encode(eph_pk),
                    private_key: zeroize::Zeroizing::new(
                        base64::engine::general_purpose::STANDARD.encode(eph_sk.to_bytes()),
                    ),
                    algo: veil_cfg::SignatureAlgorithm::Ed25519,
                }),
                rendezvous_kem_valid_until_unix: 0,
            }]));
            let fresh = Arc::new(veil_dht::KademliaService::new(
                *device_identity.node_id.as_bytes(),
            ));
            // The identity pass FIRST, on an empty store: a second pass over a
            // store that already holds the ad publishes nothing anyway, because
            // the freshness probe skips it — so this order is what makes the
            // assertion about the guard rather than about freshness.
            assert_eq!(
                crate::runtime::NodeRuntime::tick_publish_rendezvous_ads(
                    &eph_entries,
                    &x25519_sk,
                    &device_identity,
                    &cell,
                    &fresh,
                    &logger,
                    None,
                ),
                1,
                "ONE, not two: the ordinary entry above went up at both \
                 addresses, but a location-anonymous ad has only its pseudo \
                 key to go to",
            );
            assert!(
                fresh
                    .get_local(&rendezvous_ad_dht_key(&out.node_id))
                    .is_none(),
                "nothing may be written at the identity address for a \
                 location-anonymous entry — the pseudo identity exists so the \
                 ad is NOT linked to it",
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two devices of ONE identity do not fight over its slots.
    ///
    /// Both advertise at the identity's address under the same keys, and
    /// replication hands each the other's write. Each used to call the
    /// sibling's ad stale and re-sign — measured on the stand as strict
    /// turns, about a write a second from each device, forever. A fresh ad
    /// the identity's document vouches for is left in place.
    ///
    /// Control FIRST: with no document to vouch for the sibling, the same ad
    /// is overwritten — a slot held by something we cannot verify is not
    /// held.
    #[test]
    fn a_sibling_devices_fresh_ad_is_not_overwritten() {
        use std::sync::{Arc, Mutex};

        let dir = std::env::temp_dir().join(format!(
            "rzv-sibling-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let created = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rzv".to_string(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .expect("create_identity");
        // A second device key, certified into the same document; the first
        // stays valid beside it.
        let rotated = veil_identity::sovereign_flow::rotate_identity(
            veil_identity::sovereign_flow::RotateIdentityOptions {
                veil_dir: dir.clone(),
                master_seed: created.master_seed.clone(),
                now_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
            },
        )
        .expect("rotate_identity");
        let identity = created.node_id;

        let handshake = |seed: [u8; 32]| {
            let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            let public_key = base64::engine::general_purpose::STANDARD.encode(pk);
            crate::local_identity::HandshakeIdentity {
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                node_id: veil_cfg::NodeId::from_public_key(
                    veil_cfg::SignatureAlgorithm::Ed25519,
                    &public_key,
                )
                .unwrap(),
                public_key,
                private_key: base64::engine::general_purpose::STANDARD.encode(seed),
                nonce: "AAAA".to_owned(),
            }
        };
        let first = handshake(*created.identity_sk_seed.as_array());
        let second = handshake(*rotated.new_identity_sk_seed.as_array());
        assert_ne!(first.public_key, second.public_key, "fixture: two devices");

        let entries = |relay: u8, window: u64| {
            Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
                rendezvous_node_id: [relay; 32],
                auth_cookie: [relay; 16],
                validity_window_secs: window,
                push_envelope: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: Vec::new(),
                ephemeral_ad_identity: None,
                rendezvous_kem_valid_until_unix: 0,
            }]))
        };
        let logger = Arc::new(NodeLogger::new_noop());
        let x25519 = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let publish_for = |who: &crate::local_identity::HandshakeIdentity,
                           relay: u8,
                           window: u64,
                           dht: &Arc<veil_dht::KademliaService>| {
            crate::runtime::NodeRuntime::publish_rendezvous_ads_at(
                &entries(relay, window),
                &x25519,
                who,
                &identity,
                dht,
                &logger,
                None,
            )
        };
        let publish = |who: &crate::local_identity::HandshakeIdentity,
                       relay: u8,
                       dht: &Arc<veil_dht::KademliaService>| {
            publish_for(who, relay, 3600, dht)
        };
        let issuer_at = |dht: &Arc<veil_dht::KademliaService>| {
            decode_rendezvous_ad(&dht.get_local(&rendezvous_ad_dht_key(&identity)).unwrap())
                .unwrap()
                .issuer_pk
        };

        // Control: nothing vouches for the sibling, so its ad is overwritten.
        let bare = Arc::new(veil_dht::KademliaService::new(*first.node_id.as_bytes()));
        assert_eq!(
            publish(&second, 0xA1, &bare),
            1,
            "the sibling writes the slot"
        );
        assert_eq!(publish(&first, 0xB1, &bare), 1, "unvouched: overwritten");
        assert_eq!(issuer_at(&bare), first.public_key);

        // With the document both devices hold, the sibling keeps the slot.
        let dht = Arc::new(veil_dht::KademliaService::new(*first.node_id.as_bytes()));
        dht.store_local(
            veil_proto::identity_document::IdentityDocument::dht_key(&identity),
            rotated.document.encode(),
        );
        assert_eq!(
            publish(&second, 0xA1, &dht),
            1,
            "the sibling writes the slot"
        );
        assert_eq!(
            publish(&first, 0xB1, &dht),
            0,
            "a fresh ad of another device of this identity is left in place"
        );
        assert_eq!(issuer_at(&dht), second.public_key);
        assert_eq!(
            publish(&second, 0xA1, &dht),
            0,
            "and the holder, finding its own ad fresh, writes nothing either"
        );

        // A holder that stops refreshing does not keep the slot: past half its
        // window the sibling's ad is due, and another device takes over rather
        // than leaving the identity advertised at a device that went quiet.
        let aging = Arc::new(veil_dht::KademliaService::new(*first.node_id.as_bytes()));
        aging.store_local(
            veil_proto::identity_document::IdentityDocument::dht_key(&identity),
            rotated.document.encode(),
        );
        assert_eq!(publish_for(&second, 0xA2, 2, &aging), 1);
        let written =
            decode_rendezvous_ad(&aging.get_local(&rendezvous_ad_dht_key(&identity)).unwrap())
                .unwrap()
                .valid_from_unix;
        while std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < written + 1
        {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(
            publish(&first, 0xB2, &aging),
            1,
            "a sibling ad past half its window is taken over"
        );
        assert_eq!(issuer_at(&aging), first.public_key);
    }
}
