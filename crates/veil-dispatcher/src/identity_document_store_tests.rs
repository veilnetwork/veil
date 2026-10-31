//! Replica refreshes must not erase signed device revocations.
use super::*;
use ed25519_dalek::Signer;
use veil_proto::identity_document::{
    ALGO_ED25519, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey, RevokedDevice,
};

fn document(issued: u64, revoked: bool) -> IdentityDocument {
    let master = SigningKey::from_bytes(&[3; 32]);
    let device = SigningKey::from_bytes(&[4; 32]);
    let master_pk = master.verifying_key().to_bytes();
    let pk = device.verifying_key().to_bytes();
    let node_id = *blake3::hash(&master_pk).as_bytes();
    let device_id = *blake3::hash(&pk).as_bytes();
    let expires = veil_util::unix_secs_now_u64() + 3600;
    let mut doc = IdentityDocument {
        node_id,
        master_algo: ALGO_ED25519,
        master_pubkey: master_pk.to_vec(),
        issued_at_unix: issued,
        valid_until_unix: expires,
        sig_key_idx: 0,
        identity_keys: vec![IdentityKey {
            algo: ALGO_ED25519,
            pubkey: pk.to_vec(),
            device_id,
            valid_from_unix: 1,
            valid_until_unix: expires,
            master_sig: master
                .sign(&veil_crypto::identity::certify_message(
                    &node_id,
                    ALGO_ED25519,
                    &pk,
                    &device_id,
                    1,
                    expires,
                ))
                .to_bytes()
                .to_vec(),
        }],
        revoked_devices: if revoked {
            vec![RevokedDevice {
                device_id: [5; 32],
                master_sig: master
                    .sign(&RevokedDevice::signing_message(&node_id, &[5; 32]))
                    .to_bytes()
                    .to_vec(),
            }]
        } else {
            vec![]
        },
        document_sig: vec![],
    };
    let mut signed = DOC_SIG_CONTEXT.to_vec();
    signed.extend(doc.canonical_signing_bytes());
    doc.document_sig = device.sign(&signed).to_bytes().to_vec();
    veil_identity::verify::verify_identity_document(&doc, veil_util::unix_secs_now_u64()).unwrap();
    doc
}

fn store(dispatcher: &FrameDispatcher, doc: &IdentityDocument, recursive: bool, query: u8) {
    let key = IdentityDocument::dht_key(&doc.node_id);
    let (header, body) = if recursive {
        (
            FrameHeader::new(
                FrameFamily::Routing as u8,
                RoutingMsg::RecursiveQuery as u16,
            ),
            veil_proto::routing::RecursiveQueryPayload {
                query_id: [query; 16],
                target_key: key,
                reply_to: [9; 32],
                ttl: 8,
                query_type: veil_proto::routing::recursive_query_type::STORE,
                reply_port: 0,
                payload: doc.encode(),
            }
            .encode(),
        )
    } else {
        (
            FrameHeader::new(
                FrameFamily::Discovery as u8,
                veil_proto::family::DiscoveryMsg::Store as u16,
            ),
            veil_proto::discovery::StorePayload::unsigned(key, doc.encode()).encode(),
        )
    };
    let result = dispatcher.dispatch(&header, &body, [9; 32]);
    assert!(
        !matches!(result, DispatchResult::Violation(_)),
        "{result:?}"
    );
}

fn stale_republish(recursive: bool) {
    let dispatcher = make_test_dispatcher(NodeRole::Core);
    let now = veil_util::unix_secs_now_u64();
    let current = document(now - 1, true);
    let stale = document(now - 2, false);
    let key = IdentityDocument::dht_key(&current.node_id);
    store(&dispatcher, &current, recursive, 1);
    assert_eq!(dispatcher.dht.get_local(&key), Some(current.encode()));
    store(&dispatcher, &stale, recursive, 2);
    assert_eq!(
        dispatcher.dht.get_local(&key),
        Some(current.encode()),
        "a stale republish erased the master-signed revocation"
    );
}

#[test]
fn direct_identity_republish_preserves_revocations() {
    stale_republish(false);
}

#[test]
fn recursive_identity_republish_preserves_revocations() {
    stale_republish(true);
}

#[test]
fn stored_revocation_revalidates_live_authorization_without_an_app_packet() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for recursive in [false, true] {
        let dispatcher = make_test_dispatcher(NodeRole::Core);
        let doc = document(veil_util::unix_secs_now_u64() - 1, true);
        let peer = doc.node_id;
        let key = IdentityDocument::dht_key(&peer);
        let expected = doc.encode();
        let dht = Arc::clone(&dispatcher.dht);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        *dispatcher.peer_cert_revalidate.lock().unwrap() = Some(Arc::new(move |identity| {
            assert_eq!(*identity, peer);
            assert_eq!(dht.get_local(&key).as_deref(), Some(expected.as_slice()));
            observed.fetch_add(1, Ordering::SeqCst);
        }));
        store(&dispatcher, &doc, recursive, 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a verified revocation left warm authorization unchanged until the next app packet"
        );
        let mut invalid = doc;
        invalid.document_sig[0] ^= 1;
        assert!(!dispatcher.store_discovery_value(key, invalid.encode(), peer));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "invalid bytes cannot trigger revalidation"
        );
    }
}

fn resign(doc: &mut IdentityDocument) {
    let mut signed = DOC_SIG_CONTEXT.to_vec();
    signed.extend(doc.canonical_signing_bytes());
    doc.document_sig = SigningKey::from_bytes(&[4; 32])
        .sign(&signed)
        .to_bytes()
        .to_vec();
}

#[test]
fn identity_mirror_cannot_erase_revocations_even_with_a_newer_timestamp() {
    let dispatcher = make_test_dispatcher(NodeRole::Core);
    let now = veil_util::unix_secs_now_u64();
    let current = document(now - 1, true);
    let stale = document(now, false);
    let key = IdentityDocument::dht_key(&current.node_id);
    dispatcher.mirror_discovery_value(key, current.encode());
    dispatcher.mirror_discovery_value(key, stale.encode());
    assert_eq!(dispatcher.dht.get_local(&key), Some(current.encode()));
    let refreshed = document(now, true);
    dispatcher.mirror_discovery_value(key, refreshed.encode());
    assert_eq!(dispatcher.dht.get_local(&key), Some(refreshed.encode()));
}

#[test]
fn expired_signed_identity_document_still_protects_its_revocations() {
    let dispatcher = make_test_dispatcher(NodeRole::Core);
    let now = veil_util::unix_secs_now_u64();
    let mut expired = document(now - 10, true);
    expired.valid_until_unix = now - 1;
    resign(&mut expired);
    let key = IdentityDocument::dht_key(&expired.node_id);
    dispatcher.dht.store_local(key, expired.encode());
    dispatcher.mirror_discovery_value(key, document(now, false).encode());
    assert_eq!(dispatcher.dht.get_local(&key), Some(expired.encode()));
}

#[test]
fn forged_identity_document_cannot_pin_or_replace_a_valid_replica() {
    let dispatcher = make_test_dispatcher(NodeRole::Core);
    let now = veil_util::unix_secs_now_u64();
    let valid = document(now - 1, false);
    let mut forged = document(now, true);
    forged.document_sig[0] ^= 1;
    let key = IdentityDocument::dht_key(&valid.node_id);
    // A corrupt shard is repairable: unverified tombstones have no authority.
    dispatcher.dht.store_local(key, forged.encode());
    dispatcher.mirror_discovery_value(key, valid.encode());
    assert_eq!(dispatcher.dht.get_local(&key), Some(valid.encode()));
    // The same forgery cannot displace the repaired document.
    dispatcher.mirror_discovery_value(key, forged.encode());
    assert_eq!(dispatcher.dht.get_local(&key), Some(valid.encode()));
}
