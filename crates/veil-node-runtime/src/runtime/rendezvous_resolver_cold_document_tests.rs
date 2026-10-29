//! A sender must resolve delegation before trusting an identity-addressed ad.
use super::*;
use base64::Engine as _;
use std::sync::{Mutex, RwLock};
use veil_anonymity::rendezvous::{
    decode_rendezvous_ad, rendezvous_ad_dht_key, sign_rendezvous_ad_v5,
};
use veil_proto::{identity_document::IdentityDocument, routing::RecursiveQueryPayload};

#[tokio::test]
async fn mailbox_only_stream_cache_rechecks_once_for_concurrent_waiters() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use veil_anonymity::rendezvous::{MAX_RENDEZVOUS_AD_SLOTS, rendezvous_ad_dht_key_at};
    let me = [0x11; 32];
    let key = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
    let public = base64::engine::general_purpose::STANDARD
        .decode(&key.public_key)
        .unwrap();
    let receiver = *blake3::hash(&public).as_bytes();
    let mailbox = crate::NodeServices::mailbox_rendezvous_cookie(&receiver);
    let identity_mailbox = [0x42; 16];
    let stream_cookie = [0x53; 16];
    let now = veil_util::unix_secs_now_u64();
    let make_ad = |cookie, relay| {
        sign_rendezvous_ad_v5(
            receiver,
            [relay; 32],
            cookie,
            [0x33; 32],
            now,
            now + 3600,
            &[],
            &[],
            &[],
            0,
            &[],
            &key.public_key,
            &key.private_key,
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap()
    };
    let values = Arc::new(Mutex::new(std::collections::HashMap::from([
        (
            rendezvous_ad_dht_key_at(&receiver, 0),
            make_ad(mailbox, 0x71),
        ),
        (
            rendezvous_ad_dht_key_at(&receiver, 1),
            make_ad(identity_mailbox, 0x72),
        ),
    ])));
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0xAA; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 16],
        veil_dispatcher::PendingRecursive,
    >::new()));
    let queries = Arc::new(AtomicUsize::new(0));
    let replies = tokio::spawn({
        let pending = pending.clone();
        let queries = queries.clone();
        let values = values.clone();
        async move {
            while let Some((_, frame)) = rx.recv().await {
                let query =
                    RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
                queries.fetch_add(1, Ordering::Relaxed);
                let bytes = lock!(values)
                    .get(&query.target_key)
                    .cloned()
                    .unwrap_or_default();
                let waiter = lock!(pending).remove(&query.query_id).unwrap();
                let _ = waiter.tx.send(bytes);
            }
        }
    });
    let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let mode = ResolveMode::Stream {
        mailbox_cookie: mailbox,
        identity_mailbox_cookie: Some(identity_mailbox),
    };
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    let lookup = || {
        resolve_fresh_rendezvous_ads(
            &dht,
            &registry,
            &pending,
            me,
            &cache,
            &logger,
            receiver,
            std::time::Duration::from_secs(1),
            mode,
            &authorization,
        )
    };
    let initial = lookup().await;
    assert_eq!(initial.len(), 2);
    let first_queries = queries.load(Ordering::Relaxed);
    assert_eq!(first_queries, MAX_RENDEZVOUS_AD_SLOTS as usize);
    lock!(values).insert(
        rendezvous_ad_dht_key_at(&receiver, 2),
        make_ad(stream_cookie, 0x73),
    );
    for _ in 0..8 {
        assert_eq!(lookup().await.len(), 2);
    }
    assert_eq!(
        queries.load(Ordering::Relaxed),
        first_queries,
        "a recently resolved miss caused one network walk per caller"
    );
    assert_eq!(
        cache.get(&receiver, now).unwrap().len(),
        2,
        "the ordinary mailbox cache must remain usable"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let results = futures::future::join_all((0..8).map(|_| lookup())).await;
    let total_queries = queries.load(Ordering::Relaxed);
    replies.abort();
    assert!(replies.await.unwrap_err().is_cancelled());
    assert!(lock!(pending).is_empty());
    assert!(
        results
            .iter()
            .all(|ads| ads.iter().any(|ad| ad.auth_cookie == stream_cookie)),
        "a mailbox cookie, including the identity's cookie at a device address, hid the stream ad"
    );
    assert_eq!(
        total_queries,
        first_queries * 2,
        "concurrent waiters must share one refreshing slot walk"
    );
    assert_eq!(cache.get(&receiver, now).unwrap().len(), 3);
}

struct IdentityFixture {
    dir: std::path::PathBuf,
    document: IdentityDocument,
    pk: String,
    sk: String,
}

#[tokio::test]
async fn unknown_sender_prefetches_document_before_other_ad_replicas_finish() {
    check_unknown_document_prefetch(false).await;
}

#[tokio::test]
async fn cancelling_unknown_document_prefetch_releases_pending_queries() {
    check_unknown_document_prefetch(true).await;
}

async fn check_unknown_document_prefetch(cancel: bool) {
    use std::future::Future;
    let identity = IdentityFixture::new();
    let receiver = identity.document.node_id;
    let ad = identity.ad(receiver);
    assert!(
        veil_anonymity::rendezvous::verify_rendezvous_ad(&decode_rendezvous_ad(&ad).unwrap())
            .is_err()
    );
    let me = [0x11; 32];
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0xAA; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 16],
        veil_dispatcher::PendingRecursive,
    >::new()));
    let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    let mut lookup = Box::pin(resolve_fresh_rendezvous_ads(
        &dht,
        &registry,
        &pending,
        me,
        &cache,
        &logger,
        receiver,
        std::time::Duration::from_secs(60),
        ResolveMode::Stream {
            mailbox_cookie: crate::NodeServices::mailbox_rendezvous_cookie(&receiver),
            identity_mailbox_cookie: None,
        },
        &authorization,
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(lookup.as_mut().poll(&mut cx).is_pending());
    let mut ad_queries = Vec::new();
    while let Ok((_, frame)) = rx.try_recv() {
        ad_queries.push(RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap());
    }
    assert_eq!(
        ad_queries.len(),
        veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS as usize
    );
    let first = ad_queries
        .iter()
        .find(|q| q.target_key == rendezvous_ad_dht_key(&receiver))
        .unwrap();
    lock!(pending)
        .remove(&first.query_id)
        .unwrap()
        .tx
        .send(ad)
        .unwrap();
    assert!(lookup.as_mut().poll(&mut cx).is_pending());
    let document_query = rx.try_recv().ok().map(|(_, frame)| {
        RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap()
    });
    let early = document_query
        .as_ref()
        .is_some_and(|q| q.target_key == IdentityDocument::dht_key(&receiver));
    if !early {
        drop(lookup);
        assert!(lock!(pending).is_empty());
        panic!("a delegated ad arrived but the document walk still waits for unrelated ad replies");
    }
    let query = document_query.unwrap();
    if cancel {
        drop(lookup);
        assert!(lock!(pending).is_empty());
        assert!(authorization.current(&receiver).is_none());
        assert!(
            cache
                .get(&receiver, veil_util::unix_secs_now_u64())
                .is_none()
        );
        return;
    }
    lock!(pending)
        .remove(&query.query_id)
        .unwrap()
        .tx
        .send(identity.document.encode())
        .unwrap();
    assert!(lookup.as_mut().poll(&mut cx).is_pending());
    // The resolver itself must not publish or authorize the prefetched raw
    // bytes before all ad comparisons and its durable authorization barrier.
    // Replies here use pending channels, not Dispatcher transport mirroring.
    assert!(authorization.current(&receiver).is_none());
    assert!(
        dht.get_local(&IdentityDocument::dht_key(&receiver))
            .is_none()
    );
    assert!(dht.get_local(&rendezvous_ad_dht_key(&receiver)).is_none());
    assert!(
        cache
            .get(&receiver, veil_util::unix_secs_now_u64())
            .is_none()
    );
    for query in ad_queries {
        if let Some(p) = lock!(pending).remove(&query.query_id) {
            let _ = p.tx.send(Vec::new());
        }
    }
    let ads = lookup.await;
    assert_eq!(ads.len(), 1);
    assert!(authorization.current(&receiver).is_some());
    assert!(lock!(pending).is_empty());
}

impl IdentityFixture {
    fn new() -> Self {
        let now = veil_util::unix_secs_now_u64();
        let dir = std::env::temp_dir().join(format!(
            "rzv-cold-doc-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = veil_identity::sovereign_flow::create_identity(
            veil_identity::sovereign_flow::CreateIdentityOptions {
                veil_dir: dir.clone(),
                save_encrypted_with_password: None,
                argon2_params_override: Some((8, 1, 1)),
                extra_entropy: None,
                instance_label: "rendezvous cold lookup".to_owned(),
                pow_difficulty: 0,
                issued_at_unix: now,
                valid_until_unix: now + 7 * 24 * 3600,
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
        )
        .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(out.identity_sk_seed.as_array());
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            dir,
            document: out.document,
            pk: b64.encode(key.verifying_key().to_bytes()),
            sk: b64.encode(key.to_bytes()),
        }
    }

    fn ad(&self, receiver: [u8; 32]) -> Vec<u8> {
        let now = veil_util::unix_secs_now_u64();
        sign_rendezvous_ad_v5(
            receiver,
            [0xCC; 32],
            [0xDD; 16],
            [0x33; 32],
            now,
            now + 3600,
            &[],
            &[],
            &[],
            0,
            &[],
            &self.pk,
            &self.sk,
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap()
    }
}

impl Drop for IdentityFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn lookup(
    receiver: [u8; 32],
    ad: Vec<u8>,
    document: Option<Vec<u8>>,
) -> (
    Vec<veil_anonymity::rendezvous::RendezvousAd>,
    Vec<[u8; 32]>,
    Arc<veil_dht::KademliaService>,
) {
    let me = [0x11; 32];
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let ad_key = rendezvous_ad_dht_key(&receiver);
    let doc_key = IdentityDocument::dht_key(&receiver);
    assert!(
        dht.get_local(&doc_key).is_none(),
        "cold sender holds no delegation"
    );
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0xAA; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 16],
        veil_dispatcher::PendingRecursive,
    >::new()));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let replies = tokio::spawn({
        let pending = Arc::clone(&pending);
        let seen = Arc::clone(&seen);
        async move {
            while let Some((_, frame)) = rx.recv().await {
                let query =
                    RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
                lock!(seen).push(query.target_key);
                let value = if query.target_key == ad_key {
                    ad.clone()
                } else if query.target_key == doc_key {
                    document.clone().unwrap_or_default()
                } else {
                    Vec::new()
                };
                let waiter = lock!(pending).remove(&query.query_id).unwrap();
                let _ = waiter.tx.send(value);
            }
        }
    });
    let ads = resolve_fresh_rendezvous_ads(
        &dht,
        &registry,
        &pending,
        me,
        &Arc::new(super::super::anonymity_state::RendezvousResolveCache::new()),
        &Arc::new(veil_observability::NodeLogger::new_noop()),
        receiver,
        std::time::Duration::from_secs(1),
        ResolveMode::Any,
        &crate::identity_document_floor::IdentityDocumentFloor::ephemeral(),
    )
    .await;
    replies.abort();
    assert!(replies.await.unwrap_err().is_cancelled());
    assert!(lock!(pending).is_empty(), "no leaked recursive lookups");
    let queries = lock!(seen).clone();
    (ads, queries, dht)
}

#[tokio::test]
async fn cold_sender_resolves_document_before_accepting_delegated_rendezvous() {
    let receiver = IdentityFixture::new();
    let id = receiver.document.node_id;
    let ad = receiver.ad(id);
    assert!(
        veil_anonymity::rendezvous::verify_rendezvous_ad(&decode_rendezvous_ad(&ad).unwrap())
            .is_err(),
        "identity and device addresses must differ"
    );
    let (ads, queries, dht) = lookup(id, ad, Some(receiver.document.encode())).await;
    assert_eq!(
        ads.len(),
        1,
        "a cold sender must fetch the identity document to verify the receiver's device-signed ad"
    );
    assert_eq!(ads[0].receiver_node_id, id);
    assert!(
        queries.contains(&IdentityDocument::dht_key(&id)),
        "the document must actually be requested"
    );
    assert!(
        dht.get_local(&IdentityDocument::dht_key(&id)).is_some(),
        "verified delegation is cached"
    );
}

#[tokio::test]
async fn cold_sender_never_admits_unproven_delegated_rendezvous() {
    let receiver = IdentityFixture::new();
    let other = IdentityFixture::new();
    let id = receiver.document.node_id;
    let mut broken_document = receiver.document.encode();
    broken_document[0] ^= 0x80;
    let mut broken_ad = receiver.ad(id);
    *broken_ad.last_mut().unwrap() ^= 1;
    let cases = [
        ("missing document", receiver.ad(id), None),
        ("broken document", receiver.ad(id), Some(broken_document)),
        (
            "foreign document",
            receiver.ad(id),
            Some(other.document.encode()),
        ),
        (
            "unauthorized signer",
            other.ad(id),
            Some(receiver.document.encode()),
        ),
        (
            "broken signature",
            broken_ad,
            Some(receiver.document.encode()),
        ),
    ];
    for (name, ad, doc) in cases {
        let (ads, _, dht) = lookup(id, ad, doc).await;
        assert!(ads.is_empty(), "{name} must not establish a route");
        assert!(
            dht.get_local(&rendezvous_ad_dht_key(&id)).is_none(),
            "{name}: an unverified ad must not enter the mirror"
        );
    }
}

#[tokio::test]
async fn strict_rendezvous_does_not_require_a_document_walk() {
    let receiver = IdentityFixture::new();
    let key = base64::engine::general_purpose::STANDARD
        .decode(&receiver.pk)
        .unwrap();
    let id = *blake3::hash(&key).as_bytes();
    let (ads, queries, _) = lookup(id, receiver.ad(id), None).await;
    assert_eq!(ads.len(), 1);
    assert!(
        !queries.contains(&IdentityDocument::dht_key(&id)),
        "a self-bound ad must not wait on a missing document"
    );
}

async fn parallel_document_fixture(mode: ResolveMode, known: bool) {
    use tokio::sync::oneshot;
    let identity = IdentityFixture::new();
    let receiver = identity.document.node_id;
    let me = [0x51; 32];
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let ad_key = rendezvous_ad_dht_key(&receiver);
    let doc_key = IdentityDocument::dht_key(&receiver);
    let ad = identity.ad(receiver);
    let document = identity.document.encode();
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0x52; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 16],
        veil_dispatcher::PendingRecursive,
    >::new()));
    let replies = tokio::spawn({
        let pending = Arc::clone(&pending);
        async move {
            let mut held: Vec<(oneshot::Sender<Vec<u8>>, Vec<u8>)> = Vec::new();
            let mut doc_seen = false;
            while let Some((_, frame)) = rx.recv().await {
                let query =
                    RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
                let Some(waiter) = lock!(pending).remove(&query.query_id) else {
                    continue;
                };
                if query.target_key == doc_key {
                    doc_seen = true;
                    let _ = waiter.tx.send(document.clone());
                    for (tx, bytes) in held.drain(..) {
                        let _ = tx.send(bytes);
                    }
                } else {
                    let bytes = if query.target_key == ad_key {
                        ad.clone()
                    } else {
                        Vec::new()
                    };
                    if doc_seen {
                        let _ = waiter.tx.send(bytes);
                    } else {
                        held.push((waiter.tx, bytes));
                    }
                }
            }
        }
    });
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    if known {
        assert!(authorization.observe(&identity.document, veil_util::unix_secs_now_u64()));
    }
    let ads = resolve_fresh_rendezvous_ads(
        &dht,
        &registry,
        &pending,
        me,
        &Arc::new(super::super::anonymity_state::RendezvousResolveCache::new()),
        &Arc::new(veil_observability::NodeLogger::new_noop()),
        receiver,
        std::time::Duration::from_millis(300),
        mode,
        &authorization,
    )
    .await;
    replies.abort();
    assert!(replies.await.unwrap_err().is_cancelled());
    assert!(lock!(pending).is_empty());
    assert_eq!(
        ads.len(),
        1,
        "a family lookup must request the document while ad replies are still pending"
    );
}

#[tokio::test]
async fn family_document_lookup_does_not_wait_for_advertisement_replies() {
    parallel_document_fixture(ResolveMode::ChatFamily, false).await;
}

#[tokio::test]
async fn delegated_background_refresh_does_not_serialize_document_and_ad_lookups() {
    parallel_document_fixture(ResolveMode::RefreshAhead, true).await;
}

#[test]
fn generic_ad_cache_is_not_evidence_of_a_completed_family_document_lookup() {
    let identity = IdentityFixture::new();
    let receiver = identity.document.node_id;
    let now = veil_util::unix_secs_now_u64();
    let dht = Arc::new(veil_dht::KademliaService::new([0x53; 32]));
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    assert!(authorization.observe(&identity.document, now));
    let cache = super::super::anonymity_state::RendezvousResolveCache::new();
    cache.put(
        receiver,
        vec![decode_rendezvous_ad(&identity.ad(receiver)).unwrap()],
    );
    assert!(
        ResolveMode::Any
            .cached_ads(&cache, &receiver, now, &dht, &authorization)
            .is_some()
    );
    assert!(
        ResolveMode::ChatFamily
            .cached_ads(&cache, &receiver, now, &dht, &authorization)
            .is_none(),
        "an ordinary cached ad may have been checked without refreshing the list of devices"
    );
}

#[tokio::test]
async fn known_device_routes_are_requested_before_the_family_lookup_finishes() {
    let identity = IdentityFixture::new();
    let receiver = identity.document.node_id;
    let device = identity.document.identity_keys[0].device_id;
    assert_ne!(receiver, device);
    let me = [0x61; 32];
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    assert!(authorization.observe(&identity.document, veil_util::unix_secs_now_u64()));
    let values = std::collections::HashMap::from([
        (rendezvous_ad_dht_key(&receiver), identity.ad(receiver)),
        (rendezvous_ad_dht_key(&device), identity.ad(device)),
        (
            IdentityDocument::dht_key(&receiver),
            identity.document.encode(),
        ),
    ]);
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0x62; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 16],
        veil_dispatcher::PendingRecursive,
    >::new()));
    let replies = tokio::spawn({
        let pending = pending.clone();
        async move {
            let mut held = Vec::<(tokio::sync::oneshot::Sender<Vec<u8>>, Vec<u8>)>::new();
            let mut device_requested = false;
            while let Some((_, frame)) = rx.recv().await {
                let q = RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
                let Some(waiter) = lock!(pending).remove(&q.query_id) else {
                    continue;
                };
                let bytes = values.get(&q.target_key).cloned().unwrap_or_default();
                if q.target_key == rendezvous_ad_dht_key(&device) {
                    device_requested = true;
                    let _ = waiter.tx.send(bytes);
                    for (tx, bytes) in held.drain(..) {
                        let _ = tx.send(bytes);
                    }
                } else if device_requested {
                    let _ = waiter.tx.send(bytes);
                } else {
                    held.push((waiter.tx, bytes));
                }
            }
        }
    });
    let timeout = std::time::Duration::from_millis(300);
    let count = send_with_family_route_prefetch(
        &dht,
        &registry,
        &pending,
        me,
        &cache,
        &logger,
        receiver,
        timeout,
        &authorization,
        async {
            let ads = resolve_fresh_rendezvous_ads(
                &dht,
                &registry,
                &pending,
                me,
                &cache,
                &logger,
                receiver,
                timeout,
                ResolveMode::ChatFamily,
                &authorization,
            )
            .await;
            ads.len()
        },
    )
    .await;
    replies.abort();
    assert!(replies.await.unwrap_err().is_cancelled());
    assert!(lock!(pending).is_empty());
    assert_eq!(
        count, 1,
        "the serial family lookup expired before the known device was queried"
    );
    assert!(
        !cache
            .refresh_candidates(
                std::time::Duration::from_secs(300),
                std::time::Duration::from_secs(60),
            )
            .contains(&device),
        "a speculative route lookup enrolled an unused device in refresh-ahead",
    );
}

async fn check_prefetch_cancellation(known: bool, family_cached: bool) {
    let identity = IdentityFixture::new();
    let receiver = identity.document.node_id;
    let device = identity.document.identity_keys[0].device_id;
    let me = [0x63; 32];
    let dht = Arc::new(veil_dht::KademliaService::new(me));
    let cache = Arc::new(super::super::anonymity_state::RendezvousResolveCache::new());
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let authorization = crate::identity_document_floor::IdentityDocumentFloor::ephemeral();
    if known {
        assert!(authorization.observe(&identity.document, veil_util::unix_secs_now_u64()));
    }
    if family_cached {
        cache.put_with_document_check(
            receiver,
            vec![decode_rendezvous_ad(&identity.ad(receiver)).unwrap()],
            true,
        );
    }
    let mut reg = veil_session::SessionTxRegistry::new();
    let mut rx = reg.register([0x64; 32]);
    let registry = Arc::new(RwLock::new(reg));
    let pending = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let (finish, finished) = tokio::sync::oneshot::channel();
    let mut send = Box::pin(send_with_family_route_prefetch(
        &dht,
        &registry,
        &pending,
        me,
        &cache,
        &logger,
        receiver,
        std::time::Duration::from_secs(60),
        &authorization,
        async {
            finished.await.unwrap();
            17
        },
    ));
    assert!(futures::poll!(send.as_mut()).is_pending());
    if known && !family_cached {
        assert!(
            rx.try_recv().is_ok(),
            "a real speculative lookup must be in flight"
        );
        assert!(!lock!(pending).is_empty());
    } else {
        assert!(
            rx.try_recv().is_err(),
            "unknown devices must not be guessed or queried"
        );
        assert!(lock!(pending).is_empty());
    }
    finish.send(()).unwrap();
    assert!(
        matches!(futures::poll!(send.as_mut()), std::task::Poll::Ready(17)),
        "a finished send was held behind the unanswered speculative lookup"
    );
    assert!(lock!(pending).is_empty());
    assert!(
        cache
            .refresh_candidates(
                std::time::Duration::from_secs(300),
                std::time::Duration::from_secs(60),
            )
            .is_empty(),
        "prefetch must not keep the background refresher active"
    );
    let mut guard = Box::pin(cache.lock_refresh(device));
    assert!(
        futures::poll!(guard.as_mut()).is_ready(),
        "prefetch retained a cache lock"
    );
}

#[tokio::test]
async fn completed_send_cancels_slow_prefetch_and_releases_all_query_state() {
    check_prefetch_cancellation(true, false).await;
}

#[tokio::test]
async fn unknown_family_does_not_launch_speculative_device_queries() {
    check_prefetch_cancellation(false, false).await;
}

#[tokio::test]
async fn a_fresh_family_cache_needs_no_additional_speculative_reads() {
    check_prefetch_cancellation(true, true).await;
}
