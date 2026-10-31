//! DHT-backed [`IdentityPublisher`] adapter.
//!
//! The library layer ([`publish_full_identity`]) takes an abstract
//! [`IdentityPublisher`]; this module supplies the concrete adapter
//! that writes into the production Kademlia DHT.
//!
//! ## Replication behaviour
//!
//! `put` first writes locally [`KademliaService::store_local`]
//! so the publisher is always queryable for its own values, then —
//! when wired with a [`FrameBroadcaster`] + the local `node_id` —
//! fans the value out to [`DHT_REPLICATION_K`] closest peers in
//! keyspace as a `RecursiveQuery(STORE)`. Without the fan-out a
//! node going offline takes its `IdentityDocument` / `NameClaim`
//! with it as soon as foreign route-cache TTLs expire — failure
//! mode is anti-censorship-resistance, since the user disappears
//! from the public namespace the moment their phone screen locks.
//!
//! Best-effort: per-replica failures are silent at the per-frame level
//! (the design is fire-and-forget — synchronous STORE-acks would make
//! re-publish O(RTT × K) and create a DoS amplifier on slow peers).
//! The periodic re-replication tick lives at
//! [`crate::node::runtime::dht_republish::spawn_dht_republish_task`]:
//! every TTL/2 (≈ 30 min default) it walks the local store, filters
//! to self-authenticating record types only, and re-fan-outs to the
//! current K closest peers — so a peer that was unreachable at
//! original publish time picks up the record on the next tick once
//! it comes back online. audit follow-up wired
//! `veil_replicas_published_total` (per-tick fan-out total) plus
//! `veil_replicas_under_count_total` (under-replicated key alert)
//! counters so an operator can detect "records aren't propagating"
//! before they actually disappear.
//!
//! ## Why a new file
//!
//! Keeping the DHT-specific adapter separate from the library
//! layer (`publish.rs`) means the library module stays
//! transport-free and the adapter can evolve (add retry logic
//! quota checks, anti-eclipse safeguards) without touching the
//! signing side.
//!
//! [`publish_full_identity`]: super::publish::publish_full_identity
//! [`IdentityPublisher`]: super::publish::IdentityPublisher
//! [`KademliaService::store_local`]: veil_dht::KademliaService::store_local
//! [`FrameBroadcaster`]: veil_types::FrameBroadcaster
//! [`DHT_REPLICATION_K`]: veil_proto::budget::DHT_REPLICATION_K

use std::sync::{Arc, Mutex, RwLock};

mod placement;

use async_trait::async_trait;

use veil_dht::KademliaService;
use veil_session::tx_registry::SessionTxRegistry;

use veil_identity::publish::{IdentityPublisher, PublishIoError};

/// Thin [`IdentityPublisher`] impl that routes put operations into
/// the production Kademlia DHT shard *and* replicates them to the
/// K closest peers via `RecursiveQuery(STORE)` so the value
/// survives the publisher going offline.
///
/// Wrapped [`Arc`] because the dispatcher / runtime holds one
/// and shares it with the publish orchestrator + the per-name
/// republish ticks.
pub struct DhtBackedPublisher {
    dht: Arc<KademliaService>,
    /// Session-tx registry used to fan replication out to the K
    /// closest peers in keyspace. Optional because the very first
    /// boot-time publish runs before any sessions are up — local
    /// store still works, replication is a no-op until peers exist.
    /// The periodic republish tick re-runs publish at every
    /// republish_interval, so missed-replica updates catch up.
    session_tx_registry: Option<Arc<RwLock<SessionTxRegistry>>>,
    /// Local node_id — used as the `reply_to` field of the STORE
    /// recursive query and as the self-skip filter so we don't try
    /// to STORE-fan-out to ourselves.
    local_node_id: [u8; 32],
    placement: Option<Mutex<placement::PlacementTracker>>,
}

impl DhtBackedPublisher {
    /// Construct a publisher that writes locally only. Suitable for
    /// the very first boot-time publish (no peers yet) and for
    /// unit tests that don't exercise the network path.
    pub fn new(dht: Arc<KademliaService>) -> Self {
        Self {
            dht,
            session_tx_registry: None,
            local_node_id: [0u8; 32],
            placement: None,
        }
    }

    /// Construct a publisher that writes locally AND replicates to
    /// the K-closest peers via the supplied session_tx registry.
    /// Callers in `runtime/sovereign_republish.rs` use this on every
    /// tick; the very first publish in `runtime/mod.rs` uses the
    /// non-replicated `new` because peers don't exist yet.
    pub fn with_replication(
        dht: Arc<KademliaService>,
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        local_node_id: [u8; 32],
    ) -> Self {
        Self {
            dht,
            session_tx_registry: Some(session_tx_registry),
            local_node_id,
            placement: None,
        }
    }

    /// The sovereign maintenance task may repair placement without re-signing
    /// or re-sending the entire bundle to every unchanged neighbor.
    pub(crate) fn with_topology_replication(
        dht: Arc<KademliaService>,
        registry: Arc<RwLock<SessionTxRegistry>>,
        local: [u8; 32],
    ) -> Self {
        let mut publisher = Self::with_replication(dht, registry, local);
        publisher.placement = Some(Mutex::new(placement::PlacementTracker::default()));
        publisher
    }

    pub(crate) fn begin_bundle(&self) {
        if let Some(tracker) = &self.placement {
            tracker.lock().unwrap_or_else(|p| p.into_inner()).clear();
        }
    }

    pub(crate) fn reconcile_topology(&self) -> placement::PlacementReport {
        match (&self.placement, &self.session_tx_registry) {
            (Some(tracker), Some(registry)) => tracker
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .reconcile(&self.dht, registry, self.local_node_id),
            _ => placement::PlacementReport::default(),
        }
    }
}

#[async_trait]
impl IdentityPublisher for DhtBackedPublisher {
    /// Insert `value` at `dht_key` locally and — when a
    /// session-tx registry is configured — fan out a
    /// `RecursiveQuery(STORE)` to the K closest peers in keyspace.
    async fn put(&self, dht_key: [u8; 32], value: Vec<u8>) -> Result<(), PublishIoError> {
        // Local first — always succeeds.
        self.dht.store_local(dht_key, value.clone());

        // Replicate to the K-closest peers when a session-tx registry is wired
        // (no-op until peers exist). Delegated to the shared sync helper so the
        // rendezvous-ad maintenance publish replicates the same way.
        if let Some(ref tx_reg) = self.session_tx_registry {
            if let Some(tracker) = &self.placement
                && tracker.lock().unwrap_or_else(|p| p.into_inner()).publish(
                    dht_key,
                    &value,
                    &self.dht,
                    tx_reg,
                    self.local_node_id,
                )
            {
                return Ok(());
            }
            replicate_dht_value(&self.dht, tx_reg, self.local_node_id, dht_key, value);
        }
        Ok(())
    }
}

/// Fire-and-forget K-closest replication of `(dht_key, value)`: find the
/// `DHT_REPLICATION_K` closest peers in keyspace and send each a
/// `RecursiveQuery(STORE)`. Synchronous queue admission, with paced background
/// emission in the node's runtime; callers never wait for the network. Used by
/// [`DhtBackedPublisher::put`] and `NodeRuntime::tick_publish_rendezvous_ads`.
pub(crate) fn replicate_dht_value(
    dht: &Arc<KademliaService>,
    tx_reg: &Arc<RwLock<SessionTxRegistry>>,
    local_node_id: [u8; 32],
    dht_key: [u8; 32],
    value: Vec<u8>,
) {
    let candidates = replication_targets(dht, tx_reg, local_node_id, dht_key);
    if candidates.is_empty() {
        return;
    }
    let frame = encode_replication(local_node_id, dht_key, value);
    // Own best-effort records retain the same aggregate paced BACKGROUND
    // queue; interactive resolves and opaque relay transit are untouched.
    for peer in candidates {
        let _ = SessionTxRegistry::send_local_replication(tx_reg, peer, frame.clone());
    }
}

fn replication_targets(
    dht: &Arc<KademliaService>,
    tx_reg: &Arc<RwLock<SessionTxRegistry>>,
    local_node_id: [u8; 32],
    dht_key: [u8; 32],
) -> Vec<[u8; 32]> {
    let candidates_with_uri = dht
        .find_closest_with_transport(&dht_key, veil_proto::budget::DHT_REPLICATION_K)
        .into_iter()
        .filter(|(n, _)| *n != local_node_id)
        .collect::<Vec<_>>();
    // anti-eclipse safeguard: warn (but still replicate) if the K-closest set
    // has ≥2 IPv4 peers all sharing one /24 prefix (potential sybil cluster).
    let prefixes: Vec<Option<[u8; 3]>> = candidates_with_uri
        .iter()
        .map(|(_, uri)| extract_ipv4_prefix24(uri))
        .collect();
    let distinct_prefixes: std::collections::HashSet<[u8; 3]> =
        prefixes.iter().filter_map(|p| *p).collect();
    let total_v4 = prefixes.iter().filter(|p| p.is_some()).count();
    if total_v4 >= 2 && distinct_prefixes.len() <= 1 {
        log::warn!(
            target: "dht.replication.low_diversity",
            ".5 anti-eclipse: K-closest set for dht_key={} \
             has {} IPv4 peers all sharing one /24 prefix — \
             potential sybil cluster.  Replicating anyway, but \
             routing-table topology should be audited.",
            bytes_to_hex_short(&dht_key),
            total_v4,
        );
    }

    // The cold-table fallback must respect the same handshake preference as
    // closest-peer selection. Otherwise filling spare slots immediately puts
    // NO_DHT_SERVICE peers back into the publication set. Snapshot before the
    // TX-registry lock: never acquire the DHT lock while holding that lock.
    // Peers without capabilities are still eligible.
    let declined: std::collections::HashSet<_> = dht
        .routing_table_contacts()
        .into_iter()
        .filter(|contact| !contact.dht_service())
        .map(|contact| contact.node_id)
        .collect();
    let candidates = {
        let guard = tx_reg.read().unwrap_or_else(|p| p.into_inner());
        let mut candidates: Vec<[u8; 32]> = candidates_with_uri
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| !declined.contains(n) && guard.has_session(n))
            .collect();
        for peer in guard.peer_ids() {
            if candidates.len() >= veil_proto::budget::DHT_REPLICATION_K {
                break;
            }
            if peer != local_node_id && !declined.contains(&peer) && !candidates.contains(&peer) {
                candidates.push(peer);
            }
        }
        candidates
    };
    candidates
}

fn encode_replication(local_node_id: [u8; 32], dht_key: [u8; 32], value: Vec<u8>) -> Vec<u8> {
    // Build the RecursiveQuery(STORE) frame once.
    let query_id: [u8; 16] = {
        use rand_core::RngCore;
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);
        id
    };
    let q = veil_proto::routing::RecursiveQueryPayload {
        query_id,
        target_key: dht_key,
        reply_to: local_node_id,
        ttl: 40,
        query_type: veil_proto::routing::recursive_query_type::STORE,
        reply_port: 0,
        payload: value,
    };
    let q_bytes = q.encode();
    let mut hdr = veil_proto::header::FrameHeader::new(
        veil_proto::family::FrameFamily::Routing as u8,
        veil_proto::family::RoutingMsg::RecursiveQuery as u16,
    );
    hdr.body_len = q_bytes.len() as u32;
    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&q_bytes);

    frame
}

/// Notify connected verifiers of a document change, independently of which
/// nodes are closest to its DHT slot. A recursive STORE may forward elsewhere
/// without updating a leaf's local mirror; that leaves its warm certificate
/// cache accepting a device the owner has just revoked. Use the existing
/// direct STORE format and the bounded interactive TX queue. A revocation
/// notice is security control for an existing peer, not best-effort DHT
/// placement: the background publication queue can delay it for a minute or
/// refuse it behind unrelated records. Media retains its higher priority.
/// The receiver still verifies the document before changing authorization.
pub(crate) fn notify_live_identity_verifiers(
    registry: &Arc<RwLock<SessionTxRegistry>>,
    local_device: [u8; 32],
    document: &veil_proto::identity_document::IdentityDocument,
) -> usize {
    let body = veil_proto::discovery::StorePayload::unsigned(
        veil_proto::identity_document::IdentityDocument::dht_key(&document.node_id),
        document.encode(),
    )
    .encode();
    let mut header = veil_proto::header::FrameHeader::new(
        veil_proto::family::FrameFamily::Discovery as u8,
        veil_proto::family::DiscoveryMsg::Store as u16,
    );
    header.body_len = body.len() as u32;
    let mut frame = veil_proto::codec::encode_header(&header).to_vec();
    frame.extend_from_slice(&body);
    let peers = registry
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .peer_ids();
    peers
        .into_iter()
        .filter(|peer| *peer != local_device)
        .filter(|peer| {
            registry.read().unwrap_or_else(|p| p.into_inner()).send_to(
                peer,
                veil_proto::priority::INTERACTIVE,
                frame.clone(),
            )
        })
        .count()
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Pull the first 3 octets out of a transport URI's host part. Returns
/// `None` for `unix://`, IPv6, hostname-based URIs, or unparseable
/// inputs. IPv6 isn't covered by the /24 diversity check on purpose
/// — the trivially-grindable-prefix attack model is IPv4-specific
/// (cheap /24 control via a single hosting provider). IPv6 has a
/// different threat model (whole-/64-per-tenant) that needs its own
/// dedicated analysis; for now we just don't count IPv6 peers in the
/// denominator (`total_v4`) and the diversity check skips them.
fn extract_ipv4_prefix24(uri: &str) -> Option<[u8; 3]> {
    // Strip scheme: tcp://1.2.3.4:port → 1.2.3.4:port
    let after_scheme = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
    // Split host from port. Reject [...] (IPv6 bracketed form) cheaply
    // — the parse below would also reject it, but checking up-front
    // makes the fast path obvious.
    if after_scheme.starts_with('[') {
        return None;
    }
    let host = after_scheme.split(':').next().unwrap_or("");
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut out = [0u8; 3];
    for (i, oct) in octets.iter().take(3).enumerate() {
        out[i] = oct.parse::<u8>().ok()?;
    }
    Some(out)
}

/// Format the first 4 bytes of a 32-byte array as lowercase hex.
/// Matches the `hex_short` shape used everywhere else in routing logs.
fn bytes_to_hex_short(b: &[u8; 32]) -> String {
    veil_util::bytes_to_hex(&b[..4])
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use veil_dht::KademliaService;
    use veil_identity::publish::publish_identity_document;

    async fn fresh_kademlia() -> Arc<KademliaService> {
        let local_node_id = [0x01u8; 32];
        Arc::new(KademliaService::new(local_node_id))
    }

    #[test]
    fn extract_ipv4_prefix24_parses_canonical_tcp_uri() {
        assert_eq!(extract_ipv4_prefix24("tcp://1.2.3.4:9200"), Some([1, 2, 3]));
        assert_eq!(
            extract_ipv4_prefix24("tls://10.20.30.40:443"),
            Some([10, 20, 30])
        );
        assert_eq!(
            extract_ipv4_prefix24("ws://192.168.1.5:80"),
            Some([192, 168, 1])
        );
    }

    #[test]
    fn extract_ipv4_prefix24_rejects_non_ipv4_inputs() {
        // Bare hostnames return None — not an IP literal.
        assert_eq!(extract_ipv4_prefix24("tcp://example.com:9200"), None);
        // IPv6 bracketed form returns None — different threat model.
        assert_eq!(extract_ipv4_prefix24("tcp://[::1]:9200"), None);
        // Unix sockets have no IP at all.
        assert_eq!(extract_ipv4_prefix24("unix:///tmp/sock"), None);
        // Malformed input doesn't panic.
        assert_eq!(extract_ipv4_prefix24(""), None);
        assert_eq!(extract_ipv4_prefix24("garbage"), None);
        assert_eq!(extract_ipv4_prefix24("tcp://256.256.256.256:80"), None);
    }

    #[test]
    fn extract_ipv4_prefix24_groups_same_subnet() {
        let a = extract_ipv4_prefix24("tcp://10.0.0.1:9200").unwrap();
        let b = extract_ipv4_prefix24("tcp://10.0.0.99:9201").unwrap();
        let c = extract_ipv4_prefix24("tcp://10.0.1.1:9202").unwrap();
        assert_eq!(a, b, "same /24 → same prefix");
        assert_ne!(a, c, "different /24 → different prefix");
    }

    #[tokio::test]
    async fn document_update_reaches_connected_verifiers_beyond_the_closest_replica_set() {
        let document = crate::mlkem_cert_store::fixture::signer(0x31).doc;
        let mut registry = SessionTxRegistry::new();
        let mut receivers: Vec<_> = (2..(veil_proto::budget::DHT_REPLICATION_K + 4) as u8)
            .map(|id| registry.register([id; 32]))
            .collect();
        let registry = Arc::new(RwLock::new(registry));
        assert_eq!(
            notify_live_identity_verifiers(&registry, [1; 32], &document),
            receivers.len()
        );
        for receiver in &mut receivers {
            let (_, bytes) =
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .unwrap()
                    .unwrap();
            let header = veil_proto::codec::decode_header(&bytes).unwrap();
            assert_eq!(
                header.family,
                veil_proto::family::FrameFamily::Discovery as u8
            );
            assert_eq!(
                header.msg_type,
                veil_proto::family::DiscoveryMsg::Store as u16,
                "a recursive STORE could forward away without updating the verifier itself"
            );
            let stored =
                veil_proto::discovery::StorePayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                    .unwrap();
            assert_eq!(
                stored.key,
                veil_proto::identity_document::IdentityDocument::dht_key(&document.node_id)
            );
            assert_eq!(stored.value, document.encode());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn document_update_is_not_lost_behind_best_effort_replication() {
        let document = crate::mlkem_cert_store::fixture::signer(0x31).doc;
        let peer = [2; 32];
        let mut registry = SessionTxRegistry::new();
        let mut receiver = registry.register(peer);
        let registry = Arc::new(RwLock::new(registry));
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            peer,
            vec![0; 8192],
        ));
        // The first background record starts the pacing interval. Queue
        // enough unrelated publication behind it to exhaust admission; no
        // virtual time is advanced and no timing threshold is asserted.
        receiver.recv().await.unwrap();
        let mut queued = 0;
        while SessionTxRegistry::send_local_replication(&registry, peer, vec![0; 8192]) {
            queued += 1;
            assert!(queued <= 64);
        }
        assert!(queued > 0);
        assert_eq!(
            notify_live_identity_verifiers(&registry, [1; 32], &document),
            1
        );
        let (priority, frame) = receiver
            .try_recv()
            .expect("security update reaches the live TX queue");
        assert_eq!(priority, veil_proto::priority::INTERACTIVE);
        let payload =
            veil_proto::discovery::StorePayload::decode(&frame[veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(payload.value, document.encode());
    }

    #[tokio::test]
    async fn put_writes_value_to_local_store() {
        let dht = fresh_kademlia().await;
        let publisher = DhtBackedPublisher::new(Arc::clone(&dht));

        let key = [0xAA; 32];
        let value = b"hello dht".to_vec();
        publisher.put(key, value.clone()).await.unwrap();

        // The DHT's local lookup must now return the stored bytes.
        let got = dht.get_local(&key).expect("value stored locally");
        assert_eq!(got, value);
    }

    #[tokio::test(start_paused = true)]
    async fn live_replication_fallback_does_not_reintroduce_a_known_decliner() {
        let dht = fresh_kademlia().await;
        let quiet = [2; 32];
        let serving = [3; 32];
        let unknown = [4; 32];
        dht.add_contact_trusted(veil_dht::routing::Contact::with_caps(
            quiet,
            "tcp://quiet:9000",
            veil_types::DiscoveryMode::Public,
            false,
        ));
        dht.add_contact_trusted(veil_dht::routing::Contact::with_caps(
            serving,
            "tcp://serving:9000",
            veil_types::DiscoveryMode::Public,
            true,
        ));
        let mut registry = SessionTxRegistry::new();
        let receivers: Vec<_> = [quiet, serving, unknown]
            .into_iter()
            .map(|peer| (peer, registry.register(peer)))
            .collect();
        let publisher =
            DhtBackedPublisher::with_replication(dht, Arc::new(RwLock::new(registry)), [1; 32]);
        publisher.put([0xAA; 32], vec![0x42; 100]).await.unwrap();
        let mut waits = tokio::task::JoinSet::new();
        for (peer, mut receiver) in receivers {
            waits.spawn(async move {
                (
                    peer,
                    tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                        .await
                        .ok()
                        .flatten(),
                )
            });
        }
        let mut got = std::collections::HashSet::new();
        while let Some(result) = waits.join_next().await {
            let (peer, frame) = result.unwrap();
            if let Some((_, bytes)) = frame {
                let header = veil_proto::codec::decode_header(&bytes).unwrap();
                assert_eq!(
                    header.family,
                    veil_proto::family::FrameFamily::Routing as u8
                );
                let query = veil_proto::routing::RecursiveQueryPayload::decode(
                    &bytes[veil_proto::HEADER_SIZE..],
                )
                .unwrap();
                assert_eq!(
                    query.query_type,
                    veil_proto::routing::recursive_query_type::STORE
                );
                assert_eq!(query.payload, vec![0x42; 100]);
                got.insert(peer);
            }
        }
        assert_eq!(got, std::collections::HashSet::from([serving, unknown]));
    }

    #[tokio::test]
    async fn put_replicates_to_a_live_seed_before_the_routing_table_warms() {
        let dht = fresh_kademlia().await;
        assert!(dht.routing_table_contacts().is_empty());
        let peer = [0x02; 32];
        let mut registry = SessionTxRegistry::new();
        let mut received = registry.register(peer);
        let publisher =
            DhtBackedPublisher::with_replication(dht, Arc::new(RwLock::new(registry)), [0x01; 32]);

        publisher
            .put([0xAA; 32], b"identity document".to_vec())
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), received.recv())
                .await
                .is_ok_and(|frame| frame.is_some()),
            "the first live seed got no STORE"
        );
    }

    #[tokio::test]
    async fn publish_identity_document_through_adapter_roundtrips() {
        // End-to-end library-layer check: publish_identity_document
        // uses the DhtBackedPublisher to put at the canonical slot
        // and dht.get_local finds the exact encoded bytes at that
        // slot. This is the shape of what production startup will do.
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        // PoW difficulty no longer used by IdentityDocument; field retained for API stability
        const DEFAULT_IDENTITY_POW_DIFFICULTY: u32 = 0;
        use std::sync::atomic::{AtomicU64, Ordering};
        use veil_proto::identity_document::IdentityDocument;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("veil-dht-publisher-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "pubtest".into(),
            pow_difficulty: DEFAULT_IDENTITY_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        let dht = fresh_kademlia().await;
        let publisher = DhtBackedPublisher::new(Arc::clone(&dht));
        publish_identity_document(&out.document, &publisher)
            .await
            .unwrap();

        // Fetch by canonical DHT key and decode — must match.
        let key = IdentityDocument::dht_key(&out.node_id);
        let bytes = dht.get_local(&key).expect("doc stored at canonical slot");
        let decoded = IdentityDocument::decode(&bytes).unwrap();
        assert_eq!(decoded.node_id, out.node_id);
    }

    #[tokio::test]
    async fn cold_routing_table_uses_live_fallback_without_exceeding_replica_count() {
        let dht = fresh_kademlia().await;
        let mut registry = SessionTxRegistry::new();
        let receivers: Vec<_> = (2..(veil_proto::budget::DHT_REPLICATION_K + 5) as u8)
            .map(|n| registry.register([n; 32]))
            .collect();
        let publisher =
            DhtBackedPublisher::with_replication(dht, Arc::new(RwLock::new(registry)), [1; 32]);
        publisher.put([0xAA; 32], vec![0x42; 100]).await.unwrap();
        let mut waits = tokio::task::JoinSet::new();
        for mut receiver in receivers {
            waits.spawn(async move {
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .is_ok_and(|frame| frame.is_some())
            });
        }
        let mut received = 0;
        while let Some(result) = waits.join_next().await {
            received += usize::from(result.unwrap());
        }
        assert_eq!(received, veil_proto::budget::DHT_REPLICATION_K);
    }
}
