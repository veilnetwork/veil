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

use std::sync::{Arc, RwLock};

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
            replicate_dht_value(&self.dht, tx_reg, self.local_node_id, dht_key, value);
        }
        Ok(())
    }
}

/// Fire-and-forget K-closest replication of `(dht_key, value)`: find the
/// `DHT_REPLICATION_K` closest peers in keyspace and send each a
/// `RecursiveQuery(STORE)`. SYNCHRONOUS — `send_to` only queues frames (no
/// await) — so a caller in a sync context (the rendezvous-ad maintenance
/// publish) can replicate without an async hop. Used by
/// [`DhtBackedPublisher::put`] and `NodeRuntime::tick_publish_rendezvous_ads`.
pub(crate) fn replicate_dht_value(
    dht: &Arc<KademliaService>,
    tx_reg: &Arc<RwLock<SessionTxRegistry>>,
    local_node_id: [u8; 32],
    dht_key: [u8; 32],
    value: Vec<u8>,
) {
    let candidates_with_uri = dht
        .find_closest_with_transport(&dht_key, veil_proto::budget::DHT_REPLICATION_K)
        .into_iter()
        .filter(|(n, _)| *n != local_node_id)
        .collect::<Vec<_>>();
    if candidates_with_uri.is_empty() {
        return;
    }

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

    let mut candidates: Vec<[u8; 32]> = candidates_with_uri.into_iter().map(|(n, _)| n).collect();
    {
        let guard = tx_reg.read().unwrap_or_else(|p| p.into_inner());
        for peer in guard.peer_ids() {
            if peer != local_node_id && !candidates.contains(&peer) {
                candidates.push(peer);
            }
        }
    }

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

    // Fan-out — fire-and-forget. Peers without a direct session are silently
    // skipped; the STORE forwards greedily on receivers we DO have sessions to.
    let guard = tx_reg.read().unwrap_or_else(|p| p.into_inner());
    for peer in candidates {
        let _ = guard.send_to(
            &peer,
            veil_proto::header::priority::INTERACTIVE,
            frame.clone(),
        );
    }
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
}
