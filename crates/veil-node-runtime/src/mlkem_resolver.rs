//! Cold-start ML-KEM-768 EK resolver — fetches a recipient's current
//! ML-KEM encapsulation key from the DHT and populates `peer_mlkem_keys`
//! so subsequent E2E-encrypted sends work without a prior session
//! handshake.  **Epic 486.1 slice 3** (audit batch 2026-05-23).
//!
//! ## Why it exists
//!
//! Pre-fix the `peer_mlkem_keys` cache was populated **only** at
//! handshake completion (see. `peer_handshake.rs::cache.insert`).  IPC
//! client sends to peers without a direct session would hit the
//! "no recipient_ek" branch in `veil-ipc::handlers::send::handle_ipc_send`
//! and return `NO_E2E_KEY` silently.
//!
//! Every sovereign identity already publishes a signed `MlKemKeyCert`
//! to its canonical DHT slot at startup and re-publishes every 6 hours
//! (Epic 462.12 / `runtime/sovereign_republish.rs`).  This resolver
//! closes the loop: when IPC encounters a cache miss, it queries the
//! DHT, verifies the cert chain, and populates the cache.
//!
//! ## Resolution pipeline
//!
//! 1. Recursive-walk `IdentityDocument::dht_key(target_node_id)`
//!    → decode + verify Ed25519 / Falcon-512 master signature + freshness.
//! 2. Recursive-walk `InstanceRegistry::dht_key(target_node_id)`
//!    → decode + verify Ed25519 sig against one of the document's subkeys.
//! 3. Pick the most-recent-active instance by `last_seen_unix_ms`.
//! 4. Recursive-walk `MlKemKeyCert::dht_key(target_node_id, instance_id)`
//!    → decode + verify via `mlkem_fanout::verify_mlkem_cert(cert, doc, now)`.
//! 5. Insert `(node_id, (ek, Instant::now()))` into `peer_mlkem_keys`.
//! 6. Return the EK bytes so that the IPC handler can retry encryption.
//!
//! ## Failure semantics
//!
//! Every error path returns `None` to the caller (see. trait contract in
//! `veil_types::MlKemEkResolver`).  Diagnostic detail lands in the
//! `NodeLogger` (debug level) — operators turn it on via
//! `[global] log_level = "debug"`.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};
use rand_core::RngCore;
use veil_dht::KademliaService;
use veil_dispatcher::PendingRecursive;
use veil_e2e::PeerMlKemCache;
use veil_identity::mlkem_fanout::{VerifiedMlkemCert, verify_mlkem_cert, verify_relay_key};
use veil_identity::verify::verify_identity_document;
use veil_observability::NodeLogger;
use veil_proto::header::FrameHeader;
use veil_proto::identity_document::IdentityDocument;
use veil_proto::instance_registry::{INSTANCE_REGISTRY_SIG_CONTEXT, InstanceRegistry};
use veil_proto::mlkem_cert::MlKemKeyCert;
use veil_proto::relay_key::RelayKeyRecord;
use veil_proto::routing::{RecursiveQueryPayload, recursive_query_type};
use veil_session::SessionTxRegistry;
use veil_types::{MlKemEkResolver, NodeIdBytes, RelayKeyResolver};
use veil_util::{lock, rlock, wlock};

/// Default per-step timeout when none is configured (3 sec).  Three
/// sequential DHT walks (doc + registry + cert) so total budget caps
/// at ~9 sec in the worst case.
const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// DHT-driven impl of [`MlKemEkResolver`].  Wraps the same set of
/// `Arc`-shared runtime components that `NodeRuntime::dht_recursive_get`
/// uses, plus a write-through to `peer_mlkem_keys` cache.
pub struct DhtMlKemEkResolver {
    dht: Arc<KademliaService>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
    logger: Arc<NodeLogger>,
    step_timeout: Duration,
}

impl DhtMlKemEkResolver {
    /// New resolver bound to a node's runtime components.  `step_timeout`
    /// applies to each of the three DHT walks individually — total budget
    /// is at most `3 × step_timeout`.
    #[must_use]
    pub fn new(
        dht: Arc<KademliaService>,
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        pending_recursive: Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
        local_node_id: [u8; 32],
        peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
        logger: Arc<NodeLogger>,
    ) -> Self {
        Self {
            dht,
            session_tx_registry,
            pending_recursive,
            local_node_id,
            peer_mlkem_keys,
            logger,
            step_timeout: DEFAULT_STEP_TIMEOUT,
        }
    }

    /// Override the per-step DHT timeout.  Useful for tests +
    /// configurations that want a tighter / looser budget.
    #[must_use]
    pub fn with_step_timeout(mut self, t: Duration) -> Self {
        self.step_timeout = t;
        self
    }

    /// Core resolution body.  Each branch returns `None` on any failure
    /// — see module docstring.  Loggable failure points emit DEBUG events
    /// via `NodeLogger` so operators can diagnose with `log_level = "debug"`.
    /// Fetch + verify the target's `IdentityDocument` from the DHT (step 1 of
    /// the cert walk, on its own). Public so the mailbox OPEN path can obtain the
    /// sender's verified document — needed to check the auth-deliver signature —
    /// without resolving an ML-KEM cert. Returns `None` on a DHT miss, a decode
    /// failure, an invalid document signature, or a node_id mismatch.
    pub async fn fetch_verified_document(
        &self,
        target_node_id: [u8; 32],
    ) -> Option<IdentityDocument> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let doc_key = IdentityDocument::dht_key(&target_node_id);
        let doc_bytes = match self
            .dht_recursive_get(doc_key, self.step_timeout, |b| {
                IdentityDocument::decode(b).ok().is_some_and(|d| {
                    d.node_id == target_node_id && verify_identity_document(&d, now_unix).is_ok()
                })
            })
            .await
        {
            Some(b) => b,
            None => {
                self.log_dbg("mlkem_resolver.doc.dht_miss", &target_node_id, "");
                return None;
            }
        };
        let doc = IdentityDocument::decode(&doc_bytes)
            .map_err(|e| {
                self.log_dbg(
                    "mlkem_resolver.doc.decode_failed",
                    &target_node_id,
                    &format!("{e}"),
                )
            })
            .ok()?;
        verify_identity_document(&doc, now_unix)
            .map_err(|e| {
                self.log_dbg(
                    "mlkem_resolver.doc.verify_failed",
                    &target_node_id,
                    &format!("{e:?}"),
                )
            })
            .ok()?;
        if doc.node_id != target_node_id {
            self.log_dbg(
                "mlkem_resolver.doc.node_id_mismatch",
                &target_node_id,
                "DHT returned IdentityDocument for a different node_id",
            );
            return None;
        }
        Some(doc)
    }

    /// Resolve + verify the recipient's current ML-KEM cert — the full
    /// [`VerifiedMlkemCert`] (instance_id + cert_version + node_id + EK), not
    /// just the EK — via the DHT walk IdentityDocument → InstanceRegistry →
    /// MlKemKeyCert, writing the EK back to the peer cache. Public so the fan-out
    /// mailbox-seal path can obtain a cert (fan-out binds instance_id +
    /// cert_version, which the EK-only [`resolve_ek`](MlKemEkResolver::resolve_ek)
    /// surface discards).
    pub async fn fetch_verified_cert(
        &self,
        target_node_id: [u8; 32],
    ) -> Option<VerifiedMlkemCert> {
        self.log_dbg("mlkem_resolver.start", &target_node_id, "");
        // ── Step 1: IdentityDocument ────────────────────────────────
        let doc = self.fetch_verified_document(target_node_id).await?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        // ── Step 2: InstanceRegistry ────────────────────────────────
        let reg_key = InstanceRegistry::dht_key(&target_node_id);
        let reg_bytes = match self
            .dht_recursive_get(reg_key, self.step_timeout, |b| {
                InstanceRegistry::decode(b).ok().is_some_and(|r| {
                    r.node_id == target_node_id && verify_instance_registry_sig(&r, &doc)
                })
            })
            .await
        {
            Some(b) => b,
            None => {
                self.log_dbg("mlkem_resolver.registry.dht_miss", &target_node_id, "");
                return None;
            }
        };
        let reg = InstanceRegistry::decode(&reg_bytes)
            .map_err(|e| {
                self.log_dbg(
                    "mlkem_resolver.registry.decode_failed",
                    &target_node_id,
                    &format!("{e}"),
                )
            })
            .ok()?;
        if reg.node_id != target_node_id {
            self.log_dbg(
                "mlkem_resolver.registry.node_id_mismatch",
                &target_node_id,
                "DHT returned InstanceRegistry for a different node_id",
            );
            return None;
        }
        if !verify_instance_registry_sig(&reg, &doc) {
            self.log_dbg(
                "mlkem_resolver.registry.sig_invalid",
                &target_node_id,
                "InstanceRegistry signature failed verification against IdentityDocument subkeys",
            );
            return None;
        }
        let instance = reg.instances.iter().max_by_key(|i| i.last_seen_unix_ms)?;

        // ── Step 3: MlKemKeyCert ────────────────────────────────────
        let cert_key = MlKemKeyCert::dht_key(&target_node_id, &instance.instance_id);
        let cert_bytes = match self
            .dht_recursive_get(cert_key, self.step_timeout, |b| {
                MlKemKeyCert::decode(b)
                    .ok()
                    .is_some_and(|c| verify_mlkem_cert(&c, &doc, now_unix).is_ok())
            })
            .await
        {
            Some(b) => b,
            None => {
                self.log_dbg("mlkem_resolver.cert.dht_miss", &target_node_id, "");
                return None;
            }
        };
        let cert = MlKemKeyCert::decode(&cert_bytes)
            .map_err(|e| {
                self.log_dbg(
                    "mlkem_resolver.cert.decode_failed",
                    &target_node_id,
                    &format!("{e}"),
                )
            })
            .ok()?;
        let verified = verify_mlkem_cert(&cert, &doc, now_unix)
            .map_err(|e| {
                self.log_dbg(
                    "mlkem_resolver.cert.verify_failed",
                    &target_node_id,
                    &format!("{e:?}"),
                )
            })
            .ok()?;

        // ── Step 4: cache writeback ────────────────────────────────
        // PeerMlKemCache uses [`MAX_PEER_MLKEM_CACHE`]-bounded LRU
        // eviction — same policy as the handshake-time insert site in
        // `peer_handshake.rs:191-204`.  Mirror it here so cache growth
        // under cold-start traffic stays bounded.
        {
            let mut cache = wlock!(self.peer_mlkem_keys);
            if cache.len() >= veil_proto::budget::MAX_PEER_MLKEM_CACHE
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(id, _)| *id)
            {
                cache.remove(&oldest);
            }
            cache.insert(
                target_node_id,
                (verified.mlkem_pubkey.clone(), std::time::Instant::now()),
            );
        }
        self.logger.debug(
            "mlkem_resolver.resolved",
            format!(
                "target={} ek_bytes={}",
                hex8(&target_node_id),
                verified.mlkem_pubkey.len()
            ),
        );
        Some(verified)
    }

    /// EK-only resolution — the [`MlKemEkResolver`] trait surface used by the
    /// live `veil_e2e::encrypt` path. Thin wrapper over [`fetch_verified_cert`]
    /// (which already does the cache writeback), so both layers share one
    /// resolution + verification path.
    async fn fetch_inner(&self, target_node_id: [u8; 32]) -> Option<Vec<u8>> {
        Some(self.fetch_verified_cert(target_node_id).await?.mlkem_pubkey)
    }

    /// Resolve + verify a node's relay X25519 KEM public key from the DHT:
    /// fetch its verified `IdentityDocument` (to obtain the signing subkey),
    /// then recursive-walk `RelayKeyRecord::dht_key(node_id)` and verify the
    /// record's signature against that document via
    /// [`verify_relay_key`](veil_identity::mlkem_fanout::verify_relay_key).
    /// Returns the authenticated 32-byte X25519 key, or `None` on any failure
    /// (no document, no record, bad signature, expired, timeout).
    ///
    /// Reuses the same document fetch + recursive-get the ML-KEM walk uses, so
    /// the relay-key resolve shares the mirror-cache-poison-resistant fast path.
    pub async fn fetch_relay_x25519(&self, target_node_id: [u8; 32]) -> Option<[u8; 32]> {
        let doc = self.fetch_verified_document(target_node_id).await?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let key = RelayKeyRecord::dht_key(&target_node_id);
        let bytes = match self
            .dht_recursive_get(key, self.step_timeout, |b| {
                RelayKeyRecord::decode(b).ok().is_some_and(|r| {
                    r.node_id == target_node_id && verify_relay_key(&r, &doc, now_unix).is_ok()
                })
            })
            .await
        {
            Some(b) => b,
            None => {
                self.log_dbg("relay_key_resolver.dht_miss", &target_node_id, "");
                return None;
            }
        };
        let rec = RelayKeyRecord::decode(&bytes)
            .map_err(|e| {
                self.log_dbg(
                    "relay_key_resolver.decode_failed",
                    &target_node_id,
                    &format!("{e}"),
                )
            })
            .ok()?;
        let pk = verify_relay_key(&rec, &doc, now_unix)
            .map_err(|e| {
                self.log_dbg(
                    "relay_key_resolver.verify_failed",
                    &target_node_id,
                    &format!("{e}"),
                )
            })
            .ok()?;
        self.logger.debug(
            "relay_key_resolver.resolved",
            format!("target={} relay_x25519 resolved", hex8(&target_node_id)),
        );
        Some(pk)
    }

    /// Recursive DHT FIND_VALUE walk — delegates to the shared
    /// [`recursive_dht_get`] free function (also used by the rendezvous
    /// resolver), passing this resolver's shared references.
    async fn dht_recursive_get(
        &self,
        key: [u8; 32],
        timeout: Duration,
        is_valid: impl Fn(&[u8]) -> bool,
    ) -> Option<Vec<u8>> {
        recursive_dht_get(
            &self.dht,
            &self.session_tx_registry,
            &self.pending_recursive,
            self.local_node_id,
            key,
            timeout,
            is_valid,
        )
        .await
    }

    fn log_dbg(&self, event: &'static str, node_id: &[u8; 32], detail: &str) {
        self.logger
            .debug(event, format!("target={} {}", hex8(node_id), detail));
    }
}

/// Recursive DHT FIND_VALUE walk shared by the DHT resolvers (ML-KEM EK,
/// relay-key, and rendezvous-ad). Mirrors `NodeRuntime::dht_recursive_get` but
/// takes the shared references explicitly so it doesn't depend on any one
/// resolver struct. Validated-local-fast-path (mirror-cache-poison resistant) →
/// forward a `RecursiveQuery(FIND_VALUE)` to the top-2 closest session peers →
/// await the matching `RecursiveResponse`. Returns `None` on local-miss +
/// no-peers / timeout. `is_valid` gates ONLY the local fast path.
#[allow(clippy::type_complexity)]
pub(crate) async fn recursive_dht_get(
    dht: &Arc<KademliaService>,
    session_tx_registry: &Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: &Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    key: [u8; 32],
    timeout: Duration,
    is_valid: impl Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    // Validated local fast path. Only trust a locally mirror-cached value if it
    // passes the caller's verification (a malicious FIND_VALUE responder can
    // mirror-poison the local cache with a structurally-valid but forged
    // identity-family record under the victim's key; verification is the
    // resolver's job). On an invalid local value we fall through to the walk.
    if let Some(value) = dht.get_local(&key)
        && is_valid(&value)
    {
        return Some(value);
    }
    // Drop the validator before the awaits so it is never held across an await
    // point (keeps the future `Send` regardless of its captures).
    drop(is_valid);

    let mut peers: Vec<[u8; 32]> = rlock!(session_tx_registry).peer_ids();
    if peers.is_empty() {
        return None;
    }
    peers.sort_by_key(|pid| {
        let mut xor = [0u8; 32];
        for i in 0..32 {
            xor[i] = pid[i] ^ key[i];
        }
        xor
    });

    let query_id: [u8; 16] = {
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);
        id
    };
    let q = RecursiveQueryPayload {
        query_id,
        target_key: key,
        reply_to: local_node_id,
        ttl: 40,
        query_type: recursive_query_type::FIND_VALUE,
        reply_port: 0,
        payload: vec![],
    };
    let q_bytes = q.encode();
    let mut hdr = FrameHeader::new(
        veil_proto::family::FrameFamily::Routing as u8,
        veil_proto::family::RoutingMsg::RecursiveQuery as u16,
    );
    hdr.body_len = q_bytes.len() as u32;
    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&q_bytes);

    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    {
        use veil_proto::budget::MAX_PENDING_RECURSIVE;
        let mut m = lock!(pending_recursive);
        m.retain(|_, p| !p.tx.is_closed());
        if m.len() >= MAX_PENDING_RECURSIVE {
            return None;
        }
        m.insert(
            query_id,
            PendingRecursive {
                target_key: key,
                query_type: recursive_query_type::FIND_VALUE,
                tx,
            },
        );
    }

    {
        let guard = rlock!(session_tx_registry);
        for pid in peers.iter().take(2) {
            guard.send_to(
                pid,
                veil_proto::header::priority::INTERACTIVE,
                frame.clone(),
            );
        }
    }

    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(bytes)) => Some(bytes),
        _ => {
            let mut m = lock!(pending_recursive);
            m.remove(&query_id);
            None
        }
    }
}

impl MlKemEkResolver for DhtMlKemEkResolver {
    fn resolve_ek(
        &self,
        target_node_id: NodeIdBytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + '_>> {
        Box::pin(self.fetch_inner(target_node_id))
    }
}

impl RelayKeyResolver for DhtMlKemEkResolver {
    fn resolve_relay_x25519(
        &self,
        target_node_id: NodeIdBytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<[u8; 32]>> + Send + '_>> {
        Box::pin(self.fetch_relay_x25519(target_node_id))
    }
}

/// Verify the `InstanceRegistry` Ed25519 signature against the document's
/// active subkey indexed by `signing_identity_key_idx`.  Returns `true`
/// iff the signature is valid AND the subkey is present.
fn verify_instance_registry_sig(reg: &InstanceRegistry, doc: &IdentityDocument) -> bool {
    let key_idx = reg.signing_identity_key_idx as usize;
    let Some(subkey) = doc.identity_keys.get(key_idx) else {
        return false;
    };
    // Only Ed25519 subkeys can sign a registry under v1 wire format.
    // (Falcon-512 subkeys exist but the registry was never specified to
    // carry a Falcon sig.  If a future epic lifts that, expand here.)
    let Ok(pk_arr) = subkey.pubkey.as_slice().try_into() as Result<&[u8; 32], _> else {
        return false;
    };
    let Ok(pk) = EdVerifyingKey::from_bytes(pk_arr) else {
        return false;
    };
    let mut msg = Vec::with_capacity(INSTANCE_REGISTRY_SIG_CONTEXT.len() + reg.encoded_len());
    msg.extend_from_slice(INSTANCE_REGISTRY_SIG_CONTEXT);
    msg.extend_from_slice(&reg.canonical_signing_bytes());
    let Ok(sig) = EdSignature::from_slice(&reg.sig) else {
        return false;
    };
    pk.verify(&msg, &sig).is_ok()
}

/// Format the first 4 bytes of a node_id as 8 hex chars (matches the
/// rest of the codebase's log conventions).
fn hex8(node_id: &[u8; 32]) -> String {
    veil_util::bytes_to_hex(&node_id[..4])
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Unit-test coverage focuses on the **pure** parts of the pipeline.
// Full end-to-end (real DHT) coverage lives in integration tests under
// `veilcore/tests/` (Epic 486.1 slice 3.4).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex8_formats_first_four_bytes() {
        let id = [0xAB; 32];
        assert_eq!(hex8(&id), "abababab");
    }

    #[test]
    fn verify_instance_registry_sig_rejects_oob_key_idx() {
        // Build a registry pointing at a subkey index that doesn't
        // exist in the supplied document.  Verifier must say nope.
        // (Synthesising a real-signed registry needs the full identity
        // crate fixtures — covered by the integration test.)
        let reg = InstanceRegistry {
            node_id: [0x11; 32],
            reg_version: 1,
            signing_identity_key_idx: 99, // doc has 1 key — OOB
            instances: vec![],
            sig: vec![0u8; 64],
        };
        let doc = IdentityDocument {
            node_id: [0x11; 32],
            issued_at_unix: 0,
            valid_until_unix: u64::MAX,
            master_pubkey: vec![0u8; 32],
            master_algo: veil_proto::identity_document::ALGO_ED25519,
            identity_keys: vec![veil_proto::identity_document::IdentityKey {
                algo: veil_proto::identity_document::ALGO_ED25519,
                pubkey: vec![0u8; 32],
                device_id: [0u8; 32],
                valid_from_unix: 0,
                valid_until_unix: u64::MAX,
                master_sig: vec![0u8; 64],
            }],
            sig_key_idx: 0,
            document_sig: vec![0u8; 64],
        };
        assert!(!verify_instance_registry_sig(&reg, &doc));
    }

    fn make_test_resolver(dht: Arc<KademliaService>) -> DhtMlKemEkResolver {
        DhtMlKemEkResolver::new(
            dht,
            Arc::new(RwLock::new(SessionTxRegistry::new())),
            Arc::new(Mutex::new(std::collections::HashMap::new())),
            [1u8; 32],
            Arc::new(RwLock::new(PeerMlKemCache::new())),
            Arc::new(NodeLogger::new_noop()),
        )
    }

    // Regression for the DHT mirror-cache poison DoS fix: the validated local
    // fast-path must return a locally-cached value ONLY if it passes the
    // caller's validator. A poisoned/invalid local value must NOT short-circuit
    // the remote walk — with no peers configured the walk yields None, proving
    // the poison was neither returned nor allowed to block fallback.
    #[tokio::test]
    async fn dht_recursive_get_rejects_invalid_local_value() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let key = [42u8; 32];
        dht.store_local(key, b"poisoned".to_vec());
        let resolver = make_test_resolver(Arc::clone(&dht));
        let got = resolver
            .dht_recursive_get(key, Duration::from_millis(50), |_| false)
            .await;
        assert_eq!(
            got, None,
            "invalid local value must not be returned; must fall through to remote"
        );
    }

    #[tokio::test]
    async fn dht_recursive_get_returns_valid_local_value() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let key = [42u8; 32];
        dht.store_local(key, b"good".to_vec());
        let resolver = make_test_resolver(Arc::clone(&dht));
        let got = resolver
            .dht_recursive_get(key, Duration::from_millis(50), |_| true)
            .await;
        assert_eq!(got, Some(b"good".to_vec()));
    }
}
