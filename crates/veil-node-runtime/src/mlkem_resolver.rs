//! Cold-start ML-KEM-768 EK resolver — fetches а recipient's current
//! ML-KEM encapsulation key от the DHT и populates `peer_mlkem_keys`
//! so subsequent E2E-encrypted sends work без а prior session
//! handshake.  **Epic 486.1 slice 3** (audit batch 2026-05-23).
//!
//! ## Why it exists
//!
//! Pre-fix the `peer_mlkem_keys` cache was populated **only** at
//! handshake completion (см. `peer_handshake.rs::cache.insert`).  IPC
//! client sends к peers без а direct session would hit the
//! "no recipient_ek" branch в `veil-ipc::handlers::send::handle_ipc_send`
//! и return `NO_E2E_KEY` silently.
//!
//! Every sovereign identity already publishes а signed `MlKemKeyCert`
//! to its canonical DHT slot at startup и re-publishes every 6 hours
//! (Epic 462.12 / `runtime/sovereign_republish.rs`).  This resolver
//! closes the loop: when IPC encounters а cache miss, it queries the
//! DHT, verifies the cert chain, и populates the cache.
//!
//! ## Resolution pipeline
//!
//! 1. Recursive-walk `IdentityDocument::dht_key(target_node_id)`
//!    → decode + verify Ed25519 / Falcon-512 master signature + freshness.
//! 2. Recursive-walk `InstanceRegistry::dht_key(target_node_id)`
//!    → decode + verify Ed25519 sig против one of the document's subkeys.
//! 3. Pick the most-recent-active instance by `last_seen_unix_ms`.
//! 4. Recursive-walk `MlKemKeyCert::dht_key(target_node_id, instance_id)`
//!    → decode + verify via `mlkem_fanout::verify_mlkem_cert(cert, doc, now)`.
//! 5. Insert `(node_id, (ek, Instant::now()))` into `peer_mlkem_keys`.
//! 6. Return the EK bytes так that the IPC handler can retry encryption.
//!
//! ## Failure semantics
//!
//! Every error path returns `None` к the caller (см. trait contract в
//! `veil_types::MlKemEkResolver`).  Diagnostic detail lands в the
//! `NodeLogger` (debug level) — operators turn it on via
//! `[global] log_level = "debug"`.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};
use rand_core::RngCore;
use veil_dht::KademliaService;
use veil_dispatcher::PendingRecursive;
use veil_e2e::PeerMlKemCache;
use veil_identity::mlkem_fanout::verify_mlkem_cert;
use veil_identity::verify::verify_identity_document;
use veil_observability::NodeLogger;
use veil_proto::header::FrameHeader;
use veil_proto::identity_document::IdentityDocument;
use veil_proto::instance_registry::{INSTANCE_REGISTRY_SIG_CONTEXT, InstanceRegistry};
use veil_proto::mlkem_cert::MlKemKeyCert;
use veil_proto::routing::{RecursiveQueryPayload, recursive_query_type};
use veil_session::SessionTxRegistry;
use veil_types::{MlKemEkResolver, NodeIdBytes};
use veil_util::{lock, rlock, wlock};

/// Default per-step timeout when none is configured (3 sec).  Three
/// sequential DHT walks (doc + registry + cert) so total budget caps
/// at ~9 sec в the worst case.
const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// DHT-driven impl of [`MlKemEkResolver`].  Wraps the same set of
/// `Arc`-shared runtime components that `NodeRuntime::dht_recursive_get`
/// uses, plus а write-through к `peer_mlkem_keys` cache.
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
    /// New resolver bound to а node's runtime components.  `step_timeout`
    /// applies к each of the three DHT walks individually — total budget
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
    /// configurations што want а tighter / looser budget.
    #[must_use]
    pub fn with_step_timeout(mut self, t: Duration) -> Self {
        self.step_timeout = t;
        self
    }

    /// Core resolution body.  Each branch returns `None` on any failure
    /// — see module docstring.  Loggable failure points emit DEBUG events
    /// via `NodeLogger` so operators can diagnose с `log_level = "debug"`.
    async fn fetch_inner(&self, target_node_id: [u8; 32]) -> Option<Vec<u8>> {
        self.log_dbg("mlkem_resolver.start", &target_node_id, "");
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        // ── Step 1: IdentityDocument ────────────────────────────────
        let doc_key = IdentityDocument::dht_key(&target_node_id);
        let doc_bytes = match self.dht_recursive_get(doc_key, self.step_timeout).await {
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
                "DHT returned IdentityDocument for а different node_id",
            );
            return None;
        }

        // ── Step 2: InstanceRegistry ────────────────────────────────
        let reg_key = InstanceRegistry::dht_key(&target_node_id);
        let reg_bytes = match self.dht_recursive_get(reg_key, self.step_timeout).await {
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
                "DHT returned InstanceRegistry for а different node_id",
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
        let cert_bytes = match self.dht_recursive_get(cert_key, self.step_timeout).await {
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
        // eviction — same policy as the handshake-time insert site в
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
        Some(verified.mlkem_pubkey)
    }

    /// Mirror of `NodeRuntime::dht_recursive_get` adapted for the shared
    /// references that this resolver holds.  Does NOT depend on the
    /// surrounding NodeRuntime so this module stays self-contained.
    async fn dht_recursive_get(&self, key: [u8; 32], timeout: Duration) -> Option<Vec<u8>> {
        // Local fast path.
        if let Some(value) = self.dht.get_local(&key) {
            return Some(value);
        }

        // Pick К closest active session peers; bail если there are no
        // peers к forward (solo recursive walk impossible).
        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
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

        // Build the RecursiveQuery frame.
        let query_id: [u8; 16] = {
            let mut id = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut id);
            id
        };
        let q = RecursiveQueryPayload {
            query_id,
            target_key: key,
            reply_to: self.local_node_id,
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

        // Register oneshot for the matching RecursiveResponse.
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        {
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let mut m = lock!(self.pending_recursive);
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

        // Forward к top-2 closest peers.
        {
            let guard = rlock!(self.session_tx_registry);
            for pid in peers.iter().take(2) {
                guard.send_to(
                    pid,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                );
            }
        }

        // Wait for the response OR timeout.
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(bytes)) => Some(bytes),
            _ => {
                // Cleanup pending entry on timeout — the dispatcher's
                // own cleanup is best-effort но explicit removal here
                // bounds memory deterministically.
                let mut m = lock!(self.pending_recursive);
                m.remove(&query_id);
                None
            }
        }
    }

    fn log_dbg(&self, event: &'static str, node_id: &[u8; 32], detail: &str) {
        self.logger
            .debug(event, format!("target={} {}", hex8(node_id), detail));
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

/// Verify the `InstanceRegistry` Ed25519 signature against the document's
/// active subkey indexed by `signing_identity_key_idx`.  Returns `true`
/// iff the signature is valid AND the subkey is present.
fn verify_instance_registry_sig(reg: &InstanceRegistry, doc: &IdentityDocument) -> bool {
    let key_idx = reg.signing_identity_key_idx as usize;
    let Some(subkey) = doc.identity_keys.get(key_idx) else {
        return false;
    };
    // Only Ed25519 subkeys can sign а registry under v1 wire format.
    // (Falcon-512 subkeys exist but the registry was never specified to
    // carry а Falcon sig.  If а future epic lifts that, expand here.)
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

/// Format the first 4 bytes of а node_id as 8 hex chars (matches the
/// rest of the codebase's log conventions).
fn hex8(node_id: &[u8; 32]) -> String {
    veil_util::bytes_to_hex(&node_id[..4])
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Unit-test coverage focuses on the **pure** parts of the pipeline.
// Full end-to-end (real DHT) coverage lives в integration tests under
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
        // Build а registry pointing at а subkey index that doesn't
        // exist в the supplied document.  Verifier must say nope.
        // (Synthesising а real-signed registry needs the full identity
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
}
