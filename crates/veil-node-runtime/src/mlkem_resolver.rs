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

/// TTL for the verified-cert fast-path cache. A recipient's ML-KEM EK is
/// **stable for the lifetime of its instance** — `mlkem_dk_seed` is fixed and
/// the 6-hourly `MlKemKeyCert` republish only refreshes the signature +
/// timestamp, not the EK — so a previously-verified [`VerifiedMlkemCert`] stays
/// valid until the recipient rotates to a *new* instance (fresh install /
/// identity reset). A 30-min TTL bounds that rare rotation window while letting
/// an active conversation reuse a single DHT walk across **all** its live-E2E
/// encrypts AND offline mailbox seals, instead of re-walking on every call.
const CERT_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

/// `node_id → (verified cert, when-resolved)`. Shared across the live-E2E and
/// offline-mailbox-seal resolver instances (both built over `self.identity`),
/// so a live send warms the cache the subsequent seal reuses — this is what
/// makes the offline-deposit path fast + resilient to transient DHT misses
/// (it used to do a fresh 3-step DHT walk on **every** seal). LRU-bounded by
/// [`MAX_PEER_MLKEM_CACHE`](veil_proto::budget::MAX_PEER_MLKEM_CACHE).
pub type PeerMlKemCertCache =
    std::collections::HashMap<[u8; 32], (VerifiedMlkemCert, std::time::Instant)>;

/// DHT-driven impl of [`MlKemEkResolver`].  Wraps the same set of
/// `Arc`-shared runtime components that `NodeRuntime::dht_recursive_get`
/// uses, plus a write-through to `peer_mlkem_keys` cache.
pub struct DhtMlKemEkResolver {
    dht: Arc<KademliaService>,
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
    /// Verified-cert fast-path cache (see [`PeerMlKemCertCache`]). Shared with
    /// the other resolver instance over `self.identity` so live + seal paths
    /// warm each other.
    cert_cache: Arc<RwLock<PeerMlKemCertCache>>,
    logger: Arc<NodeLogger>,
    step_timeout: Duration,
    /// Verified-cert cache TTL. Defaults to [`CERT_CACHE_TTL`]; overridable
    /// via [`with_cert_ttl`](Self::with_cert_ttl) for tests.
    cert_ttl: Duration,
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
        cert_cache: Arc<RwLock<PeerMlKemCertCache>>,
        logger: Arc<NodeLogger>,
    ) -> Self {
        Self {
            dht,
            session_tx_registry,
            pending_recursive,
            local_node_id,
            peer_mlkem_keys,
            cert_cache,
            logger,
            step_timeout: DEFAULT_STEP_TIMEOUT,
            cert_ttl: CERT_CACHE_TTL,
        }
    }

    /// Override the per-step DHT timeout.  Useful for tests +
    /// configurations that want a tighter / looser budget.
    #[must_use]
    pub fn with_step_timeout(mut self, t: Duration) -> Self {
        self.step_timeout = t;
        self
    }

    /// Override the verified-cert cache TTL. Test-only knob — production keeps
    /// [`CERT_CACHE_TTL`]; lets a test force-expire a cached entry (TTL = 0)
    /// without time travel.
    #[must_use]
    pub fn with_cert_ttl(mut self, t: Duration) -> Self {
        self.cert_ttl = t;
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
        direct_peer: Option<[u8; 32]>,
    ) -> Option<IdentityDocument> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let doc_key = IdentityDocument::dht_key(&target_node_id);
        // No authoritative holder given → compare EVERY reachable holder and
        // take the freshest issue (see [`Self::dht_get_freshest`]): a stale
        // but still-valid document replica must not win the walk. With a
        // direct peer the caller knows the authoritative holder (relay-key
        // resolves), so the single steered walk stays.
        if direct_peer.is_none() {
            let doc = self
                .dht_get_freshest(
                    doc_key,
                    |b| {
                        IdentityDocument::decode(b).ok().filter(|d| {
                            d.node_id == target_node_id
                                && verify_identity_document(d, now_unix).is_ok()
                        })
                    },
                    |d| (d.issued_at_unix, 0),
                )
                .await;
            if doc.is_none() {
                self.log_dbg("mlkem_resolver.doc.dht_miss", &target_node_id, "");
            }
            return doc;
        }
        let doc_bytes = match self
            .dht_recursive_get(doc_key, self.step_timeout, direct_peer, |b| {
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
    pub async fn fetch_verified_cert(&self, target_node_id: [u8; 32]) -> Option<VerifiedMlkemCert> {
        self.log_dbg("mlkem_resolver.start", &target_node_id, "");
        // ── Step 0: verified-cert fast path ─────────────────────────
        // A recently-verified cert for this recipient short-circuits the
        // whole 3-step DHT walk. The EK is instance-stable (see
        // `CERT_CACHE_TTL`), so a fresh cache entry is as good as a
        // re-resolve — and it's what makes the offline mailbox-seal path
        // (which walked the DHT on *every* seal) fast + resilient to a
        // transient DHT miss, since a live encrypt to the same peer will
        // have warmed this cache moments earlier.
        if let Some((cert, ts)) = rlock!(self.cert_cache).get(&target_node_id)
            && ts.elapsed() < self.cert_ttl
        {
            self.log_dbg("mlkem_resolver.cert.cache_hit", &target_node_id, "");
            return Some(cert.clone());
        }
        // ── Step 1: IdentityDocument ────────────────────────────────
        // ML-KEM resolves can target any third party (not necessarily a
        // connected peer), so keep the XOR-closest recursive walk.
        let doc = self.fetch_verified_document(target_node_id, None).await?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        // ── Step 2: InstanceRegistry ────────────────────────────────
        // Freshest-of-candidates (see [`Self::dht_get_freshest`]): a stale
        // registry replica — including OUR OWN local mirror — points at an
        // outdated instance and downstream seals target the wrong material.
        // Freshness = the newest instance the registry has seen.
        let reg_key = InstanceRegistry::dht_key(&target_node_id);
        let reg = match self
            .dht_get_freshest(
                reg_key,
                |b| {
                    InstanceRegistry::decode(b).ok().filter(|r| {
                        r.node_id == target_node_id && verify_instance_registry_sig(r, &doc)
                    })
                },
                |r| {
                    (
                        r.instances
                            .iter()
                            .map(|i| i.last_seen_unix_ms)
                            .max()
                            .unwrap_or(0),
                        0,
                    )
                },
            )
            .await
        {
            Some(r) => r,
            None => {
                self.log_dbg("mlkem_resolver.registry.dht_miss", &target_node_id, "");
                return None;
            }
        };
        let instance = reg.instances.iter().max_by_key(|i| i.last_seen_unix_ms)?;

        // ── Step 3: MlKemKeyCert ────────────────────────────────────
        // Freshest-of-candidates by the cert's OWN supersede order:
        // `cert_version` is the documented monotonic rotation counter,
        // `valid_from_unix` breaks ties between republications of the same
        // version. First-replica-wins here was THE production message-loss
        // path: a mid-churn re-resolve returned a stale cert whose EK no
        // longer matched the receiver's dk → every blob sealed to it failed
        // open (`Fanout(AeadFailed)`) and was quarantined away.
        let cert_key = MlKemKeyCert::dht_key(&target_node_id, &instance.instance_id);
        let cert = match self
            .dht_get_freshest(
                cert_key,
                |b| {
                    MlKemKeyCert::decode(b)
                        .ok()
                        .filter(|c| verify_mlkem_cert(c, &doc, now_unix).is_ok())
                },
                |c| (c.cert_version, c.valid_from_unix),
            )
            .await
        {
            Some(c) => c,
            None => {
                self.log_dbg("mlkem_resolver.cert.dht_miss", &target_node_id, "");
                return None;
            }
        };
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
        // Verified-cert cache writeback (same LRU policy) — feeds the Step 0
        // fast path above for every subsequent live encrypt + offline seal.
        {
            let mut cc = wlock!(self.cert_cache);
            if cc.len() >= veil_proto::budget::MAX_PEER_MLKEM_CACHE
                && let Some(oldest) = cc.iter().min_by_key(|(_, (_, ts))| *ts).map(|(id, _)| *id)
            {
                cc.remove(&oldest);
            }
            cc.insert(
                target_node_id,
                (verified.clone(), std::time::Instant::now()),
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
        // Relay-key resolves are the cold-restart hot path: the target IS the
        // relay we're connected to and about to register a mailbox with, so steer
        // BOTH the document and the relay-key lookups straight at it (it answers
        // authoritatively from store_local) rather than walking a cold table.
        let doc = self
            .fetch_verified_document(target_node_id, Some(target_node_id))
            .await?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let key = RelayKeyRecord::dht_key(&target_node_id);
        let bytes = match self
            .dht_recursive_get(key, self.step_timeout, Some(target_node_id), |b| {
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

    /// Multi-replica FIND_VALUE: ask every directly-reachable replication
    /// holder (never letting a local mirror short-circuit the fan-out), keep
    /// the candidates that decode + verify, pick the FRESHEST by `freshness`,
    /// and repair the local mirror with the winner's bytes.
    ///
    /// The ML-KEM walk analogue of the rendezvous freshest-ad selection
    /// (`replicas_from_freshest_ads`): after receiver churn a STALE replica of
    /// the identity document / instance registry / key cert stays correctly
    /// signed and unexpired, so the old first-replica-wins walk could seal a
    /// mailbox blob to OUTDATED material — the receiver then cannot open it
    /// (generic `Failed`), quarantines it, and the message is destroyed. A
    /// sender that compares all reachable holders and takes the newest cannot
    /// be downgraded by one lagging replica.
    async fn dht_get_freshest<T>(
        &self,
        key: [u8; 32],
        decode_verify: impl Fn(&[u8]) -> Option<T>,
        freshness: impl Fn(&T) -> (u64, u64),
    ) -> Option<T> {
        let candidates = recursive_dht_get_candidates(
            &self.dht,
            &self.session_tx_registry,
            &self.pending_recursive,
            self.local_node_id,
            key,
            self.step_timeout,
            veil_proto::budget::DHT_REPLICATION_K,
            |b| decode_verify(b).is_some(),
        )
        .await;
        let mut decoded: Vec<(T, Vec<u8>)> = candidates
            .into_iter()
            .filter_map(|bytes| decode_verify(&bytes).map(|v| (v, bytes)))
            .collect();
        decoded.sort_by_key(|(v, _)| std::cmp::Reverse(freshness(v)));
        let (winner, bytes) = decoded.into_iter().next()?;
        // Keep other DHT consumers (and our own next walk) from re-reading a
        // known-older value from the ordinary local mirror.
        self.dht.store_local(key, bytes);
        Some(winner)
    }

    /// Recursive DHT FIND_VALUE walk — delegates to the shared
    /// [`recursive_dht_get`] free function (also used by the rendezvous
    /// resolver), passing this resolver's shared references.
    async fn dht_recursive_get(
        &self,
        key: [u8; 32],
        timeout: Duration,
        direct_peer: Option<[u8; 32]>,
        is_valid: impl Fn(&[u8]) -> bool,
    ) -> Option<Vec<u8>> {
        recursive_dht_get(
            &self.dht,
            &self.session_tx_registry,
            &self.pending_recursive,
            self.local_node_id,
            key,
            timeout,
            direct_peer,
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
///
/// `direct_peer` is the **connected-peer fast path** for cold routing tables:
/// when resolving a record that the target node itself is the authoritative
/// publisher of (its own relay-key / identity document) AND we already hold a
/// live session to that node, the XOR-closest top-2 fan is pointless — the
/// holder is right there on a connected socket. So if `direct_peer` is `Some`
/// and that node is in our current session set, the `FIND_VALUE` is sent ONLY
/// to it (it answers authoritatively from its own `store_local`), bypassing the
/// recursive walk that times out on a barely-warm table after a restart. This
/// is anonymity-safe: we send only to the relay we will OPENLY register a
/// mailbox publisher with — it already knows we're connected — and the value is
/// still verified byte-identically by `is_valid` / the caller's signature
/// check, so a hostile direct peer can only withhold, never forge. All other
/// callers (ML-KEM EK, rendezvous-ad, and third-party document lookups) pass
/// `None` and keep the XOR-closest walk.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) async fn recursive_dht_get(
    dht: &Arc<KademliaService>,
    session_tx_registry: &Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: &Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    key: [u8; 32],
    timeout: Duration,
    direct_peer: Option<[u8; 32]>,
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
        // Connected-peer fast path: if we're resolving a record whose
        // authoritative holder is a node we have a live session to, ask only it
        // (it answers from its own store_local) instead of walking the cold
        // table. Fall back to the XOR-closest top-2 fan when the direct peer is
        // not connected (or no direct peer was given).
        let direct_targets: Vec<[u8; 32]> = match direct_peer {
            Some(dp) if peers.contains(&dp) => vec![dp],
            _ => peers.iter().take(2).copied().collect(),
        };
        for pid in &direct_targets {
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

/// Fetch independently-served candidates for one DHT key, including a valid
/// local value but never letting that local value short-circuit the network
/// fan-out.  Rendezvous ads need this stronger read than the ordinary
/// [`recursive_dht_get`]: after a receiver moves to another relay, its old ad
/// remains correctly signed and unexpired, yet its `(relay, cookie)` is no
/// longer live. Comparing replies from several directly-connected DHT peers is
/// what lets the caller select the newest `valid_from_unix` and repair its
/// local mirror.
///
/// Each peer gets a distinct query id. A shared query id would complete on the
/// first response and reproduce the original first-replica-wins bug.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recursive_dht_get_candidates<F>(
    dht: &Arc<KademliaService>,
    session_tx_registry: &Arc<RwLock<SessionTxRegistry>>,
    pending_recursive: &Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
    local_node_id: [u8; 32],
    key: [u8; 32],
    timeout: Duration,
    max_peers: usize,
    is_valid: F,
) -> Vec<Vec<u8>>
where
    F: Fn(&[u8]) -> bool,
{
    let mut out = Vec::new();
    if let Some(value) = dht.get_local(&key)
        && is_valid(&value)
    {
        out.push(value);
    }

    let mut peers: Vec<[u8; 32]> = rlock!(session_tx_registry).peer_ids();
    peers.sort_by_key(|pid| {
        let mut xor = [0u8; 32];
        for i in 0..32 {
            xor[i] = pid[i] ^ key[i];
        }
        xor
    });
    peers.truncate(max_peers.clamp(1, veil_proto::budget::DHT_REPLICATION_K));
    if peers.is_empty() {
        return out;
    }

    struct Query {
        query_id: [u8; 16],
        peer: [u8; 32],
        frame: Vec<u8>,
        rx: tokio::sync::oneshot::Receiver<Vec<u8>>,
    }

    let mut queries = Vec::with_capacity(peers.len());
    for peer in peers {
        let mut query_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut query_id);
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

        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = lock!(pending_recursive);
            pending.retain(|_, p| !p.tx.is_closed());
            if pending.len() >= veil_proto::budget::MAX_PENDING_RECURSIVE {
                break;
            }
            pending.insert(
                query_id,
                PendingRecursive {
                    target_key: key,
                    query_type: recursive_query_type::FIND_VALUE,
                    tx,
                },
            );
        }
        queries.push(Query {
            query_id,
            peer,
            frame,
            rx,
        });
    }

    // Only wait for frames that actually entered a live session queue.
    let mut sent = Vec::with_capacity(queries.len());
    {
        let guard = rlock!(session_tx_registry);
        for query in queries {
            if guard.send_to(
                &query.peer,
                veil_proto::header::priority::INTERACTIVE,
                query.frame.clone(),
            ) {
                sent.push(query);
            } else {
                lock!(pending_recursive).remove(&query.query_id);
            }
        }
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let query_ids: Vec<_> = sent.iter().map(|q| q.query_id).collect();
    let mut replies: futures::stream::FuturesUnordered<_> = sent
        .into_iter()
        .map(|query| async move {
            tokio::time::timeout_at(deadline, query.rx)
                .await
                .ok()
                .and_then(Result::ok)
        })
        .collect();
    use futures::StreamExt;
    while let Some(reply) = replies.next().await {
        if let Some(bytes) = reply
            && !bytes.is_empty()
            && is_valid(&bytes)
        {
            out.push(bytes);
        }
    }
    // Dispatcher removes successful entries; this also clears timed-out ones.
    let mut pending = lock!(pending_recursive);
    for query_id in query_ids {
        pending.remove(&query_id);
    }
    drop(pending);

    // Exact duplicates from replicated holders carry no additional routing
    // information and only inflate the downstream sort/cache.
    out.sort();
    out.dedup();
    out
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
            Arc::new(RwLock::new(PeerMlKemCertCache::new())),
            Arc::new(NodeLogger::new_noop()),
        )
    }

    /// Resolver whose verified-cert cache we hold a handle to, so a test can
    /// pre-seed it and observe the Step-0 fast path.
    fn make_test_resolver_with_cert_cache(
        dht: Arc<KademliaService>,
        cert_cache: Arc<RwLock<PeerMlKemCertCache>>,
    ) -> DhtMlKemEkResolver {
        DhtMlKemEkResolver::new(
            dht,
            Arc::new(RwLock::new(SessionTxRegistry::new())),
            Arc::new(Mutex::new(std::collections::HashMap::new())),
            [1u8; 32],
            Arc::new(RwLock::new(PeerMlKemCache::new())),
            cert_cache,
            Arc::new(NodeLogger::new_noop()),
        )
    }

    fn dummy_cert(node_id: [u8; 32]) -> VerifiedMlkemCert {
        VerifiedMlkemCert {
            node_id,
            instance_id: [0xab; 16],
            mlkem_algo: 1,
            mlkem_pubkey: vec![0x42; 32],
            cert_version: 7,
        }
    }

    // The verified-cert fast path is what makes the offline mailbox-seal +
    // live-E2E encrypt paths fast: a recently-resolved cert short-circuits the
    // 3-step DHT walk. With NO peers configured a real walk yields `None`, so a
    // `Some(_)` here can ONLY have come from the cache.
    #[tokio::test]
    async fn fetch_verified_cert_returns_fresh_cache_entry_without_dht() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let target = [9u8; 32];
        let cert_cache = Arc::new(RwLock::new(PeerMlKemCertCache::new()));
        wlock!(cert_cache).insert(target, (dummy_cert(target), std::time::Instant::now()));
        let resolver = make_test_resolver_with_cert_cache(Arc::clone(&dht), cert_cache);
        assert_eq!(
            resolver.fetch_verified_cert(target).await,
            Some(dummy_cert(target)),
            "a fresh cached cert must short-circuit the DHT walk"
        );
    }

    // TTL gate: with TTL = 0 even a just-inserted entry is stale, so the fast
    // path is skipped and the peerless DHT walk yields `None`. Proves the TTL
    // is actually enforced — a stale entry never gets served past rotation.
    #[tokio::test]
    async fn fetch_verified_cert_ignores_expired_cache_entry() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let target = [9u8; 32];
        let cert_cache = Arc::new(RwLock::new(PeerMlKemCertCache::new()));
        wlock!(cert_cache).insert(target, (dummy_cert(target), std::time::Instant::now()));
        let resolver = make_test_resolver_with_cert_cache(Arc::clone(&dht), cert_cache)
            .with_cert_ttl(Duration::from_secs(0));
        assert_eq!(
            resolver.fetch_verified_cert(target).await,
            None,
            "an expired cache entry must NOT short-circuit; must fall through to the DHT"
        );
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
            .dht_recursive_get(key, Duration::from_millis(50), None, |_| false)
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
            .dht_recursive_get(key, Duration::from_millis(50), None, |_| true)
            .await;
        assert_eq!(got, Some(b"good".to_vec()));
    }

    // Rendezvous regression: a valid local value must be INCLUDED but must not
    // end the lookup. Each connected replica gets its own query id, so a fresh
    // value held by one seed survives another seed returning the same stale
    // value as our local mirror. The rendezvous layer can then compare
    // `valid_from_unix` and choose the fresh route.
    #[tokio::test]
    async fn recursive_get_candidates_does_not_short_circuit_on_valid_local_value() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let key = [42u8; 32];
        let stale = b"valid-stale-ad".to_vec();
        let fresh = b"valid-fresh-ad".to_vec();
        dht.store_local(key, stale.clone());

        let mut reg = SessionTxRegistry::new();
        let rx_a = reg.register([10u8; 32]);
        let rx_b = reg.register([20u8; 32]);
        let registry = Arc::new(RwLock::new(reg));
        let pending = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let spawn_answer =
            |mut rx: tokio::sync::mpsc::Receiver<veil_session::PriorityFrame>,
             pending: Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,
             value: Vec<u8>| {
                tokio::spawn(async move {
                    let (_, frame) = rx.recv().await.expect("replica query frame");
                    let query = RecursiveQueryPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .expect("decode recursive FIND_VALUE");
                    let waiter = lock!(pending)
                        .remove(&query.query_id)
                        .expect("query registered before send");
                    let _ = waiter.tx.send(value);
                })
            };
        let answer_a = spawn_answer(rx_a, Arc::clone(&pending), stale.clone());
        let answer_b = spawn_answer(rx_b, Arc::clone(&pending), fresh.clone());

        let got = recursive_dht_get_candidates(
            &dht,
            &registry,
            &pending,
            [1u8; 32],
            key,
            Duration::from_secs(1),
            2,
            |_| true,
        )
        .await;
        answer_a.await.unwrap();
        answer_b.await.unwrap();

        assert_eq!(got.len(), 2, "exact stale duplicates are deduplicated");
        assert!(got.contains(&stale), "valid local candidate is preserved");
        assert!(got.contains(&fresh), "fresh remote candidate is not hidden");
    }

    // Connected-peer fast path: when `direct_peer` is Some AND that node is in
    // our live session set, the FIND_VALUE is sent ONLY to it (it answers
    // authoritatively from its own store_local) — never the XOR-closest top-2
    // fan. This is what lets a cold-restarted node resolve its relay's key in
    // one hop instead of timing out on a barely-warm routing table.
    #[tokio::test]
    async fn recursive_get_direct_peer_targets_only_connected_holder() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let key = [42u8; 32]; // no local value → proceeds to the send fan
        let mut reg = SessionTxRegistry::new();
        let mut rx_a = reg.register([10u8; 32]);
        let mut rx_b = reg.register([20u8; 32]);
        let mut rx_c = reg.register([30u8; 32]);
        let registry = Arc::new(RwLock::new(reg));
        let pending = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let _ = recursive_dht_get(
            &dht,
            &registry,
            &pending,
            [1u8; 32],
            key,
            Duration::from_millis(30),
            Some([20u8; 32]), // a CONNECTED holder
            |_| false,
        )
        .await;
        assert!(
            rx_b.try_recv().is_ok(),
            "the connected direct peer must receive the query"
        );
        assert!(
            rx_a.try_recv().is_err() && rx_c.try_recv().is_err(),
            "non-target peers must NOT be queried on the fast path"
        );
    }

    // When `direct_peer` is set but NOT connected, the resolver must fall back
    // to the unchanged XOR-closest top-2 fan (so a stale/wrong hint never
    // strands the lookup with zero outgoing queries).
    #[tokio::test]
    async fn recursive_get_unconnected_direct_peer_falls_back_to_closest_fan() {
        let dht = Arc::new(KademliaService::new([1u8; 32]));
        let key = [42u8; 32];
        let mut reg = SessionTxRegistry::new();
        let mut rx_a = reg.register([10u8; 32]);
        let mut rx_b = reg.register([20u8; 32]);
        let mut rx_c = reg.register([30u8; 32]);
        let registry = Arc::new(RwLock::new(reg));
        let pending = Arc::new(Mutex::new(std::collections::HashMap::new()));

        let _ = recursive_dht_get(
            &dht,
            &registry,
            &pending,
            [1u8; 32],
            key,
            Duration::from_millis(30),
            Some([99u8; 32]), // NOT in the session set
            |_| false,
        )
        .await;
        let hits = [
            rx_a.try_recv().is_ok(),
            rx_b.try_recv().is_ok(),
            rx_c.try_recv().is_ok(),
        ]
        .into_iter()
        .filter(|x| *x)
        .count();
        assert_eq!(
            hits, 2,
            "an unconnected direct peer must fall back to the top-2 closest fan"
        );
    }
}
