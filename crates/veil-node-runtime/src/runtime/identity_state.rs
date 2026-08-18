//! decomposition PR5: identity-domain state
//! extracted into a dedicated [`Arc<IdentityState>`].
//!
//! ## Why a dedicated struct
//!
//! Pre-PR5, `NodeRuntime` held eight identity-domain fields directly:
//! the daemon's own handshake / sovereign identity, and five peer-side
//! caches (sovereign IDs, role bitmasks, ML-KEM keys, ML-KEM session
//! dks, pubkeys). All were sprinkled amongst session/dispatcher state.
//!
//! Bundling reduces NodeRuntime field count by 7 (8 fields → 1 Arc field)
//! and groups crypto-identity state together for navigation.
//!
//! ## Reload semantics
//!
//! `local_identity` is immutable per-process — reload swaps the whole
//! `Arc<IdentityState>` if it changes (today only the legacy / sovereign
//! upgrade path). `sovereign_identity` lives in a shared
//! [`SovereignIdentityCell`] so the half-validity delegation re-issue
//! reaches every holder in place. Peer caches (Mutex / RwLock
//! around HashMaps) are mutable in-place; reload mutates inner contents
//! without replacing the Arc, so downstream Arc-clone holders observe new
//! state automatically.
//!
//! ## What's NOT in here
//!
//! `NodeServices` and `SessionRuntimeContext` continue to carry their own
//! direct identity-field clones (built by Arc-clone from NodeRuntime's
//! IdentityState at builder time). Same Arc → same shared state; the
//! downstream contexts' fields are separate ownership handles, not
//! duplicates. Bundling on the smaller contexts didn't reduce field
//! count meaningfully relative to the migration cost (~74 callsites
//! against the 3 contexts combined); this PR limits scope to NodeRuntime
//! only, mirroring PR4 (RoutingState).

use std::sync::{Arc, Mutex, RwLock};

use crate::local_identity::HandshakeIdentity;
use crate::mlkem_resolver::PeerMlKemCertCache;
use crate::types::NodeIdBytes;
use veil_e2e::{DK_SEED_BYTES, PeerMlKemCache};
use veil_identity::sovereign::SovereignIdentity;
use veil_identity::verify::ValidatedIdentity;
use veil_types::PeerLruCache;

/// Hot-swappable holder for the node's own [`SovereignIdentity`].
///
/// All `Arc<IdentityState>` holders share one cell (`Clone` clones the
/// handle, not the contents), so a `set()` from the maintenance
/// re-issue tick is immediately visible to every reader — including
/// the per-handshake `SovereignHandshakeCtx` builder.
#[derive(Clone)]
pub struct SovereignIdentityCell {
    inner: Arc<RwLock<Option<Arc<SovereignIdentity>>>>,
    /// A mirror of `active_instance_id()`, kept in step by this cell.
    ///
    /// The frame dispatcher has to know which of our devices it is in order to
    /// key a ratchet conversation, and it cannot reach `SovereignIdentity` —
    /// veil-identity sits above it. Mirroring the id here rather than
    /// snapshotting it into the dispatcher is what keeps an identity swap from
    /// leaving the receive path answering for a device that is no longer us.
    active_instance: Arc<RwLock<Option<[u8; 16]>>>,
}

impl SovereignIdentityCell {
    pub fn new(initial: Option<Arc<SovereignIdentity>>) -> Self {
        let instance = initial.as_ref().map(|s| s.active_instance_id());
        Self {
            inner: Arc::new(RwLock::new(initial)),
            active_instance: Arc::new(RwLock::new(instance)),
        }
    }

    /// A handle on the active instance id that holders outside this crate can
    /// read. Always the instance of whatever document [`get`](Self::get)
    /// would return.
    pub fn active_instance_handle(&self) -> Arc<RwLock<Option<[u8; 16]>>> {
        Arc::clone(&self.active_instance)
    }

    /// Current document handle (cheap Arc clone; `None` on legacy nodes).
    pub fn get(&self) -> Option<Arc<SovereignIdentity>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Swap in a freshly re-issued / reloaded document.
    pub fn set(&self, doc: Arc<SovereignIdentity>) {
        let instance = doc.active_instance_id();
        *self.inner.write().unwrap_or_else(|p| p.into_inner()) = Some(doc);
        // After, not before: a reader that catches the two writes apart must
        // see the OLD instance for the new document rather than an instance
        // for a document that is not installed yet. Both orders are wrong for
        // one instant; this one cannot name a device we have never published.
        *self
            .active_instance
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(instance);
    }

    pub fn is_none(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }
}

/// Identity-domain state owned by [`crate::node::NodeRuntime`].
pub struct IdentityState {
    /// The daemon's own handshake identity (algo + raw / base64 key
    /// material). Read at every outbound handshake to assemble the
    /// `IdentityPayload`; `Arc<...>` so cloning into per-handshake
    /// contexts is cheap.
    pub local_identity: Arc<HandshakeIdentity>,

    /// optional sovereign-identity handle loaded from disk.
    /// `None` on legacy nodes (pre-462) — they fall back to the
    /// node_id-keyed handshake. Cloned into every outbound handshake
    /// via `SovereignHandshakeCtx`.
    ///
    /// Hot-swappable: the maintenance loop re-issues the standalone
    /// delegation at half-validity and MUST make the fresh document
    /// visible to every long-lived `Arc<IdentityState>` holder — above
    /// all the per-handshake `SovereignHandshakeCtx`. A plain
    /// `Option<Arc<..>>` here froze the boot-time delegation into every
    /// handshake for the life of the process, so any node with more
    /// than `DELEGATION_VALIDITY_SECS` (7 d) of uptime presented an
    /// expired proof and was rejected by every new peer until restart
    /// (observed live on the production seeds, 2026-07-17).
    pub sovereign_identity: SovereignIdentityCell,

    /// Cache of `(peer_node_id) → (algo, raw_pubkey_bytes)` for all
    /// peers we've successfully completed an OVL1 handshake with.
    /// Used by the dispatcher's relay-send path to verify cryptographic
    /// signatures on `AnnounceAttachment` frames.
    pub peer_pubkeys: veil_types::PeerPubkeysCache,

    /// `(peer, device) → ValidatedIdentity` cache that survives `reload_with`
    /// so session-resumption fast paths (which bypass the `IdentityProof`
    /// exchange) can restore the peer's sovereign binding.
    ///
    /// KEYED BY THE PAIR, not by the peer. Several devices of one identity all
    /// present that identity's `node_id` in their HELLO — that is the whole
    /// shape the delegation check exists to allow — so a peer-keyed map holds
    /// one slot for the entire family and each sibling's full handshake
    /// overwrites the last one's binding. A resumption then restores whichever
    /// sibling handshaked most recently, and the session claims to be a device
    /// it is not.
    pub peer_sovereign_identities: PeerSovereignBindings,

    /// Maps `peer_id → roles_supported` bitmask from the handshake (
    /// Cross-checked against advertised capabilities preventing
    /// Gateway-role spoofing.
    pub peer_roles: Arc<Mutex<PeerLruCache<u8>>>,

    /// This node's ML-KEM-768 mailbox keypair, and the retired seeds still
    /// inside their overlap window.
    ///
    /// One holder for both halves. They used to be two fields in two structs —
    /// the public EK here, the secret seed on `NodeRuntime` — which was fine
    /// only while neither could ever change. Rotation makes "which key is
    /// current" a question with a wrong answer available, so the pair lives
    /// behind one lock. See [`veil_e2e::MlKemSeedRing`].
    pub mlkem_keys: Arc<veil_e2e::MlKemSeedRing>,

    /// Peer ML-KEM-768 key cache — populated after each handshake.
    /// Shared with `FrameDispatcher` so the relay-send path can encrypt E2E.
    pub peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,

    /// Verified-cert (full `VerifiedMlkemCert`) fast-path cache, shared across
    /// the live-E2E + offline-mailbox-seal DHT resolver instances so one DHT
    /// walk serves both — kills the per-seal DHT round-trip that made offline
    /// deposit time out / `PeerUnresolved`. See [`PeerMlKemCertCache`].
    pub peer_mlkem_certs: Arc<RwLock<PeerMlKemCertCache>>,

    /// `peer → device X25519 key`, taken from that peer's verified certificate.
    ///
    /// The ratchet counterpart of `peer_mlkem_keys`, and shared with
    /// `CryptoContext` for the same reason: the receive path decides whether a
    /// sender is proven or merely claimed, it runs synchronously inside the
    /// frame dispatcher, and it cannot walk a DHT to find out. Written only
    /// where a certificate is actually verified.
    pub peer_ratchet_keys: Arc<RwLock<veil_e2e::PeerRatchetKeyCache>>,

    /// per-session ephemeral ML-KEM DK seeds shared with
    /// `CryptoContext`. Maps `peer_id → dk_seed`; shared with
    /// `FrameDispatcher` for E2E decryption.
    ///
    /// Phase 6 slice 6h — value type wrapped in `SensitiveBytesN<64>` so
    /// per-session DK seeds are mlocked while the session is open.
    pub per_session_mlkem_dk: Arc<
        Mutex<
            std::collections::HashMap<
                NodeIdBytes,
                veil_util::sensitive_bytes::SensitiveBytesN<DK_SEED_BYTES>,
            >,
        >,
    >,
}

/// `(sovereign node_id, device instance_id) → ValidatedIdentity`.
pub type PeerSovereignBindings =
    Arc<Mutex<std::collections::HashMap<([u8; 32], [u8; 16]), ValidatedIdentity>>>;

impl IdentityState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_identity: Arc<HandshakeIdentity>,
        sovereign_identity: SovereignIdentityCell,
        peer_pubkeys: veil_types::PeerPubkeysCache,
        peer_sovereign_identities: PeerSovereignBindings,
        peer_roles: Arc<Mutex<PeerLruCache<u8>>>,
        mlkem_keys: Arc<veil_e2e::MlKemSeedRing>,
        peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
        peer_mlkem_certs: Arc<RwLock<PeerMlKemCertCache>>,
        peer_ratchet_keys: Arc<RwLock<veil_e2e::PeerRatchetKeyCache>>,
        per_session_mlkem_dk: Arc<
            Mutex<
                std::collections::HashMap<
                    NodeIdBytes,
                    veil_util::sensitive_bytes::SensitiveBytesN<DK_SEED_BYTES>,
                >,
            >,
        >,
    ) -> Self {
        Self {
            local_identity,
            sovereign_identity,
            peer_pubkeys,
            peer_sovereign_identities,
            peer_roles,
            mlkem_keys,
            peer_mlkem_keys,
            peer_mlkem_certs,
            peer_ratchet_keys,
            per_session_mlkem_dk,
        }
    }
}
