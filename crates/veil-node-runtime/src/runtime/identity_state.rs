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
//! `local_identity` and `sovereign_identity` are immutable per-process —
//! reload swaps the whole `Arc<IdentityState>` if either changes (today
//! only the legacy / sovereign upgrade path). Peer caches (Mutex / RwLock
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
use crate::types::NodeIdBytes;
use veil_e2e::{DK_SEED_BYTES, EK_BYTES, PeerMlKemCache};
use veil_identity::sovereign::SovereignIdentity;
use veil_identity::verify::ValidatedIdentity;
use veil_types::PeerLruCache;

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
    pub sovereign_identity: Option<Arc<SovereignIdentity>>,

    /// Cache of `(peer_node_id) → (algo, raw_pubkey_bytes)` for all
    /// peers we've successfully completed an OVL1 handshake with.
    /// Used by the dispatcher's relay-send path to verify cryptographic
    /// signatures on `AnnounceAttachment` frames.
    pub peer_pubkeys: veil_types::PeerPubkeysCache,

    /// peer → `ValidatedIdentity` cache that survives
    /// `reload_with` so session-resumption fast paths (which bypass
    /// the `IdentityProof` exchange) can restore the peer's sovereign
    /// binding.
    pub peer_sovereign_identities:
        Arc<Mutex<std::collections::HashMap<NodeIdBytes, ValidatedIdentity>>>,

    /// Maps `peer_id → roles_supported` bitmask from the handshake (
    /// Cross-checked against advertised capabilities preventing
    /// Gateway-role spoofing.
    pub peer_roles: Arc<Mutex<PeerLruCache<u8>>>,

    /// Local ML-KEM-768 encapsulation key — sent to remotes during
    /// handshake so peers can encrypt payloads for this node.
    pub mlkem_ek: Arc<[u8; EK_BYTES]>,

    /// Peer ML-KEM-768 key cache — populated after each handshake.
    /// Shared with `FrameDispatcher` so the relay-send path can encrypt E2E.
    pub peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,

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

impl IdentityState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_identity: Arc<HandshakeIdentity>,
        sovereign_identity: Option<Arc<SovereignIdentity>>,
        peer_pubkeys: veil_types::PeerPubkeysCache,
        peer_sovereign_identities: Arc<
            Mutex<std::collections::HashMap<NodeIdBytes, ValidatedIdentity>>,
        >,
        peer_roles: Arc<Mutex<PeerLruCache<u8>>>,
        mlkem_ek: Arc<[u8; EK_BYTES]>,
        peer_mlkem_keys: Arc<RwLock<PeerMlKemCache>>,
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
            mlkem_ek,
            peer_mlkem_keys,
            per_session_mlkem_dk,
        }
    }
}
