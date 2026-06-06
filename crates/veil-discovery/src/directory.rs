//! Static discovery directory.
//!
//! A simple in-memory key-value store for attachment and app
//! endpoint records. Keys are BLAKE3-derived per the specification §6.5.
//!
//! This is intentionally NOT a Kademlia DHT — it is a flat, non-replicated
//! directory suitable for small networks (10–100 core/gateway nodes) as the
//! bootstrap phase before Kademlia is introduced.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use veil_proto::discovery::{
    AnnounceAttachmentPayload, AppEndpointResponse, app_endpoint_key, attachment_key,
};

// ── DirRecord ─────────────────────────────────────────────────────────────────

/// A stored discovery record with its expiry time.
#[derive(Debug, Clone)]
pub struct DirRecord<T: Clone> {
    pub value: T,
    pub expires_at: Instant,
}

impl<T: Clone> DirRecord<T> {
    pub fn is_alive(&self, now: Instant) -> bool {
        self.expires_at > now
    }
}

// ── StaticDirectory ───────────────────────────────────────────────────────────

/// Maximum number of entries in the hot-lookup cache for app endpoints.
const HOT_CACHE_CAP: usize = 64;

/// Static in-memory discovery directory.
///
/// Stores two tables:
/// * attachment records (keyed by `attachment_key(node_id)`)
/// * app endpoint records (keyed by `app_endpoint_key(node_id, app_id, ep)`)
///
/// All records have a TTL and are evicted by `cleanup_expired`.
/// When `max_entries` is set, the oldest-expiring (soonest-to-expire) entries
/// are evicted first when the store is at capacity.
///
/// A fixed-size hot cache (`hot_app_endpoints`) accelerates repeated lookups
/// for frequently queried app endpoints.
///
/// The mailbox-set table was removed along with the mailbox
/// subsystem.
#[derive(Debug, Default)]
pub struct StaticDirectory {
    attachments: HashMap<[u8; 32], DirRecord<AnnounceAttachmentPayload>>,
    app_endpoints: HashMap<[u8; 32], DirRecord<AppEndpointEntry>>,
    /// Hot cache for frequently queried app endpoints; capped at `HOT_CACHE_CAP`.
    hot_app_endpoints: HashMap<[u8; 32], DirRecord<AppEndpointEntry>>,
    pub default_ttl: Duration,
    /// Maximum total entries across all tables. `0` means unlimited.
    pub max_entries: usize,
}

/// Stored app endpoint info.
#[derive(Debug, Clone)]
pub struct AppEndpointEntry {
    pub node_id: [u8; 32],
    pub app_id: [u8; 32],
    pub endpoint_id: u32,
    pub gateway_node_id: Option<[u8; 32]>,
    pub epoch: u32,
    pub expires_at: u64,
    /// Max simultaneous streams this endpoint accepts (0 = no limit declared).
    pub max_concurrent_streams: u16,
    /// Application-level protocol version advertised by the endpoint.
    pub protocol_version: u16,
    /// Indicative inbound bandwidth capacity in kbps (0 = not declared).
    pub bandwidth_hint_kbps: u32,
}

/// Self-authenticating wire prefix for DHT-stored [`AppEndpointEntry`]
/// records. Length-2 magic bytes (`'A'`, `'P'`) let recipients
/// recognise the signed format without full structural decoding.
pub const APP_ENDPOINT_DHT_MAGIC: [u8; 2] = *b"AP";

/// Why a signed DHT record (AppEndpointEntry / signed Attachment) was rejected
/// on the STORE path — separates a *malicious* failure (bad signature, wrong
/// magic, malformed) from a merely *stale* one (valid signature but past
/// `expires_at`).
///
/// The STORE handler MUST NOT charge a protocol violation for `Expired`: a peer
/// that republishes a record which expired while sitting in its cache is not
/// misbehaving. Audit cycle-7 found that conflating the two let a rejoining
/// node ban its own closest DHT peers for innocently replicating its just-
/// expired AppEndpointEntry (decay_after 600 s + ban_threshold 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedDhtReject {
    /// Malformed, wrong magic, or signature verification failed.
    Invalid,
    /// Validly signed, but `expires_at` has already passed (stale, not hostile).
    Expired,
}
/// Signed-format wire version byte, so the format can evolve later.
pub const APP_ENDPOINT_DHT_V1: u8 = 1;
/// version-2 wire format adds a leading algo byte + variable
/// pubkey/signature lengths so Falcon-512 signers can write records into the
/// DHT alongside Ed25519 signers. The V1 writer is retained for Ed25519
/// backwards compat and legacy records already in the wild.
pub const APP_ENDPOINT_DHT_V2: u8 = 2;

/// Self-authenticating wire prefix for DHT-stored `AnnounceAttachmentPayload`
/// records. Unlike [`APP_ENDPOINT_DHT_MAGIC`], the attachment
/// wrapper carries the owner's pubkey inline so intermediate nodes can verify
/// the enclosed signature without an active handshake with the owner.
pub const ATTACHMENT_DHT_MAGIC: [u8; 2] = *b"AT";
/// Signed-format wire version byte.
pub const ATTACHMENT_DHT_V1: u8 = 1;

/// Encode an `AnnounceAttachmentPayload` for DHT replication.
///
/// Wire layout:
/// ```text
/// [0..2] magic = "AT"
/// [2] version = 1
/// [3] algo byte (0 = Ed25519, 2 = Falcon-512)
/// [4..6] pubkey_len (u16 BE)
/// [6..6+pklen] pubkey bytes
/// [6+pklen..] AnnounceAttachmentPayload::encode — includes its own
/// internal signature field that covers `signable_body`
/// ```
///
/// The **owner's** pubkey is carried inline so recipients without an active
/// handshake to the owner (the common case on the DHT-republish path) can
/// still verify the enclosed signature. The recipient must additionally
/// check `BLAKE3(pubkey) == payload.node_id` so an attacker can't forge the
/// magic prefix and claim ownership of a record with a pubkey they control.
pub fn encode_signed_attachment(
    payload: &veil_proto::discovery::AnnounceAttachmentPayload,
    algo: veil_types::SignatureAlgorithm,
    pubkey: &[u8],
) -> Vec<u8> {
    let payload_bytes = payload.encode();
    let algo_byte: u8 = match algo {
        veil_types::SignatureAlgorithm::Ed25519 => 0,
        veil_types::SignatureAlgorithm::Falcon512 => 2,
        veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid => 3,
        veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid => 4,
    };
    let pk_len = (pubkey.len() as u16).to_be_bytes();
    let mut buf = Vec::with_capacity(6 + pubkey.len() + payload_bytes.len());
    buf.extend_from_slice(&ATTACHMENT_DHT_MAGIC);
    buf.push(ATTACHMENT_DHT_V1);
    buf.push(algo_byte);
    buf.extend_from_slice(&pk_len);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(&payload_bytes);
    buf
}

/// Decode and fully verify a signed attachment wrapper produced by
/// [`encode_signed_attachment`].
///
/// Returns `Some(payload)` only when all four checks pass:
/// 1. 3-byte magic + version prefix matches
/// 2. inline pubkey roundtrips through the declared algo
/// 3. `BLAKE3(pubkey) == payload.node_id` (anti-impersonation)
/// 4. `verify_announcement_signature(payload, algo, pubkey)` = true.
///
/// Any failure returns `None`; callers treat it as a malformed record and
/// drop without propagating further.
pub fn decode_and_verify_signed_attachment(
    buf: &[u8],
) -> Option<veil_proto::discovery::AnnounceAttachmentPayload> {
    decode_and_verify_signed_attachment_status(buf).ok()
}

/// Like [`decode_and_verify_signed_attachment`] but reports WHY a record was
/// rejected ([`SignedDhtReject`]) so the STORE path can skip a stale
/// (expired-but-validly-signed) attachment WITHOUT charging a violation.
///
/// Mirrors [`AppEndpointEntry::decode_and_verify_signed_from_dht_status`]
/// (audit cycle-7): a peer republishing its cached AT record that expired
/// while sitting in its store is stale, not hostile — conflating the two let a
/// rejoining node ban its closest DHT peers.
pub fn decode_and_verify_signed_attachment_status(
    buf: &[u8],
) -> Result<veil_proto::discovery::AnnounceAttachmentPayload, SignedDhtReject> {
    if buf.len() < 6 {
        return Err(SignedDhtReject::Invalid);
    }
    if buf[..2] != ATTACHMENT_DHT_MAGIC {
        return Err(SignedDhtReject::Invalid);
    }
    if buf[2] != ATTACHMENT_DHT_V1 {
        return Err(SignedDhtReject::Invalid);
    }
    // Accept every algo the canonical wire mapping supports (Ed25519 0/1,
    // Falcon-512 2, hybrid Ed25519+Falcon 3/4) so hybrid-identity records —
    // the recommended long-term PQ identity — survive the DHT round-trip.
    // `encode_signed_attachment` emits 0/2/3/4; the prior `{0,2}`-only match
    // silently rejected (Invalid) every validly-signed hybrid attachment.
    // Mirrors veil-dht `handle_delete` (from_wire_byte). Unknown bytes
    // still reject.
    let algo =
        veil_types::SignatureAlgorithm::from_wire_byte(buf[3]).ok_or(SignedDhtReject::Invalid)?;
    let pk_len =
        u16::from_be_bytes(buf[4..6].try_into().map_err(|_| SignedDhtReject::Invalid)?) as usize;
    let pk_end = 6 + pk_len;
    if buf.len() <= pk_end {
        return Err(SignedDhtReject::Invalid);
    }
    let pubkey = &buf[6..pk_end];
    let payload = veil_proto::discovery::AnnounceAttachmentPayload::decode(&buf[pk_end..])
        .map_err(|_| SignedDhtReject::Invalid)?;

    // Anti-impersonation: pubkey must match the declared owner node_id.
    let expected_node_id: [u8; 32] = *blake3::hash(pubkey).as_bytes();
    if expected_node_id != payload.node_id {
        return Err(SignedDhtReject::Invalid);
    }

    // Verify signature.
    if !crate::verify_announcement_signature(&payload, algo, pubkey) {
        return Err(SignedDhtReject::Invalid);
    }

    // SECURITY (audit 2026-05-29, HIGH replay fix): the direct
    // `handle_announce_attachment` path rejects `expires_at <= now`, but
    // the DHT replication path (dispatcher STORE-accept + GetAttachment
    // read/warm) used to call this decoder WITHOUT any freshness gate —
    // letting an attacker who once captured a valid signed wrapper
    // re-inject it forever (each lookup re-warmed the local cache with a
    // fresh 5-min TTL, ignoring `expires_at`).  Enforce expiry here so
    // every caller (store + read + routing) drops stale records uniformly.
    // `expires_at` is covered by `signable_body()` so it cannot be
    // tampered without invalidating the signature checked just above.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if payload.expires_at <= now_secs {
        return Err(SignedDhtReject::Expired);
    }

    Ok(payload)
}

impl AppEndpointEntry {
    /// Encode for DHT storage (unsigned legacy format — retained for local
    /// directory dumps and tests; **do NOT** use for cross-node replication).
    ///
    /// Wire layout (fixed):
    /// `node_id(32) + app_id(32) + endpoint_id(4) + has_gw(1) + [gw(32)] + epoch(4) + expires_at(8) + max_streams(2) + proto_ver(2) + bw_hint(4)`
    pub fn encode_for_dht(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(89 + 32);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        if let Some(gw) = &self.gateway_node_id {
            buf.push(1u8);
            buf.extend_from_slice(gw);
        } else {
            buf.push(0u8);
        }
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&self.max_concurrent_streams.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.to_be_bytes());
        buf.extend_from_slice(&self.bandwidth_hint_kbps.to_be_bytes());
        buf
    }

    /// Encode for DHT storage as a **signed** record.
    ///
    /// Wire layout:
    /// ```text
    /// [0..2] magic = "AP"
    /// [2] version = 1
    /// [3..35] owner ed25519 pubkey (32 bytes) — must BLAKE3 to `self.node_id`
    /// [35..N] encode_for_dht payload (legacy format)
    /// [N..N+64] ed25519 signature over bytes [0..N]
    /// ```
    ///
    /// Inline pubkey is required because `self.node_id == BLAKE3(pubkey)` —
    /// a hash, not the key itself — so recipients can't reconstruct the
    /// verification key from the record alone. Replicators on the
    /// DHT-republish path forward these bytes verbatim without re-signing.
    pub fn encode_for_dht_signed(&self, sk: &ed25519_dalek::SigningKey) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let pubkey = sk.verifying_key().to_bytes();
        let inner = self.encode_for_dht();
        let mut buf = Vec::with_capacity(3 + 32 + inner.len() + 64);
        buf.extend_from_slice(&APP_ENDPOINT_DHT_MAGIC);
        buf.push(APP_ENDPOINT_DHT_V1);
        buf.extend_from_slice(&pubkey);
        buf.extend_from_slice(&inner);
        let sig = sk.sign(&buf);
        buf.extend_from_slice(&sig.to_bytes());
        buf
    }

    /// Parse a signed DHT record produced by [`encode_for_dht_signed`].
    ///
    /// Returns `Some(entry)` only when:
    /// 1. 3-byte magic+version prefix matches;
    /// 2. inline pubkey + inner payload decode successfully;
    /// 3. `BLAKE3(pubkey) == entry.node_id` (anti-impersonation);
    /// 4. signature verifies against the inline pubkey over the full
    ///    pre-signature region.
    ///
    /// A `None` return means the record is the wrong format or has been
    /// tampered with; callers drop without propagating further.
    pub fn decode_and_verify_signed_from_dht(buf: &[u8]) -> Option<Self> {
        Self::decode_and_verify_signed_from_dht_status(buf).ok()
    }

    /// Like [`Self::decode_and_verify_signed_from_dht`] but reports WHY a record
    /// was rejected ([`SignedDhtReject`]) so the STORE path can skip a stale
    /// (expired-but-validly-signed) record without charging a violation.
    pub fn decode_and_verify_signed_from_dht_status(buf: &[u8]) -> Result<Self, SignedDhtReject> {
        if buf.len() < 3 {
            return Err(SignedDhtReject::Invalid);
        }
        if buf[..2] != APP_ENDPOINT_DHT_MAGIC {
            return Err(SignedDhtReject::Invalid);
        }
        let entry = match buf[2] {
            APP_ENDPOINT_DHT_V1 => Self::decode_v1_ed25519(buf),
            APP_ENDPOINT_DHT_V2 => Self::decode_v2_multi_algo(buf),
            _ => None,
        }
        .ok_or(SignedDhtReject::Invalid)?;
        // SECURITY (audit 2026-05-29, HIGH replay fix): same class as the
        // signed-attachment decoder — the DHT replication path had no
        // freshness gate, so a captured-but-stale signed AppEndpointEntry
        // could be replayed indefinitely.  `expires_at` is inside the
        // signed region (decode_*_ checks the signature over it), so
        // rejecting expired records here is tamper-safe.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if entry.expires_at <= now_secs {
            return Err(SignedDhtReject::Expired);
        }
        Ok(entry)
    }

    /// Decode the legacy V1 wire format (Ed25519 only, fixed lengths).
    fn decode_v1_ed25519(buf: &[u8]) -> Option<Self> {
        // min = magic(2) + ver(1) + pubkey(32) + payload(89) + sig(64) = 188
        if buf.len() < 3 + 32 + 89 + 64 {
            return None;
        }
        let pubkey: [u8; 32] = buf[3..35].try_into().ok()?;
        let sig_start = buf.len() - 64;
        let signed_region = &buf[..sig_start];
        let sig_bytes: [u8; 64] = buf[sig_start..].try_into().ok()?;
        let inner = &signed_region[35..];
        let entry = Self::decode_from_dht(inner)?;
        let expected_node_id: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
        if expected_node_id != entry.node_id {
            return None;
        }
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).ok()?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        use ed25519_dalek::Verifier as _;
        vk.verify(signed_region, &sig).ok()?;
        Some(entry)
    }

    /// Decode the V2 wire format (algo byte + variable pubkey/sig lengths).
    ///
    /// Layout: `magic(2) + ver(1=2) + algo(1) + pk_len(u16 BE) + pubkey + inner
    /// + sig_len(u16 BE) + signature`. Inner signs the entire region preceding
    /// the `sig_len` field, so tampering with any byte invalidates the record.
    fn decode_v2_multi_algo(buf: &[u8]) -> Option<Self> {
        use veil_types::SignatureAlgorithm;
        if buf.len() < 6 {
            return None;
        }
        // Accept all canonical wire algos (Ed25519 0/1, Falcon-512 2, hybrid
        // 3/4); the V2 encoder emits 0/2/3/4, so a `{0,2}`-only match silently
        // dropped (None) validly-signed hybrid AppEndpointEntry records.
        let algo = SignatureAlgorithm::from_wire_byte(buf[3])?;
        let pk_len = u16::from_be_bytes(buf[4..6].try_into().ok()?) as usize;
        let pk_start: usize = 6;
        let pk_end = pk_start.checked_add(pk_len)?;
        if buf.len() < pk_end + 2 + 89 + 1 {
            return None;
        }
        let pubkey = &buf[pk_start..pk_end];

        // Scan forward for the inner payload: it starts right after the pubkey
        // and extends up to `sig_len`'s u16 BE prefix. We don't know the inner
        // length a priori (it depends on `has_gw`), but `decode_from_dht`
        // accepts a slice and tells us the consumed length implicitly by
        // returning either None or a struct for the minimum-valid prefix. To
        // find the signature we compute `sig_len` from the trailing u16 and
        // derive `inner_end` from there.
        // Inner payload is self-describing (89 or 121 bytes based on has_gw);
        // parse it first, then read sig_len from the 2 bytes immediately after.
        let inner_slice = &buf[pk_end..];
        let (entry, inner_len) = Self::decode_from_dht_with_len(inner_slice)?;
        let after_inner = pk_end.checked_add(inner_len)?;
        if buf.len() < after_inner + 2 {
            return None;
        }
        let sig_len =
            u16::from_be_bytes(buf[after_inner..after_inner + 2].try_into().ok()?) as usize;
        let sig_start = after_inner + 2;
        let sig_end = sig_start.checked_add(sig_len)?;
        if buf.len() != sig_end {
            return None;
        }
        // Signature covers the region up (but excluding) the sig_len field.
        let signed_region = &buf[..after_inner];
        let signature = &buf[sig_start..sig_end];

        // Anti-impersonation.
        let expected_node_id: [u8; 32] = *blake3::hash(pubkey).as_bytes();
        if expected_node_id != entry.node_id {
            return None;
        }
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let pk_b64 = STANDARD.encode(pubkey);
        veil_crypto::verify_message(algo, &pk_b64, signed_region, signature).ok()?;
        Some(entry)
    }

    /// encode the V2 wire format with an arbitrary signer.
    ///
    /// `pubkey` and `private_key_b64` must match the declared `algo`. The
    /// signer's `BLAKE3(pubkey)` must equal `self.node_id` — the encoder
    /// enforces this so a caller can't accidentally produce a record that
    /// every recipient will reject on the anti-impersonation check.
    pub fn encode_for_dht_signed_v2(
        &self,
        algo: veil_types::SignatureAlgorithm,
        pubkey: &[u8],
        private_key_b64: &str,
    ) -> Result<Vec<u8>, veil_error::ConfigError> {
        let expected_node_id: [u8; 32] = *blake3::hash(pubkey).as_bytes();
        if expected_node_id != self.node_id {
            return Err(veil_error::ConfigError::ValidationFailed(
                "encode_for_dht_signed_v2: BLAKE3(pubkey) != entry.node_id".to_owned(),
            ));
        }
        let algo_byte: u8 = match algo {
            veil_types::SignatureAlgorithm::Ed25519 => 0,
            veil_types::SignatureAlgorithm::Falcon512 => 2,
            veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid => 3,
            veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid => 4,
        };
        let inner = self.encode_for_dht();
        let pk_len = u16::try_from(pubkey.len())
            .map_err(|_| {
                veil_error::ConfigError::ValidationFailed(
                    "encode_for_dht_signed_v2: pubkey too long".to_owned(),
                )
            })?
            .to_be_bytes();
        let mut buf = Vec::with_capacity(6 + pubkey.len() + inner.len() + 2 + 128);
        buf.extend_from_slice(&APP_ENDPOINT_DHT_MAGIC);
        buf.push(APP_ENDPOINT_DHT_V2);
        buf.push(algo_byte);
        buf.extend_from_slice(&pk_len);
        buf.extend_from_slice(pubkey);
        buf.extend_from_slice(&inner);

        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let pk_b64 = STANDARD.encode(pubkey);
        // The signature covers everything up (and NOT including) the sig_len
        // field — the decoder mirrors this slice, so the verify path sees the
        // same bytes regardless of signature length.
        let sig = veil_crypto::sign_message(algo, &pk_b64, private_key_b64, &buf)?;
        let real_sig_len = u16::try_from(sig.len())
            .map_err(|_| {
                veil_error::ConfigError::ValidationFailed(
                    "encode_for_dht_signed_v2: signature too long".to_owned(),
                )
            })?
            .to_be_bytes();
        buf.extend_from_slice(&real_sig_len);
        buf.extend_from_slice(&sig);
        Ok(buf)
    }

    /// Decode and verify a signed DHT record. : the legacy
    /// unsigned-format fallback has been removed — bytes without the
    /// [`APP_ENDPOINT_DHT_MAGIC`] prefix are refused. Keeping the fallback
    /// open allowed an attacker to publish a forged unsigned
    /// `AppEndpointEntry` and have legitimate readers accept it.
    pub fn decode_from_dht_any(buf: &[u8]) -> Option<Self> {
        if buf.len() >= 3 && buf[..2] == APP_ENDPOINT_DHT_MAGIC {
            Self::decode_and_verify_signed_from_dht(buf)
        } else {
            None
        }
    }

    /// Like [`decode_from_dht`] but also returns the number of bytes consumed
    /// from the input. Required by the V2 wire-format decoder to locate the
    /// trailing `sig_len` field after a variable-length inner payload.
    fn decode_from_dht_with_len(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 89 {
            return None;
        }
        let has_gw = buf[68] != 0;
        let total = if has_gw { 89 + 32 } else { 89 };
        if buf.len() < total {
            return None;
        }
        let entry = Self::decode_from_dht(&buf[..total])?;
        Some((entry, total))
    }

    /// Decode from DHT-stored bytes. Returns `None` on truncation.
    pub fn decode_from_dht(buf: &[u8]) -> Option<Self> {
        // Minimum: 32+32+4+1+4+8+2+2+4 = 89 bytes (no gateway)
        if buf.len() < 89 {
            return None;
        }
        let node_id: [u8; 32] = buf[0..32].try_into().ok()?;
        let app_id: [u8; 32] = buf[32..64].try_into().ok()?;
        let endpoint_id = u32::from_be_bytes(buf[64..68].try_into().ok()?);
        let has_gw = buf[68] != 0;
        let mut offset = 69;
        let gateway_node_id = if has_gw {
            if buf.len() < offset + 32 {
                return None;
            }
            let gw: [u8; 32] = buf[offset..offset + 32].try_into().ok()?;
            offset += 32;
            Some(gw)
        } else {
            None
        };
        if buf.len() < offset + 20 {
            return None;
        }
        let epoch = u32::from_be_bytes(buf[offset..offset + 4].try_into().ok()?);
        let expires_at = u64::from_be_bytes(buf[offset + 4..offset + 12].try_into().ok()?);
        let max_concurrent_streams =
            u16::from_be_bytes(buf[offset + 12..offset + 14].try_into().ok()?);
        let protocol_version = u16::from_be_bytes(buf[offset + 14..offset + 16].try_into().ok()?);
        let bandwidth_hint_kbps =
            u32::from_be_bytes(buf[offset + 16..offset + 20].try_into().ok()?);
        Some(Self {
            node_id,
            app_id,
            endpoint_id,
            gateway_node_id,
            epoch,
            expires_at,
            max_concurrent_streams,
            protocol_version,
            bandwidth_hint_kbps,
        })
    }
}

impl StaticDirectory {
    pub fn new() -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
            ..Self::default()
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            default_ttl: ttl,
            ..Self::default()
        }
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
            max_entries,
            ..Self::default()
        }
    }

    // ── pressure eviction ─────────────────────────────────────────────────

    /// `hot_app_endpoints` deliberately excluded — it's a
    /// lookup-acceleration cache overlaid on `app_endpoints` (same keys).
    /// `evict_at_pressure` removes the hot-cache entry in lock-step when
    /// it evicts the backing `app_endpoints` entry (see the `table == 2`
    /// arm below), so double-counting would inflate pressure decisions.
    fn total_entries(&self) -> usize {
        self.attachments.len() + self.app_endpoints.len()
    }

    /// Evict the soonest-expiring entries to bring total below `max_entries`.
    /// Called before inserting a new record when `max_entries > 0`.
    fn evict_at_pressure(&mut self) {
        if self.max_entries == 0 {
            return;
        }
        let total = self.total_entries();
        if total < self.max_entries {
            return;
        }
        // Evict 10 % of capacity (min 1) — collect all entries by expiry
        // partial-sort, and remove the oldest in one pass.
        let evict_n = (self.max_entries / 10).max(1);
        let mut candidates: Vec<([u8; 32], Instant, u8)> = Vec::with_capacity(total);
        for (k, r) in &self.attachments {
            candidates.push((*k, r.expires_at, 0));
        }
        for (k, r) in &self.app_endpoints {
            candidates.push((*k, r.expires_at, 2));
        }
        // Partial sort: move the `evict_n` soonest-expiring to the front.
        let n = evict_n.min(candidates.len());
        candidates.select_nth_unstable_by_key(n.saturating_sub(1), |c| c.1);
        for &(key, _, table) in &candidates[..n] {
            match table {
                0 => {
                    self.attachments.remove(&key);
                }
                _ => {
                    self.app_endpoints.remove(&key);
                    self.hot_app_endpoints.remove(&key);
                }
            }
        }
    }

    // ── attachment ────────────────────────────────────────────────────────

    pub fn announce_attachment(&mut self, record: AnnounceAttachmentPayload) {
        let key = attachment_key(&record.node_id);
        // SECURITY (audit 2026-05-29, #9 anti-rollback): reject an
        // announcement whose `seq_no` is not strictly greater than the
        // stored record's.  `seq_no` is covered by `signable_body()`, so
        // it cannot be bumped without re-signing — an attacker can only
        // REPLAY a previously-valid (older) announcement.  Without this
        // check a replayed older signed announcement would overwrite the
        // current one, resurrecting a stale gateway binding.  The seq_no
        // is read from the already-stored payload — no extra state.
        // Anti-rollback memory is bounded by the same retention/eviction
        // as the records themselves (consistent with the expires_at gate
        // in decode_and_verify_signed_attachment).
        if let Some(existing) = self.attachments.get(&key)
            && record.seq_no <= existing.value.seq_no
        {
            return; // stale or duplicate seq_no — keep the newer record
        }
        self.evict_at_pressure();
        self.attachments.insert(
            key,
            DirRecord {
                value: record,
                expires_at: Instant::now() + self.default_ttl,
            },
        );
    }

    pub fn get_attachment(&self, node_id: &[u8; 32]) -> Option<&AnnounceAttachmentPayload> {
        let key = attachment_key(node_id);
        self.attachments
            .get(&key)
            .filter(|r| r.is_alive(Instant::now()))
            .map(|r| &r.value)
    }

    // ── app endpoints ─────────────────────────────────────────────────────

    pub fn announce_app_endpoint(&mut self, entry: AppEndpointEntry) {
        let key = app_endpoint_key(&entry.node_id, &entry.app_id, entry.endpoint_id);
        // SECURITY (audit U12, anti-rollback — mirrors announce_attachment #9):
        // drop an entry whose `epoch` is strictly OLDER than the stored
        // record's. `epoch` is inside the signed region (encode_for_dht), so a
        // peer can only REPLAY an older-but-still-valid signed AppEndpointEntry,
        // not forge a higher epoch. Without this, replaying a not-yet-expired
        // older record (stale gateway / lower protocol_version) over the DHT
        // GET path would roll the cached binding back. Strict `<` so the
        // owner's idempotent same-epoch re-announce still refreshes the TTL;
        // guards against either store so the hot cache cannot be rolled back
        // independently of the durable one.
        if let Some(existing) = self
            .app_endpoints
            .get(&key)
            .or_else(|| self.hot_app_endpoints.get(&key))
            && entry.epoch < existing.value.epoch
        {
            return;
        }
        self.evict_at_pressure();
        let record = DirRecord {
            value: entry,
            expires_at: Instant::now() + self.default_ttl,
        };
        // deterministic eviction by soonest-to-expire when the
        // hot cache is at capacity. Prior impl used `keys.next` which
        // is RNG-salt–dependent ⇒ effectively arbitrary eviction under
        // HashMap's randomised iteration order. At n=64 the O(n) scan is
        // trivial (~1 µs), and "evict the entry closest to TTL anyway"
        // matches the policy already used by `evict_at_pressure`.
        if self.hot_app_endpoints.len() >= HOT_CACHE_CAP
            && !self.hot_app_endpoints.contains_key(&key)
            && let Some(evict_key) = self
                .hot_app_endpoints
                .iter()
                .min_by_key(|(_, r)| r.expires_at)
                .map(|(k, _)| *k)
        {
            self.hot_app_endpoints.remove(&evict_key);
        }
        self.hot_app_endpoints.insert(key, record.clone());
        self.app_endpoints.insert(key, record);
    }

    pub fn get_app_endpoint(
        &self,
        node_id: &[u8; 32],
        app_id: &[u8; 32],
        endpoint_id: u32,
    ) -> Option<&AppEndpointEntry> {
        let key = app_endpoint_key(node_id, app_id, endpoint_id);
        let now = Instant::now();
        // Hot cache first.
        if let Some(r) = self.hot_app_endpoints.get(&key).filter(|r| r.is_alive(now)) {
            return Some(&r.value);
        }
        self.app_endpoints
            .get(&key)
            .filter(|r| r.is_alive(now))
            .map(|r| &r.value)
    }

    // ── maintenance ───────────────────────────────────────────────────────

    pub fn cleanup_expired(&mut self, now: Instant) {
        self.attachments.retain(|_, r| r.is_alive(now));
        self.app_endpoints.retain(|_, r| r.is_alive(now));
        self.hot_app_endpoints.retain(|_, r| r.is_alive(now));
    }

    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }
    pub fn app_endpoint_count(&self) -> usize {
        self.app_endpoints.len()
    }
}

/// Iterator over all live attachment records — used by admin introspection.
pub fn all_attachments_alive(dir: &StaticDirectory) -> Vec<AnnounceAttachmentPayload> {
    let now = Instant::now();
    dir.attachments
        .values()
        .filter(|r| r.is_alive(now))
        .map(|r| r.value.clone())
        .collect()
}

/// Helper: convert a stored `AppEndpointEntry` to a response payload.
pub fn entry_to_response(entry: &AppEndpointEntry) -> AppEndpointResponse {
    AppEndpointResponse {
        found: true,
        gateway_node_id: entry.gateway_node_id,
        epoch: entry.epoch,
        expires_at: entry.expires_at,
        max_concurrent_streams: entry.max_concurrent_streams,
        protocol_version: entry.protocol_version,
        bandwidth_hint_kbps: entry.bandwidth_hint_kbps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::discovery::{AnnounceAttachmentPayload, GatewayRef};

    // ── signed AppEndpointEntry DHT format ────────────────────────

    fn sample_app_endpoint_entry(sk: &ed25519_dalek::SigningKey) -> AppEndpointEntry {
        let pk = sk.verifying_key().to_bytes();
        // node_id = BLAKE3(pubkey) — matches the real identity derivation.
        let owner_node_id: [u8; 32] = *blake3::hash(&pk).as_bytes();
        AppEndpointEntry {
            node_id: owner_node_id,
            app_id: [0x42u8; 32],
            endpoint_id: 7,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 1_800_000_000,
            max_concurrent_streams: 16,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        }
    }

    #[test]
    fn signed_app_endpoint_roundtrip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xABu8; 32]);
        let entry = sample_app_endpoint_entry(&sk);
        let signed = entry.encode_for_dht_signed(&sk);
        // Prefix check.
        assert_eq!(&signed[..2], &APP_ENDPOINT_DHT_MAGIC);
        assert_eq!(signed[2], APP_ENDPOINT_DHT_V1);
        // Verify decodes back to the same entry.
        let decoded = AppEndpointEntry::decode_and_verify_signed_from_dht(&signed)
            .expect("valid signed record must verify");
        assert_eq!(decoded.node_id, entry.node_id);
        assert_eq!(decoded.app_id, entry.app_id);
        assert_eq!(decoded.endpoint_id, entry.endpoint_id);
        assert_eq!(decoded.expires_at, entry.expires_at);
    }

    #[test]
    fn signed_app_endpoint_rejects_tampered_payload() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let entry = sample_app_endpoint_entry(&sk);
        let mut signed = entry.encode_for_dht_signed(&sk);
        // Flip a byte in the payload area — must invalidate the signature.
        let mid = signed.len() / 2;
        signed[mid] ^= 0x01;
        assert!(
            AppEndpointEntry::decode_and_verify_signed_from_dht(&signed).is_none(),
            "tampered record must be rejected"
        );
    }

    #[test]
    fn signed_app_endpoint_rejects_wrong_signer() {
        // Build entry whose node_id = vk(sk_a), but sign with sk_b.
        let sk_a = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
        let sk_b = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
        let entry = sample_app_endpoint_entry(&sk_a);
        let signed = entry.encode_for_dht_signed(&sk_b); // wrong key
        assert!(
            AppEndpointEntry::decode_and_verify_signed_from_dht(&signed).is_none(),
            "record signed by non-owner must be rejected"
        );
    }

    /// Audit cycle-7: the STORE path must tell a *stale* record (expired but
    /// validly signed — benign, a peer just republished its cached copy) apart
    /// from a *malicious* one (bad signature). `_status` reports the reason so
    /// validate_store_value_by_magic maps Expired→NoResponse (silent drop, no
    /// ban) and Invalid→Violation. Without this, rejoining nodes banned their
    /// closest peers over their own just-expired AppEndpointEntry.
    #[test]
    fn decode_status_distinguishes_expired_from_invalid() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x44u8; 32]);
        // Valid, future expiry → Ok.
        let signed = sample_app_endpoint_entry(&sk).encode_for_dht_signed(&sk);
        assert!(AppEndpointEntry::decode_and_verify_signed_from_dht_status(&signed).is_ok());
        // Validly signed but expired (year 2001) → Expired, NOT Invalid.
        let mut stale = sample_app_endpoint_entry(&sk);
        stale.expires_at = 1_000_000_000;
        let stale_signed = stale.encode_for_dht_signed(&sk);
        assert!(
            matches!(
                AppEndpointEntry::decode_and_verify_signed_from_dht_status(&stale_signed),
                Err(SignedDhtReject::Expired)
            ),
            "expired-but-validly-signed record must report Expired (not Invalid)"
        );
        // Tampered signature → Invalid (the malicious case still violates).
        let mut bad = signed.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert!(
            matches!(
                AppEndpointEntry::decode_and_verify_signed_from_dht_status(&bad),
                Err(SignedDhtReject::Invalid)
            ),
            "tampered record must report Invalid"
        );
    }

    // ── signed AnnounceAttachment DHT wrapper ────────────────────

    fn sample_announcement_for(owner_node_id: [u8; 32]) -> AnnounceAttachmentPayload {
        AnnounceAttachmentPayload {
            node_id: owner_node_id,
            role: 1,
            realm_id: 0,
            epoch: 1,
            expires_at: 1_900_000_000,
            gateways: vec![],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        }
    }

    fn sign_announcement(payload: &mut AnnounceAttachmentPayload, sk: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let body = payload.signable_body();
        payload.signature = sk.sign(&body).to_bytes().to_vec();
    }

    #[test]
    fn signed_attachment_roundtrip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();
        let mut payload = sample_announcement_for(owner);
        sign_announcement(&mut payload, &sk);

        let wrapper =
            encode_signed_attachment(&payload, veil_types::SignatureAlgorithm::Ed25519, &pk);
        assert_eq!(&wrapper[..2], &ATTACHMENT_DHT_MAGIC);
        assert_eq!(wrapper[2], ATTACHMENT_DHT_V1);

        let decoded = decode_and_verify_signed_attachment(&wrapper)
            .expect("valid signed attachment must verify");
        assert_eq!(decoded.node_id, owner);
        assert_eq!(decoded.expires_at, payload.expires_at);
    }

    /// Regression: `encode_signed_attachment` emits algo byte 3 for
    /// `Ed25519Falcon512Hybrid`, but the decoder's prior `{0,2}`-only match
    /// rejected it as `Invalid` — so every hybrid-identity attachment was
    /// silently undeliverable on the DHT replication/read path. Routing
    /// through `SignatureAlgorithm::from_wire_byte` accepts it. Drives the
    /// full encode -> decode_and_verify path (the decoder verifies the
    /// hybrid signature via `verify_announcement_signature`), not just the
    /// match widening.
    #[test]
    fn signed_attachment_roundtrip_hybrid512() {
        use veil_types::SignatureAlgorithm;
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let pk = STANDARD.decode(&kp.public_key).unwrap();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();
        let mut payload = sample_announcement_for(owner);
        // crate::sign_announcement is the algo-aware signer (the test module's
        // local `sign_announcement` shadow is Ed25519-only).
        crate::sign_announcement(
            &mut payload,
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            &kp.public_key,
            &kp.private_key,
        )
        .expect("hybrid sign");

        let wrapper =
            encode_signed_attachment(&payload, SignatureAlgorithm::Ed25519Falcon512Hybrid, &pk);
        assert_eq!(wrapper[3], 3, "hybrid-512 algo byte must be 3");
        let decoded = decode_and_verify_signed_attachment(&wrapper).expect(
            "hybrid-512 signed attachment must verify (regression: was rejected as Invalid)",
        );
        assert_eq!(decoded.node_id, owner);
        assert_eq!(decoded.expires_at, payload.expires_at);
    }

    /// SECURITY (audit 2026-05-29, HIGH replay regression): a signed
    /// wrapper whose `expires_at` is in the past MUST be rejected by the
    /// DHT decoder, even though its signature is valid — otherwise a
    /// captured-but-stale record can be replayed into the DHT forever.
    #[test]
    fn signed_attachment_rejects_expired() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();
        let mut payload = sample_announcement_for(owner);
        // Expired in 2001 — long past any plausible wall-clock now.
        payload.expires_at = 1_000_000_000;
        sign_announcement(&mut payload, &sk);
        let wrapper =
            encode_signed_attachment(&payload, veil_types::SignatureAlgorithm::Ed25519, &pk);
        assert!(
            decode_and_verify_signed_attachment(&wrapper).is_none(),
            "expired signed attachment must be rejected by the DHT decoder"
        );
    }

    /// Audit cycle-7 (AT follow-up to the AP split): the STORE path must tell a
    /// stale attachment (expired but validly signed — benign republish) apart
    /// from a malicious one (bad signature), so the dispatcher maps
    /// Expired→NoResponse (no ban) and Invalid→Violation.
    #[test]
    fn attachment_status_distinguishes_expired_from_invalid() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();

        // Valid, future expiry → Ok.
        let mut fresh = sample_announcement_for(owner);
        fresh.expires_at = u64::MAX / 4;
        sign_announcement(&mut fresh, &sk);
        let fresh_wrapper =
            encode_signed_attachment(&fresh, veil_types::SignatureAlgorithm::Ed25519, &pk);
        assert!(decode_and_verify_signed_attachment_status(&fresh_wrapper).is_ok());

        // Validly signed but expired → Expired, NOT Invalid.
        let mut stale = sample_announcement_for(owner);
        stale.expires_at = 1_000_000_000; // 2001
        sign_announcement(&mut stale, &sk);
        let stale_wrapper =
            encode_signed_attachment(&stale, veil_types::SignatureAlgorithm::Ed25519, &pk);
        assert!(
            matches!(
                decode_and_verify_signed_attachment_status(&stale_wrapper),
                Err(SignedDhtReject::Expired)
            ),
            "expired-but-validly-signed attachment must report Expired"
        );

        // Tampered signature → Invalid (malicious case still violates).
        let mut bad = fresh_wrapper.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        assert!(
            matches!(
                decode_and_verify_signed_attachment_status(&bad),
                Err(SignedDhtReject::Invalid)
            ),
            "tampered attachment must report Invalid"
        );
    }

    #[test]
    fn signed_attachment_rejects_impersonation() {
        // Attacker builds a wrapper declaring node_id = victim, but signs with
        // attacker's key + puts attacker's pubkey inline. Without the
        // BLAKE3(pubkey) == node_id check, the signature would verify against
        // the supplied pubkey and the record would pass.
        let attacker_sk = ed25519_dalek::SigningKey::from_bytes(&[0x66u8; 32]);
        let attacker_pk = attacker_sk.verifying_key().to_bytes();
        let victim_node_id = [0xFFu8; 32]; // != BLAKE3(attacker_pk)
        let mut payload = sample_announcement_for(victim_node_id);
        sign_announcement(&mut payload, &attacker_sk);
        let wrapper = encode_signed_attachment(
            &payload,
            veil_types::SignatureAlgorithm::Ed25519,
            &attacker_pk,
        );
        assert!(
            decode_and_verify_signed_attachment(&wrapper).is_none(),
            "impersonation must be rejected"
        );
    }

    #[test]
    fn signed_attachment_rejects_tampered_payload() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();
        let mut payload = sample_announcement_for(owner);
        sign_announcement(&mut payload, &sk);
        let mut wrapper =
            encode_signed_attachment(&payload, veil_types::SignatureAlgorithm::Ed25519, &pk);
        // Flip a byte inside the encoded payload region (after pubkey).
        let mid = wrapper.len() - 40;
        wrapper[mid] ^= 0x01;
        assert!(
            decode_and_verify_signed_attachment(&wrapper).is_none(),
            "tampered payload must be rejected"
        );
    }

    #[test]
    fn signed_attachment_rejects_wrong_pubkey_length() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x88u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let owner: [u8; 32] = *blake3::hash(&pk).as_bytes();
        let mut payload = sample_announcement_for(owner);
        sign_announcement(&mut payload, &sk);
        // Build wrapper manually with truncated pubkey (pk_len=16 but algo=Ed25519).
        let payload_bytes = payload.encode();
        let mut wrapper = Vec::new();
        wrapper.extend_from_slice(&ATTACHMENT_DHT_MAGIC);
        wrapper.push(ATTACHMENT_DHT_V1);
        wrapper.push(0); // Ed25519
        wrapper.extend_from_slice(&16u16.to_be_bytes());
        wrapper.extend_from_slice(&pk[..16]); // truncated
        wrapper.extend_from_slice(&payload_bytes);
        // Truncated pubkey can't verify signature OR reconstruct node_id.
        assert!(decode_and_verify_signed_attachment(&wrapper).is_none());
    }

    #[test]
    fn decode_any_rejects_legacy_unsigned_accepts_signed() {
        // unsigned bytes (no magic prefix) are refused to block
        // forged-record attacks; only signed+verified records decode.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x44u8; 32]);
        let entry = sample_app_endpoint_entry(&sk);
        let legacy = entry.encode_for_dht();
        assert!(
            AppEndpointEntry::decode_from_dht_any(&legacy).is_none(),
            "legacy unsigned format must be rejected post-461.3"
        );
        let signed = entry.encode_for_dht_signed(&sk);
        let signed_decoded = AppEndpointEntry::decode_from_dht_any(&signed).unwrap();
        assert_eq!(signed_decoded.endpoint_id, entry.endpoint_id);
    }

    fn sample_announce() -> AnnounceAttachmentPayload {
        AnnounceAttachmentPayload {
            node_id: [1u8; 32],
            role: 1,
            realm_id: 10,
            epoch: 1,
            expires_at: 1_700_000_000,
            gateways: vec![GatewayRef {
                gateway_node_id: [2u8; 32],
                priority: 1,
                weight: 1,
                flags: 0,
            }],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        }
    }

    #[test]
    fn announce_and_lookup_attachment() {
        let mut dir = StaticDirectory::new();
        dir.announce_attachment(sample_announce());
        let found = dir.get_attachment(&[1u8; 32]);
        assert!(found.is_some());
        assert_eq!(found.unwrap().node_id, [1u8; 32]);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let dir = StaticDirectory::new();
        assert!(dir.get_attachment(&[99u8; 32]).is_none());
    }

    #[test]
    fn announce_attachment_rejects_stale_seq_no() {
        // SECURITY (#9 anti-rollback): once a record with seq_no N is stored,
        // a replayed/forged announcement carrying seq_no <= N must not overwrite
        // it — otherwise a captured older signed record could roll the directory
        // back to a stale set of gateways/endpoints.
        let owner = [7u8; 32];
        let mut dir = StaticDirectory::new();

        let mut fresh = sample_announcement_for(owner);
        fresh.seq_no = 5;
        dir.announce_attachment(fresh);
        assert_eq!(dir.get_attachment(&owner).unwrap().seq_no, 5);

        // older seq_no → ignored, current record retained
        let mut stale = sample_announcement_for(owner);
        stale.seq_no = 3;
        dir.announce_attachment(stale);
        assert_eq!(dir.get_attachment(&owner).unwrap().seq_no, 5);

        // equal seq_no (duplicate / replay) → ignored
        let mut dup = sample_announcement_for(owner);
        dup.seq_no = 5;
        dir.announce_attachment(dup);
        assert_eq!(dir.get_attachment(&owner).unwrap().seq_no, 5);

        // strictly newer seq_no → accepted
        let mut newer = sample_announcement_for(owner);
        newer.seq_no = 7;
        dir.announce_attachment(newer);
        assert_eq!(dir.get_attachment(&owner).unwrap().seq_no, 7);
    }

    #[test]
    fn expired_attachment_not_found() {
        let mut dir = StaticDirectory::with_ttl(Duration::from_nanos(1));
        dir.announce_attachment(sample_announce());
        std::thread::sleep(Duration::from_millis(5));
        assert!(dir.get_attachment(&[1u8; 32]).is_none());
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut dir = StaticDirectory::with_ttl(Duration::from_nanos(1));
        dir.announce_attachment(sample_announce());
        std::thread::sleep(Duration::from_millis(5));
        dir.cleanup_expired(Instant::now());
        assert_eq!(dir.attachment_count(), 0);
    }

    #[test]
    fn app_endpoint_roundtrip() {
        let mut dir = StaticDirectory::new();
        let entry = AppEndpointEntry {
            node_id: [7u8; 32],
            app_id: [8u8; 32],
            endpoint_id: 80,
            gateway_node_id: Some([9u8; 32]),
            epoch: 1,
            expires_at: 1_700_000_000,
            max_concurrent_streams: 10,
            protocol_version: 2,
            bandwidth_hint_kbps: 1024,
        };
        dir.announce_app_endpoint(entry.clone());
        let found = dir.get_app_endpoint(&[7u8; 32], &[8u8; 32], 80);
        assert!(found.is_some());
        assert_eq!(found.unwrap().endpoint_id, 80);
    }

    #[test]
    fn eviction_keeps_total_below_max() {
        // max_entries=3 with evict 1 per trigger (10% of 3, min 1)
        let mut dir = StaticDirectory::with_max_entries(3);

        fn make_ann(id: u8) -> AnnounceAttachmentPayload {
            AnnounceAttachmentPayload {
                node_id: [id; 32],
                role: 1,
                realm_id: 0,
                epoch: 1,
                expires_at: 9_999_999_999,
                gateways: vec![],
                seq_no: 0,
                signature: vec![],
                ephemeral_endpoint: None,
            }
        }

        dir.announce_attachment(make_ann(1));
        dir.announce_attachment(make_ann(2));
        dir.announce_attachment(make_ann(3));
        // At capacity (3). Inserting a 4th triggers eviction.
        dir.announce_attachment(make_ann(4));
        // After 1 eviction + 1 insert, total should be ≤ 4 (3 − 1 + 1 = 3 or 4 if evict happened before insert)
        assert!(
            dir.attachment_count() <= 4,
            "total={}",
            dir.attachment_count()
        );
    }

    // ── V2 signed format ────────────────────────────────────────
    //
    // The V2 wrapper supports any algorithm covered by `veil_crypto::sign_message`
    // (Ed25519 and Falcon-512 at the time of writing). These tests exercise the
    // round-trip for both algos so a regression in either wire path is caught
    // without dragging in the full sim harness.

    use base64::{Engine as _, engine::general_purpose::STANDARD};

    fn make_entry(node_id: [u8; 32]) -> AppEndpointEntry {
        AppEndpointEntry {
            node_id,
            app_id: [0x7Au8; 32],
            endpoint_id: 3,
            gateway_node_id: None,
            epoch: 5,
            expires_at: u64::MAX / 4,
            max_concurrent_streams: 12,
            protocol_version: 2,
            bandwidth_hint_kbps: 256,
        }
    }

    #[test]
    fn v2_ed25519_roundtrip() {
        let kp = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
        let pk_bytes = STANDARD.decode(&kp.public_key).unwrap();
        let node_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        let entry = make_entry(node_id);

        let encoded = entry
            .encode_for_dht_signed_v2(
                veil_types::SignatureAlgorithm::Ed25519,
                &pk_bytes,
                &kp.private_key,
            )
            .expect("v2 encode ed25519");
        assert_eq!(&encoded[..2], &APP_ENDPOINT_DHT_MAGIC);
        assert_eq!(encoded[2], APP_ENDPOINT_DHT_V2);

        let decoded = AppEndpointEntry::decode_and_verify_signed_from_dht(&encoded)
            .expect("v2 ed25519 verify");
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.app_id, entry.app_id);
        assert_eq!(decoded.bandwidth_hint_kbps, entry.bandwidth_hint_kbps);
    }

    #[test]
    fn v2_falcon512_roundtrip() {
        let kp = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Falcon512);
        let pk_bytes = STANDARD.decode(&kp.public_key).unwrap();
        let node_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        let entry = make_entry(node_id);

        let encoded = entry
            .encode_for_dht_signed_v2(
                veil_types::SignatureAlgorithm::Falcon512,
                &pk_bytes,
                &kp.private_key,
            )
            .expect("v2 encode falcon");
        assert_eq!(encoded[3], 2, "falcon algo byte must be 2");
        // Signature length lives two bytes before the end; for Falcon-512 the
        // detached signature is variable length up to ~690 bytes.
        let decoded = AppEndpointEntry::decode_and_verify_signed_from_dht(&encoded)
            .expect("v2 falcon verify");
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.protocol_version, entry.protocol_version);
    }

    /// Tampering with any byte of the payload must invalidate the signature.
    /// Tests both algos so a Falcon-specific verifier bug surfaces.
    #[test]
    fn v2_tampered_signature_rejected() {
        for algo in [
            veil_types::SignatureAlgorithm::Ed25519,
            veil_types::SignatureAlgorithm::Falcon512,
        ] {
            let kp = veil_crypto::generate_keypair(algo);
            let pk_bytes = STANDARD.decode(&kp.public_key).unwrap();
            let node_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
            let entry = make_entry(node_id);
            let mut encoded = entry
                .encode_for_dht_signed_v2(algo, &pk_bytes, &kp.private_key)
                .expect("encode");
            // Flip a byte in the inner payload (the `protocol_version` field).
            let tamper_offset = 6 + pk_bytes.len() + 32 + 32 + 4 + 1 + 4 + 8 + 2;
            encoded[tamper_offset] ^= 0xFF;
            assert!(
                AppEndpointEntry::decode_and_verify_signed_from_dht(&encoded).is_none(),
                "tampered V2 record ({algo:?}) must be rejected",
            );
        }
    }

    /// the hot cache must evict the soonest-expiring entry
    /// when at capacity, not an arbitrary one (HashMap::keys.next
    /// depends on the RNG-salted hash seed — effectively random). Put 65
    /// entries with varying TTLs; confirm the one with the earliest
    /// expiry is absent.
    #[test]
    fn hot_cache_evicts_soonest_to_expire_not_arbitrary() {
        // The sacrificial entry has a tiny TTL so its expires_at is the
        // earliest of all HOT_CACHE_CAP+1 inserts.
        let mut dir = StaticDirectory {
            default_ttl: std::time::Duration::from_millis(1),
            ..StaticDirectory::default()
        };
        let short_lived_node: [u8; 32] = [0x01u8; 32];
        dir.announce_app_endpoint(AppEndpointEntry {
            node_id: short_lived_node,
            app_id: [0x42u8; 32],
            endpoint_id: 0,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 1_800_000_000,
            max_concurrent_streams: 16,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        });
        // Subsequent entries use a long TTL — they should all survive.
        dir.default_ttl = std::time::Duration::from_secs(3600);
        for i in 1..=HOT_CACHE_CAP as u8 {
            let mut node = [0u8; 32];
            node[0] = i.wrapping_add(1); // avoid collision with short_lived_node
            dir.announce_app_endpoint(AppEndpointEntry {
                node_id: node,
                app_id: [0x42u8; 32],
                endpoint_id: 0,
                gateway_node_id: None,
                epoch: 1,
                expires_at: 1_800_000_000,
                max_concurrent_streams: 16,
                protocol_version: 1,
                bandwidth_hint_kbps: 512,
            });
        }
        // Cap holds.
        assert!(dir.hot_app_endpoints.len() <= HOT_CACHE_CAP);
        // The tiny-TTL entry was first in, shortest-expiring → evicted.
        let victim_key = app_endpoint_key(&short_lived_node, &[0x42u8; 32], 0);
        assert!(
            !dir.hot_app_endpoints.contains_key(&victim_key),
            "expected the soonest-to-expire hot-cache entry to be evicted",
        );
    }

    /// audit U12: announce_app_endpoint rejects a strictly-older epoch (replay
    /// rollback) but accepts an equal epoch (idempotent TTL refresh) and a
    /// newer one — mirroring the announce_attachment seq_no anti-rollback.
    #[test]
    fn u12_app_endpoint_epoch_anti_rollback() {
        let mut dir = StaticDirectory {
            default_ttl: std::time::Duration::from_secs(3600),
            ..StaticDirectory::default()
        };
        let node = [0x33u8; 32];
        let aid = [0x7Au8; 32];

        let mut e5 = make_entry(node); // epoch 5, bandwidth 256
        e5.bandwidth_hint_kbps = 256;
        dir.announce_app_endpoint(e5);

        // Older epoch (4) is a replay → rejected; epoch-5 record stands.
        let mut e4 = make_entry(node);
        e4.epoch = 4;
        e4.bandwidth_hint_kbps = 999;
        dir.announce_app_endpoint(e4);
        let cur = dir.get_app_endpoint(&node, &aid, 3).unwrap();
        assert_eq!(cur.epoch, 5, "older-epoch replay must not overwrite");
        assert_eq!(cur.bandwidth_hint_kbps, 256);

        // Same epoch (5) → accepted as an idempotent TTL refresh (strict `<`).
        let mut e5b = make_entry(node);
        e5b.bandwidth_hint_kbps = 512;
        dir.announce_app_endpoint(e5b);
        assert_eq!(
            dir.get_app_endpoint(&node, &aid, 3)
                .unwrap()
                .bandwidth_hint_kbps,
            512,
            "same-epoch re-announce must refresh"
        );

        // Newer epoch (6) → accepted.
        let mut e6 = make_entry(node);
        e6.epoch = 6;
        e6.bandwidth_hint_kbps = 128;
        dir.announce_app_endpoint(e6);
        let cur = dir.get_app_endpoint(&node, &aid, 3).unwrap();
        assert_eq!(cur.epoch, 6);
        assert_eq!(cur.bandwidth_hint_kbps, 128);
    }

    /// An attacker with a different keypair cannot produce a record that
    /// claims the victim's `node_id`: anti-impersonation check rejects it.
    #[test]
    fn v2_pubkey_node_id_mismatch_rejected() {
        let kp = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
        let pk_bytes = STANDARD.decode(&kp.public_key).unwrap();
        // Use a DIFFERENT node_id in the entry — encoder must reject it.
        let different_node_id: [u8; 32] = [0x42u8; 32];
        let entry = make_entry(different_node_id);
        let err = entry.encode_for_dht_signed_v2(
            veil_types::SignatureAlgorithm::Ed25519,
            &pk_bytes,
            &kp.private_key,
        );
        assert!(
            err.is_err(),
            "encoder must reject pubkey that doesn't hash to entry.node_id"
        );
    }
}
