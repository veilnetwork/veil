//! Pairing-ceremony invite + QR URI.
//!
//! # Flow (at 30 000 ft)
//!
//! 1. **Source device** (already has `master_sk`) generates a fresh
//! `pair_secret: [u8; 32]` and two distinct surfaces:
//! A signed [`PairingInvite`] published to the DHT, carrying only
//! the **hash** of the pair_secret (so a DHT observer cannot
//! impersonate the target).
//! A QR-encoded `veil:pair` URI (see [`PairingUri`]) containing
//! the **plaintext** pair_secret + a transport endpoint hint.
//! The 6-digit OOB confirmation code lives entirely on-screen — it
//! is NEVER put on the wire, in the QR, or on the DHT.
//!
//! 2. **Target device** (fresh, no identity yet) scans the QR, dials
//! the endpoint, and authenticates to the source by proving it
//! knows the pair_secret. Only a holder of the QR can do this —
//! the DHT-published invite's `pair_secret_hash` lets any peer
//! verify the invite's provenance without leaking the secret
//! itself.
//!
//! 3. The two devices complete the master-certification + OOB-compare
//! handshake (out of scope for this module — those are runtime
//! ceremonies that consume [`PairingInvite`] as one of their
//! inputs).
//!
//! This module owns the three library-layer primitives the ceremony
//! needs: the wire-format invite, the QR URI encode/decode, and the
//! `pair_secret_hash` helper. Everything else (direct-session
//! auth, `master_sk` unlock, OOB code derivation, appending a new
//! `IdentityKey` to the document, [`DeviceLinkedEvent`] emission)
//! ships with the runtime ceremony.
//!
//! # Wire format
//!
//! ```text
//! [0..2] magic b"PI"
//! [2] version u8 (=1)
//! [3..35] node_id [u8; 32]
//! [35..67] pair_secret_hash [u8; 32]
//! [67..83] source_instance_id [u8; 16]
//! [83..91] issued_at_unix u64 BE
//! [91..99] expires_at_unix u64 BE
//! [99..101] signing_identity_key_idx u16 BE
//! [..] sig_len u16 BE
//! [..] sig bytes
//! ```
//!
//! Keyed in the DHT by `BLAKE3("veil.pairing_invite.v1" ||
//! node_id || source_instance_id)` — two source instances
//! issuing invites concurrently don't collide, and re-publishing
//! from the same instance replaces the slot. Receivers drop
//! invites whose `expires_at_unix < now`.
//!
//! # QR URI format
//!
//! ```text
//! veil:pair?id=<64-hex>
//! &secret=<b64url-no-pad pair_secret>
//! &endpoint=<transport url, reserved chars forbidden>
//! &expires=<unix seconds>
//! ```
//!
//! The URI is emitted in canonical field order; the parser accepts
//! any order, is case-insensitive on scheme + field names + hex
//! bytes, and enforces a 4 KiB ceiling.
//!
//! [`DeviceLinkedEvent`]: super::identity_events::DeviceLinkedEvent

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u64};
use veil_util::bytes_to_hex;

// ── Constants ────────────────────────────────────────────────────────────────

pub const PAIRING_INVITE_MAGIC: [u8; 2] = *b"PI";
pub const PAIRING_INVITE_V1: u8 = 1;

/// Domain-separated signing-message prefix. Always prepended to
/// [`PairingInvite::canonical_signing_bytes`] before signing /
/// verifying so a pairing-invite signature cannot be replayed
/// against another record type that happens to share a suffix.
pub const PAIRING_INVITE_SIG_CONTEXT: &[u8] = b"veil.pairing_invite.v1";

/// DHT-key domain separator — same shape as the other 462 records.
pub const PAIRING_INVITE_DHT_CONTEXT: &[u8] = b"veil.pairing_invite_dht.v1";

/// Hash-domain prefix for `pair_secret_hash = BLAKE3(CTX || secret)`.
///
/// Binding the hash to this domain means a pair_secret can never
/// also serve as (say) a frame-authentication token — the two
/// hashes would be derived from different domains and cannot alias.
pub const PAIR_SECRET_HASH_CONTEXT: &[u8] = b"veil.pair_secret.v1";

/// Length of a raw `pair_secret` in bytes (matches the X25519 /
/// BLAKE3 comfort zone).
pub const PAIR_SECRET_LEN: usize = 32;

/// Upper bound on the wire payload — generous headroom over the
/// fixed-shape fields + Falcon-sized signature.
pub const MAX_PAIRING_INVITE_BYTES: usize = 2 * 1024;

/// Upper bound on the `veil:pair` URI we accept — defends
/// against DoS via oversized QR payloads. A canonical URI for
/// Ed25519 + `tcp://<ipv6>:<port>` endpoint fits well under 300 B.
pub const MAX_PAIR_URI_BYTES: usize = 4 * 1024;

/// Upper bound on the endpoint hint (per-field cap).
pub const MAX_ENDPOINT_BYTES: usize = 512;

const MAX_SIG_BYTES: usize = 1024;

/// Canonical URI scheme + path for the pairing QR surface.
pub const PAIR_URI_SCHEME: &str = "veil:pair";

// ── Struct ───────────────────────────────────────────────────────────────────

/// Signed pairing-ceremony invite.
///
/// Produced by `sign_pairing_invite` in the publish-side library;
/// verified + consumed by the runtime pairing ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInvite {
    /// Identity offering the pair (stable `node_id`).
    pub node_id: [u8; 32],
    /// `BLAKE3(PAIR_SECRET_HASH_CONTEXT || pair_secret)` — lets any
    /// peer verify invite provenance without learning the secret.
    pub pair_secret_hash: [u8; 32],
    /// Which of the owner's instances initiated the pair.
    pub source_instance_id: [u8; 16],
    /// Unix seconds when the invite was signed.
    pub issued_at_unix: u64,
    /// Unix seconds after which the invite is dead (receivers MUST
    /// drop). Signer picks — typically `now + 300`.
    pub expires_at_unix: u64,
    /// Index into `IdentityDocument.identity_keys` of the active
    /// subkey that signs this invite.
    pub signing_identity_key_idx: u16,
    /// Signature over `PAIRING_INVITE_SIG_CONTEXT ||
    /// canonical_signing_bytes`.
    pub sig: Vec<u8>,
}

impl PairingInvite {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&PAIRING_INVITE_MAGIC);
        out.push(PAIRING_INVITE_V1);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.pair_secret_hash);
        out.extend_from_slice(&self.source_instance_id);
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_PAIRING_INVITE_BYTES {
            return Err(ProtoError::Malformed(format!(
                "pairing_invite: oversized ({}B > {MAX_PAIRING_INVITE_BYTES}B)",
                buf.len()
            )));
        }
        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&PAIRING_INVITE_MAGIC[..]) {
            return Err(ProtoError::Malformed("pairing_invite: bad magic".into()));
        }
        pos += 2;
        let version = read_u8(buf, &mut pos, "pairing_invite.version")?;
        if version != PAIRING_INVITE_V1 {
            return Err(ProtoError::Malformed(format!(
                "pairing_invite: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "pairing_invite.node_id")?;
        let pair_secret_hash = read_array::<32>(buf, &mut pos, "pairing_invite.pair_secret_hash")?;
        let source_instance_id =
            read_array::<16>(buf, &mut pos, "pairing_invite.source_instance_id")?;
        let issued_at_unix = read_u64(buf, &mut pos, "pairing_invite.issued_at")?;
        let expires_at_unix = read_u64(buf, &mut pos, "pairing_invite.expires_at")?;
        if expires_at_unix < issued_at_unix {
            return Err(ProtoError::Malformed(
                "pairing_invite: expires_at < issued_at".into(),
            ));
        }
        let signing_identity_key_idx = read_u16(buf, &mut pos, "pairing_invite.signing_key_idx")?;
        let sig_len = read_u16(buf, &mut pos, "pairing_invite.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "pairing_invite: sig_len {sig_len} out of range"
            )));
        }
        let sig = read_bytes(buf, &mut pos, sig_len, "pairing_invite.sig")?;

        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "pairing_invite: {} trailing bytes",
                buf.len() - pos
            )));
        }

        Ok(Self {
            node_id,
            pair_secret_hash,
            source_instance_id,
            issued_at_unix,
            expires_at_unix,
            signing_identity_key_idx,
            sig,
        })
    }

    /// Canonical bytes the signature covers — encode output minus the
    /// trailing `sig_len` + `sig` suffix.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// Full signing message: `SIG_CONTEXT || canonical_signing_bytes`.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(PAIRING_INVITE_SIG_CONTEXT.len() + self.encoded_len());
        msg.extend_from_slice(PAIRING_INVITE_SIG_CONTEXT);
        msg.extend_from_slice(&self.canonical_signing_bytes());
        msg
    }

    fn encoded_len(&self) -> usize {
        2 + 1 + 32 + 32 + 16 + 8 + 8 + 2 + 2 + self.sig.len()
    }

    /// Is this invite still live at `now_unix_secs`?
    pub fn is_valid_at(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.issued_at_unix && now_unix_secs <= self.expires_at_unix
    }

    /// DHT key under which this invite is published. Keyed by
    /// `(node_id, source_instance_id)` so re-publishing from the
    /// same source replaces the slot, but concurrent invites from
    /// different instances don't collide.
    pub fn dht_key(node_id: &[u8; 32], source_instance_id: &[u8; 16]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(PAIRING_INVITE_DHT_CONTEXT);
        h.update(node_id);
        h.update(source_instance_id);
        *h.finalize().as_bytes()
    }
}

/// Compute `BLAKE3(PAIR_SECRET_HASH_CONTEXT || pair_secret)` — the
/// value stamped into a published [`PairingInvite::pair_secret_hash`].
///
/// Targets reconstruct this from the plaintext secret they scan out
/// of the QR and compare against the published invite; any mismatch
/// means the invite was not actually offered by the claimed identity.
pub fn hash_pair_secret(pair_secret: &[u8; PAIR_SECRET_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PAIR_SECRET_HASH_CONTEXT);
    h.update(pair_secret);
    *h.finalize().as_bytes()
}

// ── URI surface ──────────────────────────────────────────────────────────────

/// Parsed / to-be-rendered `veil:pair` QR payload.
///
/// Unlike [`PairingInvite`] this struct carries the **plaintext**
/// pair_secret — it's meant for the target device that just scanned
/// the QR. Never log this struct in full; the secret is
/// auth-equivalent for the pairing channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub node_id: [u8; 32],
    pub pair_secret: [u8; PAIR_SECRET_LEN],
    /// Transport endpoint hint (e.g., `tcp://10.0.0.5:45000`). The
    /// URI layer rejects endpoints containing `&`, `=`, `?`, `#`.
    pub endpoint: String,
    /// Convenience mirror [`PairingInvite::expires_at_unix`] so a
    /// target scanning a QR hours after it was printed can reject
    /// without dialing.
    pub expires_at_unix: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairUriError {
    #[error("pair uri: oversized ({got}B > {MAX_PAIR_URI_BYTES}B)")]
    Oversized { got: usize },
    #[error("pair uri: wrong scheme (expected `veil:pair`)")]
    BadScheme,
    #[error("pair uri: missing `?` query separator")]
    MissingQuery,
    #[error("pair uri: missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("pair uri: duplicate field `{field}`")]
    DuplicateField { field: &'static str },
    #[error("pair uri: unknown field `{field}`")]
    UnknownField { field: String },
    #[error("pair uri: malformed pair `{pair}` (expected `key=value`)")]
    MalformedPair { pair: String },
    #[error("pair uri: field `{field}` has invalid hex")]
    InvalidHex { field: &'static str },
    #[error("pair uri: field `{field}` wrong length (got {got}, expected {expected})")]
    WrongLength {
        field: &'static str,
        got: usize,
        expected: usize,
    },
    #[error("pair uri: invalid base64 in field `{field}`")]
    InvalidBase64 { field: &'static str },
    #[error("pair uri: invalid expires value `{0}`")]
    InvalidExpires(String),
    #[error(
        "pair uri: endpoint `{endpoint}` contains reserved character `{ch}` (forbidden: &, =, ?, #)"
    )]
    EndpointReservedChar { endpoint: String, ch: char },
    #[error("pair uri: endpoint empty")]
    EndpointEmpty,
    #[error("pair uri: endpoint oversized ({got}B > {max}B)")]
    EndpointOversized { got: usize, max: usize },
}

impl PairingUri {
    /// Render a canonical `veil:pair?...` URI.
    pub fn to_uri(&self) -> Result<String, PairUriError> {
        validate_endpoint(&self.endpoint)?;
        let mut out = String::with_capacity(PAIR_URI_SCHEME.len() + 128);
        out.push_str(PAIR_URI_SCHEME);
        out.push_str("?id=");
        out.push_str(&bytes_to_hex(&self.node_id));
        out.push_str("&secret=");
        out.push_str(&URL_SAFE_NO_PAD.encode(self.pair_secret));
        out.push_str("&endpoint=");
        out.push_str(&self.endpoint);
        out.push_str("&expires=");
        out.push_str(&self.expires_at_unix.to_string());
        Ok(out)
    }

    /// Parse a canonical URI. Scheme + hex comparison is
    /// case-insensitive; field names are case-sensitive; field order
    /// arbitrary on decode.
    pub fn from_uri(s: &str) -> Result<Self, PairUriError> {
        if s.len() > MAX_PAIR_URI_BYTES {
            return Err(PairUriError::Oversized { got: s.len() });
        }

        let q_idx = s.find('?').ok_or(PairUriError::MissingQuery)?;
        let (head, rest) = s.split_at(q_idx);
        let tail = &rest[1..];

        if !head.eq_ignore_ascii_case(PAIR_URI_SCHEME) {
            return Err(PairUriError::BadScheme);
        }

        let mut id_hex: Option<&str> = None;
        let mut secret_b64: Option<&str> = None;
        let mut endpoint: Option<&str> = None;
        let mut expires_str: Option<&str> = None;

        for pair in tail.split('&') {
            if pair.is_empty() {
                continue;
            }
            let eq = pair
                .find('=')
                .ok_or_else(|| PairUriError::MalformedPair { pair: pair.into() })?;
            let (key, value_eq) = pair.split_at(eq);
            let value = &value_eq[1..];
            match key {
                "id" => {
                    if id_hex.is_some() {
                        return Err(PairUriError::DuplicateField { field: "id" });
                    }
                    id_hex = Some(value);
                }
                "secret" => {
                    if secret_b64.is_some() {
                        return Err(PairUriError::DuplicateField { field: "secret" });
                    }
                    secret_b64 = Some(value);
                }
                "endpoint" => {
                    if endpoint.is_some() {
                        return Err(PairUriError::DuplicateField { field: "endpoint" });
                    }
                    endpoint = Some(value);
                }
                "expires" => {
                    if expires_str.is_some() {
                        return Err(PairUriError::DuplicateField { field: "expires" });
                    }
                    expires_str = Some(value);
                }
                other => {
                    return Err(PairUriError::UnknownField {
                        field: other.into(),
                    });
                }
            }
        }

        let id_hex = id_hex.ok_or(PairUriError::MissingField { field: "id" })?;
        let secret_b64 = secret_b64.ok_or(PairUriError::MissingField { field: "secret" })?;
        let endpoint = endpoint.ok_or(PairUriError::MissingField { field: "endpoint" })?;
        let expires_str = expires_str.ok_or(PairUriError::MissingField { field: "expires" })?;

        let node_id = decode_hex_fixed::<32>(id_hex, "id")?;

        let secret_bytes = URL_SAFE_NO_PAD
            .decode(secret_b64)
            .map_err(|_| PairUriError::InvalidBase64 { field: "secret" })?;
        if secret_bytes.len() != PAIR_SECRET_LEN {
            return Err(PairUriError::WrongLength {
                field: "secret",
                got: secret_bytes.len(),
                expected: PAIR_SECRET_LEN,
            });
        }
        let mut pair_secret = [0u8; PAIR_SECRET_LEN];
        pair_secret.copy_from_slice(&secret_bytes);

        validate_endpoint(endpoint)?;

        let expires_at_unix: u64 = expires_str
            .parse()
            .map_err(|_| PairUriError::InvalidExpires(expires_str.into()))?;

        Ok(Self {
            node_id,
            pair_secret,
            endpoint: endpoint.to_string(),
            expires_at_unix,
        })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), PairUriError> {
    if endpoint.is_empty() {
        return Err(PairUriError::EndpointEmpty);
    }
    if endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(PairUriError::EndpointOversized {
            got: endpoint.len(),
            max: MAX_ENDPOINT_BYTES,
        });
    }
    for ch in endpoint.chars() {
        if matches!(ch, '&' | '=' | '?' | '#') {
            return Err(PairUriError::EndpointReservedChar {
                endpoint: endpoint.to_string(),
                ch,
            });
        }
    }
    Ok(())
}

fn decode_hex_fixed<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], PairUriError> {
    // Audit M-G: reject non-ASCII BEFORE byte-index-slicing the &str below. A
    // multibyte UTF-8 char (from an attacker-supplied pairing URI / QR scan)
    // whose bytes straddle a 2-byte slice boundary would otherwise panic
    // ("byte index N is not a char boundary"). Hex is ASCII, so any non-ASCII
    // input is invalid regardless; over ASCII, byte indices are char boundaries.
    if !s.is_ascii() {
        return Err(PairUriError::InvalidHex { field });
    }
    if !s.len().is_multiple_of(2) {
        return Err(PairUriError::InvalidHex { field });
    }
    if s.len() / 2 != N {
        return Err(PairUriError::WrongLength {
            field,
            got: s.len() / 2,
            expected: N,
        });
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| PairUriError::InvalidHex { field })?;
    }
    Ok(out)
}

// ── Wire helpers ─────────────────────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit M-G: a hex field with a multibyte-UTF-8 char (from an attacker
    /// pairing URI) must return Err, NOT panic on a non-char-boundary slice.
    #[test]
    fn decode_hex_fixed_rejects_multibyte_without_panic_mg() {
        // 61 ASCII + one 3-byte char = 64 bytes: passes the byte-length gates
        // (even, /2 == 32) but a 2-byte slice would straddle the char boundary.
        let s = format!("{}\u{20AC}", "a".repeat(61));
        assert_eq!(s.len(), 64);
        assert!(decode_hex_fixed::<32>(&s, "id").is_err());
    }

    fn sample_invite() -> PairingInvite {
        let secret = [0xAB; PAIR_SECRET_LEN];
        PairingInvite {
            node_id: [0x11; 32],
            pair_secret_hash: hash_pair_secret(&secret),
            source_instance_id: [0x22; 16],
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_000 + 300,
            signing_identity_key_idx: 0,
            sig: vec![0x33; 64],
        }
    }

    #[test]
    fn invite_wire_roundtrip() {
        let inv = sample_invite();
        let bytes = inv.encode();
        assert_eq!(PairingInvite::decode(&bytes).unwrap(), inv);
    }

    #[test]
    fn invite_rejects_bad_magic() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes[0] ^= 0xFF;
        let err = PairingInvite::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("bad magic")));
    }

    #[test]
    fn invite_rejects_unknown_version() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes[2] = 9;
        let err = PairingInvite::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("unsupported version")));
    }

    #[test]
    fn invite_rejects_inverted_validity() {
        let mut inv = sample_invite();
        inv.expires_at_unix = inv.issued_at_unix - 1;
        let err = PairingInvite::decode(&inv.encode()).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("expires_at < issued_at")));
    }

    #[test]
    fn invite_rejects_empty_sig() {
        let mut inv = sample_invite();
        inv.sig.clear();
        let err = PairingInvite::decode(&inv.encode()).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("sig_len")));
    }

    #[test]
    fn invite_rejects_oversized() {
        let bytes = vec![0u8; MAX_PAIRING_INVITE_BYTES + 1];
        let err = PairingInvite::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("oversized")));
    }

    #[test]
    fn invite_rejects_trailing_bytes() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes.push(0xFF);
        let err = PairingInvite::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("trailing")));
    }

    #[test]
    fn invite_rejects_truncated() {
        let inv = sample_invite();
        let bytes = inv.encode();
        let err = PairingInvite::decode(&bytes[..bytes.len() - 3]).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("truncated")));
    }

    #[test]
    fn canonical_signing_bytes_drop_only_sig_suffix() {
        let inv = sample_invite();
        let encoded = inv.encode();
        let canon = inv.canonical_signing_bytes();
        assert_eq!(canon.len(), encoded.len() - 2 - inv.sig.len());
        assert!(encoded.starts_with(&canon));
    }

    #[test]
    fn signing_message_is_context_prefixed() {
        let inv = sample_invite();
        let msg = inv.signing_message();
        assert!(msg.starts_with(PAIRING_INVITE_SIG_CONTEXT));
        assert_eq!(
            &msg[PAIRING_INVITE_SIG_CONTEXT.len()..],
            inv.canonical_signing_bytes()
        );
    }

    #[test]
    fn is_valid_at_covers_window() {
        let inv = sample_invite();
        assert!(!inv.is_valid_at(inv.issued_at_unix - 1));
        assert!(inv.is_valid_at(inv.issued_at_unix));
        assert!(inv.is_valid_at(inv.expires_at_unix));
        assert!(!inv.is_valid_at(inv.expires_at_unix + 1));
    }

    #[test]
    fn dht_key_stable_and_distinct_per_source_instance() {
        let id = [0x11; 32];
        let inst_a = [0x22; 16];
        let inst_b = [0x33; 16];
        let k_a1 = PairingInvite::dht_key(&id, &inst_a);
        let k_a2 = PairingInvite::dht_key(&id, &inst_a);
        let k_b = PairingInvite::dht_key(&id, &inst_b);
        assert_eq!(k_a1, k_a2);
        assert_ne!(k_a1, k_b);
    }

    #[test]
    fn pair_secret_hash_is_domain_separated() {
        let secret = [0x77; PAIR_SECRET_LEN];
        let h1 = hash_pair_secret(&secret);
        let naive = *blake3::hash(&secret).as_bytes();
        assert_ne!(h1, naive, "hash must NOT equal raw BLAKE3(secret)");
        assert_eq!(h1, hash_pair_secret(&secret), "deterministic");
    }

    // ── PairingUri ───────────────────────────────────────────────────────────

    fn sample_uri() -> PairingUri {
        PairingUri {
            node_id: [0x11; 32],
            pair_secret: [0xAB; PAIR_SECRET_LEN],
            endpoint: "tcp://10.0.0.5:45000".into(),
            expires_at_unix: 1_700_000_000 + 300,
        }
    }

    #[test]
    fn pair_uri_roundtrip() {
        let u = sample_uri();
        let encoded = u.to_uri().unwrap();
        assert!(encoded.starts_with("veil:pair?"));
        assert!(encoded.contains("id="));
        assert!(encoded.contains("secret="));
        assert!(encoded.contains("endpoint=tcp://10.0.0.5:45000"));
        assert!(encoded.contains("expires=1700000300"));
        assert_eq!(PairingUri::from_uri(&encoded).unwrap(), u);
    }

    #[test]
    fn pair_uri_scheme_case_insensitive() {
        let u = sample_uri();
        let encoded = u.to_uri().unwrap().replacen("veil:pair", "Veil:Pair", 1);
        assert_eq!(PairingUri::from_uri(&encoded).unwrap(), u);
    }

    #[test]
    fn pair_uri_field_order_arbitrary_on_parse() {
        let u = sample_uri();
        let id_hex = bytes_to_hex(&u.node_id);
        let secret_b64 = URL_SAFE_NO_PAD.encode(u.pair_secret);
        let shuffled = format!(
            "veil:pair?expires={}&endpoint={}&secret={secret_b64}&id={id_hex}",
            u.expires_at_unix, u.endpoint
        );
        assert_eq!(PairingUri::from_uri(&shuffled).unwrap(), u);
    }

    #[test]
    fn pair_uri_rejects_missing_fields() {
        let u = sample_uri();
        let full = u.to_uri().unwrap();
        // Drop the `&secret=...` chunk.
        let stripped = full
            .split('&')
            .filter(|p| !p.starts_with("secret="))
            .collect::<Vec<_>>()
            .join("&");
        let err = PairingUri::from_uri(&stripped).unwrap_err();
        assert!(
            matches!(err, PairUriError::MissingField { field: "secret" }),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_bad_scheme() {
        let err =
            PairingUri::from_uri("mailto:alice?id=11&secret=xx&endpoint=x&expires=0").unwrap_err();
        assert!(matches!(err, PairUriError::BadScheme), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_duplicate_field() {
        let u = sample_uri();
        let full = u.to_uri().unwrap();
        let dup = format!("{full}&secret=AAAA");
        let err = PairingUri::from_uri(&dup).unwrap_err();
        assert!(
            matches!(err, PairUriError::DuplicateField { field: "secret" }),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_unknown_field() {
        let u = sample_uri();
        let full = u.to_uri().unwrap();
        let extra = format!("{full}&mystery=1");
        let err = PairingUri::from_uri(&extra).unwrap_err();
        assert!(matches!(err, PairUriError::UnknownField { .. }), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_malformed_pair() {
        let u = sample_uri();
        let full = u.to_uri().unwrap();
        let extra = format!("{full}&bare");
        let err = PairingUri::from_uri(&extra).unwrap_err();
        assert!(matches!(err, PairUriError::MalformedPair { .. }), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_invalid_hex_id() {
        // 64 non-hex chars — passes the length gate so the hex-check fires.
        let bad_id = "Z".repeat(64);
        let secret = URL_SAFE_NO_PAD.encode([0u8; PAIR_SECRET_LEN]);
        let uri = format!("veil:pair?id={bad_id}&secret={secret}&endpoint=x&expires=0");
        let err = PairingUri::from_uri(&uri).unwrap_err();
        assert!(matches!(err, PairUriError::InvalidHex { .. }), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_wrong_length_secret() {
        let id = bytes_to_hex(&[0x11; 32]);
        // Legal base64 but only 8 bytes decoded (expected 32).
        let uri = format!("veil:pair?id={id}&secret=AAECAwQFBgc&endpoint=x&expires=0");
        let err = PairingUri::from_uri(&uri).unwrap_err();
        assert!(
            matches!(
                err,
                PairUriError::WrongLength {
                    field: "secret",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_invalid_base64_secret() {
        let id = bytes_to_hex(&[0x11; 32]);
        let uri = format!("veil:pair?id={id}&secret=!!!!&endpoint=x&expires=0");
        let err = PairingUri::from_uri(&uri).unwrap_err();
        assert!(
            matches!(err, PairUriError::InvalidBase64 { field: "secret" }),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_invalid_expires() {
        let id = bytes_to_hex(&[0x11; 32]);
        let secret = URL_SAFE_NO_PAD.encode([0u8; PAIR_SECRET_LEN]);
        let uri = format!("veil:pair?id={id}&secret={secret}&endpoint=x&expires=soon");
        let err = PairingUri::from_uri(&uri).unwrap_err();
        assert!(matches!(err, PairUriError::InvalidExpires(_)), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_reserved_char_endpoint() {
        let mut u = sample_uri();
        u.endpoint = "tcp://host?x=1".into();
        let err = u.to_uri().unwrap_err();
        assert!(
            matches!(err, PairUriError::EndpointReservedChar { ch: '?', .. }),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_empty_endpoint() {
        let mut u = sample_uri();
        u.endpoint.clear();
        let err = u.to_uri().unwrap_err();
        assert!(matches!(err, PairUriError::EndpointEmpty), "{err:?}");
    }

    #[test]
    fn pair_uri_rejects_oversized_endpoint() {
        let mut u = sample_uri();
        u.endpoint = "a".repeat(MAX_ENDPOINT_BYTES + 1);
        let err = u.to_uri().unwrap_err();
        assert!(
            matches!(err, PairUriError::EndpointOversized { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn pair_uri_rejects_oversized() {
        let big = "veil:pair?".to_string() + &"a=1&".repeat(MAX_PAIR_URI_BYTES);
        let err = PairingUri::from_uri(&big).unwrap_err();
        assert!(matches!(err, PairUriError::Oversized { .. }), "{err:?}");
    }

    #[test]
    fn hash_of_uri_secret_matches_invite_pair_secret_hash() {
        // End-to-end plausibility: target scans the URI, hashes the
        // scanned secret, and gets back exactly the hash the invite
        // advertised. This is the "no impostor target" check the
        // verifier relies on.
        let uri = sample_uri();
        let inv_hash = hash_pair_secret(&uri.pair_secret);
        assert_eq!(
            inv_hash,
            hash_pair_secret(&[0xAB; PAIR_SECRET_LEN]),
            "sample secret must be deterministic"
        );
        // After the target parses the URI, it should see the same hash
        // by hashing what it scanned.
        let parsed = PairingUri::from_uri(&uri.to_uri().unwrap()).unwrap();
        assert_eq!(hash_pair_secret(&parsed.pair_secret), inv_hash);
    }
}
