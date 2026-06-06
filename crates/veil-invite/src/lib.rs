//! Invite-bundle: compact signed credential for out-of-band sharing of
//! a trusted veil listener's contact info.
//!
//! ## Use case
//!
//! Alice runs an veil node with a `visibility = "trusted"` listener
//! (not advertised in DHT/PEX).  Bob wants k connect.  Alice generates an
//! invite-bundle containing:
//! - Listener's `transport` URI (`obfs4-tcp://1.2.3.4:7821`, etc).
//! - Listener's PSK (so Bob's obfs4 handshake succeeds).
//! - Alice's `node_id` + verifying-key fingerprint.
//! - Expiry timestamp.
//! - Ed25519 signature from Alice's identity key over the canonical body.
//!
//! Alice displays it as QR on a screen / paste-able text.  Bob's veil
//! daemon scans or imports the bundle, adds it to `bootstrap_peers` +
//! drops the PSK into a psk-file.  Subsequent connections use the
//! trusted listener.
//!
//! ## Format
//!
//! Wire: CBOR-encoded `InviteBundleV1` → base32 (RFC 4648, no padding)
//! → optionally rendered to QR via `qrcode` crate.
//!
//! Length: typically 250-350 bytes on base32 (depends on URI length and
//! label).  Fits in QR code v10-15 (mobile camera reads fine).
//!
//! ## Threat model
//!
//! - Anyone holding a bundle CAN connect to the listener (PSK + URI are
//!   enough).  Bundle is a **bearer credential**.  Operator must
//!   distribute through a private channel (Signal, USB stick, QR
//!   shown briefly).
//! - Ed25519 sig over the body prevents tampering (someone editing the
//!   transport URI to redirect to a malicious endpoint will break sig).
//! - Expiry limits damage if a bundle leaks: after the date passes the
//!   bundle is no longer accepted (receiver checks `now < expiry`).
//! - **No** revocation built into the bundle itself; operator must
//!   rotate the PSK or change the listener allowlist to invalidate a
//!   leaked bundle's access.

#![forbid(unsafe_code)]

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Current wire format version.  Bump when CBOR field set changes.
pub const INVITE_VERSION: u8 = 1;

/// Domain-separation tag for the Ed25519 signature.  Prepended before
/// canonical body bytes so sig from one purpose isn't replayable as a
/// sig for another.
pub const INVITE_SIG_DOMAIN: &[u8] = b"veil-invite:v1\0";

/// Max transport URI length (UTF-8 bytes).  Matches the limit on
/// `SignedTransportAnnouncement` for consistency.
pub const MAX_TRANSPORT_URI_LEN: usize = 240;

/// Max human-readable label length.
pub const MAX_LABEL_LEN: usize = 64;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("transport URI too long: {0} > {MAX_TRANSPORT_URI_LEN}")]
    TransportTooLong(usize),

    #[error("label too long: {0} > {MAX_LABEL_LEN}")]
    LabelTooLong(usize),

    #[error("PSK must be 32 bytes, got {0}")]
    BadPskLength(usize),

    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("base32 decode error: {0}")]
    Base32Decode(String),

    #[error("unsupported invite version: {0} (expected {INVITE_VERSION})")]
    UnsupportedVersion(u8),

    #[error("Ed25519 signature verification failed")]
    BadSignature,

    #[error("node_id does not match BLAKE3(verifying_key)")]
    NodeIdMismatch,

    #[error("invite expired: expiry={expiry}, now={now}")]
    Expired { expiry: u64, now: u64 },
}

// ── Bundle structure ────────────────────────────────────────────────────────

/// Invite bundle (CBOR-serializable).  All field names are short
/// (1-2 chars) to minimize wire size in the encoded form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteBundleV1 {
    /// Wire format version.
    pub v: u8,
    /// Listener owner's node_id (32 bytes = BLAKE3(verifying_key)).
    #[serde(with = "serde_bytes")]
    pub nid: Vec<u8>,
    /// Verifying key (Ed25519, 32 bytes).
    #[serde(with = "serde_bytes")]
    pub vk: Vec<u8>,
    /// Transport URI (e.g. `obfs4-tcp://1.2.3.4:7821`).
    pub tr: String,
    /// Pre-shared key (32 bytes) for this listener's obfs4 handshake.
    #[serde(with = "serde_bytes")]
    pub psk: Vec<u8>,
    /// Unix-seconds expiry.  Receivers reject bundles when
    /// `now > expiry`.
    pub exp: u64,
    /// Optional human-readable label ("alice's home node").
    pub lbl: Option<String>,
    /// Ed25519 signature over canonical body (see `signable_bytes`).
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

mod serde_bytes {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // Accept either raw bytes either byte-array sequence (CBOR major-2
        // OR major-4 of u8).
        use serde::Deserialize;
        let b: ciborium::Value = ciborium::Value::deserialize(d)?;
        match b {
            ciborium::Value::Bytes(v) => Ok(v),
            ciborium::Value::Array(arr) => arr
                .into_iter()
                .map(|v| match v {
                    ciborium::Value::Integer(i) => i128::from(i)
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("byte > 255")),
                    _ => Err(serde::de::Error::custom("expected byte")),
                })
                .collect(),
            _ => Err(serde::de::Error::custom("expected bytes")),
        }
    }
}

impl InviteBundleV1 {
    /// Canonical bytes covered by the signature: everything EXCEPT the
    /// sig field itself.  Sig is computed over `INVITE_SIG_DOMAIN ||
    /// signable_bytes`.
    fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.tr.len());
        buf.push(self.v);
        buf.extend_from_slice(&self.nid);
        buf.extend_from_slice(&self.vk);
        buf.extend_from_slice(&(self.tr.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.tr.as_bytes());
        buf.extend_from_slice(&self.psk);
        buf.extend_from_slice(&self.exp.to_be_bytes());
        if let Some(ref lbl) = self.lbl {
            buf.extend_from_slice(&(lbl.len() as u16).to_be_bytes());
            buf.extend_from_slice(lbl.as_bytes());
        } else {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        buf
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, InviteError> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| InviteError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, InviteError> {
        let bundle: Self =
            ciborium::de::from_reader(bytes).map_err(|e| InviteError::CborDecode(e.to_string()))?;
        if bundle.v != INVITE_VERSION {
            return Err(InviteError::UnsupportedVersion(bundle.v));
        }
        if bundle.tr.len() > MAX_TRANSPORT_URI_LEN {
            return Err(InviteError::TransportTooLong(bundle.tr.len()));
        }
        if let Some(ref lbl) = bundle.lbl
            && lbl.len() > MAX_LABEL_LEN
        {
            return Err(InviteError::LabelTooLong(lbl.len()));
        }
        if bundle.psk.len() != 32 {
            return Err(InviteError::BadPskLength(bundle.psk.len()));
        }
        Ok(bundle)
    }

    /// Encode to base32 text (compact ASCII, suitable for QR / copy-paste).
    pub fn to_base32(&self) -> Result<String, InviteError> {
        Ok(BASE32_NOPAD.encode(&self.to_cbor()?))
    }

    /// Decode from base32 text.
    pub fn from_base32(s: &str) -> Result<Self, InviteError> {
        let bytes = BASE32_NOPAD
            .decode(s.trim().as_bytes())
            .map_err(|e| InviteError::Base32Decode(e.to_string()))?;
        Self::from_cbor(&bytes)
    }

    /// Render a Unicode-art QR code suitable for terminal display.
    /// Returns string with each row separated by `\n`.
    pub fn to_qr_ansi(&self) -> Result<String, InviteError> {
        let text = self.to_base32()?;
        let code = qrcode::QrCode::new(text.as_bytes())
            .map_err(|e| InviteError::CborEncode(format!("QR build: {e}")))?;
        Ok(code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build())
    }

    /// Verify the bundle's signature and age.
    ///
    /// Checks (in order):
    /// 1. `nid` length = 32 and `vk` length = 32.
    /// 2. `nid == BLAKE3(vk)` (identity binding — sig under a given vk
    ///    only meaningful if vk hashes to the claimed node_id).
    /// 3. Ed25519 sig over `INVITE_SIG_DOMAIN || signable_bytes`
    ///    verifies against `vk`.
    /// 4. `now_unix < exp` (not expired).
    pub fn verify(&self, now_unix: u64) -> Result<(), InviteError> {
        if self.nid.len() != 32 || self.vk.len() != 32 || self.sig.len() != 64 {
            return Err(InviteError::BadSignature);
        }
        let mut vk_arr = [0u8; 32];
        vk_arr.copy_from_slice(&self.vk);
        let mut nid_arr = [0u8; 32];
        nid_arr.copy_from_slice(&self.nid);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.sig);

        let expected_nid = *blake3::hash(&vk_arr).as_bytes();
        if expected_nid != nid_arr {
            return Err(InviteError::NodeIdMismatch);
        }

        let mut to_verify = Vec::with_capacity(INVITE_SIG_DOMAIN.len() + 256);
        to_verify.extend_from_slice(INVITE_SIG_DOMAIN);
        to_verify.extend_from_slice(&self.signable_bytes());

        let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|_| InviteError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(&to_verify, &sig)
            .map_err(|_| InviteError::BadSignature)?;

        if now_unix >= self.exp {
            return Err(InviteError::Expired {
                expiry: self.exp,
                now: now_unix,
            });
        }
        Ok(())
    }
}

// ── Bundle creation helper ──────────────────────────────────────────────────

/// Build + sign an `InviteBundleV1`.  Validates input lengths up-front
/// (transport URI, label, PSK) and returns an error before touching the
/// signing key if any cap is exceeded.
///
/// `signing_key`'s public part must match the `nid` parameter
/// (otherwise verify() will reject).  Caller is responsible for
/// sourcing the signing_key from the owner's identity key.
pub fn create_bundle(
    signing_key: &SigningKey,
    transport: String,
    psk: [u8; 32],
    expiry_unix: u64,
    label: Option<String>,
) -> Result<InviteBundleV1, InviteError> {
    if transport.len() > MAX_TRANSPORT_URI_LEN {
        return Err(InviteError::TransportTooLong(transport.len()));
    }
    if let Some(ref lbl) = label
        && lbl.len() > MAX_LABEL_LEN
    {
        return Err(InviteError::LabelTooLong(lbl.len()));
    }
    let vk = signing_key.verifying_key().to_bytes();
    let nid = *blake3::hash(&vk).as_bytes();
    let mut draft = InviteBundleV1 {
        v: INVITE_VERSION,
        nid: nid.to_vec(),
        vk: vk.to_vec(),
        tr: transport,
        psk: psk.to_vec(),
        exp: expiry_unix,
        lbl: label,
        sig: vec![0u8; 64],
    };
    let mut to_sign = Vec::with_capacity(INVITE_SIG_DOMAIN.len() + 256);
    to_sign.extend_from_slice(INVITE_SIG_DOMAIN);
    to_sign.extend_from_slice(&draft.signable_bytes());
    draft.sig = signing_key.sign(&to_sign).to_bytes().to_vec();
    Ok(draft)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_bundle() -> InviteBundleV1 {
        create_bundle(
            &test_key(0x42),
            "obfs4-tcp://1.2.3.4:7821".to_owned(),
            [0xCC; 32],
            1_800_000_000, // far-future expiry
            Some("alice's home".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn create_and_verify() {
        let b = sample_bundle();
        assert_eq!(b.v, INVITE_VERSION);
        assert_eq!(b.tr, "obfs4-tcp://1.2.3.4:7821");
        assert_eq!(b.psk, vec![0xCC; 32]);
        b.verify(1_700_000_000).expect("verify ok");
    }

    #[test]
    fn cbor_round_trip() {
        let b = sample_bundle();
        let cbor = b.to_cbor().unwrap();
        let decoded = InviteBundleV1::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, b);
        decoded.verify(1_700_000_000).expect("decoded verifies");
    }

    #[test]
    fn base32_round_trip() {
        let b = sample_bundle();
        let s = b.to_base32().unwrap();
        // Base32 is ASCII uppercase + digits.
        assert!(
            s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "base32 output should be ASCII-uppercase + digits: {s}"
        );
        // Expected length: CBOR ~150 bytes → base32 ≈ 240 chars.
        assert!(s.len() < 500, "base32 too long: {}", s.len());
        let decoded = InviteBundleV1::from_base32(&s).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn base32_strips_whitespace() {
        let b = sample_bundle();
        let s = b.to_base32().unwrap();
        let s_with_ws = format!("\n  {s}  \n");
        let decoded = InviteBundleV1::from_base32(&s_with_ws).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn qr_renders() {
        let b = sample_bundle();
        let qr = b.to_qr_ansi().unwrap();
        // Each row uses 1 char per 2-vertical-pixel; not zero, finite.
        assert!(qr.lines().count() > 5);
    }

    #[test]
    fn tampered_transport_breaks_signature() {
        let mut b = sample_bundle();
        b.tr = "obfs4-tcp://5.6.7.8:9999".to_owned();
        let err = b.verify(1_700_000_000).unwrap_err();
        assert!(matches!(err, InviteError::BadSignature));
    }

    #[test]
    fn tampered_psk_breaks_signature() {
        let mut b = sample_bundle();
        b.psk = vec![0xFF; 32];
        let err = b.verify(1_700_000_000).unwrap_err();
        assert!(matches!(err, InviteError::BadSignature));
    }

    #[test]
    fn wrong_vk_breaks_node_id_binding() {
        let mut b = sample_bundle();
        b.vk = test_key(0xBB).verifying_key().to_bytes().to_vec();
        let err = b.verify(1_700_000_000).unwrap_err();
        assert!(matches!(err, InviteError::NodeIdMismatch));
    }

    #[test]
    fn expired_rejected() {
        let b = sample_bundle();
        // expiry was 1_800_000_000; check with now=2_000_000_000.
        let err = b.verify(2_000_000_000).unwrap_err();
        assert!(matches!(err, InviteError::Expired { .. }));
    }

    #[test]
    fn oversize_transport_rejected_at_create() {
        let huge = "x".repeat(MAX_TRANSPORT_URI_LEN + 1);
        let err = create_bundle(&test_key(0x42), huge, [0; 32], 1, None).unwrap_err();
        assert!(matches!(err, InviteError::TransportTooLong(_)));
    }

    #[test]
    fn oversize_label_rejected_at_create() {
        let huge = "x".repeat(MAX_LABEL_LEN + 1);
        let err = create_bundle(
            &test_key(0x42),
            "tcp://1:1".to_owned(),
            [0; 32],
            1,
            Some(huge),
        )
        .unwrap_err();
        assert!(matches!(err, InviteError::LabelTooLong(_)));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut b = sample_bundle();
        b.v = 99;
        // Sig won't matter — version check runs first.
        let cbor = b.to_cbor().unwrap();
        let err = InviteBundleV1::from_cbor(&cbor).unwrap_err();
        assert!(matches!(err, InviteError::UnsupportedVersion(99)));
    }

    #[test]
    fn decode_rejects_oversize_transport() {
        let b = InviteBundleV1 {
            v: INVITE_VERSION,
            nid: vec![0; 32],
            vk: vec![0; 32],
            tr: "x".repeat(MAX_TRANSPORT_URI_LEN + 1),
            psk: vec![0; 32],
            exp: 1,
            lbl: None,
            sig: vec![0; 64],
        };
        let cbor = b.to_cbor().unwrap();
        let err = InviteBundleV1::from_cbor(&cbor).unwrap_err();
        assert!(matches!(err, InviteError::TransportTooLong(_)));
    }

    /// Two different invites (different PSK) sign to different bytes.
    #[test]
    fn different_psk_yields_different_sig() {
        let a = create_bundle(
            &test_key(0x42),
            "obfs4-tcp://1.2.3.4:7821".to_owned(),
            [0xAA; 32],
            1_800_000_000,
            None,
        )
        .unwrap();
        let b = create_bundle(
            &test_key(0x42),
            "obfs4-tcp://1.2.3.4:7821".to_owned(),
            [0xBB; 32],
            1_800_000_000,
            None,
        )
        .unwrap();
        assert_ne!(a.sig, b.sig);
    }

    /// Wire length sanity: typical bundle fits in QR-friendly size.
    #[test]
    fn wire_length_within_qr_budget() {
        let b = sample_bundle();
        let s = b.to_base32().unwrap();
        // QR code v15 holds ~470 alphanumeric bytes at level-L correction.
        // Realistic bundle: 32(nid) + 32(vk) + 25(tr) + 32(psk) + 8(exp)
        // + 13(lbl) + 64(sig) + CBOR overhead ≈ 200 bytes → ~320 chars base32.
        assert!(
            s.len() <= 470,
            "bundle base32 length {} exceeds QR v15 budget",
            s.len()
        );
    }

    /// PSK is high-entropy; bundle should fail clean if PSK not 32 bytes.
    #[test]
    fn psk_must_be_32_bytes() {
        let mut b = sample_bundle();
        b.psk = vec![0u8; 16]; // wrong size
        let cbor = b.to_cbor().unwrap();
        let err = InviteBundleV1::from_cbor(&cbor).unwrap_err();
        assert!(matches!(err, InviteError::BadPskLength(16)));
    }
}
