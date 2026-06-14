//! Private-veil-network access gate.
//!
//! `NetworkAccessGate` encapsulates the local network's membership
//! policy: which `network_id` we belong to, the owner pubkey that issued
//! certs, the local cert blob to present at handshake. The gate's
//! [`Self::verify_peer`] method takes a peer's HELLO-side cert blob and
//! either returns the decoded cert (admission) or a typed error
//! (rejection).
//!
//! Constructed once at `NodeRuntime` startup from `[network]` config;
//! threaded as an `Option<&NetworkAccessGate>` into the handshake fn.
//! Public-mode nodes pass `None`, which bypasses cert checks entirely.

use std::collections::HashSet;

use crate::network_ban::{ban_dht_key, decode_ban_blob, verify_ban_entry};
use crate::network_cert::{
    CertDecodeError, CertVerifyError, decode_cert_blob, verify_membership_cert,
};
use veil_types::{MembershipCert, SignatureAlgorithm};

/// Cached, validated network handshake context. Cheap to clone (Vec
/// internals + HashSet); shared across handshake invocations via
/// `Arc` from the runtime.
#[derive(Debug, Clone)]
pub struct NetworkAccessGate {
    /// Bincode-encoded `MembershipCert` blob to present in our outbound
    /// HELLO. Pre-encoded at startup so the hot handshake path doesn't
    /// pay serialisation cost per connection.
    pub local_cert_blob: Vec<u8>,
    /// Expected network ID (must match peer cert's `network_id`).
    pub expected_network_id: [u8; 32],
    /// Signature algorithm of the network owner key.
    pub owner_algo: SignatureAlgorithm,
    /// Raw owner public key bytes (already-decoded; pre-loaded from
    /// config so handshake path doesn't pay base64 decode cost).
    pub owner_pubkey_bytes: Vec<u8>,
    /// Admin allowlist (defense-in-depth). Only certs whose
    /// `member_node_id` falls in this set are treated as admin. Empty
    /// set = "any cert with `admin: true` flag is honoured" (config-
    /// driven trust). Used during DHT ban-record verification (P-Net
    /// Phase 3), not at handshake time.
    pub admin_node_ids: HashSet<[u8; 32]>,
}

/// Result variants for peer-cert verification at handshake time.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// Peer's HELLO did not include a `membership_cert_blob` TLV. Local
    /// network is private → rejection.
    #[error("peer did not present a membership cert (network is private)")]
    MissingCert,
    /// Cert verification failed (sig / expiry / wrong network / wrong
    /// algo / version).
    #[error("cert verification failed: {0}")]
    Verify(#[from] CertVerifyError),
    /// Cert blob wire-format decode failed.
    #[error("cert blob decode failed: {0}")]
    Decode(#[from] CertDecodeError),
    /// Cert's `member_node_id` does not match the peer's authenticated
    /// `node_id`. Anti-replay: stops Alice from presenting Bob's cert.
    #[error(
        "cert is not for this peer: cert.member_node_id={cert_node_id_hex} peer_node_id={peer_node_id_hex}"
    )]
    NotForThisPeer {
        cert_node_id_hex: String,
        peer_node_id_hex: String,
    },
}

/// Errors returned by [`NetworkAccessGate::from_config`].
#[derive(Debug, thiserror::Error)]
pub enum GateLoadError {
    #[error("[network] requires `{0}` when mode = \"private\"")]
    MissingField(&'static str),
    #[error("network.network_id is not valid 64-char lowercase hex: {0}")]
    InvalidNetworkId(String),
    #[error("network.owner_pubkey is not valid base64: {0}")]
    InvalidOwnerPubkey(String),
    #[error("network.admin_node_ids[{index}] is not valid 64-char hex: {err}")]
    InvalidAdminNodeId { index: usize, err: String },
    #[error("failed to read membership cert at `{path}`: {io}")]
    CertReadFailed { path: String, io: String },
    #[error("membership cert at `{path}` is malformed: {err}")]
    CertDecodeFailed { path: String, err: String },
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], &'static str> {
    veil_util::hex_to_array::<32>(hex).map_err(|e| match e {
        veil_util::HexError::WrongLength { .. } => "expected 64 hex characters (32-byte value)",
        veil_util::HexError::InvalidByte => "non-hex character",
    })
}

impl NetworkAccessGate {
    /// Build a gate from a fully-validated `[network]` config block. Returns
    /// `Ok(None)` for `mode = "public"` (or missing config) — caller
    /// treats this as "not private network, skip handshake gate".
    /// Returns `Ok(Some(gate))` for `mode = "private"` with everything
    /// loaded and parsed; returns `Err` if cert file read fails, cert blob
    /// is malformed, owner pubkey is not valid base64, or `network_id` /
    /// `admin_node_ids` are not valid 32-byte hex.
    ///
    /// Validation upstream (cfg::validate::structural) already enforces
    /// that the required fields are present when `mode = private`, so
    /// `unwrap`s on `Option::as_ref` are safe here — we re-check defensively
    /// in case the gate is constructed without going through validation.
    pub fn from_config(cfg: &veil_types::NetworkConfig) -> Result<Option<Self>, GateLoadError> {
        if !matches!(cfg.mode, veil_types::NetworkMode::Private) {
            return Ok(None);
        }
        let network_id_hex = cfg
            .network_id
            .as_deref()
            .ok_or(GateLoadError::MissingField("network.network_id"))?;
        let network_id = decode_hex_32(network_id_hex)
            .map_err(|e| GateLoadError::InvalidNetworkId(e.to_string()))?;

        let owner_pubkey_b64 = cfg
            .owner_pubkey
            .as_deref()
            .ok_or(GateLoadError::MissingField("network.owner_pubkey"))?;
        let owner_pubkey_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, owner_pubkey_b64)
                .map_err(|e| GateLoadError::InvalidOwnerPubkey(e.to_string()))?;

        let owner_algo = cfg
            .owner_algo
            .ok_or(GateLoadError::MissingField("network.owner_algo"))?;

        let cert_path = cfg
            .membership_cert
            .as_deref()
            .ok_or(GateLoadError::MissingField("network.membership_cert"))?;
        let local_cert_blob =
            std::fs::read(cert_path).map_err(|e| GateLoadError::CertReadFailed {
                path: cert_path.to_owned(),
                io: e.to_string(),
            })?;
        // Sanity-decode (without verifying signature) to catch corruption
        // at startup. The handshake path will verify on every use.
        crate::network_cert::decode_cert_blob(&local_cert_blob).map_err(|e| {
            GateLoadError::CertDecodeFailed {
                path: cert_path.to_owned(),
                err: e.to_string(),
            }
        })?;

        let mut admin_node_ids = HashSet::with_capacity(cfg.admin_node_ids.len());
        for (idx, hex_id) in cfg.admin_node_ids.iter().enumerate() {
            let id = decode_hex_32(hex_id).map_err(|e| GateLoadError::InvalidAdminNodeId {
                index: idx,
                err: e.to_string(),
            })?;
            admin_node_ids.insert(id);
        }

        Ok(Some(Self {
            local_cert_blob,
            expected_network_id: network_id,
            owner_algo,
            owner_pubkey_bytes,
            admin_node_ids,
        }))
    }

    /// Verify a peer's cert blob and confirm it authorises the given
    /// `peer_node_id`. Returns the decoded cert on success (caller can
    /// inspect `admin` flag, cache, etc.).
    ///
    /// Order of checks (cheap first):
    /// 1. Blob present (`MissingCert` if not).
    /// 2. Blob decode (`DecodeFailed` on parse error).
    /// 3. `cert.member_node_id == peer_node_id` (`NotForThisPeer`).
    /// 4. Full cryptographic verify (`Verify`).
    pub fn verify_peer(
        &self,
        blob: Option<&[u8]>,
        peer_node_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<MembershipCert, GateError> {
        let blob = blob.ok_or(GateError::MissingCert)?;
        let cert: MembershipCert = decode_cert_blob(blob)?;
        // Cheap identity check first so a wrong-peer cert doesn't burn
        // signature CPU.
        if &cert.member_node_id != peer_node_id {
            return Err(GateError::NotForThisPeer {
                cert_node_id_hex: hex_short(&cert.member_node_id),
                peer_node_id_hex: hex_short(peer_node_id),
            });
        }
        verify_membership_cert(
            &cert,
            &self.expected_network_id,
            self.owner_algo,
            &self.owner_pubkey_bytes,
            now_unix,
        )?;
        Ok(cert)
    }

    /// Test-only helper to check whether a decoded cert's
    /// `member_node_id` is in the configured admin allowlist. Used by
    /// P-Net Phase 3 ban-record verification and by admin-CLI guards.
    pub fn is_admin(&self, cert: &MembershipCert) -> bool {
        if !cert.admin {
            return false;
        }
        if self.admin_node_ids.is_empty() {
            // No explicit allowlist → trust the cert's admin flag
            // (owner-issued claim). Most common deployment shape.
            return true;
        }
        self.admin_node_ids.contains(&cert.member_node_id)
    }

    /// Verify a P-Net ban blob at DHT-ingest time.
    ///
    /// Order of checks (cheap first):
    /// 1. Blob carries the `PBAN` magic prefix (caller already checked).
    /// 2. Blob decodes to a `BanEntry`.
    /// 3. Cert + admin signature chain verifies against this network.
    /// 4. Admin cert's `member_node_id` is in the optional allowlist.
    /// 5. DHT key matches `ban_dht_key(network_id, banned_node_id)` —
    ///    prevents misfiled records from landing under a ban-key bucket.
    fn verify_ban_blob_inner(&self, key: &[u8; 32], value: &[u8]) -> bool {
        let entry = match decode_ban_blob(value) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let admin_cert = match verify_ban_entry(
            &entry,
            &self.expected_network_id,
            self.owner_algo,
            &self.owner_pubkey_bytes,
            now_unix,
        ) {
            Ok(c) => c,
            Err(_) => return false,
        };
        if !self.is_admin(&admin_cert) {
            return false;
        }
        let derived_key = ban_dht_key(&self.expected_network_id, &entry.banned_node_id);
        &derived_key == key
    }
}

impl veil_dht::NetworkAuthGate for NetworkAccessGate {
    fn verify_ban_record(&self, key: &[u8; 32], value: &[u8]) -> bool {
        self.verify_ban_blob_inner(key, value)
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    // First 8 bytes hex (16 chars) — matches `util::hex_short` style.
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_cert::{canonical_cert_body, encode_cert_blob};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use veil_types::MEMBERSHIP_CERT_VERSION;

    fn make_signed_cert(
        sk: &SigningKey,
        network_id: [u8; 32],
        member_node_id: [u8; 32],
        valid_until_unix: u64,
        admin: bool,
    ) -> MembershipCert {
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id,
            member_node_id,
            issued_at_unix: 1000,
            valid_until_unix,
            admin,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        let body = canonical_cert_body(&cert);
        cert.owner_signature = sk.sign(&body).to_bytes().to_vec();
        cert
    }

    fn make_gate(network_id: [u8; 32], owner_pk: Vec<u8>) -> NetworkAccessGate {
        NetworkAccessGate {
            local_cert_blob: vec![],
            expected_network_id: network_id,
            owner_algo: SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: owner_pk,
            admin_node_ids: HashSet::new(),
        }
    }

    fn encode_cert(cert: &MembershipCert) -> Vec<u8> {
        encode_cert_blob(cert)
    }

    #[test]
    fn valid_cert_admits_peer() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let peer = [0x22u8; 32];
        let cert = make_signed_cert(&sk, net, peer, 5000, false);
        let blob = encode_cert(&cert);
        let gate = make_gate(net, pk);
        let admitted = gate.verify_peer(Some(&blob), &peer, 1500).unwrap();
        assert_eq!(admitted.member_node_id, peer);
    }

    #[test]
    fn missing_cert_rejected_in_private_mode() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let gate = make_gate([0x11u8; 32], pk);
        let err = gate
            .verify_peer(None, &[0x22u8; 32], 1500)
            .expect_err("missing cert");
        matches!(err, GateError::MissingCert);
    }

    #[test]
    fn cert_for_wrong_peer_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let cert_member = [0x22u8; 32];
        let actual_peer = [0x33u8; 32];
        let cert = make_signed_cert(&sk, net, cert_member, 5000, false);
        let blob = encode_cert(&cert);
        let gate = make_gate(net, pk);
        let err = gate
            .verify_peer(Some(&blob), &actual_peer, 1500)
            .expect_err("wrong peer");
        matches!(err, GateError::NotForThisPeer { .. });
    }

    #[test]
    fn admin_flag_with_empty_allowlist_trusted() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let admin_node = [0xAAu8; 32];
        let cert = make_signed_cert(&sk, net, admin_node, 5000, true);
        let gate = make_gate(net, pk);
        assert!(gate.is_admin(&cert));
    }

    #[test]
    fn admin_flag_rejected_when_node_id_not_in_allowlist() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let admin_node = [0xAAu8; 32];
        let cert = make_signed_cert(&sk, net, admin_node, 5000, true);
        let mut gate = make_gate(net, pk);
        gate.admin_node_ids.insert([0xBBu8; 32]); // allowlist different node
        assert!(!gate.is_admin(&cert));
    }

    #[test]
    fn non_admin_cert_never_treated_as_admin() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let member = [0xCCu8; 32];
        let cert = make_signed_cert(&sk, net, member, 5000, false);
        let mut gate = make_gate(net, pk);
        gate.admin_node_ids.insert(member); // even in allowlist
        assert!(!gate.is_admin(&cert));
    }

    // ── NetworkAuthGate ban-record verification ────────────────────────────

    fn build_ban_blob_for(
        owner_sk: &SigningKey,
        admin_sk: &SigningKey,
        network_id: [u8; 32],
        banned: [u8; 32],
    ) -> Vec<u8> {
        let admin_pk = admin_sk.verifying_key().to_bytes();
        let admin_node_id = *blake3::hash(&admin_pk).as_bytes();
        // Cert expiry must exceed wall-clock time (the gate's
        // `verify_ban_record` uses `SystemTime::now()`). Pick a year
        // far enough in the future to outlive any practical CI runner.
        let valid_until = u64::MAX / 2;
        let admin_cert = make_signed_cert(owner_sk, network_id, admin_node_id, valid_until, true);
        let admin_cert_blob = encode_cert_blob(&admin_cert);
        let mut entry = veil_types::BanEntry {
            version: veil_types::BAN_ENTRY_VERSION,
            network_id,
            banned_node_id: banned,
            reason: "abuse".to_owned(),
            issued_at_unix: 2000,
            admin_node_id,
            admin_cert_blob,
            admin_pubkey: admin_pk.to_vec(),
            admin_signature: Vec::new(),
        };
        let body = crate::network_ban::canonical_ban_body(&entry);
        use ed25519_dalek::Signer;
        entry.admin_signature = admin_sk.sign(&body).to_bytes().to_vec();
        crate::network_ban::encode_ban_blob(&entry)
    }

    #[test]
    fn auth_gate_accepts_valid_ban_record() {
        use veil_dht::NetworkAuthGate as _;
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let banned = [0xBBu8; 32];
        let blob = build_ban_blob_for(&owner_sk, &admin_sk, net, banned);
        let gate = make_gate(net, owner_pk);
        let key = crate::network_ban::ban_dht_key(&net, &banned);
        assert!(gate.verify_ban_record(&key, &blob));
    }

    #[test]
    fn auth_gate_rejects_wrong_key() {
        use veil_dht::NetworkAuthGate as _;
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let banned = [0xBBu8; 32];
        let blob = build_ban_blob_for(&owner_sk, &admin_sk, net, banned);
        let gate = make_gate(net, owner_pk);
        // Wrong key — even with a valid blob, must reject.
        let bad_key = [0xFFu8; 32];
        assert!(!gate.verify_ban_record(&bad_key, &blob));
    }

    #[test]
    fn auth_gate_rejects_malformed_blob() {
        use veil_dht::NetworkAuthGate as _;
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let net = [0x11u8; 32];
        let gate = make_gate(net, owner_pk);
        // wrong magic prefix
        assert!(!gate.verify_ban_record(&[0u8; 32], b"XXXXgarbage"));
    }

    #[test]
    fn auth_gate_rejects_when_admin_not_in_allowlist() {
        use veil_dht::NetworkAuthGate as _;
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let banned = [0xBBu8; 32];
        let blob = build_ban_blob_for(&owner_sk, &admin_sk, net, banned);
        let mut gate = make_gate(net, owner_pk);
        // Restrict allowlist to a different admin.
        gate.admin_node_ids.insert([0xEEu8; 32]);
        let key = crate::network_ban::ban_dht_key(&net, &banned);
        assert!(!gate.verify_ban_record(&key, &blob));
    }
}
