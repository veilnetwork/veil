//! Private-veil-network DHT-replicated ban records.
//!
//! In а private network (`[network].mode = "private"`) admins issue
//! signed `BanEntry` records that propagate via the DHT. Each member
//! polls its DHT bucket for entries в the local `network_id`
//! namespace, verifies them through this module, и applies the bans
//! to its local `BanList`. Public-mode nodes never publish or apply
//! these records — bans stay node-local там.
//!
//! Wire format и struct definition live в `veil-types`
//! ([`veil_types::BanEntry`]); this module owns the canonical body
//! encoding + the chained verification logic.

use veil_types::{BAN_ENTRY_VERSION, BanEntry, MembershipCert, SignatureAlgorithm};

use crate::network_cert::{CertVerifyError, decode_cert_blob, verify_membership_cert};

/// Errors returned by [`verify_ban_entry`].
#[derive(Debug, thiserror::Error)]
pub enum BanVerifyError {
    #[error("unsupported ban-entry version {actual} (expected {expected})")]
    UnsupportedVersion { actual: u8, expected: u8 },
    #[error("ban network_id does not match local: expected={expected_hex} got={got_hex}")]
    WrongNetwork {
        expected_hex: String,
        got_hex: String,
    },
    #[error("admin cert blob decode failed: {0}")]
    AdminCertDecode(String),
    #[error("admin cert verification failed: {0}")]
    AdminCertVerify(#[from] CertVerifyError),
    #[error("admin cert is not flagged admin (cert.admin = false)")]
    NotAdmin,
    #[error("admin_cert.member_node_id ({cert_hex}) does не match ban admin_node_id ({entry_hex})")]
    AdminMismatch { cert_hex: String, entry_hex: String },
    #[error(
        "admin_pubkey BLAKE3 ({pubkey_hex}) does не match admin cert's member_node_id ({cert_hex})"
    )]
    AdminPubkeyMismatch {
        pubkey_hex: String,
        cert_hex: String,
    },
    #[error("admin signature invalid: {message}")]
    BadAdminSignature { message: String },
    #[error("ban reason exceeds {max} bytes ({actual} given)")]
    ReasonTooLong { actual: usize, max: usize },
}

/// Build the canonical byte encoding of а ban entry's signed body.
/// Layout (all big-endian):
/// ```text
/// [0]       version (u8)
/// [1..33]   network_id (32 bytes)
/// [33..65]  banned_node_id (32 bytes)
/// [65..73]  issued_at_unix (u64 BE)
/// [73..105] admin_node_id (32 bytes)
/// [105..107] reason_len (u16 BE)
/// [107..]   reason bytes (UTF-8, может быть пустым)
/// ```
/// `admin_pubkey` / `admin_cert_blob` / `admin_signature` are NOT in
/// the signed body — they are carried alongside для verification.
pub fn canonical_ban_body(entry: &BanEntry) -> Vec<u8> {
    let reason_bytes = entry.reason.as_bytes();
    let mut out = Vec::with_capacity(107 + reason_bytes.len());
    out.push(entry.version);
    out.extend_from_slice(&entry.network_id);
    out.extend_from_slice(&entry.banned_node_id);
    out.extend_from_slice(&entry.issued_at_unix.to_be_bytes());
    out.extend_from_slice(&entry.admin_node_id);
    let reason_len: u16 = reason_bytes
        .len()
        .try_into()
        .unwrap_or(veil_types::MAX_BAN_REASON_LEN as u16);
    out.extend_from_slice(&reason_len.to_be_bytes());
    out.extend_from_slice(&reason_bytes[..reason_len as usize]);
    out
}

/// Verify а ban entry against the local network's owner pubkey.
///
/// Cheap checks first; cryptographic verifies (cert sig + admin sig)
/// last. Returns the decoded admin cert on success so callers can
/// inspect the `member_node_id` / admin flag / `valid_until` for
/// logging or admin-allowlist gating.
pub fn verify_ban_entry(
    entry: &BanEntry,
    expected_network_id: &[u8; 32],
    owner_algo: SignatureAlgorithm,
    owner_pubkey_bytes: &[u8],
    now_unix: u64,
) -> Result<MembershipCert, BanVerifyError> {
    if entry.version != BAN_ENTRY_VERSION {
        return Err(BanVerifyError::UnsupportedVersion {
            actual: entry.version,
            expected: BAN_ENTRY_VERSION,
        });
    }
    if &entry.network_id != expected_network_id {
        return Err(BanVerifyError::WrongNetwork {
            expected_hex: hex_encode(expected_network_id),
            got_hex: hex_encode(&entry.network_id),
        });
    }
    if entry.reason.len() > veil_types::MAX_BAN_REASON_LEN {
        return Err(BanVerifyError::ReasonTooLong {
            actual: entry.reason.len(),
            max: veil_types::MAX_BAN_REASON_LEN,
        });
    }

    // Decode + verify admin cert (signed by network owner).
    let admin_cert = decode_cert_blob(&entry.admin_cert_blob)
        .map_err(|e| BanVerifyError::AdminCertDecode(e.to_string()))?;
    if !admin_cert.admin {
        return Err(BanVerifyError::NotAdmin);
    }
    if admin_cert.member_node_id != entry.admin_node_id {
        return Err(BanVerifyError::AdminMismatch {
            cert_hex: hex_encode(&admin_cert.member_node_id),
            entry_hex: hex_encode(&entry.admin_node_id),
        });
    }
    verify_membership_cert(
        &admin_cert,
        expected_network_id,
        owner_algo,
        owner_pubkey_bytes,
        now_unix,
    )?;

    // admin_pubkey ↔ admin_cert.member_node_id consistency check.
    let derived_node_id = *blake3::hash(&entry.admin_pubkey).as_bytes();
    if derived_node_id != admin_cert.member_node_id {
        return Err(BanVerifyError::AdminPubkeyMismatch {
            pubkey_hex: hex_encode(&derived_node_id),
            cert_hex: hex_encode(&admin_cert.member_node_id),
        });
    }

    // Final crypto step: admin signature over the canonical body.
    let body = canonical_ban_body(entry);
    let pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &entry.admin_pubkey,
    );
    veil_crypto::verify_message(admin_cert.algo, &pk_b64, &body, &entry.admin_signature).map_err(
        |e| BanVerifyError::BadAdminSignature {
            message: e.to_string(),
        },
    )?;

    Ok(admin_cert)
}

/// Derive the DHT key для а ban record. Layout: BLAKE3(`network_id ||
/// ":bans:" || banned_node_id`). Stable across implementations — same
/// inputs always produce same key so peers store / retrieve / dedupe
/// consistently.
pub fn ban_dht_key(network_id: &[u8; 32], banned_node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(network_id);
    hasher.update(b":bans:");
    hasher.update(banned_node_id);
    *hasher.finalize().as_bytes()
}

/// Magic prefix that marks а DHT value as а P-Net ban blob. Receivers
/// look at the first four bytes к decide whether к route the STORE
/// payload через the ban-record verifier instead of the standard
/// signed-STORE path.
pub const BAN_BLOB_MAGIC: &[u8; 4] = b"PBAN";

/// Cap on encoded ban-blob size — defence against malicious peers
/// flooding the DHT с oversized blobs. 4 KiB is comfortably larger
/// than а typical Ed25519 blob (~520 bytes signed body) and still small
/// enough that even а fully-loaded routing table can't exhaust memory.
pub const MAX_BAN_BLOB_SIZE: usize = 4096;

/// Errors returned by [`decode_ban_blob`].
#[derive(Debug, thiserror::Error)]
pub enum BanDecodeError {
    #[error("ban blob too short ({0} bytes)")]
    TooShort(usize),
    #[error("ban blob too large ({size} bytes, max {max})")]
    TooLarge { size: usize, max: usize },
    #[error("ban blob missing PBAN magic")]
    BadMagic,
    #[error("ban blob field `{0}` length prefix overruns buffer")]
    FieldOverrun(&'static str),
    #[error("ban blob reason exceeds {max} bytes ({actual} given)")]
    ReasonTooLong { actual: usize, max: usize },
    #[error("ban blob reason is not valid UTF-8: {0}")]
    ReasonNotUtf8(String),
}

/// Encode а `BanEntry` к а DHT-storable blob. Layout (all big-endian):
/// ```text
/// [0..4]   PBAN magic (b"PBAN")
/// [4]      version (u8)
/// [5..37]  network_id (32 bytes)
/// [37..69] banned_node_id (32 bytes)
/// [69..77] issued_at_unix (u64 BE)
/// [77..109] admin_node_id (32 bytes)
/// [109..111] reason_len (u16 BE)
/// [111..]   reason bytes (UTF-8)
/// [..+2]    admin_cert_len (u16 BE)
/// [..+N]    admin_cert_blob bytes
/// [..+2]    admin_pubkey_len (u16 BE)
/// [..+N]    admin_pubkey bytes
/// [..+2]    admin_signature_len (u16 BE)
/// [..+N]    admin_signature bytes
/// ```
pub fn encode_ban_blob(entry: &BanEntry) -> Vec<u8> {
    let reason_bytes = entry.reason.as_bytes();
    let reason_len = reason_bytes.len().min(veil_types::MAX_BAN_REASON_LEN);
    let mut out = Vec::with_capacity(
        4 + 1
            + 32
            + 32
            + 8
            + 32
            + 2
            + reason_len
            + 2
            + entry.admin_cert_blob.len()
            + 2
            + entry.admin_pubkey.len()
            + 2
            + entry.admin_signature.len(),
    );
    out.extend_from_slice(BAN_BLOB_MAGIC);
    out.push(entry.version);
    out.extend_from_slice(&entry.network_id);
    out.extend_from_slice(&entry.banned_node_id);
    out.extend_from_slice(&entry.issued_at_unix.to_be_bytes());
    out.extend_from_slice(&entry.admin_node_id);
    out.extend_from_slice(&(reason_len as u16).to_be_bytes());
    out.extend_from_slice(&reason_bytes[..reason_len]);
    out.extend_from_slice(&(entry.admin_cert_blob.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry.admin_cert_blob);
    out.extend_from_slice(&(entry.admin_pubkey.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry.admin_pubkey);
    out.extend_from_slice(&(entry.admin_signature.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry.admin_signature);
    out
}

/// Decode а blob produced by [`encode_ban_blob`]. Verifies the PBAN
/// magic, version byte, и field-length budgets but does NOT verify
/// signatures — callers must run [`verify_ban_entry`] afterwards.
pub fn decode_ban_blob(blob: &[u8]) -> Result<BanEntry, BanDecodeError> {
    if blob.len() > MAX_BAN_BLOB_SIZE {
        return Err(BanDecodeError::TooLarge {
            size: blob.len(),
            max: MAX_BAN_BLOB_SIZE,
        });
    }
    // Fixed prefix: magic(4) + version(1) + network_id(32) + banned_node_id(32)
    // + issued_at_unix(8) + admin_node_id(32) + reason_len(2) = 111 bytes.
    if blob.len() < 111 {
        return Err(BanDecodeError::TooShort(blob.len()));
    }
    if &blob[0..4] != BAN_BLOB_MAGIC {
        return Err(BanDecodeError::BadMagic);
    }
    let version = blob[4];
    let mut network_id = [0u8; 32];
    network_id.copy_from_slice(&blob[5..37]);
    let mut banned_node_id = [0u8; 32];
    banned_node_id.copy_from_slice(&blob[37..69]);
    let issued_at_unix = u64::from_be_bytes(blob[69..77].try_into().expect("8 bytes"));
    let mut admin_node_id = [0u8; 32];
    admin_node_id.copy_from_slice(&blob[77..109]);
    let reason_len = u16::from_be_bytes(blob[109..111].try_into().expect("2 bytes")) as usize;
    let mut cursor = 111;
    if reason_len > veil_types::MAX_BAN_REASON_LEN {
        return Err(BanDecodeError::ReasonTooLong {
            actual: reason_len,
            max: veil_types::MAX_BAN_REASON_LEN,
        });
    }
    if blob.len() < cursor + reason_len + 2 {
        return Err(BanDecodeError::FieldOverrun("reason"));
    }
    let reason_bytes = &blob[cursor..cursor + reason_len];
    let reason = std::str::from_utf8(reason_bytes)
        .map_err(|e| BanDecodeError::ReasonNotUtf8(e.to_string()))?
        .to_owned();
    cursor += reason_len;

    let admin_cert_len =
        u16::from_be_bytes(blob[cursor..cursor + 2].try_into().expect("2 bytes")) as usize;
    cursor += 2;
    if blob.len() < cursor + admin_cert_len + 2 {
        return Err(BanDecodeError::FieldOverrun("admin_cert_blob"));
    }
    let admin_cert_blob = blob[cursor..cursor + admin_cert_len].to_vec();
    cursor += admin_cert_len;

    let admin_pubkey_len =
        u16::from_be_bytes(blob[cursor..cursor + 2].try_into().expect("2 bytes")) as usize;
    cursor += 2;
    if blob.len() < cursor + admin_pubkey_len + 2 {
        return Err(BanDecodeError::FieldOverrun("admin_pubkey"));
    }
    let admin_pubkey = blob[cursor..cursor + admin_pubkey_len].to_vec();
    cursor += admin_pubkey_len;

    let admin_signature_len =
        u16::from_be_bytes(blob[cursor..cursor + 2].try_into().expect("2 bytes")) as usize;
    cursor += 2;
    if blob.len() < cursor + admin_signature_len {
        return Err(BanDecodeError::FieldOverrun("admin_signature"));
    }
    let admin_signature = blob[cursor..cursor + admin_signature_len].to_vec();

    Ok(BanEntry {
        version,
        network_id,
        banned_node_id,
        reason,
        issued_at_unix,
        admin_node_id,
        admin_cert_blob,
        admin_pubkey,
        admin_signature,
    })
}

/// Cheap probe: does this blob start with the PBAN magic? Used by the
/// DHT layer к route incoming STORE payloads to the P-Net auth gate
/// без having к decode the full blob upfront.
pub fn is_ban_blob(blob: &[u8]) -> bool {
    blob.len() >= 4 && &blob[0..4] == BAN_BLOB_MAGIC
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
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

    fn sign_admin_cert(
        owner_sk: &SigningKey,
        admin_pk: &[u8; 32],
        network_id: [u8; 32],
    ) -> MembershipCert {
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id,
            member_node_id: *blake3::hash(admin_pk).as_bytes(),
            issued_at_unix: 1000,
            valid_until_unix: 100_000,
            admin: true,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        let body = canonical_cert_body(&cert);
        cert.owner_signature = owner_sk.sign(&body).to_bytes().to_vec();
        cert
    }

    fn make_ban(
        owner_sk: &SigningKey,
        admin_sk: &SigningKey,
        network_id: [u8; 32],
        banned: [u8; 32],
        reason: &str,
    ) -> BanEntry {
        let admin_pk = admin_sk.verifying_key().to_bytes();
        let admin_node_id = *blake3::hash(&admin_pk).as_bytes();
        let admin_cert = sign_admin_cert(owner_sk, &admin_pk, network_id);
        let admin_cert_blob = encode_cert_blob(&admin_cert);
        let mut entry = BanEntry {
            version: BAN_ENTRY_VERSION,
            network_id,
            banned_node_id: banned,
            reason: reason.to_owned(),
            issued_at_unix: 2000,
            admin_node_id,
            admin_cert_blob,
            admin_pubkey: admin_pk.to_vec(),
            admin_signature: Vec::new(),
        };
        let body = canonical_ban_body(&entry);
        entry.admin_signature = admin_sk.sign(&body).to_bytes().to_vec();
        entry
    }

    #[test]
    fn valid_ban_verifies() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let ban = make_ban(&owner_sk, &admin_sk, net, [0xBBu8; 32], "abuse");
        let cert =
            verify_ban_entry(&ban, &net, SignatureAlgorithm::Ed25519, &owner_pk, 5000).unwrap();
        assert!(cert.admin);
    }

    #[test]
    fn ban_for_wrong_network_rejected() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let other_net = [0x99u8; 32];
        let ban = make_ban(&owner_sk, &admin_sk, net, [0xBBu8; 32], "abuse");
        let err = verify_ban_entry(
            &ban,
            &other_net,
            SignatureAlgorithm::Ed25519,
            &owner_pk,
            5000,
        )
        .expect_err("wrong network");
        matches!(err, BanVerifyError::WrongNetwork { .. });
    }

    #[test]
    fn tampered_banned_node_rejected() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let mut ban = make_ban(&owner_sk, &admin_sk, net, [0xBBu8; 32], "abuse");
        ban.banned_node_id = [0xCCu8; 32]; // attacker swaps target
        let err = verify_ban_entry(&ban, &net, SignatureAlgorithm::Ed25519, &owner_pk, 5000)
            .expect_err("tampered");
        matches!(err, BanVerifyError::BadAdminSignature { .. });
    }

    #[test]
    fn non_admin_cert_rejected() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let mut ban = make_ban(&owner_sk, &admin_sk, net, [0xBBu8; 32], "abuse");
        // Replace cert с а non-admin one (re-sign for cert sig
        // к remain valid; only the admin flag is flipped).
        let admin_pk = admin_sk.verifying_key().to_bytes();
        let mut non_admin_cert = sign_admin_cert(&owner_sk, &admin_pk, net);
        non_admin_cert.admin = false;
        non_admin_cert.owner_signature = owner_sk
            .sign(&canonical_cert_body(&non_admin_cert))
            .to_bytes()
            .to_vec();
        ban.admin_cert_blob = encode_cert_blob(&non_admin_cert);
        let err = verify_ban_entry(&ban, &net, SignatureAlgorithm::Ed25519, &owner_pk, 5000)
            .expect_err("non-admin");
        matches!(err, BanVerifyError::NotAdmin);
    }

    #[test]
    fn wrong_admin_pubkey_rejected() {
        // Admin tries к present someone else's cert.
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_a = SigningKey::generate(&mut OsRng);
        let admin_b = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let mut ban = make_ban(&owner_sk, &admin_a, net, [0xBBu8; 32], "abuse");
        // Swap pubkey к admin_b's; cert binding к admin_a remains.
        ban.admin_pubkey = admin_b.verifying_key().to_bytes().to_vec();
        let err = verify_ban_entry(&ban, &net, SignatureAlgorithm::Ed25519, &owner_pk, 5000)
            .expect_err("wrong pubkey");
        matches!(err, BanVerifyError::AdminPubkeyMismatch { .. });
    }

    #[test]
    fn blob_round_trip() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let banned = [0xCCu8; 32];
        let entry = make_ban(&owner_sk, &admin_sk, net, banned, "spam");
        let blob = encode_ban_blob(&entry);
        assert!(is_ban_blob(&blob));
        let decoded = decode_ban_blob(&blob).expect("decode");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn blob_decode_rejects_bad_magic() {
        let mut blob = vec![0x00u8; 200];
        blob[0..4].copy_from_slice(b"XXXX");
        let err = decode_ban_blob(&blob).expect_err("bad magic");
        matches!(err, BanDecodeError::BadMagic);
    }

    #[test]
    fn blob_decode_rejects_too_short() {
        let blob = vec![b'P', b'B', b'A', b'N', 1];
        let err = decode_ban_blob(&blob).expect_err("too short");
        matches!(err, BanDecodeError::TooShort(_));
    }

    #[test]
    fn blob_decode_rejects_truncated() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let admin_sk = SigningKey::generate(&mut OsRng);
        let entry = make_ban(&owner_sk, &admin_sk, [0x11u8; 32], [0xCCu8; 32], "x");
        let blob = encode_ban_blob(&entry);
        // truncate to just past the fixed prefix, dropping the signature
        let truncated = &blob[..115];
        let err = decode_ban_blob(truncated).expect_err("truncated");
        matches!(err, BanDecodeError::FieldOverrun(_));
    }

    #[test]
    fn blob_after_decode_verifies() {
        let owner_sk = SigningKey::generate(&mut OsRng);
        let owner_pk = owner_sk.verifying_key().to_bytes().to_vec();
        let admin_sk = SigningKey::generate(&mut OsRng);
        let net = [0x11u8; 32];
        let entry = make_ban(&owner_sk, &admin_sk, net, [0xCCu8; 32], "abuse");
        let blob = encode_ban_blob(&entry);
        let decoded = decode_ban_blob(&blob).expect("decode");
        verify_ban_entry(&decoded, &net, SignatureAlgorithm::Ed25519, &owner_pk, 5000)
            .expect("verify");
    }

    #[test]
    fn dht_key_is_deterministic() {
        let net = [0x11u8; 32];
        let banned = [0xBBu8; 32];
        let k1 = ban_dht_key(&net, &banned);
        let k2 = ban_dht_key(&net, &banned);
        assert_eq!(k1, k2);
        // different inputs → different keys
        let k3 = ban_dht_key(&[0x22u8; 32], &banned);
        assert_ne!(k1, k3);
        let k4 = ban_dht_key(&net, &[0xCCu8; 32]);
        assert_ne!(k1, k4);
    }
}
