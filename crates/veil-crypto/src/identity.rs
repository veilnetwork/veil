//! Identity helpers.
//!
//! Two conceptual layers here:
//!
//! 1. **Legacy domain-identity validation** (`identity_signature_is_valid`
//!    `identity_nonce_meets_difficulty`) — the original `[identity]`-config
//!    flow bundling pubkey + privkey + PoW nonce. Kept verbatim for now.
//! 2. **Sovereign identity primitives** — `master_sk` derivation
//!    from `master_seed`, `node_id` binding, and canonical signing-message
//!    builders used by [`proto::identity_document`](crate::proto::identity_document).
//!    See [`docs/identity-model.md`](../../../docs/identity-model.md).

// Legacy domain-identity validation helpers (`identity_signature_is_valid`
// `identity_nonce_meets_difficulty`, `identity_nonce_has_leading_zero`) moved
// to `cfg::identity` in c. They orchestrate crypto primitives over
// a higher-level `DomainIdentity` (which lives in cfg), so the caller-side
// is the natural home — keeps crypto/ free of cfg/ types.

// ═══════════════════════════════════════════════════════════════════════════
// Sovereign identity primitives
// ═══════════════════════════════════════════════════════════════════════════
//
// The items below form the crypto API consumed by the verifier
//the `identity create` / `rotate` CLIs
// and the pairing ceremony. In the
// revocation-related helpers (`revoke_message`, `freshness_message`)
// were removed alongside the in-band revocation flow.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use veil_types::CERTIFY_CONTEXT;

/// Info string for master_sk derivation from master_seed. See
/// [`derive_master_sk_ed25519`].
pub const MASTER_DERIVATION_INFO: &[u8] = b"veil.master.v1";

/// Length of the master seed (32 bytes = 256 bits).
pub const MASTER_SEED_LEN: usize = 32;

/// Derive a 32-byte Ed25519 signing key from the master seed.
///
/// HKDF-SHA256:
/// ```text
/// salt = None
/// ikm = master_seed (32 B)
/// info = "veil.master.v1"
/// okm = 32 B → Ed25519SigningKey::from_bytes
/// ```
///
/// Returns the raw 32-byte secret wrapped [`Zeroizing`] so it's erased
/// from memory on drop. Callers construct the actual [`ed25519_dalek::SigningKey`]
/// from these bytes and should zeroize that too (ed25519-dalek 2.x supports
/// `.zeroize` on the signing key).
pub fn derive_master_sk_ed25519(master_seed: &[u8; MASTER_SEED_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(MASTER_DERIVATION_INFO, out.as_mut())
        .expect("32 bytes < 255 * hash_len");
    out
}

/// Info string for the anonymity / relay X25519 secret derived from an
/// identity's Ed25519 SK seed. See [`derive_anonymity_x25519_sk`].
pub const ANONYMITY_X25519_DERIVATION_INFO: &[u8] = b"veil/anonymity-x25519/v1";

/// Derive the node's **anonymity / relay X25519 secret** deterministically
/// from its per-identity Ed25519 SK seed (`device_identity_sk.bin`).
///
/// HKDF-SHA256:
/// ```text
/// salt = None
/// ikm  = identity_sk_seed (32 B, the Ed25519 SK seed)
/// info = "veil/anonymity-x25519/v1"
/// okm  = 32 B → x25519_dalek::StaticSecret::from
/// ```
///
/// Why this exists: the anonymity X25519 keypair's PUBLIC half is what peers
/// encrypt their sealed rendezvous introduces to (it is published in the
/// node's signed `RelayKeyRecord`/ad, bound to the stable `node_id`). When the
/// secret was instead `random_from_rng` per process and persisted only in the
/// **ephemeral** runtime dir (xVeil regenerates that dir every session), the
/// pubkey churned every launch — so a peer that resolved a slightly-older ad
/// sealed to a key this node no longer held, and the AEAD silently failed
/// (`anonymity.relay_chain.forward.decrypt_failed`), black-holing delivery with
/// no signal to the sender. Deriving from the stable identity seed pins the
/// keypair across sessions: even a stale cached ad still decrypts.
///
/// Anonymity note: this adds NO linkability beyond what is already public —
/// the pubkey is already published in the signed ad bound to the (already
/// stable) `node_id`, and the derivation is a one-way PRF that never reveals
/// the seed. Per-identity isolation is automatic: master and each decoy load
/// their OWN `device_identity_sk.bin`, so they derive DISTINCT anonymity keys.
///
/// Returns the raw 32-byte scalar [`Zeroizing`]-wrapped; the caller feeds it to
/// `x25519_dalek::StaticSecret::from` (which clamps internally).
pub fn derive_anonymity_x25519_sk(identity_sk_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, identity_sk_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(ANONYMITY_X25519_DERIVATION_INFO, out.as_mut())
        .expect("32 bytes < 255 * hash_len");
    out
}

/// Info string for the node's ML-KEM-768 mailbox decapsulation seed, derived
/// from an identity's Ed25519 SK seed. See [`derive_mlkem_dk_seed`].
pub const MLKEM_DK_SEED_DERIVATION_INFO: &[u8] = b"veil/mlkem-dk-seed/v1";

/// Derive the node's **ML-KEM-768 mailbox decapsulation seed** (64 B)
/// deterministically from its per-identity Ed25519 SK seed
/// (`device_identity_sk.bin`).
///
/// HKDF-SHA256:
/// ```text
/// salt = None
/// ikm  = identity_sk_seed (32 B, the Ed25519 SK seed)
/// info = "veil/mlkem-dk-seed/v1"
/// okm  = 64 B → DK768::from_seed (recomputes the matching EK deterministically)
/// ```
///
/// Why this exists: the mailbox ML-KEM keypair's PUBLIC half (the encapsulation
/// key) is published in the node's signed `MlKemKeyCert`, bound to the stable
/// `node_id`; offline senders seal store-and-forward blobs to it. When the
/// decapsulation seed was instead generated at random per process and persisted
/// only in the **ephemeral** runtime dir (xVeil recreates that dir every
/// session), the published EK churned every launch — so after a restart a peer's
/// already-sealed blob decrypted to nothing and the open failed AEAD
/// (`mailbox_open … Failed`), black-holing reverse delivery with no signal to the
/// sender. Deriving from the stable identity seed pins the keypair across
/// sessions: even a peer's stale cached cert still opens.
///
/// Anonymity note: adds NO linkability beyond what is already public — the EK is
/// already published in a signed cert bound to the (already stable) `node_id`,
/// and HKDF is a one-way PRF that never reveals the seed. The distinct info
/// string domain-separates this from the anonymity X25519 key derived from the
/// SAME seed. Per-identity isolation is automatic: master and each decoy load
/// their OWN `device_identity_sk.bin`, so they derive DISTINCT keys.
///
/// Rotation (future, operator-initiated): bump the info string to `…/v2` AND the
/// published `cert_version`, with a grace window — do not rotate silently.
pub fn derive_mlkem_dk_seed(identity_sk_seed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let hk = Hkdf::<Sha256>::new(None, identity_sk_seed);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(MLKEM_DK_SEED_DERIVATION_INFO, out.as_mut())
        .expect("64 bytes < 255 * hash_len");
    out
}

/// Info string for an onion service's rendezvous auth-cookie. The current
/// blinded-descriptor period (`now / PERIOD_SECS`, 8 LE bytes) is appended to
/// this constant before expansion. See [`derive_onion_auth_cookie`].
pub const ONION_AUTH_COOKIE_DERIVATION_INFO: &[u8] = b"veil/onion-auth-cookie/v1";

/// Derive an onion service's 16-byte rendezvous **auth-cookie** deterministically
/// from its per-identity Ed25519 SK seed and the current blinded-descriptor
/// `period` (`current_period(now) = now / 86400`).
///
/// HKDF-SHA256:
/// ```text
/// salt = None
/// ikm  = identity_sk_seed (32 B, the Ed25519 SK seed)
/// info = "veil/onion-auth-cookie/v1" ‖ period.to_le_bytes()
/// okm  = 16 B → the auth-cookie
/// ```
///
/// Why this exists: the cookie is the value the relay keys its circuit-rendezvous
/// subscriber table by AND the value a sender copies out of the resolved ad /
/// blinded descriptor into its introduce. When it was `OsRng`-minted per process
/// (`register_onion_service`), every restart rotated it: the recipient re-registered
/// the relay under a NEW cookie while a sender resolved an ad (≤24 h valid) carrying
/// the OLD cookie, so `lookup(cookie)` missed and the relay silently dropped the
/// introduce (`cookie_unknown`) — black-holing delivery to a node that restarts every
/// few minutes. Deriving it from the stable identity seed makes a restart re-mint the
/// SAME cookie, so it matches whatever ad the sender resolves.
///
/// Anonymity note: the cookie is the only field a rendezvous relay sees in PLAINTEXT
/// (toward senders it travels inside the sealed blinded descriptor). It is derived
/// from the SECRET seed — NOT from `node_id` like the plain-path
/// [`super::...`]-style cookie — so it is opaque and non-invertible: a relay cannot
/// link it to a guessed identity (no confirmation oracle), preserving the blinded
/// descriptor's unlinkability. The `period` term makes the cookie rotate in lockstep
/// with the blinded descriptor's per-period DHT key / enc key / signature, so the
/// relay's ability to cluster this receiver's rendezvous activity is bounded to the
/// SAME 24 h period the design already concedes — period N and N+1 are unlinkable. A
/// seed-only (period-less) cookie would be a forever-stable relay pseudonym and is
/// deliberately NOT used. Per-identity isolation is automatic: master and each decoy
/// load their OWN `device_identity_sk.bin`, deriving DISTINCT cookies. The cookie is
/// PUBLIC, so it is returned unwrapped (not [`Zeroizing`]); only the seed is secret.
pub fn derive_onion_auth_cookie(identity_sk_seed: &[u8; 32], period: u64) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(None, identity_sk_seed);
    let mut info = ONION_AUTH_COOKIE_DERIVATION_INFO.to_vec();
    info.extend_from_slice(&period.to_le_bytes());
    let mut out = [0u8; 16];
    hk.expand(&info, &mut out)
        .expect("16 bytes < 255 * hash_len");
    out
}

/// Info string for an onion service's rendezvous REGISTRATION Ed25519 key seed.
/// The blinded-descriptor period is appended like the auth-cookie's. See
/// [`derive_onion_reg_seed`].
pub const ONION_REG_KEY_DERIVATION_INFO: &[u8] = b"veil/onion-reg-key/v1";

/// Derive the Ed25519 SK seed for an onion service's rendezvous registration
/// keypair, deterministically from the identity seed and the current
/// blinded-descriptor `period` (same period as [`derive_onion_auth_cookie`]).
///
/// Why this exists: the relay's cookie registry is first-wins anti-squat — a
/// registration with a DIFFERENT `reg_pk` on an existing cookie is rejected
/// (`CookieClaimed`). The keypair used to be `OsRng`-minted per process, so an
/// ABRUPT restart (crash / kill / battery) within one cookie period came back
/// with the same derived cookie but a NEW reg_pk, and the relay refused the
/// re-registration until the dead subscription aged out (teardown or the 600 s
/// GC) — on a small-relay topology that is a live-path black hole of up to
/// 10 minutes. Deriving the key from the SAME (seed, period) pair makes the
/// restarted process a same-key refresh: a strictly-fresher epoch rebinds the
/// cookie to the NEW circuit immediately.
///
/// Anonymity: exactly the auth-cookie's argument — seed-derived (opaque to the
/// relay, no confirmation oracle) and period-scoped (rotates in lockstep with
/// the cookie, so the relay's clustering ability stays bounded to the 24 h
/// period the design already concedes; a period-less key would be a forever
/// pseudonym). The relay already sees the cookie rotate per period; the reg_pk
/// riding the same period adds no new linkage.
pub fn derive_onion_reg_seed(identity_sk_seed: &[u8; 32], period: u64) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, identity_sk_seed);
    let mut info = ONION_REG_KEY_DERIVATION_INFO.to_vec();
    info.extend_from_slice(&period.to_le_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, out.as_mut())
        .expect("32 bytes < 255 * hash_len");
    out
}

/// Derive a `node_id` from a public key.
///
/// simplifies this from the previous domain-tag-prefixed shape
/// (`BLAKE3("veil.identity.v1" || len_be || pk)`) to a plain
/// `BLAKE3(pk)`. This unifies the sovereign-identity address with
/// [`cfg::NodeId::from_public_key`] (which already used the bare hash
/// for the per-device runtime address) — in standalone mode the two
/// addresses coincide because `master_pubkey == device_pubkey`.
///
/// Cross-algorithm collisions are practically impossible: BLAKE3 is
/// a 256-bit hash and the algorithm byte is part of the surrounding
/// `IdentityKey` cert that the verifier checks separately.
///
/// ```text
/// node_id = BLAKE3(master_pubkey)
/// ```
pub fn compute_node_id(master_pubkey: &[u8]) -> [u8; 32] {
    *blake3::hash(master_pubkey).as_bytes()
}

/// Build the canonical bytes that master_sk signs to certify an identity
/// subkey (a "Delegation" cert terminology).
///
/// ```text
/// CERTIFY_CONTEXT
/// || node_id
/// || algo
/// || len(subkey_pubkey) as u16 BE
/// || subkey_pubkey
/// || device_id
/// || valid_from_unix
/// || valid_until_unix
/// ```
pub fn certify_message(
    node_id: &[u8; 32],
    subkey_algo: u8,
    subkey_pubkey: &[u8],
    device_id: &[u8; 32],
    valid_from_unix: u64,
    valid_until_unix: u64,
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(CERTIFY_CONTEXT.len() + 32 + 1 + 2 + subkey_pubkey.len() + 32 + 8 + 8);
    msg.extend_from_slice(CERTIFY_CONTEXT);
    msg.extend_from_slice(node_id);
    msg.push(subkey_algo);
    msg.extend_from_slice(&(subkey_pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(subkey_pubkey);
    msg.extend_from_slice(device_id);
    msg.extend_from_slice(&valid_from_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    msg
}

// dropped `pubkey_hash` — was an alias for `BLAKE3(pubkey)`
// used to derive the stable subkey id in pairing flows. After
// the same derivation is exposed as [`compute_node_id`] (master case)
// and is the default `device_id` for per-device subkeys; see also
// [`cfg::NodeId::from_public_key`]. Callers that previously held a
// `pubkey_hash(pk)` should switch to `compute_node_id(pk)`.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_sk_derivation_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = derive_master_sk_ed25519(&seed);
        let b = derive_master_sk_ed25519(&seed);
        assert_eq!(*a, *b);
    }

    #[test]
    fn master_sk_changes_with_seed() {
        let a = derive_master_sk_ed25519(&[0x42u8; 32]);
        let b = derive_master_sk_ed25519(&[0x43u8; 32]);
        assert_ne!(*a, *b);
    }

    #[test]
    fn anonymity_x25519_derivation_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = derive_anonymity_x25519_sk(&seed);
        let b = derive_anonymity_x25519_sk(&seed);
        assert_eq!(
            *a, *b,
            "same identity seed must yield the same anonymity key"
        );
    }

    #[test]
    fn anonymity_x25519_changes_with_seed() {
        // Cross-identity isolation: master and decoy (distinct seeds) MUST
        // derive distinct anonymity keys — no cross-identity linkage.
        let a = derive_anonymity_x25519_sk(&[0x42u8; 32]);
        let b = derive_anonymity_x25519_sk(&[0x43u8; 32]);
        assert_ne!(*a, *b);
    }

    #[test]
    fn anonymity_x25519_is_domain_separated_from_master_sk() {
        // Same seed, different info label → different key. Guards against the
        // anonymity key ever colliding with the identity signing key.
        let seed = [0x42u8; 32];
        let anon = derive_anonymity_x25519_sk(&seed);
        let master = derive_master_sk_ed25519(&seed);
        assert_ne!(*anon, *master);
    }

    #[test]
    fn mlkem_dk_seed_is_deterministic() {
        // The whole point: same identity seed MUST yield the same 64-byte ML-KEM
        // decapsulation seed across restarts, so a peer's already-sealed mailbox
        // blob still opens after we restart (a rotating key was the AEAD black-hole).
        let seed = [0x42u8; 32];
        assert_eq!(*derive_mlkem_dk_seed(&seed), *derive_mlkem_dk_seed(&seed));
    }

    #[test]
    fn mlkem_dk_seed_changes_with_seed() {
        // Cross-identity isolation: master and decoy (distinct seeds) MUST derive
        // distinct mailbox keys — no cross-identity linkage.
        assert_ne!(
            *derive_mlkem_dk_seed(&[0x42u8; 32]),
            *derive_mlkem_dk_seed(&[0x43u8; 32])
        );
    }

    #[test]
    fn mlkem_dk_seed_is_domain_separated_from_anonymity_key() {
        // Same seed, different info label → the ML-KEM seed's first 32 bytes must
        // NOT equal the anonymity x25519 key. Proves the domain string actually
        // separates the two derivations from the SAME identity seed.
        let seed = [0x42u8; 32];
        let mlkem = derive_mlkem_dk_seed(&seed);
        let anon = derive_anonymity_x25519_sk(&seed);
        assert_ne!(mlkem[..32], *anon);
    }

    #[test]
    fn onion_auth_cookie_is_stable_across_restarts() {
        // The whole point: same identity seed + same period MUST yield the same
        // 16-byte cookie, so a process restart re-mints a value the relay still
        // has registered (a rotating cookie was the cookie_unknown black-hole).
        let seed = [0x42u8; 32];
        let a = derive_onion_auth_cookie(&seed, 19876);
        let b = derive_onion_auth_cookie(&seed, 19876);
        assert_eq!(a, b);
    }

    #[test]
    fn onion_auth_cookie_rotates_per_period() {
        // Adjacent blinded-descriptor periods MUST produce independent cookies so
        // a relay cannot link the receiver's rendezvous across the 24h boundary
        // (the cookie rotates in lockstep with the descriptor's DHT/enc/sig keys).
        let seed = [0x42u8; 32];
        let a = derive_onion_auth_cookie(&seed, 19876);
        let b = derive_onion_auth_cookie(&seed, 19877);
        assert_ne!(a, b);
    }

    #[test]
    fn onion_auth_cookie_isolated_between_identities() {
        // master and decoy (distinct seeds) MUST derive distinct cookies in the
        // same period — no cross-identity linkage at the relay surface.
        let p = 19876u64;
        let a = derive_onion_auth_cookie(&[0x42u8; 32], p);
        let b = derive_onion_auth_cookie(&[0x43u8; 32], p);
        assert_ne!(a, b);
    }

    #[test]
    fn onion_reg_seed_stable_within_period_rotates_across() {
        // The whole point: a crash-restarted process re-derives the SAME
        // registration key within a period (same-key refresh at the relay, no
        // CookieClaimed), while period N and N+1 keys are unlinkable — the reg
        // key rotates in lockstep with the auth-cookie.
        let seed = [0x42u8; 32];
        let p = 19876u64;
        let restart_a = derive_onion_reg_seed(&seed, p);
        let restart_b = derive_onion_reg_seed(&seed, p);
        assert_eq!(
            *restart_a, *restart_b,
            "restart must re-derive the same key"
        );
        let next = derive_onion_reg_seed(&seed, p + 1);
        assert_ne!(*restart_a, *next, "periods must not share a reg key");
        // Distinct identities (master vs decoy) never share a reg key.
        let other = derive_onion_reg_seed(&[0x43u8; 32], p);
        assert_ne!(*restart_a, *other);
        // Domain separation from the auth-cookie derivation: the cookie is
        // PUBLIC while the reg seed is SECRET key material — the 16-byte cookie
        // must not be a prefix of the reg seed under the same (seed, period).
        let cookie = derive_onion_auth_cookie(&seed, p);
        assert_ne!(cookie[..], restart_a[..16]);
    }

    #[test]
    fn onion_reg_seed_yields_deterministic_ed25519() {
        // Two "processes" derive byte-identical keypairs — the relay sees the
        // same reg_pk and takes the refresh path instead of first-wins reject.
        let seed = [0x77u8; 32];
        let a = crate::ed25519_keypair_from_seed(&derive_onion_reg_seed(&seed, 20000));
        let b = crate::ed25519_keypair_from_seed(&derive_onion_reg_seed(&seed, 20000));
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.private_key, b.private_key);
        // And the keypair actually signs/verifies.
        let sig =
            crate::sign_message(a.algo, &a.public_key, &a.private_key, b"probe").expect("sign");
        crate::verify_message(a.algo, &a.public_key, b"probe", &sig).expect("verify");
    }

    #[test]
    fn anonymity_x25519_known_answer_vector() {
        // KAT: pins the wire-visible derivation for an all-zero seed so a future
        // refactor that changes the KDF/label (and would silently invalidate
        // every peer's sealed introduce) fails loudly here. If this ever needs
        // to change it is a deliberate, coordinated key rotation.
        let okm = derive_anonymity_x25519_sk(&[0u8; 32]);
        let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "962fb33d42c62c80e1c8ca1f88b0a3a8d23f317020057a8716ca7f56b0d4e89e",
            "anonymity-x25519 KDF output changed — coordinated rotation only"
        );
    }

    #[test]
    fn master_sk_produces_valid_ed25519_keypair() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};
        let seed = [0x11u8; 32];
        let sk_bytes = derive_master_sk_ed25519(&seed);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let msg = b"test message";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig)
            .expect("derived master_sk must sign/verify");
    }

    #[test]
    fn node_id_is_deterministic() {
        let pk = vec![0xAAu8; 32];
        let a = compute_node_id(&pk);
        let b = compute_node_id(&pk);
        assert_eq!(a, b);
    }

    #[test]
    fn node_id_changes_with_pubkey() {
        let a = compute_node_id(&[0xAAu8; 32]);
        let b = compute_node_id(&[0xBBu8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn node_id_no_domain_tag_collision() {
        // `compute_node_id` is now a bare BLAKE3 over the pubkey
        // bytes (no length-prefix, no domain tag). Different pubkey
        // values still produce distinct hashes — including pubkeys of
        // different length whose shorter form is a prefix of the longer
        // form. This is the standard cryptographic-hash property; it
        // is just stronger than the previous length-prefix construction.
        let short = vec![0x00u8; 32];
        let mut long = vec![0x00u8; 897]; // Falcon-512 size
        long[..32].copy_from_slice(&short);
        let id_short = compute_node_id(&short);
        let id_long = compute_node_id(&long);
        assert_ne!(id_short, id_long);
    }

    // extraction: `node_id_matches_cfg_node_id` cross-validation test
    // moved to `veilcore/tests/node_id_consistency.rs` because it asserts
    // that crypto::compute_node_id and cfg::NodeId::from_public_key produce
    // identical bytes — a cross-layer assertion that doesn't fit inside
    // standalone veil-crypto.

    #[test]
    fn certify_message_format_stable() {
        let node_id = [0x12u8; 32];
        let pk = vec![0xABu8; 32];
        let device_id = [0x77u8; 32];
        let valid_from = 1_700_000_000u64;
        let valid_until = valid_from + 7 * 86_400;
        let msg = certify_message(&node_id, 0, &pk, &device_id, valid_from, valid_until);
        // Must start with context.
        assert!(msg.starts_with(CERTIFY_CONTEXT));
        let after = &msg[CERTIFY_CONTEXT.len()..];
        // node_id
        assert_eq!(&after[..32], &node_id);
        // algo byte
        assert_eq!(after[32], 0);
        // pk_len + pk
        assert_eq!(&after[33..35], &32u16.to_be_bytes());
        assert_eq!(&after[35..67], &pk[..]);
        // device_id
        assert_eq!(&after[67..99], &device_id);
        // valid_from
        assert_eq!(&after[99..107], &valid_from.to_be_bytes());
        // valid_until
        assert_eq!(&after[107..115], &valid_until.to_be_bytes());
    }

    #[test]
    fn end_to_end_sign_and_verify_cert() {
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
        // Genesis: derive master_sk from seed, compute node_id
        let seed = [0xAAu8; 32];
        let master_sk_bytes = derive_master_sk_ed25519(&seed);
        let master_sk = SigningKey::from_bytes(&master_sk_bytes);
        let master_pk: VerifyingKey = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        // Generate a fresh identity subkey (hot key)
        let subkey = SigningKey::from_bytes(&[0xBBu8; 32]);
        let subkey_pk = subkey.verifying_key();
        // device_id is now deterministic = BLAKE3(subkey_pk).
        let device_id = compute_node_id(subkey_pk.as_bytes());
        let valid_from = 1_700_000_000;
        let valid_until = valid_from + 7 * 86_400;

        // Master certifies the subkey
        let cert_msg = certify_message(
            &node_id,
            0,
            subkey_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let master_sig = master_sk.sign(&cert_msg);

        // Verifier side: reconstruct the message, verify cert
        let verifier_msg = certify_message(
            &node_id,
            0,
            subkey_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        master_pk
            .verify(&verifier_msg, &master_sig)
            .expect("cert verifies");
    }
}
