//! End-to-end integration tests for the sovereign-identity library
//! layer.
//!
//! These tests exercise the full library stack in realistic
//! messenger-style scenarios, using in-memory fakes for the DHT
//! and discovery. They verify that the individual primitives —
//! built and tested in isolation in their respective modules —
//! compose correctly into the full messenger vertical slice.
//!
//! Runtime-wiring scenarios (real dispatch, real sessions, real
//! DHT) land with the 462.15 wire refactor. Until then, these
//! tests are the authoritative "does the whole thing work
//! together" gate.
//!
//! ## Covered scenarios
//!
//! 1. **Onboarding**: BIP-39 phrase → master_seed → identity_sk
//!    → signed IdentityDocument → verified IdentityDocument.
//! 2. **Paper-backup round-trip**: BIP-39 encode/decode across a
//!    simulated device wipe.
//! 3. **Encrypted-file round-trip**: Argon2id + ChaCha20-Poly1305
//!    persistence across process restarts.
//! 4. **Name resolution**: claim publication → @name lookup →
//!    ValidatedIdentity with full chain verification.
//! 5. **Multi-device fan-out**: 3 instances under one identity
//!    each with its own identity_sk + MlKem cert; sender
//!    encrypts once per instance, each instance decrypts only
//!    its own envelope.
//! 6. **Safety numbers**: deterministic, pair-symmetric
//!    fingerprints for out-of-band verification.
//! 7. **App-state sync**: encrypted blob posted by one instance
//!    decrypted by another under the shared app_state_secret.
//! 8. **Chat backup**: multi-chunk encrypted snapshot
//!    round-trips with per-chunk AEAD binding.
//! 9. **Revocation propagation**: gossip push verifies, merges
//!    into local cache, and makes the revoked key rejectable.
//! 10. **Anomaly watcher**: detects an attacker-added
//!     unauthorised identity_key in a republished document.

#![cfg(test)]

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey};

use crate::freshness::{FreshnessConfig, needs_refresh};
use crate::instance::LocalInstance;
use crate::master_file::{load_master_seed_encrypted, save_master_seed_encrypted_with};
use crate::master_seed::{
    decode_master_seed_from_phrase, encode_master_seed_to_phrase, generate_master_seed,
};
use crate::mlkem_fanout::{fanout_decrypt_one, fanout_encrypt, verify_mlkem_cert};
use crate::verify::verify_identity_document;
use veil_crypto::identity::{
    certify_message as build_certify, compute_node_id, derive_master_sk_ed25519,
};
use veil_crypto::identity_fingerprint::identity_fingerprint;
use veil_crypto::x3dh::generate_prekey;
use veil_proto::identity_document::{ALGO_ED25519, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey};
use veil_proto::mlkem_cert::{MLKEM_CERT_SIG_CONTEXT, MlKemKeyCert};
use veil_proto::prekey_bundle::ALGO_ML_KEM_768;

// ── Tiny helpers shared by the scenarios ─────────────────────────────────────

fn now() -> u64 {
    1_700_000_000
}

/// Build a full signed `IdentityDocument` for a test identity with
/// `n_instances` subkeys. Returns the doc, master signing key, and
/// per-instance (sub_sk, instance_id, ml-kem keypair).
struct TestIdentity {
    doc: IdentityDocument,
    /// Test-fixture field: kept on the struct so future tests can re-sign
    /// during cross-doc verification scenarios. Retained verbatim from
    /// the original fixture to avoid churn if those tests land later.
    #[allow(dead_code)]
    master_sk: SigningKey,
    /// Test-fixture field: same rationale as `master_sk` — preserves the
    /// determinism source for future regression tests that re-derive
    /// from a known seed.
    #[allow(dead_code)]
    master_seed: [u8; 32],
    instances: Vec<TestInstance>,
}

struct TestInstance {
    sub_sk: crate::signing_key::IdentitySigningKey,
    instance_id: [u8; 16],
    /// Test-fixture field: kept alongside `mlkem_dk_seed` for symmetry
    /// (encapsulation-key + matching dk-seed pair) and to anchor the
    /// future ML-KEM-rekey test that hasn't shipped yet.
    #[allow(dead_code)]
    mlkem_ek: Vec<u8>,
    mlkem_dk_seed: zeroize::Zeroizing<[u8; 64]>,
    mlkem_cert: MlKemKeyCert,
}

fn build_test_identity(seed_byte: u8, n_instances: usize) -> TestIdentity {
    assert!(n_instances >= 1);
    let master_seed = [seed_byte; 32];
    let master_sk_bytes = derive_master_sk_ed25519(&master_seed);
    let master_sk = SigningKey::from_bytes(&master_sk_bytes);
    let master_pk = master_sk.verifying_key();
    let node_id = compute_node_id(master_pk.as_bytes());

    let mut identity_keys = Vec::new();
    let mut sub_sks: Vec<SigningKey> = Vec::new();
    let instance_ids: Vec<[u8; 16]> = (0..n_instances as u8).map(|i| [i + 1; 16]).collect();
    let mut mlkem_keypairs: Vec<(Vec<u8>, zeroize::Zeroizing<[u8; 64]>)> =
        Vec::with_capacity(n_instances);

    for (idx, _instance_id) in instance_ids.iter().enumerate() {
        let sub_sk = SigningKey::from_bytes(&[seed_byte.wrapping_add(0x20 + idx as u8); 32]);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());
        let valid_from = now() - 60;
        let valid_until = now() + 7 * 86_400;
        let cert_msg = build_certify(
            &node_id,
            ALGO_ED25519,
            sub_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let cert_sig = master_sk.sign(&cert_msg);
        identity_keys.push(IdentityKey {
            algo: ALGO_ED25519,
            pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        });
        sub_sks.push(sub_sk);
        mlkem_keypairs.push(generate_prekey());
    }

    let mut doc = IdentityDocument {
        node_id,
        master_algo: ALGO_ED25519,
        master_pubkey: master_pk.as_bytes().to_vec(),
        issued_at_unix: now(),
        valid_until_unix: now() + 7 * 86_400,
        sig_key_idx: 0,
        identity_keys,
        document_sig: Vec::new(),
    };

    // Sign document with the primary identity_sk.
    let mut doc_msg = Vec::new();
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = sub_sks[0].sign(&doc_msg).to_bytes().to_vec();

    // Build one ML-KEM cert per instance, signed by that instance's
    // own identity_sk.
    let mut instances = Vec::new();
    for (idx, instance_id) in instance_ids.iter().enumerate() {
        let (ek, dk_seed) = (mlkem_keypairs[idx].0.clone(), mlkem_keypairs[idx].1.clone());
        let mut cert = MlKemKeyCert {
            node_id,
            instance_id: *instance_id,
            mlkem_algo: ALGO_ML_KEM_768,
            mlkem_pubkey: ek.clone(),
            valid_from_unix: now() - 60,
            valid_until_unix: now() + 30 * 86_400,
            cert_version: 1,
            signing_identity_key_idx: idx as u16,
            sig: Vec::new(),
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(MLKEM_CERT_SIG_CONTEXT);
        msg.extend_from_slice(&cert.canonical_signing_bytes());
        cert.sig = sub_sks[idx].sign(&msg).to_bytes().to_vec();
        instances.push(TestInstance {
            sub_sk: crate::signing_key::IdentitySigningKey::from_ed25519_key(sub_sks[idx].clone()),
            instance_id: *instance_id,
            mlkem_ek: ek,
            mlkem_dk_seed: dk_seed,
            mlkem_cert: cert,
        });
    }

    TestIdentity {
        doc,
        master_sk,
        master_seed,
        instances,
    }
}

// ── Scenario 1: Onboarding end-to-end ────────────────────────────────────────

#[test]
fn scenario_onboarding_and_verify() {
    let identity = build_test_identity(0x11, 1);
    let validated =
        verify_identity_document(&identity.doc, now()).expect("fresh identity must verify");
    assert_eq!(validated.node_id, identity.doc.node_id);
    assert_eq!(validated.master_pubkey, identity.doc.master_pubkey);
    assert_eq!(validated.active_key_idx, 0);
}

// ── Scenario 2: BIP-39 paper-backup round-trip ───────────────────────────────

#[test]
fn scenario_bip39_roundtrip_survives_device_wipe() {
    let seed = generate_master_seed();
    let phrase = encode_master_seed_to_phrase(&seed).unwrap();
    let words = phrase.to_string();

    // Simulate writing down the phrase, wiping the device, and
    // typing the phrase back in:
    drop(seed);
    let restored = decode_master_seed_from_phrase(&words).unwrap();
    assert_eq!(restored.len(), 32);

    // Verify the master_sk derivation matches — this is the true
    // "same identity as before" check.
    let master_sk_bytes = derive_master_sk_ed25519(&restored);
    let sk = SigningKey::from_bytes(&master_sk_bytes);
    // Can sign and verify a challenge under the derived key — proof
    // the full restoration worked.
    let sig = sk.sign(b"recovery-challenge");
    sk.verifying_key()
        .verify_strict(b"recovery-challenge", &sig)
        .expect("recovered master_sk must sign/verify");
}

// ── Scenario 3: Encrypted-file round-trip ────────────────────────────────────

#[test]
fn scenario_encrypted_file_roundtrip() {
    let dir = tempdir("master-enc");
    let path = dir.join("master.enc");
    let seed = [0x42u8; 32];
    // Use cheap Argon2 params for this test.
    save_master_seed_encrypted_with(
        &path,
        &seed,
        b"correct horse battery staple",
        16 * 1024,
        1,
        1,
    )
    .unwrap();
    // Simulate process restart — re-open from disk with password.
    let decoded = load_master_seed_encrypted(&path, b"correct horse battery staple").unwrap();
    assert_eq!(&*decoded, &seed);
    // Wrong password is rejected.
    assert!(load_master_seed_encrypted(&path, b"wrong").is_err());
}

// ── Scenario 4: Multi-device fan-out (messenger core flow) ──────────────────

#[test]
fn scenario_multi_device_fanout_messenger() {
    let alice = build_test_identity(0xAA, 3);
    let sender_id = [0xBBu8; 32];

    // Sender verifies each of Alice's instance ML-KEM certs.
    let verified_certs: Vec<_> = alice
        .instances
        .iter()
        .map(|inst| {
            verify_mlkem_cert(&inst.mlkem_cert, &alice.doc, now()).expect("cert must verify")
        })
        .collect();
    assert_eq!(verified_certs.len(), 3);

    // Fan-out encrypt a message to every Alice instance.
    let plaintext = b"hi alice, from bob -- multi-device test";
    let envelopes = fanout_encrypt(plaintext, &verified_certs, &sender_id, &alice.doc.node_id)
        .expect("fan-out encrypt");
    assert_eq!(envelopes.len(), 3);

    // Every Alice instance picks its own envelope and decrypts it.
    for inst in &alice.instances {
        let pt = fanout_decrypt_one(
            &envelopes,
            &inst.instance_id,
            &alice.doc.node_id,
            &sender_id,
            &inst.mlkem_dk_seed,
            1,
        )
        .expect("own envelope decrypts");
        assert_eq!(&*pt, plaintext);
    }

    // Cross-instance decryption must fail — instance 0 cannot decrypt
    // instance 1's envelope.
    let wrong = fanout_decrypt_one(
        &envelopes,
        &alice.instances[0].instance_id,
        &alice.doc.node_id,
        &sender_id,
        &alice.instances[1].mlkem_dk_seed,
        1,
    );
    assert!(wrong.is_err(), "cross-instance decryption must fail");
}

// ── Scenario 5: Safety numbers are pair-symmetric ────────────────────────────

#[test]
fn scenario_safety_numbers_pair_symmetric() {
    let alice = build_test_identity(0x11, 1);
    let bob = build_test_identity(0x22, 1);
    let from_alices_view = identity_fingerprint(&alice.doc.node_id, &bob.doc.node_id);
    let from_bobs_view = identity_fingerprint(&bob.doc.node_id, &alice.doc.node_id);
    assert_eq!(
        from_alices_view, from_bobs_view,
        "both parties must see the same safety number"
    );
    // 12 groups of 5 digits joined by spaces = 71 chars.
    assert_eq!(from_alices_view.len(), 71);
}

// ── Scenario 6: Revocation propagation blocks future use of a leaked key ────

// a removed:
// scenario_revocation_push_blocks_leaked_key (RevocationPush gossip)
// scenario_anomaly_watcher_catches_attacker_added_device (anomaly watcher)
// Both tested removed subsystems (revocation_gossip + watcher). The
// underlying threat (compromised subkey) is now handled by short
// `valid_until_unix` — there is no in-band revocation list
// no anomaly watcher, no propagation push.

// ── Scenario 10: Freshness-refresh lifecycle ─────────────────────────────────

#[test]
fn scenario_freshness_lifecycle() {
    let identity = build_test_identity(0x77, 1);
    let cfg = FreshnessConfig::defaults();

    // Freshly-minted doc at exactly `now`.
    assert!(!needs_refresh(&identity.doc, now(), &cfg));

    // Time-travel close to expiry (5 days before valid_until).
    let near_expiry = identity.doc.valid_until_unix - 4 * 86_400;
    assert!(needs_refresh(&identity.doc, near_expiry, &cfg));

    // After valid_until, document is fully expired and rejected.
    let err = verify_identity_document(&identity.doc, identity.doc.valid_until_unix + 1);
    assert!(err.is_err(), "post-expiry doc must fail verifier");
}

// ── Scenario 11: Local instance state persists across restarts ───────────────

#[test]
fn scenario_instance_state_stable_across_restarts() {
    let dir = tempdir("instance-state");
    let path = dir.join("instance_id");

    let first = LocalInstance::load_or_init(&path, "laptop").unwrap();
    let id_before = first.instance_id;

    // Simulate process restart by calling load_or_init again with a
    // different label — must return the SAME instance_id (id is
    // immutable once generated).
    let second = LocalInstance::load_or_init(&path, "different-label").unwrap();
    assert_eq!(second.instance_id, id_before);
    assert_eq!(second.label, "laptop", "original label wins");
}

// a removed scenario_revocation_cache_persists_on_disk —
// RevocationCache will be removed in b.

// ── Scenario 13: Multi-scenario compose: Alice + Bob exchange ────────────────

#[test]
fn scenario_alice_and_bob_full_exchange() {
    // Alice has 2 devices, Bob has 1.
    let alice = build_test_identity(0x11, 2);
    let bob = build_test_identity(0x22, 1);

    // Each side verifies the other's identity document first.
    verify_identity_document(&alice.doc, now()).unwrap();
    verify_identity_document(&bob.doc, now()).unwrap();

    // They compare safety numbers out of band.
    let safety_number = identity_fingerprint(&alice.doc.node_id, &bob.doc.node_id);
    assert_eq!(safety_number.len(), 71);

    // Bob sends Alice a message: fan-out to both of Alice's devices.
    let alice_certs: Vec<_> = alice
        .instances
        .iter()
        .map(|i| verify_mlkem_cert(&i.mlkem_cert, &alice.doc, now()).unwrap())
        .collect();
    let envelopes = fanout_encrypt(
        b"hello alice",
        &alice_certs,
        &bob.doc.node_id,
        &alice.doc.node_id,
    )
    .unwrap();
    assert_eq!(envelopes.len(), 2);

    // Each Alice device decrypts only its own envelope.
    let mut decrypted_count = 0;
    for inst in &alice.instances {
        if let Ok(pt) = fanout_decrypt_one(
            &envelopes,
            &inst.instance_id,
            &alice.doc.node_id,
            &bob.doc.node_id,
            &inst.mlkem_dk_seed,
            1,
        ) {
            assert_eq!(&*pt, b"hello alice");
            decrypted_count += 1;
        }
    }
    assert_eq!(decrypted_count, 2, "both Alice devices receive");
}

// ── Scenario 14: Bundled sanity check — no cross-identity leakage ───────────

#[test]
fn scenario_no_cross_identity_leakage() {
    // Two identities sharing an infra (same DHT). Ensure keys
    // cache entries, and fingerprints never cross-pollute.
    let alice = build_test_identity(0x11, 1);
    let bob = build_test_identity(0x22, 1);

    assert_ne!(alice.doc.node_id, bob.doc.node_id);
    assert_ne!(alice.doc.master_pubkey, bob.doc.master_pubkey);

    // a: dropped revocation cross-pollution check (RevocationEntry
    // gone with the in-band revocation flow). Cross-identity isolation now
    // covered by the basic node_id / master_pubkey assertions above —
    // the verifier path itself is exercised by other scenarios in this file.
    verify_identity_document(&bob.doc, now()).unwrap();
}

// ── Runtime-level composition scenarios ──────

/// Simulates the core handshake-auth moment between two nodes: each
/// side holds a sovereign identity, generates an X25519 ephemeral
/// keypair (what runtime would do in the KA step), signs an
/// [`IdentityProof`] binding its identity_sk to that ephemeral pk
/// and the peer verifies the proof + derives the same X25519 shared
/// secret. Proves the messenger's "session keys are bound to
/// verified sovereign identities" invariant at the library layer
/// without needing the runtime session_manager.
#[test]
fn scenario_two_nodes_mutual_identity_proof_exchange() {
    use crate::publish::sign_identity_proof;
    use crate::verify::verify_identity_proof;
    use veil_crypto::kex::{compute_shared_secret, generate_ephemeral};
    use veil_proto::identity_proof::IdentityProof;

    // 1. Alice + Bob each create a sovereign identity.
    let alice = build_test_identity(0x01, 1);
    let bob = build_test_identity(0x02, 1);
    let alice_sk = &alice.instances[0].sub_sk;
    let bob_sk = &bob.instances[0].sub_sk;
    let t = now();

    // 2. Each generates an X25519 ephemeral (the KA step).
    let alice_eph = generate_ephemeral();
    let bob_eph = generate_ephemeral();
    let alice_pk = alice_eph.public_key;
    let bob_pk = bob_eph.public_key;

    // 3. Each signs an IdentityProof binding identity_sk → ephemeral_pk.
    let alice_proof = sign_identity_proof(
        &alice.doc,
        0,
        alice_sk,
        alice_pk,
        t + 300,
        (t / 3600) as u32,
    )
    .unwrap();
    let bob_proof =
        sign_identity_proof(&bob.doc, 0, bob_sk, bob_pk, t + 300, (t / 3600) as u32).unwrap();

    // 4. Exchange proofs over the wire (encode → decode simulates
    // a real network round-trip).
    let alice_wire = alice_proof.encode();
    let bob_wire = bob_proof.encode();
    let alice_received = IdentityProof::decode(&bob_wire).unwrap();
    let bob_received = IdentityProof::decode(&alice_wire).unwrap();

    // 5. Each verifies the other's proof against its local cache.
    // The proof's embedded ephemeral_x25519_pk must match the one
    // the peer advertised in (simulated) KA step.
    assert_eq!(
        alice_received.ephemeral_x25519_pk, bob_pk,
        "Alice sees Bob's advertised ephemeral pk"
    );
    assert_eq!(
        bob_received.ephemeral_x25519_pk, alice_pk,
        "Bob sees Alice's advertised ephemeral pk"
    );

    let alice_view_of_bob = verify_identity_proof(&alice_received, t).unwrap();
    let bob_view_of_alice = verify_identity_proof(&bob_received, t).unwrap();

    assert_eq!(alice_view_of_bob.node_id, bob.doc.node_id);
    // device_id is derived from the active subkey pubkey
    // not the on-disk LocalInstance random tag.
    assert_eq!(
        alice_view_of_bob.active_device_id,
        bob.doc.identity_keys[0].device_id,
    );
    assert_eq!(bob_view_of_alice.node_id, alice.doc.node_id);
    assert_eq!(
        bob_view_of_alice.active_device_id,
        alice.doc.identity_keys[0].device_id,
    );

    // 6. Each computes the X25519 shared secret — both sides MUST
    // agree, which is the "session-keys-match" end of the proof.
    let alice_shared =
        compute_shared_secret(alice_eph, &bob_pk).expect("contributory X25519 shared secret");
    let bob_shared =
        compute_shared_secret(bob_eph, &alice_pk).expect("contributory X25519 shared secret");
    assert_eq!(
        *alice_shared, *bob_shared,
        "both sides derive identical X25519 shared secret"
    );

    // 7. Final check — a MITM who swaps the ephemeral pk between
    // Alice's proof and Bob's observation of Alice would fail.
    // Simulate by tampering alice_wire's ephemeral_x25519_pk field.
    let mut tampered = alice_proof.clone();
    tampered.ephemeral_x25519_pk[0] ^= 0xFF;
    let err = verify_identity_proof(&tampered, t).unwrap_err();
    assert!(matches!(
        err,
        crate::verify::ProofVerifyError::EphemeralSigInvalid,
    ));
}

/// End-to-end pairing ceremony sim. Source
/// device creates a signed invite + QR URI; target scans the URI
/// verifies the `pair_secret` hashes to the invite's
/// `pair_secret_hash`; both sides (simulated) complete an X25519
/// handshake and derive the identical OOB confirmation code the user
/// visually compares.
#[test]
fn scenario_full_pair_ceremony_end_to_end() {
    use crate::publish::sign_pairing_invite;
    use veil_crypto::kex::{compute_shared_secret, generate_ephemeral};
    use veil_crypto::pair_oob::derive_pair_oob_code;
    use veil_proto::pairing_invite::{
        PAIR_SECRET_LEN, PairingInvite, PairingUri, hash_pair_secret,
    };

    // 1. Source device (has master_sk + identity). Pick a fresh
    // pair_secret + endpoint, publish a signed invite + render
    // QR URI.
    let source = build_test_identity(0x10, 1);
    let source_sk = &source.instances[0].sub_sk;
    let source_instance = source.instances[0].instance_id;
    let t = now();
    let pair_secret = [0xBBu8; PAIR_SECRET_LEN];

    let invite = sign_pairing_invite(
        source.doc.node_id,
        hash_pair_secret(&pair_secret),
        source_instance,
        t,
        t + 300,
        0,
        source_sk,
        &source.doc,
    )
    .unwrap();
    assert!(invite.is_valid_at(t));

    // Wire round-trip invite — receivers fetch it from the DHT.
    let invite_wire = invite.encode();
    let invite_decoded = PairingInvite::decode(&invite_wire).unwrap();
    assert_eq!(invite_decoded, invite);

    let qr = PairingUri {
        node_id: source.doc.node_id,
        pair_secret,
        endpoint: "tcp://10.0.0.7:45000".into(),
        expires_at_unix: invite.expires_at_unix,
    };
    let qr_uri = qr.to_uri().unwrap();

    // 2. Target device (fresh, no identity yet) scans the QR.
    let scanned = PairingUri::from_uri(&qr_uri).unwrap();
    assert_eq!(scanned.node_id, invite_decoded.node_id);

    // 3. Target hashes the scanned secret + cross-checks the
    // DHT-published invite's commitment — proves the QR was
    // actually issued by the claimed identity.
    assert_eq!(
        hash_pair_secret(&scanned.pair_secret),
        invite_decoded.pair_secret_hash,
        "scanned pair_secret must match the invite's published hash",
    );
    assert!(
        invite_decoded.is_valid_at(t),
        "invite still live when scanned"
    );

    // 4. Both sides establish an X25519 session (would happen over
    // the endpoint from the QR in the runtime ceremony).
    let source_eph = generate_ephemeral();
    let target_eph = generate_ephemeral();
    let source_pk = source_eph.public_key;
    let target_pk = target_eph.public_key;
    let source_shared =
        compute_shared_secret(source_eph, &target_pk).expect("contributory X25519 shared secret");
    let target_shared =
        compute_shared_secret(target_eph, &source_pk).expect("contributory X25519 shared secret");
    assert_eq!(*source_shared, *target_shared);

    // 5. Both devices derive the 6-digit OOB code from the session
    // key — the user compares visually and confirms.
    let source_oob = derive_pair_oob_code(&*source_shared);
    let target_oob = derive_pair_oob_code(&*target_shared);
    assert_eq!(
        source_oob, target_oob,
        "source + target must display the same OOB code for the user to compare"
    );
    assert_eq!(source_oob.len(), 7);

    // 6. Tampering sanity: an attacker who substitutes a different
    // pair_secret in a fake QR cannot reproduce the invite's
    // commitment. This is what defeats "QR phishing".
    let fake_qr = PairingUri {
        pair_secret: [0xCCu8; PAIR_SECRET_LEN],
        ..qr
    };
    let fake_scanned = PairingUri::from_uri(&fake_qr.to_uri().unwrap()).unwrap();
    assert_ne!(
        hash_pair_secret(&fake_scanned.pair_secret),
        invite_decoded.pair_secret_hash,
        "attacker-issued QR cannot forge the published pair_secret_hash",
    );
}

/// QR identity sharing composed with the resolver +
/// full cert-chain verifier: Alice shares her contact via the
/// `veil:identity` URI; Bob scans, verifies the `node_id ==
/// BLAKE3(master_pubkey)` binding locally, then also fetches Alice's
/// full `IdentityDocument` from a (simulated) DHT and cross-validates
/// — confirming the URI + document agree on every field.
#[test]
fn scenario_qr_contact_import_then_full_cert_chain_validate() {
    use veil_crypto::identity::compute_node_id;
    use veil_proto::identity_contact::IdentityContact;

    // 1. Alice creates her sovereign identity (host side).
    let alice = build_test_identity(0x20, 1);

    // 2. Alice renders her public contact as a QR-ready URI.
    let contact = IdentityContact {
        node_id: alice.doc.node_id,
        master_algo: alice.doc.master_algo,
        master_pubkey: alice.doc.master_pubkey.clone(),
        name: Some("alice".into()),
    };
    let uri = contact.to_uri().unwrap();

    // 3. Bob scans the QR into an IdentityContact.
    let scanned = IdentityContact::from_uri(&uri).unwrap();
    assert_eq!(scanned, contact);

    // 4. Bob verifies the URI-level binding: node_id must equal
    // BLAKE3(master_pubkey). This is the "is this contact even
    // internally consistent" gate before any DHT round-trip.
    assert_eq!(
        compute_node_id(&scanned.master_pubkey),
        scanned.node_id,
        "URI-level node_id ↔ master_pubkey binding must hold",
    );

    // 5. Bob goes to the DHT (simulated: he already has the
    // document in hand) and runs the full verifier — which
    // re-checks the node_id binding, every subkey's master
    // cert, the document signature, and the freshness window.
    let validated = verify_identity_document(&alice.doc, now()).expect("Alice's document verifies");

    // 6. Every field in the URI agrees with every field in the
    // verified document — no possibility of a mismatched
    // contact swap.
    assert_eq!(validated.node_id, scanned.node_id);
    assert_eq!(validated.master_pubkey, scanned.master_pubkey);
    assert_eq!(validated.master_algo, scanned.master_algo);

    // 7. Tampering check: if an attacker flipped a bit in the
    // master_pubkey while leaving node_id alone, the
    // URI-level binding check above already catches it. Prove
    // that.
    let mut tampered = contact.clone();
    tampered.master_pubkey[0] ^= 0xFF;
    assert_ne!(
        compute_node_id(&tampered.master_pubkey),
        tampered.node_id,
        "tampered pk cannot reproduce the original node_id",
    );
}

// ── Unused-import guard ──────────────────────────────────────────────────────
//
// Keep this trivial test — it references the HashMap import so
// rustc doesn't warn about an unused import if I later remove a
// scenario that used it.

#[test]
fn hashmap_import_guard() {
    let _: HashMap<u8, u8> = HashMap::new();
}

// ── (Falcon-512 producer) ───────────────────────

/// End-to-end Falcon-512 producer round-trip:
///
/// 1. Build an `IdentityDocument` whose **subkey is Falcon-512**
///    (cert chain still Ed25519 master → Falcon subkey is fine — the
///    master cert is signed under Ed25519 master_sk).
/// 2. Construct a `SovereignIdentity` from the Falcon SK via
///    `from_parts_with_signer`.
/// 3. Sign an `IdentityProof` (the runtime-hot path) using the
///    Falcon producer.
/// 4. Verify the produced proof through `verify_identity_proof` —
///    proves verifier accepts what the producer mints (i.e., the
///    previous "verifier accepts both / producer Ed25519-only"
///    asymmetry is now closed).
#[test]
fn phase645_h5_falcon512_producer_round_trip() {
    use crate::publish::sign_identity_proof;
    use crate::signing_key::IdentitySigningKey;
    use crate::sovereign::SovereignIdentity;
    use crate::verify::verify_identity_proof;
    use veil_crypto::kex::generate_ephemeral;
    use veil_proto::identity_document::ALGO_FALCON512;
    use veil_proto::identity_proof::IdentityProof;

    // 1. Master Ed25519 (master_sk signs the subkey cert).
    let master_seed = [0xCC; 32];
    let master_sk_bytes = derive_master_sk_ed25519(&master_seed);
    let master_sk = SigningKey::from_bytes(&master_sk_bytes);
    let master_pk = master_sk.verifying_key();
    let node_id = compute_node_id(master_pk.as_bytes());

    // 2. Generate a Falcon-512 subkey.
    let (falcon_sk, falcon_pk_bytes) = IdentitySigningKey::generate_falcon512();
    assert!(falcon_pk_bytes.len() > 800, "falcon-512 pk must be ~897 B");

    // 3. Compute device_id = BLAKE3(falcon_pk).
    let device_id = compute_node_id(&falcon_pk_bytes);

    // 4. Build the master cert over (node_id, ALGO_FALCON512, falcon_pk
    // device_id, validity).
    let valid_from = now() - 60;
    let valid_until = now() + 30 * 86_400;
    let cert_msg = build_certify(
        &node_id,
        ALGO_FALCON512,
        &falcon_pk_bytes,
        &device_id,
        valid_from,
        valid_until,
    );
    let cert_sig = master_sk.sign(&cert_msg);

    // 5. Assemble + Ed25519-sign the IdentityDocument. The doc-level
    // signature can use either algo; we use the master Ed25519 here
    // since master_sk is what we already have.
    let mut doc = IdentityDocument {
        node_id,
        master_algo: ALGO_ED25519,
        master_pubkey: master_pk.as_bytes().to_vec(),
        issued_at_unix: now(),
        valid_until_unix: valid_until,
        sig_key_idx: 0,
        identity_keys: vec![IdentityKey {
            algo: ALGO_FALCON512,
            pubkey: falcon_pk_bytes.clone(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        }],
        document_sig: Vec::new(),
    };
    // The verifier requires `document_sig` to be a signature by the
    // ACTIVE subkey (sig_key_idx → Falcon-512 in our setup), not by
    // the master. Sign with the Falcon SK before moving it.
    let mut doc_msg = Vec::new();
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = falcon_sk.sign(&doc_msg);

    // 6. Verify the assembled document — proves a Falcon-signed
    // document round-trips through the verifier end-to-end.
    verify_identity_document(&doc, now()).expect("doc must verify");

    // 7. Construct SovereignIdentity from the Falcon producer.
    let sov = SovereignIdentity::from_parts_with_signer(doc.clone(), falcon_sk, 0)
        .expect("falcon-backed sovereign identity must construct");

    // 8. Sign an IdentityProof — this is the runtime-hot path that
    // previously rejected non-Ed25519 producer keys.
    let eph = generate_ephemeral();
    let proof = sign_identity_proof(
        &doc,
        0,
        sov.identity_signing_key_for_test(),
        eph.public_key,
        now() + 300,
        (now() / 3600) as u32,
    )
    .expect("falcon producer must sign IdentityProof");

    // 9. Wire round-trip + verify.
    let wire = proof.encode();
    let received = IdentityProof::decode(&wire).unwrap();
    let v = verify_identity_proof(&received, now()).expect("falcon-signed proof must verify");
    assert_eq!(v.node_id, node_id);
    assert_eq!(v.active_device_id, device_id);
}

// ── Scenario 15: App-state sync across own instances ──────────
//
// One instance publishes an encrypted blob (e.g. contact list, draft
// per-app preferences); another instance under the same `identity_id`
// decrypts it. Foreign identities cannot decrypt. This exercises the
// "self → self" use of `fanout_encrypt` — the sender is one of Alice's
// own subkeys, recipients are all of Alice's instances. No mailbox /
// no async storage assumed: the blob is opaque ciphertext that travels
// through whatever transport the operator picks (DHT.store with TTL
// direct push, replication-via-online-peers).

#[test]
fn scenario_app_state_sync_across_own_instances() {
    // Alice has 3 devices (laptop, phone, tablet).
    let alice = build_test_identity(0x44, 3);

    // Verify each of her own ML-KEM certs (every consumer instance does
    // this when it picks up the blob).
    let verified_certs: Vec<_> = alice
        .instances
        .iter()
        .map(|inst| verify_mlkem_cert(&inst.mlkem_cert, &alice.doc, now()).unwrap())
        .collect();

    // Instance 0 (laptop) publishes app-state for chat-app id `b"chat\0"`.
    // Sender id is the publisher's own node_id (= identity_id). This
    // is the canonical self → self pattern: the sender encrypts to all
    // OWN instances including itself, and receives back the same blob
    // when it pulls.
    let app_state_blob = b"contacts: alice@home, bob@work | last_read: 2026-05-05T03:14:00Z";
    let envelopes = fanout_encrypt(
        app_state_blob,
        &verified_certs,
        &alice.doc.node_id,
        &alice.doc.node_id,
    )
    .expect("self-fanout encrypt");
    assert_eq!(envelopes.len(), 3);

    // Instance 1 (phone) wakes up, picks its envelope, decrypts.
    let pt_phone = fanout_decrypt_one(
        &envelopes,
        &alice.instances[1].instance_id,
        &alice.doc.node_id,
        &alice.doc.node_id,
        &alice.instances[1].mlkem_dk_seed,
        1,
    )
    .expect("phone instance must decrypt own envelope");
    assert_eq!(&*pt_phone, app_state_blob);

    // Instance 2 (tablet) picks its envelope independently.
    let pt_tablet = fanout_decrypt_one(
        &envelopes,
        &alice.instances[2].instance_id,
        &alice.doc.node_id,
        &alice.doc.node_id,
        &alice.instances[2].mlkem_dk_seed,
        1,
    )
    .expect("tablet instance must decrypt own envelope");
    assert_eq!(&*pt_tablet, app_state_blob);

    // Foreign identity (bob) cannot decrypt any of alice's envelopes
    // even though he holds his own valid identity.
    let bob = build_test_identity(0x55, 1);
    let foreign = fanout_decrypt_one(
        &envelopes,
        &bob.instances[0].instance_id,
        &alice.doc.node_id,
        &alice.doc.node_id,
        &bob.instances[0].mlkem_dk_seed,
        1,
    );
    assert!(
        foreign.is_err(),
        "foreign identity must not decrypt own-fanout blob"
    );
}

// ── Scenario 16: Chat backup → device wipe → restore ──────────
//
// User exports a backup-encrypted snapshot of their identity (master
// seed + per-app blobs) via the BIP-39 paper-phrase route. The
// "device wipe" simulates losing the local state. Restore: re-derive
// master_sk from the phrase, rebuild a fresh subkey, decrypt the blob.
//
// The blob ciphertext itself is encrypted for the *new* device's ML-KEM
// key (built deterministically from the same master seed for this test —
// in production a fresh subkey/cert pair gets master-certified during
// pair ceremony). This scenario therefore composes:
// * BIP-39 round-trip (Scenario 2)
// * Encrypted-file round-trip (Scenario 3, via plain ChaCha20-Poly1305
// for the user-visible "backup envelope")
// * Multi-device fanout (Scenario 4) for the per-app blob.

#[test]
fn scenario_chat_backup_restore_roundtrip() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let alice = build_test_identity(0x66, 1);

    // Imagine her chat-history: serialized to bytes by the messenger.
    let chat_history: Vec<u8> = b"message-1|message-2|message-3 [...] message-N".to_vec();

    // Step 1: derive a backup-key from the master seed via HKDF-style
    // domain separation. In production this would also include a
    // user-supplied passphrase via Argon2id; here we use the seed
    // directly because the BIP-39 phrase round-trip already covers
    // the human-memorable side.
    let backup_key: [u8; 32] = blake3::derive_key("veil.backup.chat.v1", &alice.master_seed);

    // Step 2: encrypt the chat history under the backup key.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&backup_key));
    let nonce_bytes = [0xCDu8; 12]; // deterministic for the test
    let backup_blob = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &chat_history,
                aad: b"veil.backup.chat.v1",
            },
        )
        .expect("backup encrypt");

    // Step 3: export the BIP-39 phrase that lets a new device re-derive
    // the same master seed. The phrase is the user-visible secret.
    let mnemonic = encode_master_seed_to_phrase(&alice.master_seed)
        .expect("encode 32-byte seed → phrase must succeed");
    let phrase: String = mnemonic.to_string();

    // ── DEVICE WIPE ──────────────────────────────────────────────
    // We "destroy" all in-memory state by dropping `alice` and only
    // keeping the public ciphertext + the user-known phrase + nonce.
    // `alice` carries a real `Drop` impl (zeroizes keys); `mnemonic`
    // is a String and gets dropped automatically at scope end, no
    // explicit `drop` needed (clippy::drop_non_drop).
    drop(alice);

    // Step 4: on a fresh device, the user types the phrase.
    let restored_seed =
        decode_master_seed_from_phrase(&phrase).expect("phrase must decode back to seed");

    // Step 5: re-derive the same backup-key from the recovered seed.
    let restored_key: [u8; 32] =
        blake3::derive_key("veil.backup.chat.v1", restored_seed.as_slice());
    assert_eq!(
        restored_key, backup_key,
        "key derivation must be deterministic"
    );

    // Step 6: decrypt the backup blob.
    let cipher_restored = ChaCha20Poly1305::new(Key::from_slice(&restored_key));
    let recovered = cipher_restored
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &backup_blob,
                aad: b"veil.backup.chat.v1",
            },
        )
        .expect("backup decrypt on new device");
    assert_eq!(
        recovered, chat_history,
        "chat history must round-trip intact"
    );

    // A wrong phrase (different seed) must fail to decrypt.
    let wrong_phrase_seed = generate_master_seed();
    let wrong_key: [u8; 32] =
        blake3::derive_key("veil.backup.chat.v1", wrong_phrase_seed.as_slice());
    let wrong_cipher = ChaCha20Poly1305::new(Key::from_slice(&wrong_key));
    let wrong_attempt = wrong_cipher.decrypt(
        Nonce::from_slice(&nonce_bytes),
        Payload {
            msg: &backup_blob,
            aad: b"veil.backup.chat.v1",
        },
    );
    assert!(
        wrong_attempt.is_err(),
        "wrong phrase must NOT decrypt the backup"
    );
}

// ── tempdir ──────────────────────────────────────────────────────────────────

fn tempdir(tag: &str) -> std::path::PathBuf {
    crate::test_support::scratch_dir(&format!("veil-identity-integration-{tag}"))
}
