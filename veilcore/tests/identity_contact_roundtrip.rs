//! Integration test moved from `proto::identity_contact` (
//! crate-extraction). Verifies the wire-rule binding
//! `node_id == BLAKE3("veil.identity.v1" || len || pk)` holds end-to-end:
//! a URI produced from a live IdentityDocument decodes to a contact whose
//! node_id binds to its master_pubkey under the same rule a peer's scanner
//! would use.
//!
//! Lives at the integration-test layer because it touches both
//! `cfg::sovereign_flow::create_identity` and `crypto::compute_node_id` —
//! cross-layer assertions that don't fit inside the standalone veil-proto
//! crate.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use veilcore::cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
use veilcore::crypto::identity::compute_node_id;
use veilcore::proto::identity_contact::IdentityContact;

#[test]
fn uri_roundtrips_against_a_real_identity_document() {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let veil_dir: PathBuf =
        std::env::temp_dir().join(format!("veil-contact-tests-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&veil_dir).unwrap();
    let out = create_identity(CreateIdentityOptions {
        veil_dir,
        save_encrypted_with_password: None,
        argon2_params_override: None,
        extra_entropy: None,
        instance_label: "qr".into(),
        pow_difficulty: 0,
        issued_at_unix: 1_700_000_000,
        valid_until_unix: 1_700_000_000 + 7 * 86_400,
        algo: veil_types::SignatureAlgorithm::Ed25519,
    })
    .unwrap();

    let contact = IdentityContact {
        node_id: out.node_id,
        master_algo: out.document.master_algo,
        master_pubkey: out.document.master_pubkey.clone(),
        name: Some("alice".into()),
    };
    let uri = contact.to_uri().unwrap();
    let parsed = IdentityContact::from_uri(&uri).unwrap();

    assert_eq!(parsed, contact);
    assert_eq!(compute_node_id(&parsed.master_pubkey), parsed.node_id);
}
