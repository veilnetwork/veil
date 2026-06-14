//! Cross-layer consistency test moved from `crypto::identity` (
//! crate-extraction). Asserts that the sovereign-identity layer's
//! `node_id` derivation (`crypto::compute_node_id`) coincides with the
//! runtime's per-device address derivation (`cfg::NodeId::from_public_key`)
//! byte-for-byte for the same pubkey — the invariant that lets the
//! standalone-mode flow produce a single canonical node identifier.
//!
//! Lives at the integration-test layer because it spans crypto + cfg.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use veil_types::SignatureAlgorithm;

use veilcore::cfg::NodeId;
use veilcore::crypto::identity::compute_node_id;

#[test]
fn node_id_matches_cfg_node_id() {
    let pk_bytes = [0xABu8; 32];
    let pk_b64 = STANDARD.encode(pk_bytes);
    let crypto_id = compute_node_id(&pk_bytes);
    let cfg_id = NodeId::from_public_key(SignatureAlgorithm::Ed25519, &pk_b64).unwrap();
    assert_eq!(&crypto_id, cfg_id.as_bytes());
}
