//! Mesh-beacon signature verification.
//!
//! Moved here from `proto::mesh::MeshBeaconPayload::verify_auth`
//! to break the `proto → crypto` dependency direction (cycle
//! blocker for crate extraction): proto remains pure-data
//! wire-format definitions; orchestration of sign/verify lives at
//! the caller layer (`node/`).
//!
//! See `docs/CRATE_ARCHITECTURE.md` status discussion.

use veil_types::SignatureAlgorithm;

use veil_crypto::verify_message;
use veil_proto::mesh::MeshBeaconPayload;

/// Verify the beacon signature.
///
/// Returns `true` iff `BLAKE3(public_key) == node_id` AND the
/// signature is valid. Unsigned beacons (empty `public_key`)
/// return `false`. Callers that accept unsigned beacons should
/// check `!beacon.is_signed` first.
pub fn verify_mesh_beacon_auth(beacon: &MeshBeaconPayload) -> bool {
    if beacon.public_key.is_empty() {
        return false;
    }
    // Check identity binding.
    let expected_id: [u8; 32] = *blake3::hash(&beacon.public_key).as_bytes();
    if expected_id != beacon.node_id {
        return false;
    }
    // Verify signature.
    let algo = if beacon.algo == 2 {
        SignatureAlgorithm::Falcon512
    } else {
        SignatureAlgorithm::Ed25519
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let pubkey_b64 = STANDARD.encode(&beacon.public_key);
    let body = beacon.signable_body();
    verify_message(algo, &pubkey_b64, &body, &beacon.signature).is_ok()
}
