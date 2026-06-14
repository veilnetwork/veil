//! Cross-validation test moved from `node::anonymity::directory` (
//! crate-extraction). Two DHT-key derivations in the codebase share the
//! BLAKE3 substrate (relay-directory keys vs bootstrap-bundle
//! keys) — their domain prefixes MUST NOT collide for identical input
//! otherwise an attacker could write to one namespace and have it
//! interpreted in the other (cross-protocol injection oracle).
//!
//! Lives at the integration-test layer because it spans the now-extracted
//! veil-anonymity crate AND veilcore's `node::bootstrap`.

use veil_anonymity::directory::relay_directory_dht_key;
use veil_bootstrap::bootstrap_bundle_dht_key;

#[test]
fn relay_directory_and_bootstrap_dht_keys_use_distinct_domain_prefix() {
    let n = [0u8; 32];
    let relay_key = relay_directory_dht_key(&n);
    let bootstrap_key = bootstrap_bundle_dht_key();
    assert_ne!(
        relay_key, bootstrap_key,
        "relay-directory and bootstrap-bundle DHT keys must NOT collide \
         (cross-protocol injection oracle would otherwise be possible)"
    );
}
