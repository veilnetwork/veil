//! Compile-time builtin seed set.
//!
//! When `config.peers` and `config.bootstrap_peers` are both empty, the node
//! falls back to this hardcoded list to find the network.
//!
//! # Updating seeds
//!
//! Edit the entries in `builtin_seeds` below. Each seed needs the node's
//! public key (base64), nonce (base64), transport URI, and signature
//! algorithm. Rebuild with `--features production-seeds` after changes.

use veil_types::BootstrapPeer;

// fail the build if the seed list is empty AND the operator
// did not opt into an explicit stance. Requires one of:
// * `production-seeds` — real seed entries populated in `builtin_seeds`.
// * `allow-empty-seeds` — testnet / custom-deployment, no builtins.
// Dev builds (`debug_assertions`) and tests are exempt.
//
// The guard is now trivially "is `production-seeds` missing AND
// `allow-empty-seeds` missing" — the actual non-emptiness of the Vec is
// the author's responsibility; we don't re-check it at build time because
// `Vec::with_capacity`/`push` aren't const-evaluable.
#[cfg(all(
    not(debug_assertions),
    not(test),
    not(feature = "production-seeds"),
    not(feature = "allow-empty-seeds"),
))]
compile_error!(
    "release build without seeds: populate `builtin_seeds()` in \
     node/bootstrap/seeds.rs and build with `--features production-seeds`, \
     or opt in to `--features allow-empty-seeds` for testnet / \
     custom-deployment builds."
);

/// Hardcoded bootstrap seed list.
///
/// This is the last-resort discovery mechanism — used only when no peers
/// are configured, no DNS TXT records for `_veil._bootstrap.<domain>`
/// resolve, and no bootstrap-bundle is cached.
///
/// **Build-feature semantics**:
/// * `production-seeds` (or `debug_assertions` / `cfg(test)`) — return
/// the real production seed list compiled in below. Operators
/// update by editing the entries and rebuilding.
/// * `allow-empty-seeds` — return `Vec::new`. This keeps testnet /
/// custom-deployment builds from accidentally dialing the production
/// seed nodes at startup, which would leak DNS + TLS-handshake
/// attempts to production infrastructure (a censorship-evasion
/// leak when the build is supposed to be isolated).
/// bug surfaced by 5-node devnet smoke: node-0 ran with empty
/// `peers`/`bootstrap_peers` and fell back to the prod seeds.
///
/// In a no-default-features release build the workspace `compile_error!`
/// at the top of the file refuses to build without one of the two
/// stances explicitly chosen, so production binaries can't accidentally
/// ship with empty seeds either.
// under `allow-empty-seeds` (and not `production-seeds`
// not test, not debug) the builtin list is empty by design — testnet
// operators provide peers via `peers add` / DNS / OOB-bundle, and we
// don't want a testnet binary phoning home to production seeds (DNS
// + TLS-handshake attempts to production infra leak censorship-
// resistance posture and operationally pollute the prod seed nodes
// with unrelated probe traffic). Tests + dev builds get the full
// list because most unit tests exercise the "we have a seed list"
// code path.
#[cfg(all(
    not(test),
    not(debug_assertions),
    feature = "allow-empty-seeds",
    not(feature = "production-seeds"),
))]
pub fn builtin_seeds() -> Vec<BootstrapPeer> {
    Vec::new()
}

#[cfg(not(all(
    not(test),
    not(debug_assertions),
    feature = "allow-empty-seeds",
    not(feature = "production-seeds"),
)))]
pub fn builtin_seeds() -> Vec<BootstrapPeer> {
    // The public source ships with NO built-in seed nodes. Operators running
    // their own network populate this list with their bootstrap nodes'
    // transport URIs + Ed25519 pubkeys/nonces and build with
    // `--features production-seeds`; until then a release build must use
    // `--features allow-empty-seeds` and supply peers via config /
    // `peers add` / DNS / an out-of-band bootstrap bundle.
    //
    // veilnetwork production seed nodes (veilnet1/2/3). obfs4-tcp, advertised by
    // IP; the deployment-wide obfs4 PSK is supplied at runtime (it is a network
    // anti-probe secret, NOT compiled in here). Ed25519 identity pubkey + PoW
    // nonce per node (`config init -d 24`, lazy_mining pinned off so these stay
    // stable). Built into the binary under `--features production-seeds`.
    vec![
        veil_types::BootstrapPeer {
            transport: "obfs4-tcp://203.12.31.146:5556".to_owned(),
            public_key: "VVxxLVptuXZ/qFV94aPP1daiz6ZYg2yf1JLbc1VHXhQ=".to_owned(),
            nonce: "AdW8kw==".to_owned(),
            algo: veil_types::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
        veil_types::BootstrapPeer {
            transport: "obfs4-tcp://203.12.31.145:5556".to_owned(),
            public_key: "9j/nd+Bm/lao9M+W/Bq+oee7X3H2JmR4w4vJ2ji2tU4=".to_owned(),
            nonce: "AMiD9w==".to_owned(),
            algo: veil_types::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
        veil_types::BootstrapPeer {
            transport: "obfs4-tcp://203.12.31.134:5556".to_owned(),
            public_key: "cjuRf8cH3KLWqwAT89NRn+8QG7JsXc6PH4jXjOM7SJM=".to_owned(),
            nonce: "ACr87g==".to_owned(),
            algo: veil_types::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        },
    ]
}

/// DHT key under which the dynamically-published bootstrap bundle lives
///. The bundle is a JSON array [`BootstrapPeer`] entries
/// stored under this well-known key so that operators can update the list
/// without a binary rebuild. Consumers query the DHT for this key and
/// merge the result into their local `config.bootstrap_peers`.
///
/// Derived as `BLAKE3("veil:v1:bootstrap-bundle")`. Computed lazily
/// the first time it's read to avoid a build-time const-fn dependency.
pub fn bootstrap_bundle_dht_key() -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil:v1:bootstrap-bundle");
    *h.finalize().as_bytes()
}

/// Serialize a list of bootstrap peers into the on-wire bundle format.
/// JSON is chosen over a custom binary codec because the bundle is a
/// config blob, not a hot-path frame: it's fetched once at startup (or on
/// operator request), size is bounded by `MAX_DHT_VALUE_BYTES = 16 KiB`, and
/// JSON keeps the format extensible and debuggable via `jq`.
pub fn encode_bootstrap_bundle(peers: &[BootstrapPeer]) -> Result<Vec<u8>, String> {
    serde_json::to_vec(peers).map_err(|e| format!("serialize bootstrap bundle: {e}"))
}

/// Parse a bundle previously serialized by [`encode_bootstrap_bundle`].
pub fn decode_bootstrap_bundle(blob: &[u8]) -> Result<Vec<BootstrapPeer>, String> {
    serde_json::from_slice(blob).map_err(|e| format!("parse bootstrap bundle: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_types::SignatureAlgorithm;

    fn sample_peer() -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://seed1.example:9000".to_owned(),
            public_key: "dGVzdC1wdWJsaWMta2V5".to_owned(),
            nonce: "dGVzdC1ub25jZQ==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    #[test]
    fn bundle_roundtrip_empty() {
        let blob = encode_bootstrap_bundle(&[]).unwrap();
        let decoded = decode_bootstrap_bundle(&blob).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn bundle_roundtrip_preserves_fields() {
        let original = vec![sample_peer()];
        let blob = encode_bootstrap_bundle(&original).unwrap();
        let decoded = decode_bootstrap_bundle(&blob).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn bundle_fits_in_dht_value_for_reasonable_counts() {
        // 8 peers with typical sizes must fit under MAX_DHT_VALUE_BYTES.
        let peers = (0..8)
            .map(|i| BootstrapPeer {
                transport: format!("tcp://seed{i}.example:9000"),
                public_key: "A".repeat(44), // base64 of 32-byte ed25519 pubkey
                nonce: "B".repeat(24),      // base64 of 16-byte nonce
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            })
            .collect::<Vec<_>>();
        let blob = encode_bootstrap_bundle(&peers).unwrap();
        assert!(
            blob.len() <= veil_proto::budget::MAX_DHT_VALUE_BYTES,
            "8-peer bundle was {} bytes, exceeds MAX_DHT_VALUE_BYTES = {}",
            blob.len(),
            veil_proto::budget::MAX_DHT_VALUE_BYTES,
        );
    }

    #[test]
    fn bundle_dht_key_is_deterministic() {
        assert_eq!(bootstrap_bundle_dht_key(), bootstrap_bundle_dht_key());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_bootstrap_bundle(b"not json").is_err());
    }
}
