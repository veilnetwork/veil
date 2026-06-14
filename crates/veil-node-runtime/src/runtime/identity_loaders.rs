//! Identity-material loaders called during runtime construction and
//! handshake-reload paths.
//!
//! Three loaders, all stateless and infallible-where-graceful (a missing
//! key or mismatched algo returns `None` instead of panicking):
//!
//! - [`load_falcon_signer`][] — extracts a `FalconSigner` when the operator
//!   has configured a Falcon-512 identity.
//! - [`load_signing_key`][] — extracts the runtime's Ed25519 `SigningKey`
//!   when the operator has configured an Ed25519 identity.  Returns
//!   `None` for Falcon-512 nodes (they don't use ed25519 for routing).
//! - [`build_standalone_sovereign_identity`][] — degenerate
//!   `SovereignIdentity` constructor for nodes that have no
//!   `identity_document.bin` on disk yet — promotes the runtime's
//!   `[identity]` Ed25519 keypair into a self-signed sovereign identity
//!   where `master_pk == device_pk`.
//!
//! Exactly one of `load_signing_key` / `load_falcon_signer` yields
//! `Some` for any given config; both yield `None` when the `[identity]`
//! section is absent (pure outbound clients).

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use veil_cfg::{self, Config};
use veil_discovery::service::FalconSigner;
use veil_identity::sovereign::SovereignIdentity;
use veil_observability::NodeLogger;

/// Build a [`FalconSigner`] from the node's identity config.
///
/// Returns `None` when the identity is absent or uses Ed25519 — exactly
/// one of `load_signing_key` / `load_falcon_signer` yields `Some` for a
/// given config, never both.
pub fn load_falcon_signer(config: &Config) -> Option<Arc<FalconSigner>> {
    let identity = config.identity.as_ref()?;
    if identity.algo != veil_cfg::SignatureAlgorithm::Falcon512 {
        return None;
    }
    let pubkey_bytes = STANDARD.decode(&identity.public_key).ok()?;
    Some(Arc::new(FalconSigner {
        public_key: pubkey_bytes,
        private_key_b64: identity.private_key.clone(),
    }))
}

/// Load the local ed25519 `SigningKey` from the config, if available.
///
/// Returns `None` when the identity section is missing or the private
/// key cannot be decoded (e.g. Falcon-512 nodes do not use ed25519 for
/// routing).
pub fn load_signing_key(config: &Config) -> Option<Arc<ed25519_dalek::SigningKey>> {
    let identity = config.identity.as_ref()?;
    if identity.algo != veil_cfg::SignatureAlgorithm::Ed25519 {
        return None;
    }
    // Zeroizing wraps the decoded vec so the seed bytes wipe on every
    // early-return path (length-mismatch, try_into-failure) and on the
    // happy path the moment we transfer the bytes to the SigningKey.
    // Without this the base64-decoded heap allocation lingers in the
    // tokio runtime's allocator until the page gets reused.
    let key_bytes: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(STANDARD.decode(&identity.private_key).ok()?);
    if key_bytes.len() != 32 {
        return None;
    }
    let mut arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&key_bytes);
    Some(Arc::new(ed25519_dalek::SigningKey::from_bytes(&arr)))
}

/// Build a degenerate "standalone" `SovereignIdentity` from the runtime's
/// `[identity]` Ed25519 keypair when no `identity_document.bin` exists
/// on disk.
///
/// In standalone mode the device IS the master: `master_pk == device_pk`,
/// `node_id == device_id == BLAKE3(pk)`, and the lone `IdentityKey` is a
/// self-signed delegation.  The rest of the runtime sees a normal
/// `IdentityDocument` and does not branch on standalone-ness — verifier,
/// dispatcher, mesh DHT republish all work unchanged.
///
/// Returns `None` (and logs the reason at INFO) when the config lacks an
/// Ed25519 keypair (Falcon-512 nodes, missing identity section).  Such
/// nodes fall through to the legacy node_id-keyed handshake path.
pub fn build_standalone_sovereign_identity(
    veil_dir: &std::path::Path,
    config: &Config,
    logger: &Arc<NodeLogger>,
) -> Option<Arc<SovereignIdentity>> {
    use veil_cfg::sovereign_flow::save_standalone_identity_to_dir;
    use veil_proto::identity_document::DELEGATION_VALIDITY_SECS;

    // Need an Ed25519 device SK.  Falcon-512 + missing identity blocks
    // both fail this check.
    let Some(sk_arc) = load_signing_key(config) else {
        logger.info(
            "node.sovereign_identity.standalone_skipped",
            "no Ed25519 [identity] keypair — running as legacy \
             node_id-keyed (no sovereign identity)",
        );
        return None;
    };

    let sk_bytes = sk_arc.to_bytes();
    // Stage 6 slice 6i — mlocked storage for the standalone-mode SK seed.
    let device_sk_seed: veil_util::sensitive_bytes::SensitiveBytesN<32> =
        veil_util::sensitive_bytes::SensitiveBytesN::from_bytes(sk_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let valid_until = now.saturating_add(DELEGATION_VALIDITY_SECS);

    let _doc = match save_standalone_identity_to_dir(veil_dir, &device_sk_seed, now, valid_until) {
        Ok(d) => d,
        Err(e) => {
            logger.warn(
                "node.sovereign_identity.standalone_build_failed",
                format!(
                    "could not build degenerate standalone identity: {e} \
                         — running as legacy node_id-keyed"
                ),
            );
            return None;
        }
    };

    match SovereignIdentity::load_from_dir(veil_dir) {
        Ok(sov) => {
            logger.info(
                "node.sovereign_identity.standalone_built",
                format!(
                    "node_id={} (master_pk == device_pk; auto-built degenerate \
                     IdentityDocument from [identity] keypair)",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            );
            Some(Arc::new(sov))
        }
        Err(e) => {
            logger.warn(
                "node.sovereign_identity.standalone_load_failed",
                format!(
                    "wrote degenerate IdentityDocument but reload failed: \
                     {e} — running as legacy node_id-keyed"
                ),
            );
            None
        }
    }
}
