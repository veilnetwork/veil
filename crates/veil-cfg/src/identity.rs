use veil_crypto::{Base64Nonce, Base64PrivateKey, Base64PublicKey};

use super::{ConfigError, IdentityConfig, NodeId, Result, SignatureAlgorithm};

/// Strongly-typed companion to `IdentityConfig`: the same fields with the
/// base64-encoded key material already parsed and length-checked, ready for
/// use by crypto code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainIdentity {
    /// Signature algorithm this identity uses (Ed25519 / Falcon512).
    pub algo: SignatureAlgorithm,
    /// Parsed raw public key.
    pub public_key: Base64PublicKey,
    /// Parsed raw private key.
    pub private_key: Base64PrivateKey,
    /// Parsed PoW nonce.
    pub nonce: Base64Nonce,
}

impl DomainIdentity {
    /// Decode an on-disk `IdentityConfig` into the validated domain form.
    /// Returns [`ConfigError`] on malformed base64 or algorithm/key-length mismatch.
    pub fn from_config(config: &IdentityConfig) -> Result<Self> {
        Ok(Self {
            algo: config.algo,
            public_key: Base64PublicKey::new(config.algo, config.public_key.clone())?,
            private_key: Base64PrivateKey::new(config.algo, config.private_key.clone())?,
            nonce: Base64Nonce::new(config.nonce.clone())?,
        })
    }

    /// Re-encode this identity back into an on-disk `IdentityConfig` shape
    /// (for tests / migrations that round-trip through the domain form).
    /// `role` reverts to its default — this method is lossy for anything
    /// outside the core key material.
    pub fn into_config(self) -> IdentityConfig {
        let node_id = self.node_id().ok();
        IdentityConfig {
            algo: self.algo,
            role: Default::default(),
            public_key: self.public_key.into_inner(),
            private_key: self.private_key.into_inner(),
            nonce: self.nonce.into_inner(),
            node_id,
            key_passphrase: None,
            key_passphrase_file: None,
            key_passphrase_prompt: false,
            lazy_mining: true,
            max_lazy_difficulty: 64,
        }
    }

    /// Derive the `NodeId` (BLAKE3 of public key) for this identity.
    pub fn node_id(&self) -> Result<NodeId> {
        NodeId::from_public_key(self.algo, self.public_key.as_str())
    }

    /// Compute the leading-zero-bit PoW score for this identity's nonce.
    pub fn pow_score(&self) -> Result<veil_crypto::PowScore> {
        veil_crypto::pow_score(self.algo, &self.public_key, &self.private_key, &self.nonce)
    }
}

/// Extract the identity block from `config` as a validated `DomainIdentity`.
/// Returns [`ConfigError::MissingIdentityField`] when `config.identity` is `None`.
pub fn require_identity(config: &super::Config) -> Result<DomainIdentity> {
    let identity = config
        .identity
        .as_ref()
        .ok_or(ConfigError::MissingIdentityField("Identity"))?;
    DomainIdentity::from_config(identity)
}

// ── Legacy domain-identity validation (moved from crypto in c) ─────────
//
// Orchestration helpers that take a `DomainIdentity` (cfg-layer type) and
// dispatch into crypto primitives. Live here so crypto/ stays free of cfg/
// types — preserves crypto's standalone extractability.

/// Round-trip a known message through sign + verify using this identity's
/// keys. Returns `false` if either step fails.
pub fn identity_signature_is_valid(identity: &DomainIdentity) -> bool {
    let message = b"veil-cli identity validation";
    veil_crypto::sign_message(
        identity.algo,
        identity.public_key.as_str(),
        identity.private_key.as_str(),
        message,
    )
    .and_then(|signature| {
        veil_crypto::verify_message(
            identity.algo,
            identity.public_key.as_str(),
            message,
            &signature,
        )
    })
    .is_ok()
}

/// Whether this identity's PoW nonce meets `difficulty`.
pub fn identity_nonce_meets_difficulty(identity: &DomainIdentity, difficulty: u32) -> bool {
    veil_crypto::pow_score(
        identity.algo,
        &identity.public_key,
        &identity.private_key,
        &identity.nonce,
    )
    .map(|score| score.zero_bits >= difficulty)
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn domain_identity_pow_score_matches_crypto_function() {
        let identity = DomainIdentity::from_config(&test_support::valid_identity()).unwrap();

        let score = identity.pow_score().unwrap();
        let expected = veil_crypto::pow_score(
            identity.algo,
            &identity.public_key,
            &identity.private_key,
            &identity.nonce,
        )
        .unwrap();

        assert_eq!(score, expected);
    }

    #[test]
    fn node_id_matches_configured_public_key() {
        let identity = DomainIdentity::from_config(&test_support::valid_identity()).unwrap();

        let node_id = identity.node_id().unwrap();
        let expected =
            NodeId::from_public_key(identity.algo, identity.public_key.as_str()).unwrap();

        assert_eq!(node_id, expected);
    }
}
