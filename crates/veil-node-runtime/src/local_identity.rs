//! Local node identity used during the OVL1 handshake (formerly `node/handshake.rs`).

use veil_cfg::{self, Config, NodeId, SignatureAlgorithm};

use crate::error::Result;
use crate::types::NodeId as RuntimeNodeId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeIdentity {
    pub algo: SignatureAlgorithm,
    pub public_key: String,
    /// private key for signing ephemeral KeyAgreement keys (anti-MITM).
    pub private_key: String,
    pub nonce: String,
    pub node_id: RuntimeNodeId,
}

impl HandshakeIdentity {
    pub fn from_config(config: &Config) -> Result<Self> {
        let identity = config
            .identity
            .as_ref()
            .ok_or(veil_cfg::ConfigError::MissingIdentityField("Identity"))?;
        Ok(Self {
            algo: identity.algo,
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone(),
            nonce: identity.nonce.clone(),
            node_id: identity.node_id.unwrap_or(NodeId::from_public_key(
                identity.algo,
                &identity.public_key,
            )?),
        })
    }
}

// Phase 2 session 2 prep: session/handshake.rs decoupled от concrete
// `HandshakeIdentity` via the `LocalHandshakeIdentity` trait — see
// `session::handshake::LocalHandshakeIdentity`.  Implementation here
// delegates к the struct fields.
impl veil_session::handshake::LocalHandshakeIdentity for HandshakeIdentity {
    fn algo(&self) -> SignatureAlgorithm {
        self.algo
    }
    fn public_key(&self) -> &str {
        &self.public_key
    }
    fn private_key(&self) -> &str {
        &self.private_key
    }
    fn nonce(&self) -> &str {
        &self.nonce
    }
    fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}
