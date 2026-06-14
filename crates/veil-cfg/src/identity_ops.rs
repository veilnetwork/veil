use std::sync::mpsc;
use std::time::Duration;

use super::identity_policy::{IdentityPolicy, PowPolicy};
use super::{Config, IdentityConfig, SignatureAlgorithm};
use crate as cfg;
use veil_crypto as crypto;

#[derive(Clone, Debug)]
pub struct IdentityPowParams {
    pub difficulty: u32,
    pub timeout: Duration,
    pub threads: usize,
}

impl Default for IdentityPowParams {
    fn default() -> Self {
        Self::from(PowPolicy::canonical())
    }
}

#[derive(Clone, Debug)]
pub struct IdentityProvisionParams {
    pub algo: SignatureAlgorithm,
    pub pow: IdentityPowParams,
}

#[derive(Clone, Debug)]
pub struct ExplicitKeyMaterial {
    pub algo: SignatureAlgorithm,
    pub public_key: String,
    pub private_key: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedKeyMaterial {
    pub algo: SignatureAlgorithm,
    pub public_key: crypto::Base64PublicKey,
    pub private_key: crypto::Base64PrivateKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityRepairPlan {
    RegenerateKeysAndNonce,
    RecomputeNonce,
}

#[derive(Clone, Debug)]
pub struct IdentityUseCases {
    pow: IdentityPowParams,
}

impl Default for IdentityProvisionParams {
    fn default() -> Self {
        let policy = IdentityPolicy::canonical();
        Self {
            algo: policy.algo,
            pow: IdentityPowParams::from(policy.pow),
        }
    }
}

impl From<PowPolicy> for IdentityPowParams {
    fn from(value: PowPolicy) -> Self {
        Self {
            difficulty: value.difficulty,
            timeout: value.timeout,
            threads: value.threads,
        }
    }
}

impl IdentityUseCases {
    pub fn new(pow: IdentityPowParams) -> Self {
        Self { pow }
    }

    pub fn provision(
        &self,
        algo: SignatureAlgorithm,
        progress: Option<mpsc::Sender<crypto::PowProgress>>,
    ) -> cfg::Result<IdentityConfig> {
        let keypair = crypto::generate_keypair(algo);
        let node_id = cfg::NodeId::from_public_key(algo, &keypair.public_key)?;
        let nonce = self
            .search_for_explicit_key_material(
                ExplicitKeyMaterial {
                    algo,
                    public_key: keypair.public_key.clone(),
                    private_key: keypair.private_key.clone(),
                },
                crypto::Base64Nonce::zero(),
                progress,
            )?
            .best_nonce
            .into_inner();

        Ok(IdentityConfig {
            algo,
            role: Default::default(),
            public_key: keypair.public_key,
            private_key: keypair.private_key,
            nonce,
            node_id: Some(node_id),
            key_passphrase: None,
            key_passphrase_file: None,
            key_passphrase_prompt: false,
            lazy_mining: true,
            max_lazy_difficulty: 64,
        })
    }

    pub fn recompute_nonce(&self, identity: &mut IdentityConfig) -> cfg::Result<bool> {
        let result = self.search_for_explicit_key_material(
            ExplicitKeyMaterial {
                algo: identity.algo,
                public_key: identity.public_key.clone(),
                private_key: identity.private_key.clone(),
            },
            crypto::Base64Nonce::zero(),
            None,
        )?;
        identity.nonce = result.best_nonce.into_inner();
        Ok(true)
    }

    pub fn regenerate_and_repair(&self, identity: &mut IdentityConfig) -> cfg::Result<bool> {
        let generated = crypto::generate_keypair(identity.algo);
        identity.public_key = generated.public_key;
        identity.private_key = generated.private_key;
        self.recompute_nonce(identity)
    }

    pub fn apply_repairs(
        &self,
        config: &mut Config,
        repairs: &[IdentityRepairPlan],
    ) -> cfg::Result<usize> {
        let Some(identity) = config.identity.as_mut() else {
            return Ok(0);
        };

        let mut fixed = 0;
        let needs_regenerate = repairs.contains(&IdentityRepairPlan::RegenerateKeysAndNonce);
        let needs_nonce = needs_regenerate || repairs.contains(&IdentityRepairPlan::RecomputeNonce);

        if needs_nonce {
            let repaired = if needs_regenerate {
                self.regenerate_and_repair(identity)?
            } else {
                self.recompute_nonce(identity)?
            };
            if repaired {
                fixed = repairs.len();
            }
        }

        Ok(fixed)
    }

    pub fn search_for_explicit_key_material(
        &self,
        key_material: ExplicitKeyMaterial,
        start_from: crypto::Base64Nonce,
        progress: Option<mpsc::Sender<crypto::PowProgress>>,
    ) -> cfg::Result<crypto::PowResult> {
        self.search_for_verified_key_material(
            VerifiedKeyMaterial {
                algo: key_material.algo,
                public_key: crypto::Base64PublicKey::new(
                    key_material.algo,
                    key_material.public_key,
                )?,
                private_key: crypto::Base64PrivateKey::new(
                    key_material.algo,
                    key_material.private_key,
                )?,
            },
            start_from,
            progress,
        )
    }

    pub fn search_for_verified_key_material(
        &self,
        key_material: VerifiedKeyMaterial,
        start_from: crypto::Base64Nonce,
        progress: Option<mpsc::Sender<crypto::PowProgress>>,
    ) -> cfg::Result<crypto::PowResult> {
        // Reset any leftover Ctrl-C signal from a previous interactive search
        // before starting a new one. This must happen here (at the CLI entry
        // point) rather than inside search_nonce to avoid racing with
        // concurrent searches in tests.
        crypto::reset_interrupt_flag()?;
        crypto::search_nonce(crypto::PowParams {
            algo: key_material.algo,
            public_key: key_material.public_key,
            private_key: key_material.private_key,
            target_zero_bits: self.pow.difficulty,
            timeout: self.pow.timeout,
            start_from,
            threads: self.pow.threads,
            progress,
        })
    }
}
