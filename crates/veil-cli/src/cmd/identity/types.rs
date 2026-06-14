use std::path::{Path, PathBuf};

use veil_cfg;
use veil_cfg::identity_ops::IdentityPowParams;
use veil_crypto;

#[derive(Clone, Debug)]
pub(super) enum LoadedIdentityConfig {
    Missing,
    Loaded {
        path: PathBuf,
        config: Box<veil_cfg::Config>,
    },
}

impl LoadedIdentityConfig {
    pub(super) fn missing() -> Self {
        Self::Missing
    }

    pub(super) fn loaded(path: PathBuf, config: veil_cfg::Config) -> Self {
        Self::Loaded {
            path,
            config: Box::new(config),
        }
    }

    pub(super) fn is_loaded(&self) -> bool {
        matches!(self, Self::Loaded { .. })
    }

    pub(super) fn path(&self) -> Option<&Path> {
        match self {
            Self::Missing => None,
            Self::Loaded { path, .. } => Some(path.as_path()),
        }
    }

    pub(super) fn identity(&self) -> Option<&veil_cfg::IdentityConfig> {
        match self {
            Self::Missing => None,
            Self::Loaded { config, .. } => config.identity.as_ref(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct KeyMaterial {
    pub(super) algo: veil_cfg::SignatureAlgorithm,
    pub(super) public_key: veil_crypto::Base64PublicKey,
    pub(super) private_key: veil_crypto::Base64PrivateKey,
}

impl KeyMaterial {
    pub(super) fn new(
        algo: veil_cfg::SignatureAlgorithm,
        public_key: String,
        private_key: String,
    ) -> veil_cfg::Result<Self> {
        Ok(Self {
            algo,
            public_key: veil_crypto::Base64PublicKey::new(algo, public_key)?,
            private_key: veil_crypto::Base64PrivateKey::new(algo, private_key)?,
        })
    }

    pub(super) fn matches_identity(&self, identity: &veil_cfg::IdentityConfig) -> bool {
        identity.algo == self.algo
            && identity.public_key == self.public_key.as_str()
            && identity.private_key == self.private_key.as_str()
    }

    pub(super) fn pow_score(
        &self,
        nonce: &veil_crypto::Base64Nonce,
    ) -> veil_cfg::Result<veil_crypto::PowScore> {
        veil_crypto::pow_score(self.algo, &self.public_key, &self.private_key, nonce)
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedPowInput {
    pub(super) loaded: LoadedIdentityConfig,
    pub(super) key_material: KeyMaterial,
    pub(super) start_from: veil_crypto::Base64Nonce,
    pub(super) pow: IdentityPowParams,
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedKeyGen {
    pub(super) loaded: LoadedIdentityConfig,
    pub(super) algo: veil_cfg::SignatureAlgorithm,
    pub(super) should_output_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_identity_config_builders_preserve_presence_invariant() {
        let missing = LoadedIdentityConfig::missing();
        assert!(!missing.is_loaded());
        assert!(missing.path().is_none());
        assert!(missing.identity().is_none());

        let loaded = LoadedIdentityConfig::loaded(
            PathBuf::from("/tmp/config.toml"),
            veil_cfg::Config {
                identity: Some(veil_cfg::IdentityConfig::default()),
                ..veil_cfg::Config::default()
            },
        );
        assert!(loaded.is_loaded());
        assert_eq!(loaded.path(), Some(Path::new("/tmp/config.toml")));
        assert!(loaded.identity().is_some());
    }

    #[test]
    fn loaded_identity_config_distinguishes_loaded_config_without_identity() {
        let loaded = LoadedIdentityConfig::loaded(
            PathBuf::from("/tmp/config.toml"),
            veil_cfg::Config::default(),
        );

        assert!(loaded.is_loaded());
        assert_eq!(loaded.path(), Some(Path::new("/tmp/config.toml")));
        assert!(loaded.identity().is_none());
    }
}
