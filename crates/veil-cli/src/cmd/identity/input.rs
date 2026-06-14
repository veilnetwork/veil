use std::time::Duration;

use veil_cfg;
use veil_cfg::identity_ops::IdentityPowParams;
use veil_cfg::identity_policy::{IdentityPolicy, PowPolicy};
use veil_crypto;

use super::super::cli::{KeyGenArgs, KeyNonceArgs};
use super::super::handlers::{ConfigHandle, ConfigOps};
use super::types::{KeyMaterial, LoadedIdentityConfig, ResolvedKeyGen, ResolvedPowInput};

pub(super) struct IdentityInputResolver;

impl IdentityInputResolver {
    fn config_identity(loaded: &LoadedIdentityConfig) -> Option<&veil_cfg::IdentityConfig> {
        loaded.identity()
    }

    fn resolve_optional<T: Clone>(cli_value: Option<T>, config_value: Option<&T>) -> Option<T> {
        cli_value.or_else(|| config_value.cloned())
    }

    fn require_identity_value<T: Clone>(
        cli_value: Option<T>,
        config_value: Option<&T>,
        field: &'static str,
        cli_flag: &'static str,
        config_key: &'static str,
    ) -> veil_cfg::Result<T> {
        Self::resolve_optional(cli_value, config_value).ok_or(
            veil_cfg::ConfigError::MissingIdentityInput {
                field,
                cli_flag,
                config_key,
            },
        )
    }

    fn resolve_algo(
        cli_value: Option<veil_cfg::SignatureAlgorithm>,
        config_identity: Option<&veil_cfg::IdentityConfig>,
    ) -> veil_cfg::Result<veil_cfg::SignatureAlgorithm> {
        Self::require_identity_value(
            cli_value,
            config_identity.map(|identity| &identity.algo),
            "algorithm",
            "--algo",
            "identity.algo",
        )
    }

    fn resolve_public_key(
        cli_value: Option<String>,
        config_identity: Option<&veil_cfg::IdentityConfig>,
    ) -> veil_cfg::Result<String> {
        Self::require_identity_value(
            cli_value,
            config_identity.map(|identity| &identity.public_key),
            "public key",
            "--public-key",
            "identity.public_key",
        )
    }

    fn resolve_private_key(
        cli_value: Option<String>,
        config_identity: Option<&veil_cfg::IdentityConfig>,
    ) -> veil_cfg::Result<String> {
        Self::require_identity_value(
            cli_value,
            config_identity.map(|identity| &identity.private_key),
            "private key",
            "--private-key",
            "identity.private_key",
        )
    }

    fn resolve_start_nonce(
        cli_value: Option<String>,
        config_identity: Option<&veil_cfg::IdentityConfig>,
    ) -> veil_cfg::Result<veil_crypto::Base64Nonce> {
        Ok(
            Self::resolve_optional(cli_value, config_identity.map(|identity| &identity.nonce))
                .map(veil_crypto::Base64Nonce::new)
                .transpose()?
                .unwrap_or_else(veil_crypto::Base64Nonce::zero),
        )
    }

    fn resolve_pow_params(args: &KeyNonceArgs) -> IdentityPowParams {
        let default_pow = PowPolicy::canonical();

        IdentityPowParams {
            difficulty: args.difficulty.difficulty,
            timeout: Duration::from_secs(args.timeout),
            threads: args.threads.unwrap_or(default_pow.threads),
        }
    }

    pub(super) fn load_config(
        config: &ConfigHandle<'_, impl ConfigOps>,
    ) -> veil_cfg::Result<LoadedIdentityConfig> {
        match config.try_locate()? {
            Some(path) => Ok(LoadedIdentityConfig::loaded(
                path.clone(),
                config.load(&path)?,
            )),
            None => Ok(LoadedIdentityConfig::missing()),
        }
    }

    pub(super) fn resolve_key_gen(
        config: &ConfigHandle<'_, impl ConfigOps>,
        args: &KeyGenArgs,
    ) -> veil_cfg::Result<ResolvedKeyGen> {
        let loaded = Self::load_config(config)?;
        let config_identity = Self::config_identity(&loaded);
        let algo = Self::resolve_optional(
            args.algo.map(Into::into),
            config_identity.map(|identity| &identity.algo),
        )
        .unwrap_or(IdentityPolicy::DEFAULT_ALGO);

        Ok(ResolvedKeyGen {
            loaded,
            algo,
            should_output_only: args.output,
        })
    }

    pub(super) fn resolve_pow_input(
        config: &ConfigHandle<'_, impl ConfigOps>,
        args: KeyNonceArgs,
    ) -> veil_cfg::Result<ResolvedPowInput> {
        let loaded = Self::load_config(config)?;
        let config_identity = Self::config_identity(&loaded);
        let algo = Self::resolve_algo(args.algo.map(Into::into), config_identity)?;
        let public_key = Self::resolve_public_key(args.public_key.clone(), config_identity)?;
        let private_key_arg = super::super::util::resolve_secret_arg(
            args.private_key.clone(),
            args.private_key_file.as_deref(),
            "--private-key",
            "--private-key-file",
        )?;
        let private_key = Self::resolve_private_key(private_key_arg, config_identity)?;
        let start_from = Self::resolve_start_nonce(args.from.clone(), config_identity)?;
        let pow = Self::resolve_pow_params(&args);
        let key_material = KeyMaterial::new(algo, public_key, private_key)?;

        Ok(ResolvedPowInput {
            loaded,
            key_material,
            start_from,
            pow,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::cmd::{
        cli::{DifficultyArgs, KeyNonceArgs, SignatureAlgorithmArg},
        test_support::MockConfigOps,
    };
    use crate::test_support;

    use super::*;

    fn config_handle(config: veil_cfg::Config) -> ConfigHandle<'static, MockConfigOps> {
        let ops = Box::leak(Box::new(MockConfigOps {
            locate_path: PathBuf::from("/tmp/config.toml"),
            loaded_config: config,
            ..MockConfigOps::default()
        }));

        ConfigHandle::new(None, ops)
    }

    fn nonce_args() -> KeyNonceArgs {
        KeyNonceArgs {
            difficulty: DifficultyArgs { difficulty: 7 },
            timeout: 5,
            from: None,
            threads: None,
            public_key: None,
            private_key: None,
            private_key_file: None,
            algo: None,
        }
    }

    #[test]
    fn resolve_pow_input_prefers_cli_values() {
        let keypair = test_support::ed25519_keypair();
        let handle = config_handle(veil_cfg::Config {
            identity: Some(veil_cfg::IdentityConfig {
                algo: veil_cfg::SignatureAlgorithm::Falcon512,
                role: Default::default(),
                public_key: "config-public".to_owned(),
                private_key: "config-private".to_owned(),
                nonce: "AAAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }),
            ..veil_cfg::Config::default()
        });
        let mut args = nonce_args();
        args.algo = Some(SignatureAlgorithmArg::Ed25519);
        args.public_key = Some(keypair.public_key.clone());
        args.private_key = Some(keypair.private_key.clone());
        args.from = Some("AQAAAA==".to_owned());

        let resolved = IdentityInputResolver::resolve_pow_input(&handle, args).unwrap();

        assert_eq!(
            resolved.key_material.algo,
            veil_cfg::SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            resolved.key_material.public_key.as_str(),
            keypair.public_key
        );
        assert_eq!(
            resolved.key_material.private_key.as_str(),
            keypair.private_key
        );
        assert_eq!(resolved.start_from.as_str(), "AQAAAA==");
    }

    #[test]
    fn resolve_pow_input_uses_config_identity_values() {
        let keypair = test_support::ed25519_keypair();
        let handle = config_handle(veil_cfg::Config {
            identity: Some(veil_cfg::IdentityConfig {
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: "AQAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }),
            ..veil_cfg::Config::default()
        });

        let resolved = IdentityInputResolver::resolve_pow_input(&handle, nonce_args()).unwrap();

        assert_eq!(
            resolved.key_material.algo,
            veil_cfg::SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            resolved.key_material.public_key.as_str(),
            keypair.public_key
        );
        assert_eq!(
            resolved.key_material.private_key.as_str(),
            keypair.private_key
        );
        assert_eq!(resolved.start_from.as_str(), "AQAAAA==");
    }

    #[test]
    fn resolve_pow_input_reads_private_key_from_file() {
        let keypair = test_support::ed25519_keypair();
        let dir = test_support::scratch_dir("veil-cli-pk-file");
        let pk_path = dir.join("private_key");
        // Trailing newline must be trimmed by the resolver.
        std::fs::write(&pk_path, format!("{}\n", keypair.private_key)).unwrap();
        let handle = config_handle(veil_cfg::Config::default());

        let mut args = nonce_args();
        args.algo = Some(SignatureAlgorithmArg::Ed25519);
        args.public_key = Some(keypair.public_key.clone());
        args.private_key_file = Some(pk_path);

        let resolved = IdentityInputResolver::resolve_pow_input(&handle, args).unwrap();

        assert_eq!(
            resolved.key_material.private_key.as_str(),
            keypair.private_key
        );
    }

    #[test]
    fn resolve_pow_input_errors_when_required_value_is_missing() {
        let handle = config_handle(veil_cfg::Config::default());

        let err = IdentityInputResolver::resolve_pow_input(&handle, nonce_args()).unwrap_err();

        assert!(matches!(
            err,
            veil_cfg::ConfigError::MissingIdentityInput {
                field: "algorithm",
                cli_flag: "--algo",
                config_key: "identity.algo",
            }
        ));
        assert_eq!(
            err.to_string(),
            "identity algorithm is missing; pass --algo or configure identity.algo"
        );
    }
}
