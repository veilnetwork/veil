use veil_cfg;
use veil_crypto;

use super::super::handlers::{ConfigHandle, ConfigMutation, ConfigOps};
use super::types::ResolvedPowInput;

pub(super) struct NoncePersistencePolicy;

impl NoncePersistencePolicy {
    pub(super) fn persist_better_nonce(
        config_handle: &ConfigHandle<'_, impl ConfigOps>,
        resolved: ResolvedPowInput,
        result: &veil_crypto::PowResult,
    ) -> veil_cfg::Result<()> {
        if !Self::has_loaded_config(&resolved) {
            return Ok(());
        }

        config_handle.update_existing(|_path, config| {
            let Some(identity) = config.identity.as_mut() else {
                return Ok(ConfigMutation::keep(()));
            };

            if !Self::should_replace_nonce(identity, &resolved, result)? {
                return Ok(ConfigMutation::keep(()));
            }

            identity.nonce = result.best_nonce.clone().into_inner();
            Ok(ConfigMutation::save(()))
        })?;

        Ok(())
    }

    fn has_loaded_config(resolved: &ResolvedPowInput) -> bool {
        resolved.loaded.path().is_some()
    }

    fn should_replace_nonce(
        identity: &veil_cfg::IdentityConfig,
        resolved: &ResolvedPowInput,
        result: &veil_crypto::PowResult,
    ) -> veil_cfg::Result<bool> {
        if !resolved.key_material.matches_identity(identity) {
            return Ok(false);
        }

        let current_score = veil_cfg::DomainIdentity::from_config(identity)?.pow_score()?;
        let candidate_score = resolved.key_material.pow_score(&result.best_nonce)?;

        Ok(candidate_score.zero_bits > current_score.zero_bits)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use crate::cmd::{adapters::StdConfigOps, handlers::ConfigHandle};
    use crate::test_support;
    use veil_cfg::{RuntimeFlavor, SignatureAlgorithm};

    use super::super::types::{KeyMaterial, LoadedIdentityConfig, ResolvedPowInput};
    use super::*;

    #[test]
    fn persist_better_nonce_saves_only_when_result_improves_score() {
        let keypair = test_support::ed25519_keypair();
        let public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .expect("valid public key");
        let private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .expect("valid private key");
        let current_nonce = veil_crypto::Base64Nonce::zero();
        let better_nonce = find_nonce_with_more_zero_bits(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            current_nonce.clone(),
        );
        let path = temp_config_path("persist-better-nonce");
        let config_handle = save_config(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
        );
        let resolved = resolved_input(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
            public_key.clone(),
            private_key.clone(),
        );

        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            resolved,
            &pow_result(better_nonce.clone(), &public_key, &private_key),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert_eq!(
            loaded.identity.expect("identity present").nonce,
            better_nonce.into_inner()
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_better_nonce_skips_when_config_was_not_loaded() {
        let keypair = test_support::ed25519_keypair();
        let public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .expect("valid public key");
        let private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .expect("valid private key");
        let current_nonce = veil_crypto::Base64Nonce::zero();
        let better_nonce = find_nonce_with_more_zero_bits(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            current_nonce.clone(),
        );
        let path = temp_config_path("persist-config-not-loaded");
        let config_handle = save_config(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
        );
        let resolved = resolved_missing_input(public_key.clone(), private_key.clone());

        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            resolved,
            &pow_result(better_nonce, &public_key, &private_key),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert_eq!(
            loaded.identity.expect("identity present").nonce,
            current_nonce.into_inner()
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_better_nonce_skips_equal_or_worse_score() {
        let keypair = test_support::ed25519_keypair();
        let public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .expect("valid public key");
        let private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .expect("valid private key");
        let current_nonce = find_nonce_with_min_zero_bits(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            1,
        );
        let path = temp_config_path("persist-same-or-worse");
        let config_handle = save_config(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
        );

        let same_score = resolved_input(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
            public_key.clone(),
            private_key.clone(),
        );
        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            same_score,
            &pow_result(current_nonce.clone(), &public_key, &private_key),
        )
        .unwrap();

        let worse_nonce = veil_crypto::Base64Nonce::zero();
        let worse_score = resolved_input(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
            public_key.clone(),
            private_key.clone(),
        );
        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            worse_score,
            &pow_result(worse_nonce, &public_key, &private_key),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert_eq!(
            loaded.identity.expect("identity present").nonce,
            current_nonce.into_inner()
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_better_nonce_skips_when_identity_is_missing() {
        let keypair = test_support::ed25519_keypair();
        let public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .expect("valid public key");
        let private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .expect("valid private key");
        let path = temp_config_path("persist-missing-identity");
        let config_handle = save_full_config(&path, veil_cfg::Config::default());
        let resolved = resolved_missing_identity(&path, public_key.clone(), private_key.clone());
        let better_nonce = find_nonce_with_min_zero_bits(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            1,
        );

        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            resolved,
            &pow_result(better_nonce, &public_key, &private_key),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert!(loaded.identity.is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_better_nonce_skips_when_key_material_differs() {
        let stored = test_support::ed25519_keypair();
        let candidate = test_support::ed25519_keypair();
        let candidate_public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            candidate.public_key.clone(),
        )
        .expect("valid public key");
        let candidate_private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            candidate.private_key.clone(),
        )
        .expect("valid private key");
        let stored_nonce = veil_crypto::Base64Nonce::zero();
        let better_candidate_nonce = find_nonce_with_more_zero_bits(
            SignatureAlgorithm::Ed25519,
            &candidate_public_key,
            &candidate_private_key,
            stored_nonce.clone(),
        );
        let path = temp_config_path("persist-key-mismatch");
        let config_handle = save_config(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: stored.public_key.clone(),
                private_key: stored.private_key.clone(),
                nonce: stored_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
        );
        let resolved = resolved_input(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: stored.public_key.clone(),
                private_key: stored.private_key.clone(),
                nonce: stored_nonce.clone().into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
            candidate_public_key.clone(),
            candidate_private_key.clone(),
        );

        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            resolved,
            &pow_result(
                better_candidate_nonce,
                &candidate_public_key,
                &candidate_private_key,
            ),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert_eq!(
            loaded.identity.expect("identity present").nonce,
            stored_nonce.into_inner()
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_better_nonce_keeps_unrelated_fresh_config_changes() {
        let keypair = test_support::ed25519_keypair();
        let public_key = veil_crypto::Base64PublicKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.public_key.clone(),
        )
        .expect("valid public key");
        let private_key = veil_crypto::Base64PrivateKey::new(
            SignatureAlgorithm::Ed25519,
            keypair.private_key.clone(),
        )
        .expect("valid private key");
        let current_nonce = veil_crypto::Base64Nonce::zero();
        let better_nonce = find_nonce_with_more_zero_bits(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            current_nonce.clone(),
        );
        let path = temp_config_path("persist-stale-snapshot");
        let config_handle = save_full_config(
            &path,
            veil_cfg::Config {
                identity: Some(veil_cfg::IdentityConfig {
                    algo: SignatureAlgorithm::Ed25519,
                    role: Default::default(),
                    public_key: keypair.public_key.clone(),
                    private_key: keypair.private_key.clone(),
                    nonce: current_nonce.clone().into_inner(),
                    node_id: None,
                    key_passphrase: None,
                    key_passphrase_file: None,
                    key_passphrase_prompt: false,
                    lazy_mining: true,
                    max_lazy_difficulty: 64,
                }),
                ..veil_cfg::Config::default()
            },
        );
        let stale_resolved = resolved_input(
            &path,
            veil_cfg::IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key.clone(),
                private_key: keypair.private_key.clone(),
                nonce: current_nonce.into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            },
            public_key.clone(),
            private_key.clone(),
        );

        veil_cfg::save_config(
            &path,
            &veil_cfg::Config {
                global: veil_cfg::GlobalConfig {
                    runtime_flavor: RuntimeFlavor::CurrentThread,
                    ..veil_cfg::GlobalConfig::default()
                },
                identity: Some(veil_cfg::IdentityConfig {
                    algo: SignatureAlgorithm::Ed25519,
                    role: Default::default(),
                    public_key: keypair.public_key.clone(),
                    private_key: keypair.private_key.clone(),
                    nonce: veil_crypto::Base64Nonce::zero().into_inner(),
                    node_id: None,
                    key_passphrase: None,
                    key_passphrase_file: None,
                    key_passphrase_prompt: false,
                    lazy_mining: true,
                    max_lazy_difficulty: 64,
                }),
                ..veil_cfg::Config::default()
            },
        )
        .expect("config must save");

        NoncePersistencePolicy::persist_better_nonce(
            &config_handle,
            stale_resolved,
            &pow_result(better_nonce.clone(), &public_key, &private_key),
        )
        .unwrap();

        let loaded = veil_cfg::load_config(&path).expect("config must load");
        assert_eq!(loaded.global.runtime_flavor, RuntimeFlavor::CurrentThread);
        assert_eq!(
            loaded.identity.expect("identity present").nonce,
            better_nonce.into_inner()
        );

        let _ = fs::remove_file(&path);
    }

    fn resolved_input(
        path: &std::path::Path,
        identity: veil_cfg::IdentityConfig,
        public_key: veil_crypto::Base64PublicKey,
        private_key: veil_crypto::Base64PrivateKey,
    ) -> ResolvedPowInput {
        ResolvedPowInput {
            loaded: LoadedIdentityConfig::loaded(
                path.to_path_buf(),
                veil_cfg::Config {
                    identity: Some(identity),
                    ..veil_cfg::Config::default()
                },
            ),
            key_material: KeyMaterial {
                algo: SignatureAlgorithm::Ed25519,
                public_key,
                private_key,
            },
            start_from: veil_crypto::Base64Nonce::zero(),
            pow: veil_cfg::identity_ops::IdentityPowParams {
                difficulty: 1,
                timeout: Duration::from_secs(1),
                threads: 1,
            },
        }
    }

    fn resolved_missing_input(
        public_key: veil_crypto::Base64PublicKey,
        private_key: veil_crypto::Base64PrivateKey,
    ) -> ResolvedPowInput {
        ResolvedPowInput {
            loaded: LoadedIdentityConfig::missing(),
            key_material: KeyMaterial {
                algo: SignatureAlgorithm::Ed25519,
                public_key,
                private_key,
            },
            start_from: veil_crypto::Base64Nonce::zero(),
            pow: veil_cfg::identity_ops::IdentityPowParams {
                difficulty: 1,
                timeout: Duration::from_secs(1),
                threads: 1,
            },
        }
    }

    fn resolved_missing_identity(
        path: &std::path::Path,
        public_key: veil_crypto::Base64PublicKey,
        private_key: veil_crypto::Base64PrivateKey,
    ) -> ResolvedPowInput {
        ResolvedPowInput {
            loaded: LoadedIdentityConfig::loaded(path.to_path_buf(), veil_cfg::Config::default()),
            key_material: KeyMaterial {
                algo: SignatureAlgorithm::Ed25519,
                public_key,
                private_key,
            },
            start_from: veil_crypto::Base64Nonce::zero(),
            pow: veil_cfg::identity_ops::IdentityPowParams {
                difficulty: 1,
                timeout: Duration::from_secs(1),
                threads: 1,
            },
        }
    }

    fn save_config(
        path: &std::path::Path,
        identity: veil_cfg::IdentityConfig,
    ) -> ConfigHandle<'static, StdConfigOps> {
        save_full_config(
            path,
            veil_cfg::Config {
                identity: Some(identity),
                ..veil_cfg::Config::default()
            },
        )
    }

    fn save_full_config(
        path: &std::path::Path,
        config: veil_cfg::Config,
    ) -> ConfigHandle<'static, StdConfigOps> {
        veil_cfg::save_config(path, &config).expect("config must save");

        let ops = Box::leak(Box::new(StdConfigOps));
        let config_arg: &'static std::path::Path = Box::leak(path.to_path_buf().into_boxed_path());
        ConfigHandle::new(Some(config_arg), ops)
    }

    fn pow_result(
        nonce: veil_crypto::Base64Nonce,
        public_key: &veil_crypto::Base64PublicKey,
        private_key: &veil_crypto::Base64PrivateKey,
    ) -> veil_crypto::PowResult {
        let score =
            veil_crypto::pow_score(SignatureAlgorithm::Ed25519, public_key, private_key, &nonce)
                .expect("pow score");

        veil_crypto::PowResult {
            best_nonce: nonce.clone(),
            best_zero_bits: score.zero_bits,
            stopped_at: nonce,
            stop_reason: veil_crypto::PowStopReason::Found,
        }
    }

    fn find_nonce_with_more_zero_bits(
        algo: SignatureAlgorithm,
        public_key: &veil_crypto::Base64PublicKey,
        private_key: &veil_crypto::Base64PrivateKey,
        current_nonce: veil_crypto::Base64Nonce,
    ) -> veil_crypto::Base64Nonce {
        let current_score = veil_crypto::pow_score(algo, public_key, private_key, &current_nonce)
            .expect("pow score");
        find_nonce_with_min_zero_bits(algo, public_key, private_key, current_score.zero_bits + 1)
    }

    fn find_nonce_with_min_zero_bits(
        algo: SignatureAlgorithm,
        public_key: &veil_crypto::Base64PublicKey,
        private_key: &veil_crypto::Base64PrivateKey,
        min_zero_bits: u32,
    ) -> veil_crypto::Base64Nonce {
        veil_crypto::search_nonce(veil_crypto::PowParams {
            algo,
            public_key: public_key.clone(),
            private_key: private_key.clone(),
            target_zero_bits: min_zero_bits,
            timeout: Duration::from_secs(30),
            start_from: veil_crypto::Base64Nonce::zero(),
            threads: 1,
            progress: None,
        })
        .expect("pow result")
        .best_nonce
    }

    fn temp_config_path(prefix: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}.toml"))
    }
}
