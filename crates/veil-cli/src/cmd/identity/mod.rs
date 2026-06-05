mod input;
mod output;
mod persistence;
mod progress;
mod types;

use std::path::Path;

use veil_cfg;
use veil_cfg::identity_ops::IdentityProvisionParams;

use super::cli::{KeyCommand, KeyGenArgs, KeyNonceArgs};
use super::handlers::{CommandContext, ConfigMutation, ConfigOps};
use super::output::CommandIo;

use input::IdentityInputResolver;
use output::IdentityOutput;
use persistence::NoncePersistencePolicy;
use progress::IdentityProgressRunner;
use types::ResolvedKeyGen;

pub fn handle_key_command<I: CommandIo, O: ConfigOps>(
    context: CommandContext<'_, I, O>,
    command: KeyCommand,
) -> veil_cfg::Result<()> {
    IdentityService::handle_key_command(context, command)
}

pub(crate) struct IdentityService;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyGenDecision {
    ReuseExisting,
    GenerateAndOutput,
    GenerateAndSave,
}

impl IdentityService {
    pub(crate) fn handle_key_command<I: CommandIo, O: ConfigOps>(
        mut context: CommandContext<'_, I, O>,
        command: KeyCommand,
    ) -> veil_cfg::Result<()> {
        match command {
            KeyCommand::Gen(args) => Self::key_gen(&mut context, args),
            KeyCommand::Show => Self::key_show(&mut context),
            KeyCommand::Info => Self::key_info(&mut context),
            KeyCommand::Nonce(args) => Self::key_nonce(&mut context, args),
        }
    }

    pub(crate) fn generate_identity_with_nonce(
        io: &mut impl CommandIo,
        params: IdentityProvisionParams,
    ) -> veil_cfg::Result<veil_cfg::IdentityConfig> {
        IdentityProgressRunner::provision_identity(io, params)
    }

    fn key_gen<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        args: KeyGenArgs,
    ) -> veil_cfg::Result<()> {
        Self::key_gen_with(context, args, Self::generate_identity_with_nonce)
    }

    fn key_gen_with<I: CommandIo, O: ConfigOps, F>(
        context: &mut CommandContext<'_, I, O>,
        args: KeyGenArgs,
        generate_identity: F,
    ) -> veil_cfg::Result<()>
    where
        F: FnOnce(&mut I, IdentityProvisionParams) -> veil_cfg::Result<veil_cfg::IdentityConfig>,
    {
        let resolved = IdentityInputResolver::resolve_key_gen(&context.config(), &args)?;
        let decision = Self::decide_key_gen(context, &resolved, &args)?;

        if decision == KeyGenDecision::ReuseExisting {
            Self::emit_existing_keys_message(&mut context.io);
            return Ok(());
        }

        let generated = generate_identity(
            &mut context.io,
            IdentityProvisionParams {
                algo: resolved.algo,
                ..IdentityProvisionParams::default()
            },
        )?;

        Self::finish_key_gen(context, decision, generated)
    }

    fn decide_key_gen<I: CommandIo, O: ConfigOps>(
        context: &CommandContext<'_, I, O>,
        resolved: &ResolvedKeyGen,
        args: &KeyGenArgs,
    ) -> veil_cfg::Result<KeyGenDecision> {
        if resolved.should_output_only {
            return Ok(KeyGenDecision::GenerateAndOutput);
        }

        if !resolved.loaded.is_loaded() {
            context.config().load_existing().map(|_| ())?;
        }

        if !args.force
            && resolved
                .loaded
                .identity()
                .is_some_and(Self::has_key_material)
        {
            return Ok(KeyGenDecision::ReuseExisting);
        }

        Ok(KeyGenDecision::GenerateAndSave)
    }

    fn emit_existing_keys_message(io: &mut impl CommandIo) {
        IdentityOutput::emit_existing_keys_message(io);
    }

    fn finish_key_gen<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        decision: KeyGenDecision,
        generated: veil_cfg::IdentityConfig,
    ) -> veil_cfg::Result<()> {
        match decision {
            KeyGenDecision::ReuseExisting => Ok(()),
            KeyGenDecision::GenerateAndOutput => {
                IdentityOutput::emit_identity(&mut context.io, &generated);
                Ok(())
            }
            KeyGenDecision::GenerateAndSave => {
                let saved_path = Self::save_generated_identity(&context.config(), generated)?;
                IdentityOutput::emit_saved_path(&mut context.io, &saved_path);
                Ok(())
            }
        }
    }

    fn key_show<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
    ) -> veil_cfg::Result<()> {
        Self::with_identity_config(context, |io, _path, identity| {
            IdentityOutput::emit_identity(io, &identity.into_config());
            Ok(())
        })
    }

    fn key_info<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
    ) -> veil_cfg::Result<()> {
        IdentityOutput::emit_supported_algorithms(&mut context.io);

        // Show current identity difficulty and mining config if available.
        if let Ok((_, config)) = context.config().load_existing()
            && let Some(ref id) = config.identity
        {
            let difficulty = veil_cfg::identity::DomainIdentity::from_config(id)
                .ok()
                .and_then(|di| di.pow_score().ok())
                .map(|s| s.zero_bits)
                .unwrap_or(0);
            let node_id = id
                .node_id
                .as_ref()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".to_owned());
            let lazy = if id.lazy_mining {
                "enabled"
            } else {
                "disabled"
            };
            let max_diff = id.max_lazy_difficulty;

            context.io.emit(super::output::OutputEvent::message(format!(
                    "node_id: {node_id}\nalgorithm: {}\ndifficulty: {difficulty}\nlazy_mining: {lazy}\nmax_lazy_difficulty: {max_diff}",
                    id.algo
                )));
        }
        Ok(())
    }

    fn key_nonce<I: CommandIo, O: ConfigOps>(
        context: &mut CommandContext<'_, I, O>,
        args: KeyNonceArgs,
    ) -> veil_cfg::Result<()> {
        let resolved = IdentityInputResolver::resolve_pow_input(&context.config(), args)?;
        let result = IdentityProgressRunner::search_nonce(
            &mut context.io,
            resolved.key_material.clone(),
            resolved.start_from.clone(),
            resolved.pow.clone(),
        )?;

        NoncePersistencePolicy::persist_better_nonce(&context.config(), resolved, &result)?;
        IdentityOutput::emit_pow_result(&mut context.io, &result);
        Ok(())
    }

    fn with_identity_config<I: CommandIo, O: ConfigOps, T>(
        context: &mut CommandContext<'_, I, O>,
        action: impl FnOnce(&mut I, &Path, veil_cfg::DomainIdentity) -> veil_cfg::Result<T>,
    ) -> veil_cfg::Result<T> {
        let (path, config) = context.config().load_existing()?;
        let identity = veil_cfg::require_identity(&config)?;
        action(&mut context.io, &path, identity)
    }

    fn save_generated_identity<O: ConfigOps>(
        config: &super::handlers::ConfigHandle<'_, O>,
        mut identity: veil_cfg::IdentityConfig,
    ) -> veil_cfg::Result<std::path::PathBuf> {
        identity.node_id = Some(veil_cfg::NodeId::from_public_key(
            identity.algo,
            &identity.public_key,
        )?);
        config.update_existing(|path, config| {
            config.identity = Some(identity);
            Ok(ConfigMutation::save(path.to_path_buf()))
        })
    }

    fn has_key_material(identity: &veil_cfg::IdentityConfig) -> bool {
        !identity.public_key.is_empty() && !identity.private_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::{BufferIo, MockConfigOps};
    use crate::test_support;
    use std::cell::Cell;
    use std::path::PathBuf;

    mod unit {
        use super::*;
        use std::path::Path;

        struct NotFoundConfigOps;

        impl ConfigOps for NotFoundConfigOps {
            fn default_init_path(&self) -> PathBuf {
                PathBuf::from("/tmp/config.toml")
            }

            fn prepare_init_path(&self, path: &Path, _force: bool) -> veil_cfg::Result<PathBuf> {
                Ok(path.to_path_buf())
            }

            fn locate_config(&self, _config_arg: Option<&Path>) -> veil_cfg::Result<PathBuf> {
                Err(veil_cfg::ConfigError::NotFound)
            }

            fn read_raw_config(&self, _path: &Path) -> veil_cfg::Result<String> {
                unreachable!("not used in key gen tests")
            }

            fn load_config(&self, _path: &Path) -> veil_cfg::Result<veil_cfg::Config> {
                unreachable!("not used when config is missing")
            }

            fn save_config(
                &self,
                _path: &Path,
                _config: &veil_cfg::Config,
            ) -> veil_cfg::Result<()> {
                unreachable!("must fail before save")
            }

            fn write_raw_config(&self, _path: &Path, _content: &str) -> veil_cfg::Result<()> {
                unreachable!("must fail before raw-write")
            }
        }

        #[test]
        fn key_show_uses_loaded_identity() {
            let keypair = test_support::ed25519_keypair();
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: MockConfigOps {
                    locate_path: PathBuf::from("/tmp/config.toml"),
                    loaded_config: veil_cfg::Config {
                        identity: Some(veil_cfg::IdentityConfig {
                            algo: veil_cfg::SignatureAlgorithm::Ed25519,
                            role: Default::default(),
                            public_key: keypair.public_key.clone(),
                            private_key: keypair.private_key,
                            nonce: "AAAAAA==".to_owned(),
                            node_id: None,
                            key_passphrase: None,
                            key_passphrase_file: None,
                            key_passphrase_prompt: false,
                            lazy_mining: true,
                            max_lazy_difficulty: 64,
                        }),
                        ..veil_cfg::Config::default()
                    },
                    ..MockConfigOps::default()
                },
            };

            IdentityService::key_show(&mut context).unwrap();

            assert!(context.io.output.contains("algo: ed25519"));
            assert!(
                context
                    .io
                    .output
                    .contains(&format!("public_key: {}", keypair.public_key))
            );
        }

        #[test]
        fn key_gen_fails_before_generation_when_config_is_missing() {
            let called = Cell::new(false);
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: NotFoundConfigOps,
            };

            let err = IdentityService::key_gen_with(
                &mut context,
                KeyGenArgs {
                    force: false,
                    output: false,
                    algo: None,
                },
                |_io, _params| {
                    called.set(true);
                    Err(veil_cfg::ConfigError::PowWorkerDisconnected)
                },
            )
            .expect_err("missing config must fail before generation");

            assert!(matches!(err, veil_cfg::ConfigError::NotFound));
            assert!(!called.get(), "generation must not start");
            assert!(context.io.output.is_empty());
        }

        #[test]
        fn key_gen_saves_generated_identity_when_config_is_available() {
            let called = Cell::new(false);
            let keypair = test_support::ed25519_keypair();
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: MockConfigOps {
                    locate_path: PathBuf::from("/tmp/config.toml"),
                    loaded_config: veil_cfg::Config::default(),
                    ..MockConfigOps::default()
                },
            };

            IdentityService::key_gen_with(
                &mut context,
                KeyGenArgs {
                    force: false,
                    output: false,
                    algo: None,
                },
                |_io, params| {
                    called.set(true);
                    Ok(veil_cfg::IdentityConfig {
                        algo: params.algo,
                        role: Default::default(),
                        public_key: keypair.public_key.clone(),
                        private_key: keypair.private_key.clone(),
                        nonce: "AAAAAA==".to_owned(),
                        node_id: None,
                        key_passphrase: None,
                        key_passphrase_file: None,
                        key_passphrase_prompt: false,
                        lazy_mining: true,
                        max_lazy_difficulty: 64,
                    })
                },
            )
            .expect("generation must succeed");

            assert!(called.get(), "generation must be invoked");
            assert_eq!(context.io.output, "/tmp/config.toml\n");
        }

        #[test]
        fn key_gen_outputs_generated_identity_without_config_lookup() {
            let called = Cell::new(false);
            let keypair = test_support::ed25519_keypair();
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: NotFoundConfigOps,
            };

            IdentityService::key_gen_with(
                &mut context,
                KeyGenArgs {
                    force: false,
                    output: true,
                    algo: None,
                },
                |_io, params| {
                    called.set(true);
                    Ok(veil_cfg::IdentityConfig {
                        algo: params.algo,
                        role: Default::default(),
                        public_key: keypair.public_key.clone(),
                        private_key: keypair.private_key.clone(),
                        nonce: "AAAAAA==".to_owned(),
                        node_id: None,
                        key_passphrase: None,
                        key_passphrase_file: None,
                        key_passphrase_prompt: false,
                        lazy_mining: true,
                        max_lazy_difficulty: 64,
                    })
                },
            )
            .expect("output mode must not require config");

            assert!(called.get(), "generation must be invoked");
            assert!(context.io.output.contains("algo: ed25519"));
            assert!(
                context
                    .io
                    .output
                    .contains(&format!("public_key: {}", keypair.public_key))
            );
        }

        #[test]
        fn key_gen_reuses_existing_keys_without_generation() {
            let called = Cell::new(false);
            let keypair = test_support::ed25519_keypair();
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: MockConfigOps {
                    locate_path: PathBuf::from("/tmp/config.toml"),
                    loaded_config: veil_cfg::Config {
                        identity: Some(veil_cfg::IdentityConfig {
                            algo: veil_cfg::SignatureAlgorithm::Ed25519,
                            role: Default::default(),
                            public_key: keypair.public_key,
                            private_key: keypair.private_key,
                            nonce: "AAAAAA==".to_owned(),
                            node_id: None,
                            key_passphrase: None,
                            key_passphrase_file: None,
                            key_passphrase_prompt: false,
                            lazy_mining: true,
                            max_lazy_difficulty: 64,
                        }),
                        ..veil_cfg::Config::default()
                    },
                    ..MockConfigOps::default()
                },
            };

            IdentityService::key_gen_with(
                &mut context,
                KeyGenArgs {
                    force: false,
                    output: false,
                    algo: None,
                },
                |_io, _params| {
                    called.set(true);
                    Err(veil_cfg::ConfigError::PowWorkerDisconnected)
                },
            )
            .expect("existing keys must short-circuit");

            assert!(!called.get(), "generation must not be invoked");
            assert_eq!(
                context.io.output,
                "identity keys already exist in the config; use --force to overwrite them\n"
            );
        }

        #[test]
        fn key_gen_force_regenerates_even_when_keys_already_exist() {
            let called = Cell::new(false);
            let keypair = test_support::ed25519_keypair();
            let new_keypair = test_support::ed25519_keypair();
            let mut context = CommandContext {
                config_arg: None,
                io: BufferIo::default(),
                ops: MockConfigOps {
                    locate_path: PathBuf::from("/tmp/config.toml"),
                    loaded_config: veil_cfg::Config {
                        identity: Some(veil_cfg::IdentityConfig {
                            algo: veil_cfg::SignatureAlgorithm::Ed25519,
                            role: Default::default(),
                            public_key: keypair.public_key,
                            private_key: keypair.private_key,
                            nonce: "AAAAAA==".to_owned(),
                            node_id: None,
                            key_passphrase: None,
                            key_passphrase_file: None,
                            key_passphrase_prompt: false,
                            lazy_mining: true,
                            max_lazy_difficulty: 64,
                        }),
                        ..veil_cfg::Config::default()
                    },
                    ..MockConfigOps::default()
                },
            };

            IdentityService::key_gen_with(
                &mut context,
                KeyGenArgs {
                    force: true,
                    output: false,
                    algo: None,
                },
                |_io, params| {
                    called.set(true);
                    Ok(veil_cfg::IdentityConfig {
                        algo: params.algo,
                        role: Default::default(),
                        public_key: new_keypair.public_key.clone(),
                        private_key: new_keypair.private_key.clone(),
                        nonce: "AQAAAA==".to_owned(),
                        node_id: None,
                        key_passphrase: None,
                        key_passphrase_file: None,
                        key_passphrase_prompt: false,
                        lazy_mining: true,
                        max_lazy_difficulty: 64,
                    })
                },
            )
            .expect("force must bypass key reuse");

            assert!(called.get(), "generation must be invoked");
            assert_eq!(context.io.output, "/tmp/config.toml\n");
        }
    }

    mod integration_pow {
        use super::*;

        #[test]
        fn generate_identity_with_nonce_produces_valid_pow() {
            let mut io = BufferIo::default();
            let identity = IdentityService::generate_identity_with_nonce(
                &mut io,
                IdentityProvisionParams {
                    algo: veil_cfg::SignatureAlgorithm::Ed25519,
                    pow: test_support::fast_pow_params(),
                },
            )
            .unwrap();
            let score = veil_crypto::pow_score(
                identity.algo,
                &veil_crypto::Base64PublicKey::new(identity.algo, identity.public_key.clone())
                    .unwrap(),
                &veil_crypto::Base64PrivateKey::new(identity.algo, identity.private_key.clone())
                    .unwrap(),
                &veil_crypto::Base64Nonce::new(identity.nonce.clone()).unwrap(),
            )
            .unwrap();

            assert!(score.zero_bits >= 1);
        }
    }
}
